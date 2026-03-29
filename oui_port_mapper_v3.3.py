#!/usr/bin/env python3
"""
OUI Port Mapper v3.3
====================
Author:    Robare Pruyn
Copyright: Mediacast Network Solutions, Inc. 2026

Multi-platform network automation tool that locates devices by OUI prefix
across a campus switching fabric. Supports Cisco IOS/IOS-XE, Cisco NX-OS,
and Aruba AOS-CX with automatic platform detection.

Connects to a starting switch, identifies matching MAC addresses, and
recursively traces them through the switching fabric using CDP/LLDP
neighbor discovery and multi-MAC uplink heuristics until the actual
access port is found.

Supported Platforms:
  - Cisco IOS / IOS-XE  (Catalyst 9000, 3850, 3650, etc.)
  - Cisco NX-OS         (Nexus 9000, 7000, 5000, etc.)
  - Aruba AOS-CX        (CX 6300, 6400, 8xxx, etc.)

NOT Supported:
  - Ubiquiti UniFi (controller-managed, no usable SSH CLI)

Workflow:
  1. SSH to starting switch (auto-detect platform or use --platform flag)
  2. Pull ARP table → build MAC-to-IP lookup
  3. Pull MAC address table → filter by OUI prefix(es)
  4. Pull CDP/LLDP neighbors → build interface-to-neighbor map
  5. Classify each matching MAC:
     a. Access port (single MAC or no neighbor) → record it
     b. Uplink port (CDP/LLDP neighbor OR multiple MACs) → recurse into
        that downstream switch and repeat from step 2
  6. Export results to CSV
  7. Optionally shut/no-shut/port-cycle discovered ports (with confirmation)

Discovery Modes:
  Normal:   Follow OUI-matching MACs down through CDP/LLDP neighbors.
  Fan-out:  Visit ALL CDP/LLDP neighbors from the starting switch (depth 0
            only), then normal MAC-tracing at depth 1+. Required for
            routed-access designs where endpoint VLANs are L3-terminated
            at the edge and never trunked L2 to core.

Safety Features:
  - Access-port-only filter: shut/no-shut/port-cycle operations reject
    any record with notes (multi-MAC, uplink, not-resolved), port-channel
    or aggregate interface names, or unknown/missing interfaces.
  - Hostname-based dedup prevents revisiting the same switch via
    different VRF sub-interface IPs.
  - Fan-out limited to depth 0 to prevent runaway recursion through
    datacenter infrastructure.
  - Running-config only — no write mem / copy run start.
  - YES confirmation prompt (exact, case-sensitive) before any changes.
  - --dry-run flag shows planned changes without executing.

Requirements:
  pip install netmiko

Usage:
  # Auto-detect platform, single OUI
  python oui_port_mapper.py --core 10.1.1.1 --user admin --oui 00:1A:2B

  # Fan-out mode for routed-access venues, 10 concurrent workers
  python oui_port_mapper.py --core 10.1.1.1 --user admin --oui-file ouis.txt --fan-out --workers 10

  # Multiple OUIs, deeper recursion limit
  python oui_port_mapper.py --core 10.1.1.1 --user admin --oui-file ouis.txt --max-depth 8

  # Discover, then shut down from exported CSV
  python oui_port_mapper.py --from-csv inventory.csv --user admin --shutdown

  # Port-cycle from CSV (shut → wait 5s → no-shut)
  python oui_port_mapper.py --from-csv inventory.csv --user admin --port-cycle --cycle-delay 5

  # Track which VLANs are active per switch
  python oui_port_mapper.py --core 10.1.1.1 --user admin --oui 4C:A0:03 --track-vlans 21,22,23,24,25

  # Reassign ports to their correct tracked VLAN
  python oui_port_mapper.py --from-csv inventory.csv --user admin --vlan-assign --dry-run

Version History:
  v3.3  — VLAN reassignment (--vlan-assign) moves access ports to the
           tracked VLAN for their switch. Platform-aware commands for
           Cisco IOS/NX-OS and Aruba AOS-CX.
  v3.2  — Configurable MAC threshold (--mac-threshold) for dual-NIC
           devices. Management subnet filter (--mgmt-subnet) prevents
           recursion into LLDP-advertising endpoints. Fixed AOS-CX
           LLDP command and parser, AOS-CX LAG parser.
  v3.1  — VLAN tracking (--track-vlans) for per-switch VLAN activity
           reporting. CSV gains switch_tracked_vlan column.
  v3.0  — Fan-out mode (depth-0 only), concurrent threading, hostname
           dedup, access-port-only safety filter, port-cycle operation,
           MAC dedup in CSV export.
  v2.0  — Multi-platform support (IOS, NX-OS, AOS-CX), port-channel
           traversal, NX-OS ~~~ age field fix, recursive discovery.
  v1.0  — Initial single-hop core-only discovery.
"""

import argparse
import csv
import getpass
import logging
import re
import sys
import threading
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from typing import Optional

# ---------------------------------------------------------------------------
# netmiko import with helpful error
# ---------------------------------------------------------------------------
try:
    from netmiko import ConnectHandler
    from netmiko.ssh_autodetect import SSHDetect
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )
except ImportError:
    print("ERROR: netmiko is required.  Install with:  pip install netmiko")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DeviceRecord:
    """One discovered device pinned to a specific switch port."""
    switch_hostname: str
    switch_ip: str
    interface: str
    mac_address: str          # normalized xxxx.xxxx.xxxx (Cisco notation)
    ip_address: str           # from ARP; "unknown" if not found
    vlan: str
    matched_oui: str          # which OUI prefix triggered the match
    platform: str = ""        # detected platform of the switch
    discovery_depth: int = 0  # how many hops from the starting switch
    notes: str = ""           # additional context (e.g., "multi-MAC uplink, no neighbor")
    switch_tracked_vlan: str = ""  # active tracked VLAN(s) on this switch (from --track-vlans)


@dataclass
class Neighbor:
    """A CDP or LLDP neighbor learned on a local interface."""
    local_interface: str
    neighbor_hostname: str
    neighbor_ip: str
    neighbor_platform: str
    neighbor_interface: str
    protocol: str             # "CDP" or "LLDP"


@dataclass
class MacEntry:
    """A single MAC address table entry."""
    vlan: str
    mac_address: str          # normalized xxxx.xxxx.xxxx
    entry_type: str           # DYNAMIC, STATIC, etc.
    interface: str


# ---------------------------------------------------------------------------
# MAC address normalization
# ---------------------------------------------------------------------------

def normalize_mac_to_cisco(raw_mac: str) -> str:
    """
    Convert any MAC format to Cisco dotted notation: xxxx.xxxx.xxxx

    Accepts:
      00:1A:2B:3C:4D:5E   (colon-separated — Linux, Aruba)
      00-1A-2B-3C-4D-5E   (dash-separated — Windows)
      001a.2b3c.4d5e      (Cisco dotted)
      001A2B3C4D5E        (bare hex)

    Returns:
      001a.2b3c.4d5e
    """
    hex_only = re.sub(r'[^0-9a-fA-F]', '', raw_mac).lower()
    if len(hex_only) != 12:
        return raw_mac.lower()
    return f"{hex_only[0:4]}.{hex_only[4:8]}.{hex_only[8:12]}"


def normalize_oui_prefix(raw_oui: str) -> str:
    """
    Normalize an OUI to hex-only lowercase for prefix matching.
    '00:1A:2B' → '001a2b',  '001A2B' → '001a2b'
    """
    return re.sub(r'[^0-9a-fA-F]', '', raw_oui).lower()


def mac_matches_oui(mac_cisco: str, normalized_oui_list: list[str]) -> Optional[str]:
    """
    Check if a Cisco-format MAC matches any OUI prefix in the list.
    Returns the matched OUI string if found, None otherwise.
    Strictly prefix-based: the OUI hex is compared against the leading
    hex characters of the MAC.
    """
    mac_hex = mac_cisco.replace('.', '')
    for oui_prefix in normalized_oui_list:
        if mac_hex.startswith(oui_prefix):
            return oui_prefix
    return None


# ---------------------------------------------------------------------------
# Platform abstraction layer
# ---------------------------------------------------------------------------

class SwitchPlatform(ABC):
    """
    Abstract base class for platform-specific command syntax and output
    parsing.  Each supported platform (Cisco IOS, Aruba AOS-CX, etc.)
    subclasses this and implements the abstract methods.
    """

    # Human-readable platform name for logging and CSV output
    platform_name: str = "unknown"

    # netmiko device_type string
    netmiko_device_type: str = "autodetect"

    @abstractmethod
    def get_arp_command(self) -> str:
        """Return the CLI command to display the ARP table."""
        ...

    @abstractmethod
    def get_mac_table_command(self) -> str:
        """Return the CLI command to display the MAC address table."""
        ...

    @abstractmethod
    def get_neighbor_command(self) -> str:
        """Return the CLI command to display CDP/LLDP neighbor detail."""
        ...

    @abstractmethod
    def get_shutdown_commands(self, interface: str) -> list[str]:
        """Return config commands to shut down an interface."""
        ...

    @abstractmethod
    def get_no_shutdown_commands(self, interface: str) -> list[str]:
        """Return config commands to enable an interface."""
        ...

    @abstractmethod
    def get_vlan_assign_commands(self, interface: str, vlan: str) -> list[str]:
        """Return config commands to set an access port's VLAN."""
        ...

    @abstractmethod
    def parse_mac_table(self, raw_output: str) -> list[MacEntry]:
        """Parse MAC address table output into MacEntry objects."""
        ...

    @abstractmethod
    def parse_arp_table(self, raw_output: str) -> dict[str, str]:
        """Parse ARP table output into a MAC→IP lookup dict."""
        ...

    @abstractmethod
    def parse_neighbors(self, raw_output: str) -> list[Neighbor]:
        """Parse CDP/LLDP neighbor detail into Neighbor objects."""
        ...

    @abstractmethod
    def normalize_interface(self, raw_name: str) -> str:
        """Normalize an interface name to its full canonical form."""
        ...

    def get_port_channel_command(self) -> str:
        """
        Return the CLI command to display port-channel/LAG membership.
        Used to map logical port-channel interfaces to their physical
        member interfaces, which is critical for correlating MAC table
        entries (learned on port-channel) with CDP/LLDP neighbors
        (reported on physical members).
        """
        return ""  # Override in subclasses

    def parse_port_channel_members(self, raw_output: str) -> dict[str, list[str]]:
        """
        Parse port-channel summary output into a mapping of
        port-channel name → list of physical member interfaces.

        Returns:
            {"Port-channel1": ["GigabitEthernet1/0/49", "GigabitEthernet1/0/50"],
             "Port-channel2": ["GigabitEthernet1/0/51"]}
        """
        return {}  # Override in subclasses

    def get_hostname(self, connection) -> str:
        """Extract the switch hostname from the netmiko prompt."""
        prompt = connection.find_prompt()
        return re.sub(r'[#>]\s*$', '', prompt)


# ---------------------------------------------------------------------------
# Cisco IOS / IOS-XE platform
# ---------------------------------------------------------------------------

class CiscoIOSPlatform(SwitchPlatform):
    """
    Command syntax and output parsers for Cisco IOS and IOS-XE.
    Covers Catalyst 9000, 3850, 3650, 2960, and similar platforms.
    """

    platform_name = "cisco_ios"
    netmiko_device_type = "cisco_ios"

    def get_arp_command(self) -> str:
        return "show ip arp"

    def get_mac_table_command(self) -> str:
        return "show mac address-table"

    def get_neighbor_command(self) -> str:
        # Primary protocol for Cisco — CDP
        return "show cdp neighbors detail"

    def get_lldp_command(self) -> str:
        """Cisco also supports LLDP; we query both protocols."""
        return "show lldp neighbors detail"

    def get_shutdown_commands(self, interface: str) -> list[str]:
        return [f"interface {interface}", "shutdown"]

    def get_no_shutdown_commands(self, interface: str) -> list[str]:
        return [f"interface {interface}", "no shutdown"]

    def get_vlan_assign_commands(self, interface: str, vlan: str) -> list[str]:
        """Set access VLAN on a Cisco IOS/IOS-XE port with edge port hardening."""
        return [
            f"interface {interface}",
            f"switchport access vlan {vlan}",
            "spanning-tree portfast",
            "spanning-tree bpduguard enable",
        ]

    def parse_mac_table(self, raw_output: str) -> list[MacEntry]:
        """
        Parse Cisco IOS/IOS-XE 'show mac address-table' output.

        Expected format:
          Vlan    Mac Address       Type        Ports
          ----    -----------       --------    -----
             1    001a.2b3c.4d5e    DYNAMIC     Gi1/0/1
        """
        entries = []
        pattern = re.compile(
            r'^\s*(\d+)\s+'                                          # VLAN ID
            r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+' # MAC (Cisco dotted)
            r'(\S+)\s+'                                               # Type
            r'(\S+)',                                                  # Port
            re.MULTILINE
        )
        for match in pattern.finditer(raw_output):
            entries.append(MacEntry(
                vlan=match.group(1),
                mac_address=match.group(2).lower(),
                entry_type=match.group(3).upper(),
                interface=match.group(4),
            ))
        return entries

    def parse_arp_table(self, raw_output: str) -> dict[str, str]:
        """
        Parse Cisco 'show ip arp' output.

        Expected format:
          Internet  10.1.1.1   -   001a.2b3c.4d5e  ARPA   Vlan10
        """
        mac_to_ip: dict[str, str] = {}
        pattern = re.compile(
            r'Internet\s+'
            r'(\d+\.\d+\.\d+\.\d+)\s+'                               # IP
            r'[\d-]+\s+'                                               # Age
            r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+'  # MAC
            r'\S+',                                                    # Type
            re.MULTILINE
        )
        for match in pattern.finditer(raw_output):
            mac_to_ip[match.group(2).lower()] = match.group(1)
        return mac_to_ip

    def parse_neighbors(self, raw_output: str) -> list[Neighbor]:
        """
        Parse Cisco 'show cdp neighbors detail' output.
        Each neighbor block is separated by a line of dashes.
        """
        neighbors = []
        blocks = re.split(r'-{10,}', raw_output)

        for block in blocks:
            if not block.strip():
                continue

            device_id = re.search(r'Device ID:\s*(\S+)', block)
            # Try multiple IP address formats Cisco uses
            ip_match = re.search(
                r'(?:IP address|IPv4 Address|Management address\(es\))\s*:\s*'
                r'(\d+\.\d+\.\d+\.\d+)', block
            )
            if not ip_match:
                # IP sometimes on the next line after "Management address(es):"
                ip_match = re.search(
                    r'Management address\(es\):\s*\n\s*IP address:\s*'
                    r'(\d+\.\d+\.\d+\.\d+)', block
                )
            platform_match = re.search(r'Platform:\s*(.+?)(?:,|\n)', block)
            local_intf = re.search(r'Interface:\s*(\S+)', block)
            remote_intf = re.search(
                r'Port ID\s*\(outgoing port\):\s*(\S+)', block
            )

            if device_id and ip_match:
                neighbors.append(Neighbor(
                    local_interface=local_intf.group(1) if local_intf else "unknown",
                    neighbor_hostname=device_id.group(1).split('.')[0],
                    neighbor_ip=ip_match.group(1),
                    neighbor_platform=platform_match.group(1).strip() if platform_match else "unknown",
                    neighbor_interface=remote_intf.group(1) if remote_intf else "unknown",
                    protocol="CDP",
                ))

        return neighbors

    def parse_lldp_neighbors(self, raw_output: str) -> list[Neighbor]:
        """
        Parse Cisco 'show lldp neighbors detail' output.
        Structured similarly to CDP but with different field labels.
        """
        neighbors = []
        blocks = re.split(r'-{10,}', raw_output)

        for block in blocks:
            if not block.strip():
                continue

            sys_name = re.search(r'System Name:\s*(\S+)', block)
            ip_match = re.search(
                r'(?:Management Address|IP):\s*(\d+\.\d+\.\d+\.\d+)', block
            )
            local_intf = re.search(r'Local Intf:\s*(\S+)', block)
            remote_intf = re.search(r'Port id:\s*(\S+)', block)
            sys_desc = re.search(
                r'System Description:\s*(.+?)(?:\n\n|\Z)', block, re.DOTALL
            )

            if sys_name and ip_match:
                neighbors.append(Neighbor(
                    local_interface=local_intf.group(1) if local_intf else "unknown",
                    neighbor_hostname=sys_name.group(1).split('.')[0],
                    neighbor_ip=ip_match.group(1),
                    neighbor_platform=sys_desc.group(1).strip()[:80] if sys_desc else "unknown",
                    neighbor_interface=remote_intf.group(1) if remote_intf else "unknown",
                    protocol="LLDP",
                ))

        return neighbors

    def normalize_interface(self, raw_name: str) -> str:
        """
        Expand Cisco abbreviated interface names to full canonical form.
        Gi1/0/1 → GigabitEthernet1/0/1, Te1/0/1 → TenGigabitEthernet1/0/1
        """
        abbreviations = [
            (r'^Gi(\d)',  r'GigabitEthernet\1'),
            (r'^Te(\d)',  r'TenGigabitEthernet\1'),
            (r'^Tw(\d)',  r'TwentyFiveGigE\1'),
            (r'^Fo(\d)',  r'FortyGigabitEthernet\1'),
            (r'^Hu(\d)',  r'HundredGigE\1'),
            (r'^Fa(\d)',  r'FastEthernet\1'),
            (r'^Et(\d)',  r'Ethernet\1'),
            (r'^Po(\d)',  r'Port-channel\1'),
        ]
        for pattern, replacement in abbreviations:
            expanded = re.sub(pattern, replacement, raw_name)
            if expanded != raw_name:
                return expanded
        return raw_name

    def get_port_channel_command(self) -> str:
        return "show etherchannel summary"

    def parse_port_channel_members(self, raw_output: str) -> dict[str, list[str]]:
        """
        Parse IOS/IOS-XE 'show etherchannel summary' output.

        Expected format:
          Group  Port-channel  Protocol    Ports
          ------+-------------+-----------+------------------------------------
          1      Po1(SU)       LACP        Gi1/0/49(P)  Gi1/0/50(P)
          2      Po2(SU)       LACP        Te1/0/1(P)   Te1/0/2(P)

        Parenthetical flags: (P)=bundled, (s)=suspended, (D)=down, etc.
        We capture all members regardless of state — CDP/LLDP may still
        be running on suspended or down members.
        """
        channel_to_members: dict[str, list[str]] = {}

        # Match lines with a port-channel and member ports
        # Group number, Po<n>(flags), protocol, then member ports
        line_pattern = re.compile(
            r'^\s*\d+\s+'                # Group number
            r'(Po\d+)\(\S+\)\s+'         # Port-channel name with flags
            r'\S+\s+'                     # Protocol (LACP, PAgP, etc.)
            r'(.+)$',                     # Rest of line: member ports
            re.MULTILINE
        )

        for match in line_pattern.finditer(raw_output):
            po_name_abbrev = match.group(1)          # e.g., "Po1"
            members_raw = match.group(2)             # e.g., "Gi1/0/49(P)  Gi1/0/50(P)"

            # Normalize port-channel name
            po_name = self.normalize_interface(po_name_abbrev)

            # Extract each member interface, stripping the (flags)
            member_pattern = re.compile(r'(\S+?)\(\S+\)')
            members = []
            for member_match in member_pattern.finditer(members_raw):
                member_intf = self.normalize_interface(member_match.group(1))
                members.append(member_intf)

            if members:
                channel_to_members[po_name] = members
                # Also store under abbreviated name for fallback matching
                channel_to_members[po_name_abbrev] = members

        return channel_to_members


# ---------------------------------------------------------------------------
# Cisco NX-OS platform
# ---------------------------------------------------------------------------

class CiscoNXOSPlatform(CiscoIOSPlatform):
    """
    Command syntax and output parsers for Cisco NX-OS (Nexus).
    Covers Nexus 9000, 7000, 5000 series.

    Inherits from CiscoIOSPlatform because CDP/LLDP parsing and most
    commands are identical. Overrides only what differs:
      - MAC address table has extra columns (*, age, Secure, NTFY)
      - ARP table header format differs
      - Interface abbreviations differ (Eth1/1 instead of Gi1/0/1)
      - NX-OS uses 'copy running-config startup-config' to persist
        (this tool does NOT save to startup by default)
    """

    platform_name = "cisco_nxos"
    netmiko_device_type = "cisco_nxos"

    def get_vlan_assign_commands(self, interface: str, vlan: str) -> list[str]:
        """Set access VLAN on a Cisco NX-OS port with edge port hardening."""
        return [
            f"interface {interface}",
            f"switchport access vlan {vlan}",
            "spanning-tree port type edge",
            "spanning-tree bpduguard enable",
        ]

    def parse_mac_table(self, raw_output: str) -> list[MacEntry]:
        """
        Parse NX-OS 'show mac address-table' output.

        NX-OS format includes extra columns not present in IOS/IOS-XE:
          Legend:
            * - primary entry, G - Gateway MAC, (R) - Routed MAC, ...
           VLAN     MAC Address      Type      age     Secure NTFY Ports
          ---------+-----------------+--------+---------+------+----+----------
          *   10     001a.2b3c.4d5e   dynamic  0         F      F    Eth1/1
          +   20     aabb.ccdd.eeff   dynamic  0         F      F    Po1
          G    -     001a.2b3c.0001   static   -         F      F    sup-eth1(R)

        The leading flag character (*, +, G, ~) and the age/Secure/NTFY
        columns must be accounted for. We skip gateway (G) and routed (R)
        entries since they're not real learned MACs on physical ports.
        """
        entries = []

        # Pattern explanation:
        #   ^[*+~\s]   → leading flag character or whitespace
        #   \s*(\d+)   → VLAN ID (NX-OS uses '-' for non-VLAN entries; we
        #                 require a number to skip gateway/sup entries)
        #   \s+(xxxx.xxxx.xxxx) → MAC in Cisco dotted notation
        #   \s+(\S+)   → Type (dynamic, static)
        #   \s+\S+     → Age (number, -, or ~~~ on older NX-OS)
        #   \s+\S+     → Secure flag (F/T)
        #   \s+\S+     → NTFY flag (F/T)
        #   \s+(\S+)   → Port (Eth1/1, Po1, etc.)
        pattern = re.compile(
            r'^[*+~\s]\s*'
            r'(\d+)\s+'                                               # VLAN
            r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+'  # MAC
            r'(\S+)\s+'                                                # Type
            r'\S+\s+'                                                  # Age (~~~ or digits or -)
            r'\S+\s+'                                                  # Secure
            r'\S+\s+'                                                  # NTFY
            r'(\S+)',                                                   # Port
            re.MULTILINE
        )

        for match in pattern.finditer(raw_output):
            port = match.group(4)

            # Skip supervisor/internal ports — these aren't real access ports
            # sup-eth1(R), sup-eth1(R)(T), etc.
            if 'sup-eth' in port.lower() or '(R)' in port:
                continue

            entries.append(MacEntry(
                vlan=match.group(1),
                mac_address=match.group(2).lower(),
                entry_type=match.group(3).upper(),
                interface=port,
            ))

        return entries

    def parse_arp_table(self, raw_output: str) -> dict[str, str]:
        """
        Parse NX-OS 'show ip arp' output.

        NX-OS format:
          IP ARP Table for context default
          Total number of entries: 5
          Address         Age       MAC Address     Interface
          10.1.1.1        00:01:30  001a.2b3c.4d5e  Vlan10
          10.1.1.2        00:05:15  aabb.ccdd.eeff  Vlan10

        Key difference from IOS: no "Internet" prefix, no "ARPA" type.
        Age is in HH:MM:SS format instead of minutes.
        """
        mac_to_ip: dict[str, str] = {}

        pattern = re.compile(
            r'(\d+\.\d+\.\d+\.\d+)\s+'                               # IP
            r'\S+\s+'                                                  # Age (HH:MM:SS or -)
            r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+'  # MAC
            r'\S+',                                                    # Interface
            re.MULTILINE
        )

        for match in pattern.finditer(raw_output):
            mac_to_ip[match.group(2).lower()] = match.group(1)

        return mac_to_ip

    def normalize_interface(self, raw_name: str) -> str:
        """
        Expand NX-OS abbreviated interface names to full canonical form.

        NX-OS abbreviations differ from IOS:
          Eth1/1     → Ethernet1/1       (not GigabitEthernet)
          Po1        → port-channel1     (lowercase 'p' in NX-OS)
          Vlan10     → Vlan10            (already canonical)
          mgmt0      → mgmt0             (already canonical)

        Also handles the less common:
          Eth1/1/1   → Ethernet1/1/1     (FEX host interfaces)
        """
        abbreviations = [
            (r'^Eth(\d)',  r'Ethernet\1'),
            (r'^Po(\d)',   r'port-channel\1'),
        ]
        for pattern, replacement in abbreviations:
            expanded = re.sub(pattern, replacement, raw_name)
            if expanded != raw_name:
                return expanded
        return raw_name

    def get_port_channel_command(self) -> str:
        return "show port-channel summary"

    def parse_port_channel_members(self, raw_output: str) -> dict[str, list[str]]:
        """
        Parse NX-OS 'show port-channel summary' output.

        Expected format:
          Group Port-       Type     Protocol  Member Ports
                Channel
          -----+----------+---------+---------+---------------------------------
          1     Po1(SU)    Eth      LACP      Eth1/49(P)   Eth1/50(P)
          2     Po2(SU)    Eth      LACP      Eth1/51(P)   Eth1/52(P)

        NX-OS uses Eth abbreviations and lowercase port-channel naming.
        """
        channel_to_members: dict[str, list[str]] = {}

        line_pattern = re.compile(
            r'^\s*\d+\s+'                # Group number
            r'(Po\d+)\(\S+\)\s+'         # Port-channel with flags
            r'\S+\s+'                     # Type (Eth)
            r'\S+\s+'                     # Protocol (LACP, etc.)
            r'(.+)$',                     # Member ports
            re.MULTILINE
        )

        for match in line_pattern.finditer(raw_output):
            po_name_abbrev = match.group(1)          # "Po1"
            members_raw = match.group(2)             # "Eth1/49(P)   Eth1/50(P)"

            # Normalize: Po1 → port-channel1 on NX-OS
            po_name = self.normalize_interface(po_name_abbrev)

            member_pattern = re.compile(r'(\S+?)\(\S+\)')
            members = []
            for member_match in member_pattern.finditer(members_raw):
                member_intf = self.normalize_interface(member_match.group(1))
                members.append(member_intf)

            if members:
                channel_to_members[po_name] = members
                channel_to_members[po_name_abbrev] = members

        return channel_to_members


# ---------------------------------------------------------------------------
# Aruba AOS-CX platform
# ---------------------------------------------------------------------------

class ArubaAOSCXPlatform(SwitchPlatform):
    """
    Command syntax and output parsers for Aruba AOS-CX.
    Covers CX 6300, 6400, 8320, 8325, 8400, 10000 series.

    Key differences from Cisco:
      - Interface naming: 1/1/1 instead of GigabitEthernet1/0/1
      - Uses LLDP natively (CDP is optional/off by default)
      - MAC format in output: colon-separated (00:1a:2b:3c:4d:5e)
      - ARP output format differs
    """

    platform_name = "aruba_aoscx"
    netmiko_device_type = "aruba_aoscx"

    def get_arp_command(self) -> str:
        return "show arp"

    def get_mac_table_command(self) -> str:
        return "show mac-address-table"

    def get_neighbor_command(self) -> str:
        return "show lldp neighbor-info detail"

    def get_shutdown_commands(self, interface: str) -> list[str]:
        return [f"interface {interface}", "shutdown"]

    def get_no_shutdown_commands(self, interface: str) -> list[str]:
        return [f"interface {interface}", "no shutdown"]

    def get_vlan_assign_commands(self, interface: str, vlan: str) -> list[str]:
        """Set access VLAN on an Aruba AOS-CX port with edge port hardening."""
        return [
            f"interface {interface}",
            "no routing",
            f"vlan access {vlan}",
            "spanning-tree bpdu-guard",
            "spanning-tree port-type admin-edge",
        ]

    def parse_mac_table(self, raw_output: str) -> list[MacEntry]:
        """
        Parse AOS-CX 'show mac-address-table' output.

        Common formats across AOS-CX versions:

        Format A (tabular):
          MAC Address          VLAN     Type      Port
          --------------------------------------------------
          00:1a:2b:3c:4d:5e   10       dynamic   1/1/1

        Format B (some versions include additional columns):
          MAC Address          VLAN  Type      Port        From
          00:1a:2b:3c:4d:5e   10    dynamic   1/1/1       dynamic
        """
        entries = []

        # Pattern matches colon-separated MAC, VLAN, type, and AOS-CX port name
        # AOS-CX ports: 1/1/1, lag1, vlan10, etc.
        pattern = re.compile(
            r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+'   # MAC (colon-separated)
            r'(\d+)\s+'                                       # VLAN
            r'(\S+)\s+'                                       # Type (dynamic/static)
            r'(\S+)',                                          # Port
            re.MULTILINE
        )

        for match in pattern.finditer(raw_output):
            raw_mac = match.group(1)
            cisco_mac = normalize_mac_to_cisco(raw_mac)
            port_name = match.group(4)

            entries.append(MacEntry(
                vlan=match.group(2),
                mac_address=cisco_mac,
                entry_type=match.group(3).upper(),
                interface=port_name,
            ))

        return entries

    def parse_arp_table(self, raw_output: str) -> dict[str, str]:
        """
        Parse AOS-CX 'show arp' output.

        Typical format:
          IPv4 Address     MAC                Port       Physical Port  State
          -----------------------------------------------------------------------
          10.1.1.1         00:1a:2b:3c:4d:5e  vlan10     1/1/1          reachable
        """
        mac_to_ip: dict[str, str] = {}

        pattern = re.compile(
            r'(\d+\.\d+\.\d+\.\d+)\s+'                      # IP address
            r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})',      # MAC (colon-separated)
            re.MULTILINE
        )

        for match in pattern.finditer(raw_output):
            ip_address = match.group(1)
            cisco_mac = normalize_mac_to_cisco(match.group(2))
            mac_to_ip[cisco_mac] = ip_address

        return mac_to_ip

    def parse_neighbors(self, raw_output: str) -> list[Neighbor]:
        """
        Parse AOS-CX 'show lldp neighbor-info detail' output.

        Neighbor blocks are separated by lines of dashes (80+ chars).
        Key fields per block:
          Port                           : 1/1/2:1
          Neighbor System-Name           : SL203-48
          Neighbor Management-Address    : 10.10.0.48
          Neighbor System-Description    : Aruba R8S90A  FL.10.10.1070
          Neighbor Port-ID               : 1/1/51
        """
        neighbors = []

        # Split on the dash-separator lines between neighbor blocks
        blocks = re.split(r'-{20,}', raw_output)

        for block in blocks:
            if not block.strip():
                continue

            # Local port — "Port : 1/1/2:1"
            local_port_match = re.search(
                r'^Port\s+:\s*(\S+)', block, re.MULTILINE
            )
            # Neighbor hostname — "Neighbor System-Name : SL203-48"
            sys_name_match = re.search(
                r'Neighbor System-Name\s+:\s*(\S+)', block
            )
            # Neighbor management IP — "Neighbor Management-Address : 10.10.0.48"
            mgmt_ip_match = re.search(
                r'Neighbor Management-Address\s+:\s*'
                r'(\d+\.\d+\.\d+\.\d+)', block
            )
            # Neighbor remote port — "Neighbor Port-ID : 1/1/51"
            remote_port_match = re.search(
                r'Neighbor Port-ID\s+:\s*(\S+)', block
            )
            # Neighbor platform — "Neighbor System-Description : Aruba R8S90A ..."
            sys_desc_match = re.search(
                r'Neighbor System-Description\s+:\s*(.+)', block
            )

            # Must have at least hostname and management IP to be useful
            if sys_name_match and mgmt_ip_match:
                neighbors.append(Neighbor(
                    local_interface=(
                        local_port_match.group(1)
                        if local_port_match else "unknown"
                    ),
                    neighbor_hostname=sys_name_match.group(1).strip(),
                    neighbor_ip=mgmt_ip_match.group(1),
                    neighbor_platform=(
                        sys_desc_match.group(1).strip()[:80]
                        if sys_desc_match else "unknown"
                    ),
                    neighbor_interface=(
                        remote_port_match.group(1)
                        if remote_port_match else "unknown"
                    ),
                    protocol="LLDP",
                ))

        return neighbors

    def normalize_interface(self, raw_name: str) -> str:
        """
        AOS-CX interface names are already in canonical form: 1/1/1, lag1, etc.
        No abbreviation expansion needed, but we normalize whitespace and case.
        """
        return raw_name.strip()

    def get_port_channel_command(self) -> str:
        return "show lag"

    def parse_port_channel_members(self, raw_output: str) -> dict[str, list[str]]:
        """
        Parse AOS-CX 'show lag' output.

        Format:
          Aggregate lag1 is up
           Aggregated-interfaces       : 1/1/2:1
           ...

          Aggregate lag127 is up
           Aggregated-interfaces       : 1/1/27 1/1/28
           ...

        Members are space-separated on the Aggregated-interfaces line.
        Some LAGs have empty member lists (down, no interfaces assigned).
        Interface names can include breakout notation (1/1/2:1).
        """
        channel_to_members: dict[str, list[str]] = {}

        # Split on "Aggregate lagN" headers
        blocks = re.split(r'(?=Aggregate\s+lag\d+\s+is\s+)', raw_output)

        for block in blocks:
            # Extract LAG name from header: "Aggregate lag2 is up"
            header_match = re.search(
                r'Aggregate\s+(lag\d+)\s+is\s+', block
            )
            if not header_match:
                continue

            lag_name = header_match.group(1).lower()

            # Extract members: "Aggregated-interfaces : 1/1/2:1"
            # or multi-member: "Aggregated-interfaces : 1/1/27 1/1/28"
            # or empty: "Aggregated-interfaces       : "
            members_match = re.search(
                r'Aggregated-interfaces\s*:\s*(.*)', block
            )
            if not members_match:
                continue

            members_str = members_match.group(1).strip()
            if not members_str:
                continue  # empty LAG, no members assigned

            # Split space-separated interface names
            # Handles both 1/1/2:1 (breakout) and 1/1/27 (non-breakout)
            members = [
                m.strip() for m in members_str.split()
                if re.match(r'\d+/\d+/\d+', m.strip())
            ]

            if members:
                channel_to_members[lag_name] = members

        return channel_to_members


# ---------------------------------------------------------------------------
# Platform detection and factory
# ---------------------------------------------------------------------------

# Map netmiko device_type strings to our platform classes
PLATFORM_MAP: dict[str, type[SwitchPlatform]] = {
    "cisco_ios":      CiscoIOSPlatform,
    "cisco_xe":       CiscoIOSPlatform,   # IOS-XE uses same syntax as IOS
    "cisco_nxos":     CiscoNXOSPlatform,
    "aruba_aoscx":     ArubaAOSCXPlatform,
    "aruba_osswitch": ArubaAOSCXPlatform, # close enough for our parsers
}

# Patterns in 'show version' output to identify platform
VERSION_FINGERPRINTS: list[tuple[str, str]] = [
    (r'Cisco IOS Software',    "cisco_ios"),
    (r'Cisco IOS XE Software', "cisco_ios"),
    (r'Cisco IOS-XE',         "cisco_ios"),
    (r'Cisco Nexus',          "cisco_nxos"),
    (r'ArubaOS-CX',           "aruba_aoscx"),
    (r'Aruba.*CX',            "aruba_aoscx"),
    (r'AOS-CX',               "aruba_aoscx"),
    (r'HP.*Aruba',            "aruba_aoscx"),
]


def detect_platform(
    host: str,
    username: str,
    password: str,
    enable_secret: str,
    log: logging.Logger,
) -> tuple[Optional[str], Optional[object]]:
    """
    Auto-detect the platform of a network device by SSH fingerprinting.

    Uses netmiko's SSHDetect first, then validates with 'show version'
    output if needed. Returns (device_type, active_connection) or
    (None, None) on failure.

    The connection is returned still open so the caller doesn't have to
    reconnect after detection.
    """
    log.info(f"Auto-detecting platform for {host}...")

    # --- Attempt 1: netmiko SSHDetect ---
    try:
        detect_params = {
            "device_type": "autodetect",
            "host": host,
            "username": username,
            "password": password,
            "secret": enable_secret,
            "timeout": 30,
        }
        detector = SSHDetect(**detect_params)
        best_match = detector.autodetect()
        log.info(f"SSHDetect result for {host}: {best_match}")

        if best_match and best_match in PLATFORM_MAP:
            # SSHDetect's internal connection is not fully set up for
            # reliable command execution, so disconnect and let the
            # caller reconnect with the proper device_type
            detector.connection.disconnect()
            return best_match, None

        if best_match:
            log.debug(
                f"SSHDetect returned '{best_match}' which is not in "
                f"our platform map; trying show version fingerprint"
            )
            detector.connection.disconnect()

    except Exception as exc:
        log.debug(f"SSHDetect failed for {host}: {exc}")

    # --- Attempt 2: Connect generic, run 'show version', fingerprint ---
    for try_type in ["cisco_ios", "cisco_nxos", "aruba_aoscx"]:
        try:
            conn_params = {
                "device_type": try_type,
                "host": host,
                "username": username,
                "password": password,
                "secret": enable_secret,
                "timeout": 30,
                "read_timeout_override": 30,
            }
            conn = ConnectHandler(**conn_params)
            conn.enable()

            version_output = conn.send_command("show version")

            for pattern, device_type in VERSION_FINGERPRINTS:
                if re.search(pattern, version_output, re.IGNORECASE):
                    log.info(
                        f"Fingerprinted {host} as {device_type} "
                        f"via 'show version'"
                    )
                    # If we connected with the right type, return the
                    # live connection so the caller doesn't have to reconnect
                    if try_type == device_type or (
                        try_type == "cisco_ios"
                        and device_type == "cisco_ios"
                    ):
                        return device_type, conn
                    else:
                        conn.disconnect()
                        return device_type, None

            # No fingerprint matched but we got a working session
            log.warning(
                f"Could not fingerprint {host} from show version; "
                f"falling back to {try_type}"
            )
            return try_type, conn

        except Exception as exc:
            log.debug(f"Connection as {try_type} to {host} failed: {exc}")
            continue

    log.error(f"Platform auto-detection failed for {host}")
    return None, None


def get_platform(device_type: str) -> SwitchPlatform:
    """
    Factory: return a SwitchPlatform instance for the given netmiko
    device_type string. Falls back to CiscoIOSPlatform if unknown.
    """
    platform_class = PLATFORM_MAP.get(device_type, CiscoIOSPlatform)
    return platform_class()


# ---------------------------------------------------------------------------
# Core automation engine
# ---------------------------------------------------------------------------

class OUIPortMapper:
    """
    Main discovery engine. Recursively traverses a switching fabric
    to locate devices by OUI prefix.
    """

    # Multi-MAC threshold: if a port has MORE than this many MACs learned
    # on it, treat it as a trunk/uplink rather than an access port.
    # Default 1: a port with 2+ MACs is flagged as multi-MAC.
    # For venues with dual-NIC devices (e.g., VITEC encoders),
    # set to 2 or 3 via --mac-threshold.
    DEFAULT_MAC_THRESHOLD = 1

    def __init__(
        self,
        core_ip: str,
        username: str,
        password: str,
        oui_list: list[str],
        enable_secret: str = "",
        forced_platform: Optional[str] = None,
        output_file: str = "oui_port_inventory.csv",
        max_depth: int = 10,
        fan_out: bool = False,
        max_workers: int = 10,
        mac_threshold: int = 1,
        mgmt_subnet: str = "",
        track_vlans: Optional[list[str]] = None,
        dry_run: bool = False,
        verbose: bool = False,
    ):
        self.core_ip = core_ip
        self.username = username
        self.password = password
        self.enable_secret = enable_secret or password
        self.forced_platform = forced_platform
        self.output_file = output_file
        self.max_depth = max_depth
        self.fan_out = fan_out
        self.max_workers = max_workers
        self.mac_threshold = mac_threshold
        self.dry_run = dry_run

        # Management subnet filter: if set, only recurse into neighbors
        # whose management IP falls within this subnet. Prevents the
        # tool from trying to SSH into endpoints (e.g., VITEC encoders)
        # that advertise LLDP but aren't switches.
        self.mgmt_subnet = None
        if mgmt_subnet:
            import ipaddress
            self.mgmt_subnet = ipaddress.ip_network(mgmt_subnet, strict=False)

        # Normalize OUIs for prefix matching
        self.normalized_oui_list = [normalize_oui_prefix(o) for o in oui_list]

        # Global MAC→IP lookup, merged from ARP tables across all switches
        self.mac_to_ip_lookup: dict[str, str] = {}

        # Discovery results
        self.discovered_records: list[DeviceRecord] = []

        # Track visited switches by BOTH IP and hostname to prevent
        # revisiting the same switch via different VRF sub-interface IPs.
        # Key: switch IP, Value: detected platform string
        self.visited_switches: dict[str, str] = {}
        # Hostname dedup: case-insensitive set of visited hostnames
        self.visited_hostnames: set[str] = set()

        # Set of MAC addresses that have been definitively located on an
        # access port. Used to avoid duplicate recording when a MAC is
        # visible at multiple points in the fabric.
        self.resolved_macs: set[str] = set()

        # Thread lock for shared state in concurrent fan-out
        self._lock = threading.Lock()

        # VLAN tracking: --track-vlans records which of the specified
        # VLANs have active MAC entries on each visited switch.
        # Used to determine "which IPTV VLAN belongs to this IDF."
        self.track_vlans: list[str] = track_vlans or []
        # Map: hostname (lowercase) → set of active tracked VLAN IDs
        self.switch_vlan_map: dict[str, set[str]] = {}

        # Logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        )
        self.log = logging.getLogger("oui_mapper")

    # ------------------------------------------------------------------
    # SSH connection helpers
    # ------------------------------------------------------------------

    def _connect(
        self,
        target_ip: str,
        device_type: Optional[str] = None,
    ) -> tuple[Optional[object], Optional[SwitchPlatform]]:
        """
        SSH to a switch. Auto-detects platform unless device_type is
        specified. Returns (connection, platform) or (None, None).
        """
        # Determine device type to use
        if device_type:
            resolved_type = device_type
            reuse_conn = None
        elif self.forced_platform:
            resolved_type = self.forced_platform
            reuse_conn = None
        elif target_ip in self.visited_switches:
            # We've seen this switch before; use cached platform
            resolved_type = self.visited_switches[target_ip]
            reuse_conn = None
        else:
            # Auto-detect
            resolved_type, reuse_conn = detect_platform(
                host=target_ip,
                username=self.username,
                password=self.password,
                enable_secret=self.enable_secret,
                log=self.log,
            )
            if not resolved_type:
                return None, None

        platform = get_platform(resolved_type)

        # If auto-detection returned an open connection, reuse it
        if reuse_conn:
            self.log.info(
                f"Connected to {target_ip} "
                f"(platform: {platform.platform_name})"
            )
            return reuse_conn, platform

        # Connect fresh
        try:
            conn_params = {
                "device_type": resolved_type,
                "host": target_ip,
                "username": self.username,
                "password": self.password,
                "secret": self.enable_secret,
                "timeout": 30,
                "read_timeout_override": 90,
            }
            self.log.info(
                f"Connecting to {target_ip} "
                f"(platform: {platform.platform_name})..."
            )
            connection = ConnectHandler(**conn_params)
            connection.enable()
            return connection, platform

        except NetmikoAuthenticationException:
            self.log.error(f"Authentication failed for {target_ip}")
            return None, None
        except NetmikoTimeoutException:
            self.log.error(f"Connection timed out for {target_ip}")
            return None, None
        except Exception as exc:
            self.log.error(f"Connection error for {target_ip}: {exc}")
            return None, None

    # ------------------------------------------------------------------
    # Neighbor collection (handles both CDP and LLDP on Cisco)
    # ------------------------------------------------------------------

    def _collect_neighbors(
        self,
        connection,
        platform: SwitchPlatform,
    ) -> list[Neighbor]:
        """
        Collect all neighbors from a switch. On Cisco, queries both
        CDP and LLDP. On Aruba, uses LLDP only. Deduplicates by
        (local_interface, neighbor_ip).
        """
        all_neighbors: list[Neighbor] = []

        # Primary neighbor protocol for this platform
        primary_cmd = platform.get_neighbor_command()
        self.log.debug(f"Running: {primary_cmd}")
        primary_output = connection.send_command(primary_cmd)
        all_neighbors.extend(platform.parse_neighbors(primary_output))

        # On Cisco, also query LLDP (some mixed-vendor links only run LLDP)
        if isinstance(platform, CiscoIOSPlatform):
            lldp_cmd = platform.get_lldp_command()
            self.log.debug(f"Running: {lldp_cmd}")
            try:
                lldp_output = connection.send_command(lldp_cmd)
                lldp_neighbors = platform.parse_lldp_neighbors(lldp_output)
                all_neighbors.extend(lldp_neighbors)
            except Exception:
                self.log.debug("LLDP query failed (may not be enabled)")

        # Deduplicate: prefer CDP over LLDP when both report the same neighbor
        seen: dict[tuple, Neighbor] = {}
        for nbr in all_neighbors:
            key = (
                platform.normalize_interface(nbr.local_interface),
                nbr.neighbor_ip,
            )
            if key not in seen or nbr.protocol == "CDP":
                seen[key] = nbr

        deduped = list(seen.values())
        cdp_count = sum(1 for n in deduped if n.protocol == "CDP")
        lldp_count = sum(1 for n in deduped if n.protocol == "LLDP")
        self.log.info(
            f"Neighbors: {len(deduped)} unique "
            f"({cdp_count} CDP, {lldp_count} LLDP)"
        )
        return deduped

    # ------------------------------------------------------------------
    # Management subnet filter
    # ------------------------------------------------------------------

    def _ip_in_mgmt_subnet(self, ip_address: str) -> bool:
        """
        Check if an IP is within the management subnet filter.
        Returns True if no filter is set, or if the IP matches.
        """
        if not self.mgmt_subnet:
            return True  # no filter — allow all
        import ipaddress
        try:
            return ipaddress.ip_address(ip_address) in self.mgmt_subnet
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Recursive discovery engine
    # ------------------------------------------------------------------

    def discover(self) -> list[DeviceRecord]:
        """Entry point: start recursive discovery from the core switch."""
        self.log.info(f"Starting OUI discovery from {self.core_ip}")
        self.log.info(
            f"OUI prefixes: {', '.join(self.normalized_oui_list)}"
        )
        self.log.info(f"Max traversal depth: {self.max_depth}")
        if self.mac_threshold > 1:
            self.log.info(
                f"MAC threshold: {self.mac_threshold} "
                f"(ports with ≤{self.mac_threshold} MACs treated as access)"
            )
        if self.mgmt_subnet:
            self.log.info(
                f"Management subnet filter: {self.mgmt_subnet}"
            )
        if self.fan_out:
            self.log.info(
                "Fan-out mode: will visit ALL CDP/LLDP neighbors, "
                "not just switches with matching MACs"
            )

        self._discover_switch(
            switch_ip=self.core_ip,
            current_depth=0,
            trail="core",
        )

        self.log.info(
            f"\nDiscovery complete. "
            f"{len(self.discovered_records)} device(s) found across "
            f"{len(self.visited_switches)} switch(es)."
        )

        # Print tracked VLAN summary if --track-vlans was used
        if self.track_vlans and self.switch_vlan_map:
            print(f"\n{'='*70}")
            print(f"  TRACKED VLAN SUMMARY  (VLANs: "
                  f"{', '.join(self.track_vlans)})")
            print(f"{'='*70}")
            for host_key in sorted(self.switch_vlan_map.keys()):
                active = self.switch_vlan_map[host_key]
                if active:
                    vlan_str = ", ".join(sorted(active))
                    print(f"  {host_key:40s}  → VLAN {vlan_str}")
            # Show switches with no tracked VLANs active
            hosts_without = set(self.visited_hostnames) - set(
                h for h, v in self.switch_vlan_map.items() if v
            )
            if hosts_without:
                print(f"  {'--- no tracked VLANs ---':^70s}")
                for h in sorted(hosts_without):
                    print(f"  {h:40s}  → (none)")
            print(f"{'='*70}\n")

        return self.discovered_records

    def _discover_switch(
        self,
        switch_ip: str,
        current_depth: int,
        trail: str,
    ):
        """
        Recursive per-switch discovery. Connects to a switch, finds
        OUI-matching MACs, classifies ports as access or uplink, records
        access-port devices, and recurses into downstream switches for
        uplink-port MACs.

        Args:
            switch_ip:     Management IP of the switch to query
            current_depth: Current hop count from the starting switch
            trail:         Human-readable path for log context
        """
        # --- Guard: depth limit ---
        if current_depth > self.max_depth:
            self.log.warning(
                f"Max depth ({self.max_depth}) reached at {switch_ip}. "
                f"Trail: {trail}. Stopping this branch."
            )
            return

        # --- Guard: already visited ---
        if switch_ip in self.visited_switches:
            self.log.debug(
                f"Already visited {switch_ip}, skipping. Trail: {trail}"
            )
            return

        # --- Connect and detect platform ---
        connection, platform = self._connect(switch_ip)
        if not connection or not platform:
            self.log.error(
                f"Cannot connect to {switch_ip}. Trail: {trail}"
            )
            return

        hostname = platform.get_hostname(connection)
        hostname_key = hostname.lower().strip()

        # --- Guard: hostname-based dedup ---
        # The same switch can appear via different IPs (VRF sub-interfaces).
        # If we've already visited this hostname, disconnect and skip.
        with self._lock:
            if hostname_key in self.visited_hostnames:
                self.log.debug(
                    f"Already visited {hostname} via different IP, "
                    f"skipping {switch_ip}. Trail: {trail}"
                )
                connection.disconnect()
                return
            self.visited_hostnames.add(hostname_key)
            self.visited_switches[switch_ip] = platform.platform_name

        indent = "  " * min(current_depth, 5)  # cap indent for readability

        self.log.info(
            f"{indent}[depth={current_depth}] {hostname} "
            f"({switch_ip}) — {platform.platform_name}"
        )

        try:
            # --- Pull ARP table → merge into global MAC→IP lookup ---
            self.log.info(f"{indent}  Pulling ARP table...")
            arp_output = connection.send_command(platform.get_arp_command())
            local_arp = platform.parse_arp_table(arp_output)
            self.mac_to_ip_lookup.update(local_arp)
            self.log.info(f"{indent}  ARP entries: {len(local_arp)}")

            # --- Pull MAC address table → filter by OUI ---
            self.log.info(f"{indent}  Pulling MAC address table...")
            mac_output = connection.send_command(
                platform.get_mac_table_command()
            )
            all_mac_entries = platform.parse_mac_table(mac_output)
            self.log.info(
                f"{indent}  MAC entries: {len(all_mac_entries)} total"
            )

            # --- Track which monitored VLANs have active MACs ---
            # This determines "which IPTV VLAN is active on this IDF"
            active_tracked_vlans: set[str] = set()
            if self.track_vlans:
                for entry in all_mac_entries:
                    if entry.vlan in self.track_vlans:
                        active_tracked_vlans.add(entry.vlan)
                if active_tracked_vlans:
                    self.log.info(
                        f"{indent}  Tracked VLANs active: "
                        f"{', '.join(sorted(active_tracked_vlans))}"
                    )
                with self._lock:
                    self.switch_vlan_map[hostname_key] = active_tracked_vlans

            # String form for embedding in DeviceRecord
            tracked_vlan_str = ",".join(sorted(active_tracked_vlans))

            # Filter to OUI matches that haven't already been resolved
            matching_entries: list[tuple[MacEntry, str]] = []
            for entry in all_mac_entries:
                if entry.mac_address in self.resolved_macs:
                    continue  # already pinned to an access port elsewhere
                matched_oui = mac_matches_oui(
                    entry.mac_address, self.normalized_oui_list
                )
                if matched_oui:
                    matching_entries.append((entry, matched_oui))

            self.log.info(
                f"{indent}  OUI matches (unresolved): "
                f"{len(matching_entries)}"
            )

            if not matching_entries:
                if not (self.fan_out and current_depth == 0):
                    return
                self.log.info(
                    f"{indent}  No OUI matches here, but fan-out mode "
                    f"will check neighbors"
                )

            # --- Pull CDP/LLDP neighbors ---
            self.log.info(f"{indent}  Pulling neighbor tables...")
            neighbors = self._collect_neighbors(connection, platform)

            # Build neighbor lookup: normalized interface → Neighbor
            neighbor_by_intf: dict[str, Neighbor] = {}
            for nbr in neighbors:
                norm = platform.normalize_interface(nbr.local_interface)
                neighbor_by_intf[norm] = nbr
                neighbor_by_intf[nbr.local_interface] = nbr

            # --- Pull port-channel / LAG membership ---
            # This maps logical port-channel interfaces to their physical
            # member interfaces. Critical because MACs are learned on the
            # port-channel, but CDP/LLDP neighbors are on the members.
            po_cmd = platform.get_port_channel_command()
            port_channel_members: dict[str, list[str]] = {}
            if po_cmd:
                self.log.info(
                    f"{indent}  Pulling port-channel membership..."
                )
                po_output = connection.send_command(po_cmd)
                port_channel_members = platform.parse_port_channel_members(
                    po_output
                )
                if port_channel_members:
                    self.log.info(
                        f"{indent}  Port-channels: "
                        f"{len(port_channel_members)} found"
                    )
                    # Promote: if a port-channel has a member with a
                    # CDP/LLDP neighbor, register that neighbor under the
                    # port-channel name too so the classification loop
                    # finds it directly
                    for po_name, members in port_channel_members.items():
                        if po_name in neighbor_by_intf:
                            continue  # already has a direct neighbor entry
                        for member_intf in members:
                            norm_member = platform.normalize_interface(
                                member_intf
                            )
                            nbr = (
                                neighbor_by_intf.get(norm_member)
                                or neighbor_by_intf.get(member_intf)
                            )
                            if nbr:
                                # Register neighbor under the port-channel
                                # name so the MAC→neighbor lookup works
                                neighbor_by_intf[po_name] = nbr
                                norm_po = platform.normalize_interface(
                                    po_name
                                )
                                neighbor_by_intf[norm_po] = nbr
                                self.log.debug(
                                    f"{indent}    Mapped {po_name} → "
                                    f"{nbr.neighbor_hostname} "
                                    f"(via member {member_intf})"
                                )
                                break  # one neighbor is enough

            # --- Build per-port MAC count (multi-MAC heuristic) ---
            # Count ALL MACs per port (not just OUI matches) to detect
            # trunk/uplink ports vs. access ports
            mac_count_by_port: dict[str, int] = {}
            for entry in all_mac_entries:
                norm_port = platform.normalize_interface(entry.interface)
                mac_count_by_port[norm_port] = (
                    mac_count_by_port.get(norm_port, 0) + 1
                )
                mac_count_by_port[entry.interface] = (
                    mac_count_by_port.get(entry.interface, 0) + 1
                )

            # --- Classify each matching MAC ---
            recurse_targets: dict[str, list[tuple[MacEntry, str]]] = {}

            for entry, matched_oui in matching_entries:
                norm_port = platform.normalize_interface(entry.interface)

                # Is there a CDP/LLDP neighbor on this port?
                # (port-channel → member promotion above ensures this
                # works for both physical and logical interfaces)
                neighbor = (
                    neighbor_by_intf.get(norm_port)
                    or neighbor_by_intf.get(entry.interface)
                )

                # Multi-MAC heuristic: more than 1 MAC on this port?
                port_mac_count = max(
                    mac_count_by_port.get(norm_port, 0),
                    mac_count_by_port.get(entry.interface, 0),
                )
                is_multi_mac = port_mac_count > self.mac_threshold

                # If the neighbor is outside the management subnet,
                # it's an endpoint advertising LLDP (e.g., VITEC),
                # not a switch. Clear it so the MAC count heuristic
                # handles classification instead.
                if neighbor and not self._ip_in_mgmt_subnet(
                    neighbor.neighbor_ip
                ):
                    self.log.debug(
                        f"{indent}    {entry.mac_address} on "
                        f"{entry.interface} — neighbor "
                        f"{neighbor.neighbor_hostname} "
                        f"({neighbor.neighbor_ip}) outside mgmt "
                        f"subnet, treating as endpoint"
                    )
                    neighbor = None

                if neighbor:
                    # --- Known uplink: queue for recursion ---
                    nbr_ip = neighbor.neighbor_ip
                    if nbr_ip not in recurse_targets:
                        recurse_targets[nbr_ip] = []
                    recurse_targets[nbr_ip].append((entry, matched_oui))
                    self.log.debug(
                        f"{indent}    {entry.mac_address} on "
                        f"{entry.interface} → neighbor "
                        f"{neighbor.neighbor_hostname} ({nbr_ip}) "
                        f"[{neighbor.protocol}]"
                    )

                elif is_multi_mac:
                    # --- Multi-MAC port, no neighbor protocol data ---
                    # Likely an unmanaged switch, hub, or CDP/LLDP
                    # disabled on that link. We can't determine a
                    # management IP to recurse into, so record here.
                    ip_addr = self.mac_to_ip_lookup.get(
                        entry.mac_address, "unknown"
                    )
                    self.discovered_records.append(DeviceRecord(
                        switch_hostname=hostname,
                        switch_ip=switch_ip,
                        interface=entry.interface,
                        mac_address=entry.mac_address,
                        ip_address=ip_addr,
                        vlan=entry.vlan,
                        matched_oui=matched_oui,
                        platform=platform.platform_name,
                        discovery_depth=current_depth,
                        notes=(
                            f"multi-MAC port ({port_mac_count} MACs), "
                            f"no CDP/LLDP neighbor"
                        ),
                        switch_tracked_vlan=tracked_vlan_str,
                    ))
                    # NOTE: Do NOT add to resolved_macs here. Multi-MAC
                    # uplink records are "best effort" — if the same MAC
                    # is later found on a clean access port on the actual
                    # edge switch, that find should take priority. The
                    # CSV dedup prefers clean records over noted ones.
                    self.log.info(
                        f"{indent}    {entry.mac_address} on "
                        f"{entry.interface} — multi-MAC "
                        f"({port_mac_count}), no neighbor "
                        f"(recording here)"
                    )

                else:
                    # --- Access port: endpoint found ---
                    ip_addr = self.mac_to_ip_lookup.get(
                        entry.mac_address, "unknown"
                    )
                    self.discovered_records.append(DeviceRecord(
                        switch_hostname=hostname,
                        switch_ip=switch_ip,
                        interface=entry.interface,
                        mac_address=entry.mac_address,
                        ip_address=ip_addr,
                        vlan=entry.vlan,
                        matched_oui=matched_oui,
                        platform=platform.platform_name,
                        discovery_depth=current_depth,
                        switch_tracked_vlan=tracked_vlan_str,
                    ))
                    self.resolved_macs.add(entry.mac_address)
                    self.log.info(
                        f"{indent}    FOUND: {entry.mac_address} "
                        f"({ip_addr}) → {hostname} {entry.interface} "
                        f"VLAN {entry.vlan}"
                    )

        finally:
            connection.disconnect()
            self.log.debug(f"{indent}  Disconnected from {hostname}")

        # --- Recurse into downstream switches ---
        if self.fan_out and current_depth == 0:
            # Fan-out mode (starting switch only): visit EVERY CDP/LLDP
            # neighbor concurrently. This catches devices on VLANs that
            # are L3-terminated at the edge and never appear in the
            # core's MAC table. Fan-out does NOT propagate — edge
            # switches use normal MAC-tracing recursion only.
            all_neighbor_ips: dict[str, str] = {}  # IP → hostname
            for nbr in neighbors:
                if nbr.neighbor_ip not in all_neighbor_ips:
                    all_neighbor_ips[nbr.neighbor_ip] = nbr.neighbor_hostname

            # Pre-filter: skip neighbors whose hostname we've already
            # visited (catches multi-IP same-switch cases cheaply)
            targets: list[tuple[str, str]] = []
            for nbr_ip, nbr_name in all_neighbor_ips.items():
                nbr_key = nbr_name.lower().strip()
                with self._lock:
                    already_done = (
                        nbr_ip in self.visited_switches
                        or nbr_key in self.visited_hostnames
                    )
                if already_done:
                    self.log.debug(
                        f"{indent}    Skipping {nbr_name} ({nbr_ip}) "
                        f"— already visited"
                    )
                    continue
                if not self._ip_in_mgmt_subnet(nbr_ip):
                    self.log.debug(
                        f"{indent}    Skipping {nbr_name} ({nbr_ip}) "
                        f"— outside management subnet"
                    )
                    continue
                targets.append((nbr_ip, nbr_name))

            self.log.info(
                f"{indent}  Fan-out: {len(targets)} neighbor(s) to visit "
                f"({self.max_workers} concurrent workers)"
            )

            # --- Concurrent fan-out ---
            def _fan_out_worker(nbr_ip: str, nbr_name: str):
                """Worker function for concurrent fan-out."""
                new_trail = f"{trail} → {nbr_name}"
                self.log.info(
                    f"  Fan-out → {nbr_name} ({nbr_ip})..."
                )
                self._discover_switch(
                    switch_ip=nbr_ip,
                    current_depth=current_depth + 1,
                    trail=new_trail,
                )

            with ThreadPoolExecutor(
                max_workers=self.max_workers
            ) as executor:
                futures = {
                    executor.submit(_fan_out_worker, ip, name): (ip, name)
                    for ip, name in targets
                }
                for future in as_completed(futures):
                    ip, name = futures[future]
                    try:
                        future.result()
                    except Exception as exc:
                        self.log.error(
                            f"Fan-out worker for {name} ({ip}) "
                            f"failed: {exc}"
                        )

            # Handle any OUI-matching MACs that were on uplink ports
            # but didn't get resolved on the downstream switch
            for downstream_ip, mac_group in recurse_targets.items():
                for entry, matched_oui in mac_group:
                    if entry.mac_address in self.resolved_macs:
                        continue
                    ip_addr = self.mac_to_ip_lookup.get(
                        entry.mac_address, "unknown"
                    )
                    self.discovered_records.append(DeviceRecord(
                        switch_hostname=hostname,
                        switch_ip=switch_ip,
                        interface=entry.interface,
                        mac_address=entry.mac_address,
                        ip_address=ip_addr,
                        vlan=entry.vlan,
                        matched_oui=matched_oui,
                        platform=platform.platform_name,
                        discovery_depth=current_depth,
                        notes="on uplink, not resolved downstream",
                        switch_tracked_vlan=tracked_vlan_str,
                    ))
                    self.resolved_macs.add(entry.mac_address)

        else:
            # Normal mode (or fan-out at depth > 0): only recurse into
            # switches where matching MACs were found on uplink ports
            for downstream_ip, mac_group in recurse_targets.items():
                if downstream_ip in self.visited_switches:
                    # Already visited — record unresolved MACs at uplink
                    for entry, matched_oui in mac_group:
                        if entry.mac_address in self.resolved_macs:
                            continue
                        ip_addr = self.mac_to_ip_lookup.get(
                            entry.mac_address, "unknown"
                        )
                        self.discovered_records.append(DeviceRecord(
                            switch_hostname=hostname,
                            switch_ip=switch_ip,
                            interface=entry.interface,
                            mac_address=entry.mac_address,
                            ip_address=ip_addr,
                            vlan=entry.vlan,
                            matched_oui=matched_oui,
                            platform=platform.platform_name,
                            discovery_depth=current_depth,
                            notes="downstream already visited",
                            switch_tracked_vlan=tracked_vlan_str,
                        ))
                        self.resolved_macs.add(entry.mac_address)
                    continue

                # Skip neighbors outside management subnet (e.g., endpoints
                # advertising LLDP like VITEC encoders)
                if not self._ip_in_mgmt_subnet(downstream_ip):
                    self.log.debug(
                        f"{indent}    Skipping {downstream_ip} — "
                        f"outside management subnet "
                        f"{self.mgmt_subnet}"
                    )
                    # Record MACs here since we won't recurse
                    for entry, matched_oui in mac_group:
                        if entry.mac_address in self.resolved_macs:
                            continue
                        ip_addr = self.mac_to_ip_lookup.get(
                            entry.mac_address, "unknown"
                        )
                        self.discovered_records.append(DeviceRecord(
                            switch_hostname=hostname,
                            switch_ip=switch_ip,
                            interface=entry.interface,
                            mac_address=entry.mac_address,
                            ip_address=ip_addr,
                            vlan=entry.vlan,
                            matched_oui=matched_oui,
                            platform=platform.platform_name,
                            discovery_depth=current_depth,
                            notes="neighbor outside mgmt subnet",
                            switch_tracked_vlan=tracked_vlan_str,
                        ))
                        self.resolved_macs.add(entry.mac_address)
                    continue

                # Look up the neighbor hostname for readable logging
                downstream_name = downstream_ip
                for nbr in neighbors:
                    if nbr.neighbor_ip == downstream_ip:
                        downstream_name = nbr.neighbor_hostname
                        break

                new_trail = f"{trail} → {downstream_name}"
                self.log.info(
                    f"{indent}  Recursing → {downstream_name} "
                    f"({downstream_ip})..."
                )

                # Recurse
                self._discover_switch(
                    switch_ip=downstream_ip,
                    current_depth=current_depth + 1,
                    trail=new_trail,
                )

                # After recursion, any MACs from this group that still
                # haven't been resolved get recorded at the uplink port
                for entry, matched_oui in mac_group:
                    if entry.mac_address in self.resolved_macs:
                        continue  # found downstream — good
                    ip_addr = self.mac_to_ip_lookup.get(
                        entry.mac_address, "unknown"
                    )
                    self.discovered_records.append(DeviceRecord(
                        switch_hostname=hostname,
                        switch_ip=switch_ip,
                        interface=entry.interface,
                        mac_address=entry.mac_address,
                        ip_address=ip_addr,
                        vlan=entry.vlan,
                        matched_oui=matched_oui,
                        platform=platform.platform_name,
                        discovery_depth=current_depth,
                        notes=(
                            f"not found on downstream "
                            f"{downstream_name}; recorded at uplink"
                        ),
                        switch_tracked_vlan=tracked_vlan_str,
                    ))
                    self.resolved_macs.add(entry.mac_address)

    # ------------------------------------------------------------------
    # CSV export / import
    # ------------------------------------------------------------------

    def export_csv(
        self,
        records: Optional[list[DeviceRecord]] = None,
        filename: Optional[str] = None,
    ) -> str:
        """Export discovered records to CSV, deduplicating by MAC address."""
        records = records or self.discovered_records
        filename = filename or self.output_file

        # Deduplicate by MAC address, preferring clean access-port finds
        # over multi-MAC uplink records. Sort so clean records (empty notes)
        # come first, then keep the first occurrence of each MAC.
        sorted_records = sorted(
            records,
            key=lambda r: (0 if not r.notes.strip() else 1)
        )
        seen_macs: set[str] = set()
        unique_records: list[DeviceRecord] = []
        for record in sorted_records:
            if record.mac_address not in seen_macs:
                seen_macs.add(record.mac_address)
                unique_records.append(record)

        if len(unique_records) < len(records):
            self.log.info(
                f"Deduped: {len(records)} → {len(unique_records)} "
                f"({len(records) - len(unique_records)} duplicates removed)"
            )

        csv_columns = [
            "switch_hostname", "switch_ip", "interface", "mac_address",
            "ip_address", "vlan", "matched_oui", "platform",
            "discovery_depth", "notes", "switch_tracked_vlan",
        ]

        with open(filename, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            for record in unique_records:
                writer.writerow(asdict(record))

        self.log.info(
            f"Exported {len(unique_records)} records to {filename}"
        )
        return filename

    @staticmethod
    def load_from_csv(filename: str) -> list[DeviceRecord]:
        """Load DeviceRecord list from a previously exported CSV."""
        records = []
        with open(filename, "r") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                row["discovery_depth"] = int(row.get("discovery_depth", 0))
                # Handle CSVs from older versions without tracked VLAN
                if "switch_tracked_vlan" not in row:
                    row["switch_tracked_vlan"] = ""
                records.append(DeviceRecord(**row))
        return records

    # ------------------------------------------------------------------
    # Port actions: shutdown / no shutdown
    # ------------------------------------------------------------------

    def toggle_ports(
        self,
        records: list[DeviceRecord],
        action: str = "shutdown",
    ):
        """
        Shut or no-shut interfaces for discovered devices.

        SAFETY: Only acts on clean access-port records. A port is
        considered safe to toggle if ALL of these are true:
          - Interface is a real port name (not "unknown", "not found", etc.)
          - Interface is not a port-channel, LAG, or virtual interface
          - Notes field is empty (clean find — single MAC, access port)
        Any record with notes (multi-MAC, uplink, not resolved, etc.)
        is automatically excluded.
        """
        if action not in ("shutdown", "no shutdown"):
            self.log.error(f"Invalid action: {action}")
            return

        # --- Strict access-port-only filter ---
        # Reject: unknown/missing interfaces
        skip_keywords = {"unknown", "not found", "unreachable"}
        # Reject: logical/aggregate interfaces (port-channels, LAGs, vPCs)
        trunk_keywords = {"port-channel", "po", "lag", "vpc", "peer-link"}

        actionable = []
        skipped_notes = 0
        skipped_trunk = 0
        skipped_bad_intf = 0

        for r in records:
            intf_lower = r.interface.lower()

            # Skip records with bad/missing interface names
            if any(kw in intf_lower for kw in skip_keywords):
                skipped_bad_intf += 1
                continue

            # Skip port-channels and logical interfaces
            if any(kw in intf_lower for kw in trunk_keywords):
                skipped_trunk += 1
                continue

            # Skip anything that isn't a clean access-port find
            # (multi-MAC, uplink, not resolved downstream, etc.)
            if r.notes.strip():
                skipped_notes += 1
                continue

            actionable.append(r)

        # Report filtering results
        total_skipped = skipped_notes + skipped_trunk + skipped_bad_intf
        if total_skipped > 0:
            self.log.info(
                f"Safety filter: {len(records)} total → "
                f"{len(actionable)} actionable "
                f"({skipped_notes} had notes, "
                f"{skipped_trunk} were trunk/aggregate ports, "
                f"{skipped_bad_intf} had bad interfaces)"
            )

        if not actionable:
            self.log.info("No actionable ports found after safety filter.")
            return

        # Display action plan
        print(f"\n{'='*80}")
        print(f"  PORT ACTION: {action.upper()}")
        print(f"  Ports to act on: {len(actionable)}  "
              f"(filtered from {len(records)} total records)")
        print(f"{'='*80}")
        for r in actionable:
            print(
                f"  {r.switch_hostname:22s} {r.interface:22s} "
                f"{r.mac_address}  {r.ip_address:15s}  {r.platform}"
            )
        print(f"{'='*80}\n")

        if self.dry_run:
            print("[DRY RUN] No changes will be made.")
            return

        confirm = input(
            f"Type 'YES' to {action} these {len(actionable)} port(s): "
        )
        if confirm != "YES":
            print("Aborted. No changes made.")
            return

        # Group by switch IP for efficient SSH sessions
        by_switch: dict[str, list[DeviceRecord]] = {}
        for r in actionable:
            by_switch.setdefault(r.switch_ip, []).append(r)

        for switch_ip, switch_records in by_switch.items():
            platform_name = switch_records[0].platform or "cisco_ios"
            platform = get_platform(platform_name)

            conn, _ = self._connect(switch_ip, device_type=platform_name)
            if not conn:
                self.log.error(
                    f"Cannot connect to {switch_ip} for port changes"
                )
                continue

            try:
                config_commands = []
                for r in switch_records:
                    if action == "shutdown":
                        cmds = platform.get_shutdown_commands(r.interface)
                    else:
                        cmds = platform.get_no_shutdown_commands(r.interface)
                    config_commands.extend(cmds)
                    self.log.info(
                        f"  {action}: {r.switch_hostname} {r.interface}"
                    )

                output = conn.send_config_set(config_commands)
                self.log.debug(f"Config output:\n{output}")
                # NOTE: Changes are in running-config ONLY.
                # A reload will revert them. To persist, manually
                # run 'write mem' / 'copy run start' on each switch.
                self.log.info(
                    f"Changes applied to running-config on {switch_ip} "
                    f"(NOT saved to startup)"
                )

            finally:
                conn.disconnect()

        print(f"\n{action.upper()} complete on {len(actionable)} port(s).")

    def cycle_ports(
        self,
        records: list[DeviceRecord],
        delay_seconds: int = 5,
    ):
        """
        Port-cycle: shutdown all matched access ports, wait, then
        no-shut them. Same safety filter as toggle_ports applies.

        Args:
            records:        List of DeviceRecord to act on
            delay_seconds:  Seconds to wait between shut and no-shut
        """
        self.log.info(
            f"Port cycle requested: shutdown → wait {delay_seconds}s "
            f"→ no shutdown"
        )

        # Run shutdown (includes safety filter + confirmation)
        self.toggle_ports(records, action="shutdown")

        # If dry_run, toggle_ports already printed the plan and returned
        if self.dry_run:
            print(
                f"[DRY RUN] Would wait {delay_seconds}s then "
                f"no-shut the same ports."
            )
            return

        # Wait
        print(f"\nWaiting {delay_seconds} seconds before re-enabling ports...")
        for remaining in range(delay_seconds, 0, -1):
            print(f"  {remaining}...", end="\r")
            time.sleep(1)
        print(f"  Delay complete.{' ' * 20}")

        # No-shut — skip confirmation since they already said YES
        print(f"\nRe-enabling ports...")
        self._execute_port_action(records, action="no shutdown")

        print(f"\nPort cycle complete.")

    def _execute_port_action(
        self,
        records: list[DeviceRecord],
        action: str,
    ):
        """
        Internal: execute a port action WITHOUT the confirmation prompt.
        Used by cycle_ports for the no-shut phase after the user already
        confirmed the shutdown. Same safety filter applies.
        """
        # Apply the same safety filter as toggle_ports
        skip_keywords = {"unknown", "not found", "unreachable"}
        trunk_keywords = {"port-channel", "po", "lag", "vpc", "peer-link"}

        actionable = [
            r for r in records
            if not any(kw in r.interface.lower() for kw in skip_keywords)
            and not any(kw in r.interface.lower() for kw in trunk_keywords)
            and not r.notes.strip()
        ]

        if not actionable:
            self.log.info("No actionable ports for no-shut phase.")
            return

        # Group by switch IP
        by_switch: dict[str, list[DeviceRecord]] = {}
        for r in actionable:
            by_switch.setdefault(r.switch_ip, []).append(r)

        for switch_ip, switch_records in by_switch.items():
            platform_name = switch_records[0].platform or "cisco_ios"
            platform = get_platform(platform_name)

            conn, _ = self._connect(switch_ip, device_type=platform_name)
            if not conn:
                self.log.error(
                    f"Cannot connect to {switch_ip} for port changes"
                )
                continue

            try:
                config_commands = []
                for r in switch_records:
                    cmds = platform.get_no_shutdown_commands(r.interface)
                    config_commands.extend(cmds)
                    self.log.info(
                        f"  no shutdown: {r.switch_hostname} {r.interface}"
                    )

                output = conn.send_config_set(config_commands)
                self.log.debug(f"Config output:\n{output}")
                self.log.info(
                    f"Changes applied to running-config on {switch_ip} "
                    f"(NOT saved to startup)"
                )

            finally:
                conn.disconnect()

        print(
            f"\nNO SHUTDOWN complete on {len(actionable)} port(s)."
        )

    def assign_vlans(
        self,
        records: list[DeviceRecord],
    ):
        """
        Reassign access port VLANs based on the switch_tracked_vlan
        field. For each device whose current VLAN differs from the
        tracked VLAN on its switch, push the VLAN change.

        SAFETY: Same access-port-only filter as toggle_ports. Also:
          - Skips devices already on the correct VLAN
          - Skips devices where switch_tracked_vlan is empty or
            contains multiple VLANs (ambiguous — e.g., core switch)
          - Requires YES confirmation
          - Running-config only
        """
        # --- Strict access-port-only filter ---
        skip_keywords = {"unknown", "not found", "unreachable"}
        trunk_keywords = {"port-channel", "po", "lag", "vpc", "peer-link"}

        actionable = []
        skipped_correct_vlan = 0
        skipped_ambiguous = 0
        skipped_no_tracked = 0
        skipped_notes = 0
        skipped_trunk = 0
        skipped_bad_intf = 0

        for r in records:
            intf_lower = r.interface.lower()

            # Skip bad/missing interfaces
            if any(kw in intf_lower for kw in skip_keywords):
                skipped_bad_intf += 1
                continue

            # Skip trunk/aggregate interfaces
            if any(kw in intf_lower for kw in trunk_keywords):
                skipped_trunk += 1
                continue

            # Skip anything that isn't a clean access-port find
            if r.notes.strip():
                skipped_notes += 1
                continue

            # Skip if no tracked VLAN data
            tracked = r.switch_tracked_vlan.strip()
            if not tracked:
                skipped_no_tracked += 1
                continue

            # Skip if tracked VLAN is ambiguous (multiple VLANs)
            if "," in tracked:
                skipped_ambiguous += 1
                continue

            # Skip if already on the correct VLAN
            if r.vlan == tracked:
                skipped_correct_vlan += 1
                continue

            actionable.append((r, tracked))

        # Report filtering
        total_filtered = (
            skipped_notes + skipped_trunk + skipped_bad_intf
            + skipped_no_tracked + skipped_ambiguous
            + skipped_correct_vlan
        )
        self.log.info(
            f"VLAN assign filter: {len(records)} total → "
            f"{len(actionable)} need reassignment "
            f"({skipped_correct_vlan} already correct, "
            f"{skipped_ambiguous} ambiguous tracked VLAN, "
            f"{skipped_no_tracked} no tracked VLAN, "
            f"{skipped_notes} had notes, "
            f"{skipped_trunk} trunk ports, "
            f"{skipped_bad_intf} bad interfaces)"
        )

        if not actionable:
            self.log.info("No ports need VLAN reassignment.")
            return

        # Display action plan
        print(f"\n{'='*90}")
        print(f"  VLAN REASSIGNMENT PLAN")
        print(f"  Ports to change: {len(actionable)}")
        print(f"{'='*90}")
        print(
            f"  {'Switch':<22s} {'Interface':<15s} {'MAC':<16s} "
            f"{'IP':<16s} {'Current':<10s} {'Target':<10s}"
        )
        print(f"  {'-'*86}")
        for r, target_vlan in actionable:
            print(
                f"  {r.switch_hostname:<22s} {r.interface:<15s} "
                f"{r.mac_address:<16s} {r.ip_address:<16s} "
                f"VLAN {r.vlan:<5s} → VLAN {target_vlan}"
            )
        print(f"{'='*90}\n")

        if self.dry_run:
            print("[DRY RUN] No changes will be made.")
            return

        confirm = input(
            f"Type 'YES' to reassign VLANs on these "
            f"{len(actionable)} port(s): "
        )
        if confirm != "YES":
            print("Aborted. No changes made.")
            return

        # Group by switch IP for efficient SSH sessions
        by_switch: dict[str, list[tuple[DeviceRecord, str]]] = {}
        for r, target_vlan in actionable:
            by_switch.setdefault(r.switch_ip, []).append((r, target_vlan))

        changed_count = 0
        for switch_ip, switch_records in by_switch.items():
            platform_name = switch_records[0][0].platform or "aruba_aoscx"
            platform = get_platform(platform_name)

            conn, _ = self._connect(switch_ip, device_type=platform_name)
            if not conn:
                self.log.error(
                    f"Cannot connect to {switch_ip} for VLAN changes"
                )
                continue

            try:
                config_commands = []
                for r, target_vlan in switch_records:
                    cmds = platform.get_vlan_assign_commands(
                        r.interface, target_vlan
                    )
                    config_commands.extend(cmds)
                    self.log.info(
                        f"  VLAN assign: {r.switch_hostname} "
                        f"{r.interface} → VLAN {target_vlan}"
                    )
                    changed_count += 1

                output = conn.send_config_set(config_commands)
                self.log.debug(f"Config output:\n{output}")
                self.log.info(
                    f"VLAN changes applied to running-config on "
                    f"{switch_ip} (NOT saved to startup)"
                )

            finally:
                conn.disconnect()

        print(
            f"\nVLAN REASSIGNMENT complete on {changed_count} port(s)."
        )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "OUI Port Mapper v3.3 — Locate devices by OUI across a "
            "multi-vendor switching fabric (Cisco IOS/IOS-XE, NX-OS, "
            "Aruba AOS-CX). Recursively traces MACs through CDP/LLDP "
            "and multi-MAC uplink detection."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --core 10.1.1.1 --user admin --oui 00:1A:2B\n"
            "  %(prog)s --core 10.1.1.1 --user admin --oui 00:1A:2B "
            "--platform aruba_aoscx\n"
            "  %(prog)s --core 10.1.1.1 --user admin "
            "--oui-file ouis.txt --max-depth 8\n"
            "  %(prog)s --from-csv results.csv --user admin --shutdown\n"
        ),
    )

    conn = parser.add_argument_group("Connection")
    conn.add_argument(
        "--core",
        help="IP of the starting (core/distribution) switch",
    )
    conn.add_argument("--user", "-u", help="SSH username")
    conn.add_argument(
        "--password", "-p",
        help="SSH password (omit to be prompted securely)",
    )
    conn.add_argument(
        "--enable-secret",
        help="Enable secret (defaults to SSH password)",
    )
    conn.add_argument(
        "--platform",
        choices=["cisco_ios", "cisco_xe", "cisco_nxos", "aruba_aoscx", "auto"],
        default="auto",
        help=(
            "Force platform for ALL switches. "
            "'auto' (default) detects each switch individually. "
            "Use 'auto' for mixed-vendor fabrics."
        ),
    )

    oui = parser.add_argument_group("OUI Selection")
    oui.add_argument(
        "--oui", action="append",
        help="OUI prefix (e.g., 00:1A:2B). Repeatable.",
    )
    oui.add_argument(
        "--oui-file",
        help="File with one OUI per line (# comments allowed)",
    )

    out = parser.add_argument_group("Output")
    out.add_argument(
        "--output", "-o", default="oui_port_inventory.csv",
        help="CSV output filename (default: oui_port_inventory.csv)",
    )

    trav = parser.add_argument_group("Traversal")
    trav.add_argument(
        "--max-depth", type=int, default=10,
        help=(
            "Max recursion depth (default: 10). "
            "0 = starting switch only."
        ),
    )
    trav.add_argument(
        "--fan-out", action="store_true",
        help=(
            "Visit ALL CDP/LLDP neighbors from the starting switch, "
            "not just switches where matching MACs are visible. "
            "Required for routed-access designs where endpoint VLANs "
            "are not trunked to core."
        ),
    )
    trav.add_argument(
        "--workers", type=int, default=10,
        help=(
            "Number of concurrent SSH sessions for fan-out mode "
            "(default: 10). Higher values = faster but more load "
            "on the network and management plane."
        ),
    )
    trav.add_argument(
        "--mac-threshold", type=int, default=1,
        help=(
            "Multi-MAC threshold (default: 1). Ports with more than "
            "this many MACs are treated as uplinks. Set to 2 or 3 "
            "for venues with dual-NIC devices (e.g., VITEC encoders) "
            "to prevent them from being flagged as multi-MAC uplinks."
        ),
    )
    trav.add_argument(
        "--mgmt-subnet",
        help=(
            "Only recurse into LLDP/CDP neighbors whose management IP "
            "falls within this CIDR subnet. Prevents the tool from "
            "trying to SSH into endpoints that advertise LLDP. "
            "Example: --mgmt-subnet 10.10.0.0/24"
        ),
    )
    trav.add_argument(
        "--track-vlans",
        help=(
            "Comma-separated list of VLAN IDs to track across "
            "switches. On each visited switch, the tool checks "
            "which of these VLANs have active MAC entries. "
            "Results appear in the CSV and in a summary table. "
            "Example: --track-vlans 21,22,23,24,25"
        ),
    )

    act = parser.add_argument_group("Port Actions")
    act_mx = act.add_mutually_exclusive_group()
    act_mx.add_argument(
        "--shutdown", action="store_true",
        help="Shutdown discovered ports (with confirmation)",
    )
    act_mx.add_argument(
        "--no-shutdown", action="store_true",
        help="No-shut discovered ports (with confirmation)",
    )
    act_mx.add_argument(
        "--port-cycle", action="store_true",
        help=(
            "Shut down all matched access ports, wait, then "
            "re-enable them. Single confirmation prompt."
        ),
    )
    act_mx.add_argument(
        "--vlan-assign", action="store_true",
        help=(
            "Reassign access port VLANs to match the tracked VLAN "
            "for each switch (from --track-vlans). Only changes ports "
            "where the current VLAN differs from the target. Requires "
            "switch_tracked_vlan data in the CSV."
        ),
    )
    act.add_argument(
        "--cycle-delay", type=int, default=5,
        help="Seconds to wait between shut and no-shut (default: 5)",
    )
    act.add_argument(
        "--dry-run", action="store_true",
        help="Show planned changes without executing",
    )

    parser.add_argument(
        "--from-csv",
        help="Load records from CSV instead of running discovery",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )

    return parser.parse_args()


def load_oui_list(args: argparse.Namespace) -> list[str]:
    """Collect OUI prefixes from --oui flags and --oui-file."""
    oui_list = []
    if args.oui:
        oui_list.extend(args.oui)
    if args.oui_file:
        try:
            with open(args.oui_file, "r") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        oui_list.append(stripped)
        except FileNotFoundError:
            print(f"ERROR: OUI file not found: {args.oui_file}")
            sys.exit(1)
    return oui_list


def main():
    args = parse_arguments()

    # --- Mode 1: Act on saved CSV ---
    if args.from_csv:
        if not (args.shutdown or args.no_shutdown or args.port_cycle
                or args.vlan_assign):
            print(
                "ERROR: --from-csv requires --shutdown, --no-shutdown, "
                "--port-cycle, or --vlan-assign"
            )
            sys.exit(1)

        username = args.user or input("SSH Username: ")
        password = args.password or getpass.getpass("SSH Password: ")

        records = OUIPortMapper.load_from_csv(args.from_csv)
        print(f"Loaded {len(records)} records from {args.from_csv}")

        mapper = OUIPortMapper(
            core_ip="",
            username=username,
            password=password,
            oui_list=[],
            enable_secret=args.enable_secret or password,
            dry_run=args.dry_run,
            verbose=args.verbose,
        )

        if args.port_cycle:
            mapper.cycle_ports(records, delay_seconds=args.cycle_delay)
        elif args.vlan_assign:
            mapper.assign_vlans(records)
        else:
            action = "shutdown" if args.shutdown else "no shutdown"
            mapper.toggle_ports(records, action=action)
        return

    # --- Mode 2: Discovery ---
    if not args.core:
        print("ERROR: --core is required for discovery mode")
        sys.exit(1)

    oui_list = load_oui_list(args)
    if not oui_list:
        print("ERROR: At least one OUI required (--oui or --oui-file)")
        sys.exit(1)

    username = args.user or input("SSH Username: ")
    password = args.password or getpass.getpass("SSH Password: ")
    forced_platform = None if args.platform == "auto" else args.platform

    # Parse --track-vlans comma-separated list
    track_vlans_list = []
    if args.track_vlans:
        track_vlans_list = [
            v.strip() for v in args.track_vlans.split(",") if v.strip()
        ]

    mapper = OUIPortMapper(
        core_ip=args.core,
        username=username,
        password=password,
        oui_list=oui_list,
        enable_secret=args.enable_secret or password,
        forced_platform=forced_platform,
        output_file=args.output,
        max_depth=args.max_depth,
        fan_out=args.fan_out,
        max_workers=args.workers,
        mac_threshold=args.mac_threshold,
        mgmt_subnet=args.mgmt_subnet or "",
        track_vlans=track_vlans_list,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )

    discovered = mapper.discover()

    if discovered:
        mapper.export_csv()
        if args.shutdown:
            mapper.toggle_ports(discovered, action="shutdown")
        elif args.no_shutdown:
            mapper.toggle_ports(discovered, action="no shutdown")
        elif args.port_cycle:
            mapper.cycle_ports(discovered, delay_seconds=args.cycle_delay)
        elif args.vlan_assign:
            mapper.assign_vlans(discovered)
    else:
        print("No matching devices found. No CSV exported.")


if __name__ == "__main__":
    main()
