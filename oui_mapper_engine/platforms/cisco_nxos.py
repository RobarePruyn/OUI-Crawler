"""Cisco NX-OS platform implementation."""
import re
from ..models import MacEntry
from .cisco_ios import CiscoIOSPlatform


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

    def get_svi_config_command(self) -> str:
        return 'show running-config | section "interface Vlan"'

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
