"""Aruba AOS-CX platform implementation."""
import re
from ..models import MacEntry, Neighbor
from ..mac_utils import normalize_mac_to_cisco
from . import SwitchPlatform


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
