"""Cisco IOS / IOS-XE platform implementation."""
import re
from ..models import MacEntry, Neighbor
from . import SwitchPlatform


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
