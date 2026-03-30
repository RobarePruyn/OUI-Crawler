"""Cisco IOS / IOS-XE platform implementation."""
import ipaddress
import re
from ..models import MacEntry, Neighbor, VlanInfo
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

    def get_interface_config_command(self, interface: str) -> str:
        return f"show running-config interface {interface}"

    def get_interface_stats_command(self, interface: str) -> str:
        return f"show interface {interface}"

    def parse_interface_stats(self, raw_output: str) -> dict:
        """
        Parse Cisco IOS/IOS-XE 'show interface X' output.

        Extracts status, rates, and error counters from the well-known
        IOS interface detail format.
        """
        stats: dict = {}

        # Line 1: "GigabitEthernet1/0/1 is up, line protocol is up (connected)"
        status_match = re.search(
            r'(\S+) is (administratively )?(up|down),\s+line protocol is (up|down)',
            raw_output
        )
        if status_match:
            admin = "administratively down" if status_match.group(2) else status_match.group(3)
            stats["status"] = admin
            stats["protocol_status"] = status_match.group(4)

        # Description
        desc_match = re.search(r'Description:\s*(.+)', raw_output)
        if desc_match:
            stats["description"] = desc_match.group(1).strip()

        # 30-second rates
        rate_30_in = re.search(
            r'30 second input rate\s+(\d+)\s+bits/sec,\s+(\d+)\s+packets/sec',
            raw_output
        )
        if rate_30_in:
            stats["input_rate_30sec"] = f"{rate_30_in.group(1)} bits/sec"
            stats["input_packets_sec"] = int(rate_30_in.group(2))

        rate_30_out = re.search(
            r'30 second output rate\s+(\d+)\s+bits/sec,\s+(\d+)\s+packets/sec',
            raw_output
        )
        if rate_30_out:
            stats["output_rate_30sec"] = f"{rate_30_out.group(1)} bits/sec"
            stats["output_packets_sec"] = int(rate_30_out.group(2))

        # 5-minute rates (IOS-XE includes these)
        rate_5_in = re.search(
            r'5 minute input rate\s+(\d+)\s+bits/sec', raw_output
        )
        if rate_5_in:
            stats["input_rate_5min"] = f"{rate_5_in.group(1)} bits/sec"

        rate_5_out = re.search(
            r'5 minute output rate\s+(\d+)\s+bits/sec', raw_output
        )
        if rate_5_out:
            stats["output_rate_5min"] = f"{rate_5_out.group(1)} bits/sec"

        # Packet counters
        in_packets = re.search(r'(\d+) packets input', raw_output)
        if in_packets:
            stats["input_packets"] = int(in_packets.group(1))

        out_packets = re.search(r'(\d+) packets output', raw_output)
        if out_packets:
            stats["output_packets"] = int(out_packets.group(1))

        # Error counters
        in_errors = re.search(r'(\d+) input errors', raw_output)
        if in_errors:
            stats["input_errors"] = int(in_errors.group(1))

        out_errors = re.search(r'(\d+) output errors', raw_output)
        if out_errors:
            stats["output_errors"] = int(out_errors.group(1))

        crc = re.search(r'(\d+) CRC', raw_output)
        if crc:
            stats["crc_errors"] = int(crc.group(1))

        return stats

    # ── VLAN discovery ──────────────────────────────────────────────

    def get_vlan_brief_command(self) -> str:
        return "show vlan brief"

    def get_svi_config_command(self) -> str:
        return "show running-config | section interface Vlan"

    def parse_vlan_brief(self, raw_output: str, hostname: str = "", ip: str = "") -> list[VlanInfo]:
        """
        Parse IOS/IOS-XE 'show vlan brief' output.

        Format:
          VLAN Name                             Status    Ports
          ---- -------------------------------- --------- --------------------
          1    default                          active    Gi1/0/1, Gi1/0/2
          10   DATA                             active
          1002 fddi-default                     act/unsup
        """
        entries = []
        # Skip VLAN 1 and the reserved range 1002-1005
        skip_vlans = {1, 1002, 1003, 1004, 1005}
        pattern = re.compile(
            r'^(\d+)\s+(\S+)\s+(active|sus|act/unsup)',
            re.MULTILINE
        )
        for match in pattern.finditer(raw_output):
            vlan_id = int(match.group(1))
            if vlan_id in skip_vlans:
                continue
            entries.append(VlanInfo(
                vlan_id=vlan_id,
                name=match.group(2),
                status=match.group(3),
                switch_hostname=hostname,
                switch_ip=ip,
            ))
        return entries

    def parse_svi_config(self, raw_output: str, vlan_map: dict[int, VlanInfo]) -> dict[int, VlanInfo]:
        """
        Parse IOS 'show running-config | section interface Vlan' output.
        Enriches vlan_map entries with SVI details.

        Splits on 'interface Vlan' boundaries, extracts:
          ip address, ip helper-address, ip igmp, ip pim sparse-mode
        """
        blocks = re.split(r'(?=^interface Vlan)', raw_output, flags=re.MULTILINE)
        for block in blocks:
            header = re.match(r'interface Vlan(\d+)', block)
            if not header:
                continue
            vlan_id = int(header.group(1))
            if vlan_id not in vlan_map:
                continue

            info = vlan_map[vlan_id]
            info.has_svi = True

            # "ip address 10.1.21.1 255.255.255.0"
            ip_match = re.search(r'ip address (\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', block)
            if ip_match:
                try:
                    net = ipaddress.IPv4Network(f"{ip_match.group(1)}/{ip_match.group(2)}", strict=False)
                    info.svi_ip_address = f"{ip_match.group(1)}/{net.prefixlen}"
                except ValueError:
                    info.svi_ip_address = f"{ip_match.group(1)}/{ip_match.group(2)}"

            # "shutdown" or absence thereof
            if re.search(r'^\s+shutdown\s*$', block, re.MULTILINE):
                info.svi_status = "shutdown"
            else:
                info.svi_status = "up"

            # DHCP helpers: "ip helper-address 10.1.1.10"
            for helper in re.finditer(r'ip helper-address (\d+\.\d+\.\d+\.\d+)', block):
                info.dhcp_helpers.append(helper.group(1))

            # IGMP
            if re.search(r'ip igmp', block):
                info.igmp_enabled = True

            # PIM sparse-mode
            if re.search(r'ip pim sparse-mode', block):
                info.pim_sparse_enabled = True

        return vlan_map

    # ── VLAN provisioning ───────────────────────────────────────────

    def get_vlan_create_commands(self, vlan_id: int, name: str = "") -> list[str]:
        cmds = [f"vlan {vlan_id}"]
        if name:
            cmds.append(f" name {name}")
        return cmds

    def get_svi_create_commands(
        self,
        vlan_id: int,
        ip_address: str = "",
        gateway_ip: str = "",
        gateway_mac: str = "",
        dhcp_servers: list[str] | None = None,
        igmp: bool = False,
        pim_sparse: bool = False,
    ) -> list[str]:
        """Build IOS SVI config commands. ip_address is CIDR (e.g. 10.1.21.1/24)."""
        cmds = [f"interface Vlan{vlan_id}"]
        if ip_address:
            try:
                iface = ipaddress.IPv4Interface(ip_address)
                cmds.append(f" ip address {iface.ip} {iface.netmask}")
            except ValueError:
                pass
        if dhcp_servers:
            for server in dhcp_servers:
                cmds.append(f" ip helper-address {server}")
        if igmp:
            cmds.append(" ip igmp join-group 224.0.0.0")
        if pim_sparse:
            cmds.append(" ip pim sparse-mode")
        cmds.append(" no shutdown")
        return cmds

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
