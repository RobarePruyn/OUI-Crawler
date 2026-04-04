"""Aruba AOS-CX platform implementation."""
import re
from ..models import MacEntry, Neighbor, PortConfig, VlanInfo
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

    def get_poe_off_command(self, interface: str) -> list[str]:
        return [f"interface {interface}", "no power-over-ethernet"]

    def get_poe_on_command(self, interface: str) -> list[str]:
        return [f"interface {interface}", "power-over-ethernet"]

    def get_port_config_commands(
        self,
        interface: str,
        *,
        bpdu_guard: bool = True,
        portfast: bool = True,
        storm_control: bool = False,
        storm_control_level: str = "1.00",
        description: str | None = None,
    ) -> list[str]:
        """Apply port policy config on Aruba AOS-CX."""
        cmds = [f"interface {interface}"]
        if portfast:
            cmds.append("spanning-tree port-type admin-edge")
        if bpdu_guard:
            cmds.append("spanning-tree bpdu-guard")
        if storm_control:
            try:
                pct = int(float(storm_control_level))
                pct = max(1, min(100, pct))
            except (ValueError, TypeError):
                pct = 1
            # Convert percentage to kbps assuming 1Gbps port (1000000 kbps).
            # kbps works on all AOS-CX firmware versions; "percent" only
            # works on FL.01.17+ and is rejected on older firmware like FL.01.11.
            kbps = int(1000000 * pct / 100)
            cmds.append(f"rate-limit broadcast {kbps} kbps")
            cmds.append(f"rate-limit multicast {kbps} kbps")
            cmds.append(f"rate-limit unknown-unicast {kbps} kbps")
        if description:
            cmds.append(f"description {description}")
        return cmds

    def get_all_interface_configs_command(self) -> str:
        return "show running-config interface"

    def parse_interface_configs(self, raw_output: str) -> dict[str, PortConfig]:
        """Parse Aruba AOS-CX 'show running-config interface' output.

        AOS-CX uses 'spanning-tree bpdu-guard' and 'spanning-tree port-type admin-edge'.
        Interface names are like '1/1/1', 'lag1', 'vlan10'.
        """
        configs: dict[str, PortConfig] = {}
        blocks = re.split(r'(?=^interface\s)', raw_output, flags=re.MULTILINE)
        for block in blocks:
            header = re.match(r'interface\s+(\S+)', block)
            if not header:
                continue
            intf = header.group(1)
            pc = PortConfig()
            if re.search(r'spanning-tree port-type admin-edge', block):
                pc.has_portfast = True
            if re.search(r'spanning-tree bpdu-guard\b', block):
                pc.has_bpdu_guard = True
            # Match rate-limit in percent or kbps format
            storm = re.search(r'rate-limit broadcast\s+([\d.]+)\s+percent', block)
            if storm:
                pc.has_storm_control = True
                pc.storm_control_level = storm.group(1)
            else:
                storm_kbps = re.search(r'rate-limit broadcast\s+(\d+)\s+kbps', block)
                if storm_kbps:
                    pc.has_storm_control = True
                    # Convert kbps back to percentage (assuming 1Gbps port)
                    pc.storm_control_level = str(int(int(storm_kbps.group(1)) / 10000))
            desc = re.search(r'^\s+description\s+(.+)', block, re.MULTILINE)
            if desc:
                pc.description = desc.group(1).strip()
            # AOS-CX civic location is inline: lldp med-location civic-location
            #   or location civic-location identifier reference
            civic_name = re.search(r'^\s+lldp med-location civic-location\s+"?([^"\n]+)"?', block, re.MULTILINE)
            if civic_name:
                pc.civic_location = civic_name.group(1).strip()
            configs[intf] = pc
            norm = self.normalize_interface(intf)
            if norm != intf:
                configs[norm] = pc
        return configs

    def get_interface_config_command(self, interface: str) -> str:
        return f"show running-config interface {interface}"

    def get_interface_stats_command(self, interface: str) -> str:
        return f"show interface {interface}"

    def parse_interface_stats(self, raw_output: str) -> dict:
        """
        Parse AOS-CX 'show interface X' output.

        AOS-CX format differs from Cisco:
          Interface 1/1/1 is up
           Admin state is up
           Description : AP-01
           ...
           RX
              123456 input packets ...
              0 input errors ...
           TX
              654321 output packets ...
              0 output errors ...
        """
        stats: dict = {}

        # "Interface 1/1/1 is up" or "Interface 1/1/1 is down"
        status_match = re.search(
            r'Interface\s+\S+\s+is\s+(up|down)', raw_output
        )
        if status_match:
            stats["status"] = status_match.group(1)

        # "Admin state is up"
        admin_match = re.search(
            r'Admin state is\s+(up|down)', raw_output
        )
        if admin_match:
            admin = admin_match.group(1)
            if admin == "down":
                stats["status"] = "administratively down"
            stats["protocol_status"] = stats.get("status", "down")

        # Description
        desc_match = re.search(r'Description\s*:\s*(.+)', raw_output)
        if desc_match:
            stats["description"] = desc_match.group(1).strip()

        # Input/output rates — AOS-CX shows "X bps" or "X Kbps" or "X Mbps"
        in_rate = re.search(
            r'(?:RX|Input).*?(\d+[\d.]*)\s*(bps|[KMG]bps)', raw_output, re.DOTALL
        )
        if in_rate:
            stats["input_rate_30sec"] = f"{in_rate.group(1)} {in_rate.group(2)}"

        out_rate = re.search(
            r'(?:TX|Output).*?(\d+[\d.]*)\s*(bps|[KMG]bps)', raw_output, re.DOTALL
        )
        if out_rate:
            stats["output_rate_30sec"] = f"{out_rate.group(1)} {out_rate.group(2)}"

        # Packet counters
        in_packets = re.search(r'(\d+)\s+input packets', raw_output)
        if in_packets:
            stats["input_packets"] = int(in_packets.group(1))

        out_packets = re.search(r'(\d+)\s+output packets', raw_output)
        if out_packets:
            stats["output_packets"] = int(out_packets.group(1))

        # Error counters
        in_errors = re.search(r'(\d+)\s+input errors', raw_output)
        if in_errors:
            stats["input_errors"] = int(in_errors.group(1))

        out_errors = re.search(r'(\d+)\s+output errors', raw_output)
        if out_errors:
            stats["output_errors"] = int(out_errors.group(1))

        crc = re.search(r'(\d+)\s+(?:CRC|crc)', raw_output)
        if crc:
            stats["crc_errors"] = int(crc.group(1))

        return stats

    # ── VLAN discovery ──────────────────────────────────────────────

    def get_vlan_brief_command(self) -> str:
        return "show vlan"

    def get_svi_config_command(self) -> str:
        return "show running-config interface vlan"

    def get_spanning_tree_vlan_command(self) -> str:
        return "show spanning-tree"

    def parse_vlan_brief(self, raw_output: str, hostname: str = "", ip: str = "") -> list[VlanInfo]:
        """
        Parse AOS-CX 'show vlan' output.

        Format:
          VLAN  Name                              Status  Reason          Type     Interfaces
          ----- --------------------------------- ------- --------------- -------- ----------
          1     default                           up      no_member_port  default
          21    DATA                              up      ok              static   1/1/1-1/1/48
        """
        entries = []
        skip_vlans = {1}
        pattern = re.compile(
            r'^(\d+)\s+(\S+)\s+(up|down)',
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
        Parse AOS-CX 'show running-config' output for interface vlan blocks.

        Extracts: vsx-sync active-gateways, ip address, active-gateway ip mac,
        active-gateway ip, ip helper-address, ip igmp enable, ip pim-sparse enable
        """
        # Split on "interface vlan N" headers (AOS-CX uses a space before the ID)
        blocks = re.split(r'(?=^interface vlan\s*\d+)', raw_output, flags=re.MULTILINE)
        for block in blocks:
            header = re.match(r'interface vlan\s*(\d+)', block)
            if not header:
                continue
            vlan_id = int(header.group(1))
            if vlan_id not in vlan_map:
                continue

            info = vlan_map[vlan_id]
            info.has_svi = True

            # "ip address 10.1.21.1/24"
            ip_match = re.search(r'ip address (\d+\.\d+\.\d+\.\d+/\d+)', block)
            if ip_match:
                info.svi_ip_address = ip_match.group(1)

            # "vsx-sync active-gateways"
            if re.search(r'vsx-sync active-gateways', block):
                info.vsx_sync = True

            # "active-gateway ip mac aa:bb:cc:dd:ee:ff"
            gw_mac = re.search(r'active-gateway ip mac\s+(\S+)', block)
            if gw_mac:
                info.active_gateway_mac = gw_mac.group(1)

            # "active-gateway ip 10.1.21.254"
            gw_ip = re.search(r'active-gateway ip\s+(\d+\.\d+\.\d+\.\d+)', block)
            if gw_ip:
                info.active_gateway_ip = gw_ip.group(1)

            # DHCP helpers
            for helper in re.finditer(r'ip helper-address (\d+\.\d+\.\d+\.\d+)', block):
                info.dhcp_helpers.append(helper.group(1))

            # Shutdown check
            if re.search(r'^\s+shutdown\s*$', block, re.MULTILINE):
                info.svi_status = "shutdown"
            else:
                info.svi_status = "up"

            # IGMP
            if re.search(r'ip igmp enable', block):
                info.igmp_enabled = True

            # PIM sparse
            if re.search(r'ip pim-sparse enable', block):
                info.pim_sparse_enabled = True

        return vlan_map

    def parse_spanning_tree_vlans(self, raw_output: str) -> set[int]:
        """
        Parse AOS-CX 'show spanning-tree' output for VLAN IDs.
        Looks for lines like "VLAN 21" or "Spanning tree status.*VLAN 21".
        """
        vlans = set()
        for match in re.finditer(r'VLAN\s+(\d+)', raw_output):
            vlans.add(int(match.group(1)))
        return vlans

    # ── VLAN provisioning ───────────────────────────────────────────

    def get_vlan_create_commands(self, vlan_id: int, name: str = "", *, spanning_tree: bool = True) -> list[str]:
        cmds = [f"vlan {vlan_id}"]
        if name:
            cmds.append(f" name {name}")
        # Aruba requires explicit spanning-tree per VLAN (Cisco does it by default)
        if spanning_tree:
            cmds.append(f"spanning-tree vlan {vlan_id}")
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
        """Build AOS-CX SVI config commands. ip_address is CIDR (e.g. 10.1.21.1/24)."""
        cmds = [f"interface vlan{vlan_id}"]
        if gateway_mac:
            cmds.append(" vsx-sync active-gateways")
        if ip_address:
            cmds.append(f" ip address {ip_address}")
        if gateway_mac:
            cmds.append(f" active-gateway ip mac {gateway_mac}")
        if gateway_ip:
            cmds.append(f" active-gateway ip {gateway_ip}")
        if dhcp_servers:
            for server in dhcp_servers:
                cmds.append(f" ip helper-address {server}")
        if igmp:
            cmds.append(" ip igmp enable")
        if pim_sparse:
            cmds.append(" ip pim-sparse enable")
        cmds.append(" no shutdown")
        return cmds

    def get_spanning_tree_vlan_commands(self, vlan_id: int) -> list[str]:
        return [f"spanning-tree vlan {vlan_id}"]

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
