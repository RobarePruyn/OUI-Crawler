"""
OUI Port Mapper Engine — core discovery and automation logic.
"""
import csv
import ipaddress
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from typing import Optional, Callable

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

from .models import (
    DeviceRecord, SwitchRecord, Neighbor, MacEntry,
    ProgressEvent, ActionPlan, ActionResult, DiffResult,
    VlanInfo,
)
from .mac_utils import normalize_oui_prefix, mac_matches_oui, normalize_mac_to_cisco
from .platforms import (
    SwitchPlatform, CiscoIOSPlatform, CiscoNXOSPlatform, ArubaAOSCXPlatform,
    PLATFORM_MAP, detect_platform, get_platform,
)


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
        discover_vlans: bool = False,
        save_config: bool = False,
        verbose: bool = False,
        progress_callback: Optional[Callable[[ProgressEvent], None]] = None,
        logger: Optional[logging.Logger] = None,
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
        self.save_config = save_config
        self.progress_callback = progress_callback
        self._cancelled = False
        self._last_detected_platform: Optional[str] = None

        # Management subnet filter: if set, only recurse into neighbors
        # whose management IP falls within this subnet. Prevents the
        # tool from trying to SSH into endpoints (e.g., VITEC encoders)
        # that advertise LLDP but aren't switches.
        self.mgmt_subnet = None
        if mgmt_subnet:
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

        # VLAN discovery: when True, _inventory_switch collects VLAN
        # definitions, SVIs, and spanning-tree state from each switch.
        self.discover_vlans = discover_vlans
        # Map: hostname → list[VlanInfo]
        self.discovered_vlans: dict[str, list] = {}

        # Logging
        if logger is not None:
            self.log = logger
        else:
            self.log = logging.getLogger("oui_mapper")
            if verbose and not self.log.handlers:
                self.log.setLevel(logging.DEBUG)

    # ------------------------------------------------------------------
    # Progress event helper
    # ------------------------------------------------------------------

    def _emit(self, event_type: str, **kwargs):
        """Emit a progress event if a callback is registered."""
        if self.progress_callback:
            event = ProgressEvent(
                event_type=event_type,
                switches_visited=len(self.visited_switches),
                devices_found=len(self.discovered_records),
                **kwargs,
            )
            try:
                self.progress_callback(event)
            except Exception:
                pass  # Never let callback errors break discovery

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
            # Auto-detect, passing last successful type as hint
            resolved_type, reuse_conn = detect_platform(
                host=target_ip,
                username=self.username,
                password=self.password,
                enable_secret=self.enable_secret,
                log=self.log,
                hint=self._last_detected_platform,
            )
            if not resolved_type:
                return None, None
            # Remember for next switch
            self._last_detected_platform = resolved_type

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
        try:
            return ipaddress.ip_address(ip_address) in self.mgmt_subnet
        except ValueError:
            return False

    def _maybe_save_config(self, conn, platform, switch_ip: str):
        """
        Optionally save running-config to startup-config.
        Only runs if --save-config was specified.
        """
        if not self.save_config:
            self.log.info(
                f"Changes applied to running-config on {switch_ip} "
                f"(NOT saved to startup)"
            )
            return

        save_cmd = platform.get_save_config_command()
        self.log.info(
            f"Saving config on {switch_ip} ({save_cmd})..."
        )
        try:
            output = conn.send_command_timing(
                save_cmd, strip_command=False, strip_prompt=False
            )
            self.log.debug(f"Save output: {output}")
            self.log.info(
                f"Config saved to startup on {switch_ip}"
            )
        except Exception as exc:
            self.log.error(
                f"Failed to save config on {switch_ip}: {exc}"
            )

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
                f"(ports with <={self.mac_threshold} MACs treated as access)"
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
            f"Discovery complete. "
            f"{len(self.discovered_records)} device(s) found across "
            f"{len(self.visited_switches)} switch(es)."
        )

        # Log tracked VLAN summary if --track-vlans was used
        if self.track_vlans and self.switch_vlan_map:
            self.log.info("TRACKED VLAN SUMMARY (VLANs: "
                          f"{', '.join(self.track_vlans)})")
            for host_key in sorted(self.switch_vlan_map.keys()):
                active = self.switch_vlan_map[host_key]
                if active:
                    vlan_str = ", ".join(sorted(active))
                    self.log.info(f"  {host_key} -> VLAN {vlan_str}")
            # Show switches with no tracked VLANs active
            hosts_without = set(self.visited_hostnames) - set(
                h for h, v in self.switch_vlan_map.items() if v
            )
            if hosts_without:
                for h in sorted(hosts_without):
                    self.log.info(f"  {h} -> (none)")

        self._emit("complete", message=f"Discovery complete. {len(self.discovered_records)} device(s) found.")

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

        if self._cancelled:
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

        self._emit("switch_start", switch_ip=switch_ip, switch_hostname=hostname)

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
                    self._emit("device_found", switch_ip=switch_ip, switch_hostname=hostname, message=f"Found {entry.mac_address} on {entry.interface}")

        finally:
            connection.disconnect()
            self.log.debug(f"{indent}  Disconnected from {hostname}")

        self._emit("switch_done", switch_ip=switch_ip, switch_hostname=hostname)

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
            # switches where matching MACs were found on uplink ports.
            # Pre-filter targets, then dispatch concurrently.

            # Phase 1: Handle already-visited and outside-mgmt-subnet
            valid_targets: list[tuple[str, str, list]] = []  # (ip, name, mac_group)

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

                # Skip neighbors outside management subnet
                if not self._ip_in_mgmt_subnet(downstream_ip):
                    self.log.debug(
                        f"{indent}    Skipping {downstream_ip} — "
                        f"outside management subnet "
                        f"{self.mgmt_subnet}"
                    )
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

                # Valid recursion target
                downstream_name = downstream_ip
                for nbr in neighbors:
                    if nbr.neighbor_ip == downstream_ip:
                        downstream_name = nbr.neighbor_hostname
                        break
                valid_targets.append(
                    (downstream_ip, downstream_name, mac_group)
                )

            # Phase 2: Dispatch all valid targets concurrently
            if valid_targets:
                def _recurse_worker(ds_ip, ds_name, mg):
                    """Worker for concurrent normal recursion."""
                    new_trail = f"{trail} → {ds_name}"
                    self.log.info(
                        f"{indent}  Recursing → {ds_name} ({ds_ip})..."
                    )
                    self._discover_switch(
                        switch_ip=ds_ip,
                        current_depth=current_depth + 1,
                        trail=new_trail,
                    )

                with ThreadPoolExecutor(
                    max_workers=self.max_workers
                ) as executor:
                    futures = {
                        executor.submit(
                            _recurse_worker, ds_ip, ds_name, mg
                        ): (ds_ip, ds_name, mg)
                        for ds_ip, ds_name, mg in valid_targets
                    }
                    for future in as_completed(futures):
                        ds_ip, ds_name, mg = futures[future]
                        try:
                            future.result()
                        except Exception as exc:
                            self.log.error(
                                f"Recursion worker for {ds_name} "
                                f"({ds_ip}) failed: {exc}"
                            )

                # Phase 3: After all recursion completes, record any
                # MACs that still haven't been found downstream
                for ds_ip, ds_name, mac_group in valid_targets:
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
                            notes=(
                                f"not found on downstream "
                                f"{ds_name}; recorded at uplink"
                            ),
                            switch_tracked_vlan=tracked_vlan_str,
                        ))
                        self.resolved_macs.add(entry.mac_address)

    # ------------------------------------------------------------------
    # Switch inventory (--switch-inventory)
    # ------------------------------------------------------------------

    def discover_switches(self) -> list[SwitchRecord]:
        """
        Crawl the switching fabric via CDP/LLDP and return a list of
        every reachable switch. No OUI matching or MAC tracing — just
        neighbor discovery with the same dedup and guard rails as the
        normal discovery engine.
        """
        self.log.info(
            f"Starting switch inventory crawl from {self.core_ip}"
        )
        self.log.info(f"Max traversal depth: {self.max_depth}")
        if self.mgmt_subnet:
            self.log.info(
                f"Management subnet filter: {self.mgmt_subnet}"
            )

        self.switch_inventory_records: list[SwitchRecord] = []

        self._inventory_switch(
            switch_ip=self.core_ip,
            current_depth=0,
            trail="core",
            upstream_hostname="",
            upstream_ip="",
            upstream_interface="",
        )

        self.log.info(
            f"Switch inventory complete. "
            f"{len(self.switch_inventory_records)} switch(es) found."
        )

        # Log summary by platform
        platform_counts: dict[str, int] = {}
        for rec in self.switch_inventory_records:
            platform_counts[rec.platform] = (
                platform_counts.get(rec.platform, 0) + 1
            )

        self.log.info(
            f"SWITCH INVENTORY — {len(self.switch_inventory_records)} switches"
        )
        for rec in self.switch_inventory_records:
            depth_prefix = "  " * min(rec.discovery_depth, 5)
            self.log.info(
                f"  {depth_prefix}{rec.switch_hostname:30s}  "
                f"{rec.switch_ip:16s}  {rec.platform}"
            )
        for plat, count in sorted(platform_counts.items()):
            self.log.info(f"  {plat}: {count}")

        self._emit("complete", message=f"Switch inventory complete. {len(self.switch_inventory_records)} switch(es) found.")

        return self.switch_inventory_records

    def _inventory_switch(
        self,
        switch_ip: str,
        current_depth: int,
        trail: str,
        upstream_hostname: str,
        upstream_ip: str,
        upstream_interface: str,
    ):
        """
        Recursive per-switch inventory worker. Connects, records the
        switch, collects CDP/LLDP neighbors, and recurses into all of
        them. Skips ARP/MAC/OUI — purely topology crawl.
        """
        # --- Guard: depth limit ---
        if current_depth > self.max_depth:
            self.log.warning(
                f"Max depth ({self.max_depth}) reached at {switch_ip}. "
                f"Trail: {trail}. Stopping this branch."
            )
            return

        if self._cancelled:
            return

        # --- Guard: already visited (IP) ---
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

        indent = "  " * min(current_depth, 5)

        self.log.info(
            f"{indent}[depth={current_depth}] {hostname} "
            f"({switch_ip}) — {platform.platform_name}"
        )

        # --- Record this switch ---
        record = SwitchRecord(
            switch_hostname=hostname,
            switch_ip=switch_ip,
            platform=platform.platform_name,
            discovery_depth=current_depth,
            upstream_hostname=upstream_hostname,
            upstream_ip=upstream_ip,
            upstream_interface=upstream_interface,
        )
        with self._lock:
            self.switch_inventory_records.append(record)

        self._emit("switch_start", switch_ip=switch_ip, switch_hostname=hostname)

        try:
            # --- Collect CDP/LLDP neighbors ---
            neighbors = self._collect_neighbors(connection, platform)
            self.log.info(
                f"{indent}  Neighbors: {len(neighbors)}"
            )

            # --- VLAN discovery (when enabled) ---
            if self.discover_vlans:
                vlan_cmd = platform.get_vlan_brief_command()
                if vlan_cmd:
                    try:
                        vlan_output = connection.send_command(vlan_cmd)
                        vlans = platform.parse_vlan_brief(vlan_output, hostname, switch_ip)
                        vlan_map = {v.vlan_id: v for v in vlans}

                        svi_cmd = platform.get_svi_config_command()
                        if svi_cmd:
                            svi_output = connection.send_command(svi_cmd)
                            platform.parse_svi_config(svi_output, vlan_map)

                        st_cmd = platform.get_spanning_tree_vlan_command()
                        if st_cmd:
                            st_output = connection.send_command(st_cmd)
                            st_vlans = platform.parse_spanning_tree_vlans(st_output)
                            for vid, info in vlan_map.items():
                                info.spanning_tree_enabled = vid in st_vlans

                        with self._lock:
                            self.discovered_vlans[hostname] = list(vlan_map.values())

                        self.log.info(
                            f"{indent}  VLANs discovered: {len(vlan_map)}"
                        )
                    except Exception as exc:
                        self.log.warning(
                            f"{indent}  VLAN discovery failed on {hostname}: {exc}"
                        )
        finally:
            connection.disconnect()
            self.log.debug(f"{indent}  Disconnected from {hostname}")

        # --- Build target list (all neighbors, deduped) ---
        all_neighbor_ips: dict[str, tuple[str, str]] = {}  # IP → (hostname, local_intf)
        for nbr in neighbors:
            if nbr.neighbor_ip and nbr.neighbor_ip not in all_neighbor_ips:
                all_neighbor_ips[nbr.neighbor_ip] = (
                    nbr.neighbor_hostname,
                    nbr.local_interface,
                )

        targets: list[tuple[str, str, str]] = []  # (IP, hostname, local_intf)
        for nbr_ip, (nbr_name, local_intf) in all_neighbor_ips.items():
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
            targets.append((nbr_ip, nbr_name, local_intf))

        self._emit("switch_done", switch_ip=switch_ip, switch_hostname=hostname)

        if not targets:
            return

        self.log.info(
            f"{indent}  Crawling {len(targets)} neighbor(s) "
            f"({self.max_workers} concurrent workers)"
        )

        # --- Concurrent dispatch to all neighbors ---
        def _inventory_worker(nbr_ip: str, nbr_name: str, local_intf: str):
            new_trail = f"{trail} → {nbr_name}"
            self.log.info(
                f"{indent}    → {nbr_name} ({nbr_ip})"
            )
            self._inventory_switch(
                switch_ip=nbr_ip,
                current_depth=current_depth + 1,
                trail=new_trail,
                upstream_hostname=hostname,
                upstream_ip=switch_ip,
                upstream_interface=local_intf,
            )

        with ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            futures = {
                executor.submit(
                    _inventory_worker, ip, name, intf
                ): (ip, name)
                for ip, name, intf in targets
            }
            for future in as_completed(futures):
                ip, name = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    self.log.error(
                        f"Inventory worker for {name} ({ip}) "
                        f"failed: {exc}"
                    )

    def export_switch_inventory_csv(
        self,
        records: Optional[list[SwitchRecord]] = None,
        filename: Optional[str] = None,
    ) -> str:
        """Export switch inventory records to CSV."""
        records = records or self.switch_inventory_records
        filename = filename or self.output_file

        fieldnames = [
            "switch_hostname",
            "switch_ip",
            "platform",
            "discovery_depth",
            "upstream_hostname",
            "upstream_ip",
            "upstream_interface",
        ]

        # Sort by depth, then hostname for readable output
        sorted_records = sorted(
            records,
            key=lambda r: (r.discovery_depth, r.switch_hostname.lower()),
        )

        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for rec in sorted_records:
                writer.writerow({
                    "switch_hostname": rec.switch_hostname,
                    "switch_ip": rec.switch_ip,
                    "platform": rec.platform,
                    "discovery_depth": rec.discovery_depth,
                    "upstream_hostname": rec.upstream_hostname,
                    "upstream_ip": rec.upstream_ip,
                    "upstream_interface": rec.upstream_interface,
                })

        self.log.info(f"Switch inventory exported to {filename}")
        return filename

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
    # Port actions: plan / execute pairs
    # ------------------------------------------------------------------

    # Safety filter keywords — shared across all plan methods
    _SKIP_KEYWORDS = {"unknown", "not found", "unreachable"}
    _TRUNK_KEYWORDS = {"port-channel", "po", "lag", "vpc", "peer-link"}

    def _apply_safety_filter(
        self,
        records: list[DeviceRecord],
    ) -> tuple[list[DeviceRecord], int, int, int]:
        """
        Apply the standard access-port-only safety filter.
        Returns (actionable, skipped_notes, skipped_trunk, skipped_bad_intf).
        """
        actionable = []
        skipped_notes = 0
        skipped_trunk = 0
        skipped_bad_intf = 0

        for r in records:
            intf_lower = r.interface.lower()

            # Skip records with bad/missing interface names
            if any(kw in intf_lower for kw in self._SKIP_KEYWORDS):
                skipped_bad_intf += 1
                continue

            # Skip port-channels and logical interfaces
            if any(kw in intf_lower for kw in self._TRUNK_KEYWORDS):
                skipped_trunk += 1
                continue

            # Skip anything that isn't a clean access-port find
            # (multi-MAC, uplink, not resolved downstream, etc.)
            if r.notes.strip():
                skipped_notes += 1
                continue

            actionable.append(r)

        return actionable, skipped_notes, skipped_trunk, skipped_bad_intf

    def plan_toggle(
        self,
        records: list[DeviceRecord],
        action: str = "shutdown",
    ) -> ActionPlan:
        """
        Plan a port toggle action (shutdown or no shutdown).
        Applies the safety filter and returns an ActionPlan with the
        list of actionable DeviceRecords.
        """
        if action not in ("shutdown", "no shutdown"):
            self.log.error(f"Invalid action: {action}")
            return ActionPlan()

        actionable, skipped_notes, skipped_trunk, skipped_bad_intf = (
            self._apply_safety_filter(records)
        )

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

        return ActionPlan(
            actionable=actionable,
            skipped_notes=skipped_notes,
            skipped_trunk=skipped_trunk,
            skipped_bad_intf=skipped_bad_intf,
        )

    def execute_toggle(
        self,
        actionable: list[DeviceRecord],
        action: str = "shutdown",
    ) -> list[ActionResult]:
        """
        Execute a port toggle action on a pre-filtered list of records.
        Returns a list of ActionResult for each switch group processed.
        """
        if action not in ("shutdown", "no shutdown"):
            self.log.error(f"Invalid action: {action}")
            return []

        if not actionable:
            self.log.info("No actionable ports to toggle.")
            return []

        results: list[ActionResult] = []

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
                for r in switch_records:
                    results.append(ActionResult(
                        switch_hostname=r.switch_hostname,
                        switch_ip=r.switch_ip,
                        interface=r.interface,
                        action=action,
                        status="failed",
                        error=f"Cannot connect to {switch_ip}",
                    ))
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
                self._maybe_save_config(conn, platform, switch_ip)

                for r in switch_records:
                    results.append(ActionResult(
                        switch_hostname=r.switch_hostname,
                        switch_ip=r.switch_ip,
                        interface=r.interface,
                        action=action,
                        status="success",
                    ))

            except Exception as exc:
                self.log.error(
                    f"Error executing {action} on {switch_ip}: {exc}"
                )
                for r in switch_records:
                    results.append(ActionResult(
                        switch_hostname=r.switch_hostname,
                        switch_ip=r.switch_ip,
                        interface=r.interface,
                        action=action,
                        status="failed",
                        error=str(exc),
                    ))
            finally:
                conn.disconnect()

        self.log.info(
            f"{action.upper()} complete on {len(actionable)} port(s)."
        )
        return results

    def execute_cycle(
        self,
        actionable: list[DeviceRecord],
        delay_seconds: int = 5,
    ) -> list[ActionResult]:
        """
        Port-cycle: shutdown all matched access ports, wait, then
        no-shut them. Takes a pre-filtered list of records.

        Args:
            actionable:     Pre-filtered list of DeviceRecord to act on
            delay_seconds:  Seconds to wait between shut and no-shut

        Returns:
            Combined list of ActionResult from both shut and no-shut phases.
        """
        self.log.info(
            f"Port cycle requested: shutdown → wait {delay_seconds}s "
            f"→ no shutdown"
        )

        if not actionable:
            self.log.info("No actionable ports for port cycle.")
            return []

        # Shutdown phase
        shut_results = self.execute_toggle(actionable, action="shutdown")

        # Wait
        self.log.info(f"Waiting {delay_seconds} seconds before re-enabling ports...")
        time.sleep(delay_seconds)
        self.log.info("Delay complete.")

        # No-shut phase
        no_shut_results = self.execute_toggle(actionable, action="no shutdown")

        self.log.info("Port cycle complete.")
        return shut_results + no_shut_results

    def plan_vlan_assign(
        self,
        records: list[DeviceRecord],
    ) -> ActionPlan:
        """
        Plan VLAN reassignment based on the switch_tracked_vlan field.
        Applies safety + VLAN filters. actionable is a list of
        (DeviceRecord, target_vlan) tuples.
        """
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
            if any(kw in intf_lower for kw in self._SKIP_KEYWORDS):
                skipped_bad_intf += 1
                continue

            # Skip trunk/aggregate interfaces
            if any(kw in intf_lower for kw in self._TRUNK_KEYWORDS):
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

        return ActionPlan(
            actionable=actionable,
            skipped_notes=skipped_notes,
            skipped_trunk=skipped_trunk,
            skipped_bad_intf=skipped_bad_intf,
            skipped_correct_vlan=skipped_correct_vlan,
            skipped_ambiguous=skipped_ambiguous,
            skipped_no_tracked=skipped_no_tracked,
        )

    def execute_vlan_assign(
        self,
        actionable: list[tuple[DeviceRecord, str]],
    ) -> list[ActionResult]:
        """
        Execute VLAN reassignment on a pre-filtered list of
        (DeviceRecord, target_vlan) tuples.
        """
        if not actionable:
            self.log.info("No ports need VLAN reassignment.")
            return []

        results: list[ActionResult] = []

        # Group by switch IP for efficient SSH sessions
        by_switch: dict[str, list[tuple[DeviceRecord, str]]] = {}
        for r, target_vlan in actionable:
            by_switch.setdefault(r.switch_ip, []).append((r, target_vlan))

        for switch_ip, switch_records in by_switch.items():
            platform_name = switch_records[0][0].platform or "aruba_aoscx"
            platform = get_platform(platform_name)

            conn, _ = self._connect(switch_ip, device_type=platform_name)
            if not conn:
                self.log.error(
                    f"Cannot connect to {switch_ip} for VLAN changes"
                )
                for r, target_vlan in switch_records:
                    results.append(ActionResult(
                        switch_hostname=r.switch_hostname,
                        switch_ip=r.switch_ip,
                        interface=r.interface,
                        action=f"vlan {target_vlan}",
                        status="failed",
                        error=f"Cannot connect to {switch_ip}",
                    ))
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

                output = conn.send_config_set(config_commands)
                self.log.debug(f"Config output:\n{output}")
                self._maybe_save_config(conn, platform, switch_ip)

                for r, target_vlan in switch_records:
                    results.append(ActionResult(
                        switch_hostname=r.switch_hostname,
                        switch_ip=r.switch_ip,
                        interface=r.interface,
                        action=f"vlan {target_vlan}",
                        status="success",
                    ))

            except Exception as exc:
                self.log.error(
                    f"Error executing VLAN assign on {switch_ip}: {exc}"
                )
                for r, target_vlan in switch_records:
                    results.append(ActionResult(
                        switch_hostname=r.switch_hostname,
                        switch_ip=r.switch_ip,
                        interface=r.interface,
                        action=f"vlan {target_vlan}",
                        status="failed",
                        error=str(exc),
                    ))
            finally:
                conn.disconnect()

        self.log.info(
            f"VLAN REASSIGNMENT complete on {len(actionable)} port(s)."
        )
        return results

    # ------------------------------------------------------------------
    # Port status check
    # ------------------------------------------------------------------

    def check_port_status(
        self,
        records: list[DeviceRecord],
    ) -> list[tuple[DeviceRecord, str, str]]:
        """
        SSH to each switch in the record list and check the current
        operational status of each recorded interface.

        Groups by switch IP so each switch gets a single SSH session.
        No safety filter — reads only, no config changes.

        Returns:
            List of (record, link_state, detail) tuples.
        """
        if not records:
            self.log.info("No records to check.")
            return []

        # Group by switch IP
        by_switch: dict[str, list[DeviceRecord]] = {}
        for r in records:
            if r.interface.lower() in ("unknown", "not found"):
                continue
            by_switch.setdefault(r.switch_ip, []).append(r)

        # Collect results: (record, link_state, detail)
        results: list[tuple[DeviceRecord, str, str]] = []

        for switch_ip, switch_records in by_switch.items():
            platform_name = switch_records[0].platform or "cisco_ios"
            conn, platform = self._connect(switch_ip, device_type=platform_name)
            if not conn:
                self.log.error(
                    f"Cannot connect to {switch_ip} for status check"
                )
                for r in switch_records:
                    results.append((r, "unreachable", ""))
                continue

            try:
                # Pull interface status for the whole switch once
                if platform_name in ("aruba_aoscx", "aruba_osswitch"):
                    raw = conn.send_command("show interface brief")
                else:
                    raw = conn.send_command("show interface status")

                # Parse into a lookup: normalized_interface → (status, speed_duplex)
                status_lookup = self._parse_interface_status(
                    raw, platform_name
                )

                for r in switch_records:
                    intf_key = r.interface.lower().strip()
                    if intf_key in status_lookup:
                        link_state, detail = status_lookup[intf_key]
                        results.append((r, link_state, detail))
                    else:
                        results.append((r, "not found in status", ""))

            finally:
                conn.disconnect()

        return results

    @staticmethod
    def _parse_interface_status(
        raw_output: str,
        platform_name: str,
    ) -> dict[str, tuple[str, str]]:
        """
        Parse 'show interface status' (Cisco) or 'show interface brief'
        (Aruba) into a dict mapping normalized interface name to
        (link_state, detail_string).
        """
        lookup: dict[str, tuple[str, str]] = {}

        if platform_name in ("aruba_aoscx", "aruba_osswitch"):
            # AOS-CX 'show interface brief' format:
            #   Port   Status   ...
            #   1/1/1  up       ...
            for line in raw_output.splitlines():
                line = line.strip()
                if not line or line.startswith("-") or line.lower().startswith("port"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    intf = parts[0].lower().strip()
                    state = parts[1].lower().strip()
                    detail = " ".join(parts[2:]) if len(parts) > 2 else ""
                    lookup[intf] = (state, detail)
        else:
            # Cisco IOS/NX-OS 'show interface status' format:
            #   Port      Name   Status       Vlan  Duplex  Speed  Type
            #   Gi1/0/1          connected    10    a-full  a-1000 10/100/1000BaseTX
            # NX-OS:
            #   Port       Name   Status    Vlan   Duplex  Speed   Type
            #   Eth1/1     --     connected trunk  full    10G     10Gbase-SR
            for line in raw_output.splitlines():
                line = line.strip()
                if not line or line.startswith("-") or line.lower().startswith("port"):
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    intf = parts[0].lower().strip()
                    # Find the status keyword — it's the first token that
                    # matches a known state
                    known_states = {
                        "connected", "notconnect", "disabled",
                        "err-disabled", "up", "down", "sfpAbsent",
                        "xcvrAbsen", "noOperMem", "channelDo",
                    }
                    state = ""
                    detail_parts = []
                    found_state = False
                    for i, p in enumerate(parts[1:], 1):
                        if not found_state and p.lower().rstrip("*") in {
                            s.lower() for s in known_states
                        }:
                            state = p.lower().rstrip("*")
                            found_state = True
                            detail_parts = parts[i + 1:]
                            break

                    if not state:
                        # Fallback: assume second-to-last-ish field
                        state = parts[2].lower() if len(parts) > 2 else "unknown"
                        detail_parts = parts[3:] if len(parts) > 3 else []

                    detail = " ".join(detail_parts)
                    lookup[intf] = (state, detail)

        return lookup

    # ------------------------------------------------------------------
    # Interface description push
    # ------------------------------------------------------------------

    def plan_set_descriptions(
        self,
        records: list[DeviceRecord],
        template: str = "{mac} {ip}",
    ) -> ActionPlan:
        """
        Plan interface description updates. Applies the safety filter
        and builds description strings from the template.
        actionable is a list of (DeviceRecord, description_string) tuples.

        Template placeholders:
          {mac}       — MAC address (Cisco dotted)
          {ip}        — IP address from ARP
          {oui}       — matched OUI prefix
          {vlan}      — VLAN number
          {hostname}  — switch hostname
        """
        filtered, skipped_notes, skipped_trunk, skipped_bad_intf = (
            self._apply_safety_filter(records)
        )

        total_skipped = skipped_notes + skipped_trunk + skipped_bad_intf
        if total_skipped:
            self.log.info(
                f"Safety filter: {len(records)} total → "
                f"{len(filtered)} actionable ({total_skipped} excluded)"
            )

        # Build description for each record
        actionable: list[tuple[DeviceRecord, str]] = []
        for r in filtered:
            desc = template.format(
                mac=r.mac_address,
                ip=r.ip_address,
                oui=r.matched_oui,
                vlan=r.vlan,
                hostname=r.switch_hostname,
            )
            # Cisco IOS limits descriptions to 240 chars, NX-OS to 254,
            # Aruba AOS-CX to 80. Truncate to 80 for safety.
            desc = desc[:80]
            actionable.append((r, desc))

        return ActionPlan(
            actionable=actionable,
            skipped_notes=skipped_notes,
            skipped_trunk=skipped_trunk,
            skipped_bad_intf=skipped_bad_intf,
        )

    def execute_set_descriptions(
        self,
        actionable: list[tuple[DeviceRecord, str]],
    ) -> list[ActionResult]:
        """
        Execute interface description updates on a pre-filtered list
        of (DeviceRecord, description_string) tuples.
        """
        if not actionable:
            self.log.info(
                "No actionable ports found for description update."
            )
            return []

        results: list[ActionResult] = []

        # Group by switch IP
        by_switch: dict[str, list[tuple[DeviceRecord, str]]] = {}
        for r, desc in actionable:
            by_switch.setdefault(r.switch_ip, []).append((r, desc))

        for switch_ip, switch_records in by_switch.items():
            platform_name = switch_records[0][0].platform or "cisco_ios"
            platform = get_platform(platform_name)

            conn, _ = self._connect(switch_ip, device_type=platform_name)
            if not conn:
                self.log.error(
                    f"Cannot connect to {switch_ip} for description push"
                )
                for r, desc in switch_records:
                    results.append(ActionResult(
                        switch_hostname=r.switch_hostname,
                        switch_ip=r.switch_ip,
                        interface=r.interface,
                        action=f"description {desc}",
                        status="failed",
                        error=f"Cannot connect to {switch_ip}",
                    ))
                continue

            try:
                config_commands = []
                for r, desc in switch_records:
                    config_commands.append(f"interface {r.interface}")
                    config_commands.append(f"description {desc}")
                    self.log.info(
                        f"  description: {r.switch_hostname} "
                        f'{r.interface} → "{desc}"'
                    )

                output = conn.send_config_set(config_commands)
                self.log.debug(f"Config output:\n{output}")
                self._maybe_save_config(conn, platform, switch_ip)

                for r, desc in switch_records:
                    results.append(ActionResult(
                        switch_hostname=r.switch_hostname,
                        switch_ip=r.switch_ip,
                        interface=r.interface,
                        action=f"description {desc}",
                        status="success",
                    ))

            except Exception as exc:
                self.log.error(
                    f"Error setting descriptions on {switch_ip}: {exc}"
                )
                for r, desc in switch_records:
                    results.append(ActionResult(
                        switch_hostname=r.switch_hostname,
                        switch_ip=r.switch_ip,
                        interface=r.interface,
                        action=f"description {desc}",
                        status="failed",
                        error=str(exc),
                    ))
            finally:
                conn.disconnect()

        self.log.info(
            f"DESCRIPTION SET complete on {len(actionable)} port(s)."
        )
        return results

    # ------------------------------------------------------------------
    # CSV diff
    # ------------------------------------------------------------------

    @staticmethod
    def diff_records(
        old_records: list[dict],
        new_records: list[dict],
    ) -> DiffResult:
        """
        Compare two sets of record dicts (keyed by mac_address) and
        return a structured DiffResult with added, removed, and moved
        devices.
        """
        # Build lookup by MAC
        old_by_mac: dict[str, dict] = {}
        for row in old_records:
            mac = row.get("mac_address", "").strip()
            if mac:
                old_by_mac[mac] = row

        new_by_mac: dict[str, dict] = {}
        for row in new_records:
            mac = row.get("mac_address", "").strip()
            if mac:
                new_by_mac[mac] = row

        old_macs = set(old_by_mac.keys())
        new_macs = set(new_by_mac.keys())

        added_macs = new_macs - old_macs
        removed_macs = old_macs - new_macs
        common = old_macs & new_macs

        added = [new_by_mac[mac] for mac in sorted(added_macs)]
        removed = [old_by_mac[mac] for mac in sorted(removed_macs)]

        # Check for moves: same MAC, different switch or port
        moved: list[tuple[str, dict, dict]] = []
        for mac in common:
            old = old_by_mac[mac]
            new = new_by_mac[mac]
            if (old.get("switch_ip") != new.get("switch_ip")
                    or old.get("interface") != new.get("interface")):
                moved.append((mac, old, new))

        moved.sort(key=lambda x: x[0])

        return DiffResult(
            added=added,
            removed=removed,
            moved=moved,
            unchanged_count=len(common) - len(moved),
            old_count=len(old_by_mac),
            new_count=len(new_by_mac),
        )

    @staticmethod
    def diff_csv(old_file: str, new_file: str) -> DiffResult:
        """
        Compare two OUI Port Mapper CSV exports and return a DiffResult
        with added, removed, and moved devices. Keyed by MAC address.
        """
        def load_csv_rows(filename: str) -> list[dict]:
            rows = []
            with open(filename, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rows.append(row)
            return rows

        old_records = load_csv_rows(old_file)
        new_records = load_csv_rows(new_file)
        return OUIPortMapper.diff_records(old_records, new_records)
