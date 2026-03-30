"""
Single-device lookup — find a MAC or IP on the network and return
comprehensive information about where it lives and its port state.
"""
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from netmiko import ConnectHandler

from .mac_utils import normalize_mac_to_cisco
from .platforms import detect_platform, get_platform, PLATFORM_MAP


@dataclass
class LookupResult:
    """Complete result of a single device lookup."""
    mac_address: str = ""
    ip_address: str = ""
    switch_hostname: str = ""
    switch_ip: str = ""
    interface: str = ""
    vlan: str = ""
    platform: str = ""
    interface_config: str = ""
    interface_stats: dict = field(default_factory=dict)
    hops: list = field(default_factory=list)    # [{switch, switch_ip, port, reason}]
    warnings: list = field(default_factory=list)


def _is_ip(term: str) -> bool:
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', term.strip()))


def _is_mac(term: str) -> bool:
    """Accept any common MAC format: colon, dash, dotted, or bare hex."""
    cleaned = re.sub(r'[^0-9a-fA-F]', '', term)
    return len(cleaned) == 12


def _connect(host, username, password, enable_secret, device_type, log):
    """Open a netmiko connection with standard timeouts."""
    conn = ConnectHandler(
        device_type=device_type,
        host=host,
        username=username,
        password=password,
        secret=enable_secret or password,
        timeout=15,
        read_timeout_override=30,
    )
    conn.enable()
    return conn


def lookup_device(
    search_term: str,
    core_ip: str,
    username: str,
    password: str,
    enable_secret: str = "",
    platform_hint: str = None,
    mgmt_subnet: str = None,
    logger: Optional[logging.Logger] = None,
) -> LookupResult:
    """
    Look up a single device by MAC or IP address.

    Connects to the core switch, resolves MAC↔IP, finds the access port,
    follows one CDP/LLDP hop if needed, and gathers interface config + stats.
    """
    log = logger or logging.getLogger(__name__)
    result = LookupResult()
    search_term = search_term.strip()

    # Determine search type
    searching_by_ip = _is_ip(search_term)
    searching_by_mac = _is_mac(search_term)

    if not searching_by_ip and not searching_by_mac:
        result.warnings.append(f"'{search_term}' does not look like a MAC or IP address")
        return result

    if searching_by_mac:
        result.mac_address = normalize_mac_to_cisco(search_term)
        log.info(f"Lookup by MAC: {result.mac_address}")
    else:
        result.ip_address = search_term
        log.info(f"Lookup by IP: {result.ip_address}")

    # --- Connect to core switch ---
    hint = platform_hint if platform_hint and platform_hint != "auto" else None
    log.info(f"Connecting to core switch {core_ip}...")
    device_type, conn = detect_platform(core_ip, username, password, enable_secret or password, log, hint=hint)

    if not device_type:
        result.warnings.append(f"Could not connect to core switch {core_ip}")
        return result

    platform = get_platform(device_type)

    # If detect_platform returned no live connection, reconnect
    if not conn:
        try:
            conn = _connect(core_ip, username, password, enable_secret, device_type, log)
        except Exception as exc:
            result.warnings.append(f"Failed to connect to {core_ip}: {exc}")
            return result

    try:
        hostname = platform.get_hostname(conn)
        result.platform = device_type

        # --- If searching by IP, ping first to populate ARP, then resolve MAC ---
        if searching_by_ip:
            log.info(f"Pinging {search_term} from {core_ip} to populate ARP...")
            try:
                conn.send_command(
                    f"ping {search_term} repeat 2 timeout 1",
                    read_timeout=10,
                )
            except Exception:
                pass  # Ping may fail but ARP might already be populated

        # --- Get ARP table ---
        log.info("Querying ARP table...")
        arp_output = conn.send_command(platform.get_arp_command())
        arp_table = platform.parse_arp_table(arp_output)  # mac → ip

        if searching_by_ip:
            # Find MAC for this IP
            found_mac = None
            for mac, ip in arp_table.items():
                if ip == search_term:
                    found_mac = mac
                    break
            if found_mac:
                result.mac_address = found_mac
                log.info(f"Resolved IP {search_term} → MAC {found_mac}")
            else:
                result.warnings.append(f"IP {search_term} not found in ARP table on {hostname} ({core_ip})")
                return result
        else:
            # Find IP for this MAC
            ip = arp_table.get(result.mac_address)
            if ip:
                result.ip_address = ip
                log.info(f"Resolved MAC {result.mac_address} → IP {ip}")
            else:
                result.warnings.append(f"MAC {result.mac_address} not found in ARP table (device may be on a different VLAN or offline)")

        # --- Get MAC address table ---
        log.info("Querying MAC address table...")
        mac_output = conn.send_command(platform.get_mac_table_command())
        mac_table = platform.parse_mac_table(mac_output)

        # Find entries for our MAC
        target_mac = result.mac_address
        matching_entries = [e for e in mac_table if e.mac_address == target_mac]

        if not matching_entries:
            result.warnings.append(f"MAC {target_mac} not found in MAC address table on {hostname} ({core_ip})")
            result.switch_hostname = hostname
            result.switch_ip = core_ip
            return result

        # Use the first match (usually there's only one)
        mac_entry = matching_entries[0]
        port = mac_entry.interface
        vlan = mac_entry.vlan

        log.info(f"MAC {target_mac} found on {hostname} port {port} VLAN {vlan}")

        # --- Check for port-channel ---
        po_cmd = platform.get_port_channel_command()
        port_channel_members = {}
        if po_cmd:
            po_output = conn.send_command(po_cmd)
            port_channel_members = platform.parse_port_channel_members(po_output)

        # --- Get CDP/LLDP neighbors ---
        log.info("Querying neighbors...")
        nbr_output = conn.send_command(platform.get_neighbor_command())
        neighbors = platform.parse_neighbors(nbr_output)

        # Also get LLDP neighbors if platform has it (Cisco runs both)
        lldp_cmd = getattr(platform, 'get_lldp_command', None)
        if lldp_cmd and callable(lldp_cmd):
            lldp_output = conn.send_command(lldp_cmd())
            lldp_parser = getattr(platform, 'parse_lldp_neighbors', None)
            if lldp_parser:
                neighbors.extend(lldp_parser(lldp_output))

        # Build interface → neighbor map
        neighbor_by_intf = {}
        for nbr in neighbors:
            norm_local = platform.normalize_interface(nbr.local_interface)
            neighbor_by_intf[norm_local] = nbr
            neighbor_by_intf[nbr.local_interface] = nbr

        # Port-channel promotion: if the port is a Po/LAG, check members for neighbors
        norm_port = platform.normalize_interface(port)
        downstream_nbr = neighbor_by_intf.get(norm_port) or neighbor_by_intf.get(port)

        if not downstream_nbr and norm_port in port_channel_members:
            for member in port_channel_members[norm_port]:
                norm_member = platform.normalize_interface(member)
                downstream_nbr = neighbor_by_intf.get(norm_member) or neighbor_by_intf.get(member)
                if downstream_nbr:
                    break

        # --- Follow downstream neighbor if found ---
        if downstream_nbr:
            result.hops.append({
                "switch_hostname": hostname,
                "switch_ip": core_ip,
                "port": port,
                "reason": f"MAC learned on trunk to {downstream_nbr.neighbor_hostname}",
            })

            log.info(
                f"Following neighbor hop: {hostname}:{port} → "
                f"{downstream_nbr.neighbor_hostname} ({downstream_nbr.neighbor_ip})"
            )

            # Disconnect from core
            conn.disconnect()
            conn = None

            # Connect to downstream switch
            downstream_ip = downstream_nbr.neighbor_ip
            try:
                ds_type, ds_conn = detect_platform(
                    downstream_ip, username, password, enable_secret or password, log, hint=device_type
                )
                if not ds_type:
                    result.warnings.append(f"Could not detect platform on {downstream_ip}")
                    result.switch_hostname = hostname
                    result.switch_ip = core_ip
                    result.interface = port
                    result.vlan = vlan
                    return result

                ds_platform = get_platform(ds_type)
                if not ds_conn:
                    ds_conn = _connect(downstream_ip, username, password, enable_secret, ds_type, log)

                ds_hostname = ds_platform.get_hostname(ds_conn)

                # Find MAC on the downstream switch
                ds_mac_output = ds_conn.send_command(ds_platform.get_mac_table_command())
                ds_mac_table = ds_platform.parse_mac_table(ds_mac_output)
                ds_matches = [e for e in ds_mac_table if e.mac_address == target_mac]

                if ds_matches:
                    mac_entry = ds_matches[0]
                    port = mac_entry.interface
                    vlan = mac_entry.vlan
                    log.info(f"MAC found on downstream {ds_hostname} port {port} VLAN {vlan}")

                    # Gather interface details from downstream
                    _gather_interface_details(result, ds_conn, ds_platform, ds_hostname, downstream_ip, port, vlan, log)
                    ds_conn.disconnect()
                    return result
                else:
                    result.warnings.append(
                        f"MAC {target_mac} not found in MAC table on downstream switch "
                        f"{ds_hostname} ({downstream_ip}) — recording last known location"
                    )
                    ds_conn.disconnect()
                    # Fall through to record the core switch location
                    result.switch_hostname = hostname
                    result.switch_ip = core_ip
                    result.interface = port
                    result.vlan = vlan
                    return result

            except Exception as exc:
                result.warnings.append(f"Failed to connect to downstream {downstream_ip}: {exc}")
                result.switch_hostname = hostname
                result.switch_ip = core_ip
                result.interface = port
                result.vlan = vlan
                return result

        # --- No downstream neighbor — this is the access port ---
        _gather_interface_details(result, conn, platform, hostname, core_ip, port, vlan, log)

    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass

    return result


def _gather_interface_details(result, conn, platform, hostname, switch_ip, port, vlan, log):
    """Populate result with interface config and stats from the current switch."""
    result.switch_hostname = hostname
    result.switch_ip = switch_ip
    result.interface = port
    result.vlan = vlan

    # Running config
    config_cmd = platform.get_interface_config_command(port)
    if config_cmd:
        log.info(f"Getting running config for {port}...")
        try:
            result.interface_config = conn.send_command(config_cmd)
        except Exception as exc:
            result.warnings.append(f"Failed to get interface config: {exc}")

    # Interface stats
    stats_cmd = platform.get_interface_stats_command(port)
    if stats_cmd:
        log.info(f"Getting interface stats for {port}...")
        try:
            stats_output = conn.send_command(stats_cmd)
            result.interface_stats = platform.parse_interface_stats(stats_output)
        except Exception as exc:
            result.warnings.append(f"Failed to get interface stats: {exc}")
