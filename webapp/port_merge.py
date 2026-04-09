"""Merge discovered devices into the VenuePort table."""

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from oui_mapper_engine.mac_utils import (
    mac_matches_oui,
    normalize_mac_to_cisco,
    normalize_oui_prefix,
)

from .changelog import log_changes, log_created
from .db_models import OUIEntry, VenuePort, VenueSwitch

logger = logging.getLogger(__name__)

_TRACKED_FIELDS = ("mac_address", "ip_address", "vlan", "matched_oui", "notes")


def merge_discovered_ports(
    db: Session,
    venue_id: int,
    job_id: str,
    discovered_devices: list,
    port_census: dict | None = None,
) -> None:
    """
    Merge discovered devices into persistent VenuePort records.

    1. Ensure VenueSwitch records exist for all referenced switches
       (creates stubs if discovery ran without a prior inventory).
    2. Consolidate by (switch_hostname, interface) — prefer OUI-matched records.
    3. Merge into VenuePort:
       - Existing → log changes, update mac, ip, vlan, oui, notes, last_seen_at
       - New → create with source="discovered", log created
    4. Stale ports are NOT deleted or cleared.
    """
    now = datetime.now(timezone.utc)

    if not discovered_devices and not port_census:
        return

    # --- Step 1: Ensure switches exist ---
    existing_switches = db.query(VenueSwitch).filter(
        VenueSwitch.venue_id == venue_id,
    ).all()
    switch_map: dict[str, VenueSwitch] = {
        s.hostname.lower(): s for s in existing_switches
    }

    # Collect unique switches from discovered devices (and census)
    device_switches: dict[str, str] = {}  # hostname_lower → switch_ip
    for dev in discovered_devices:
        key = dev.switch_hostname.strip().lower()
        if key and key not in device_switches:
            device_switches[key] = dev.switch_ip
    if port_census:
        for hostname_key in port_census.keys():
            k = hostname_key.strip().lower()
            if k and k not in device_switches:
                device_switches[k] = ""

    # Build a reverse lookup for original-case hostnames
    hostname_original: dict[str, str] = {}
    for dev in discovered_devices:
        k = dev.switch_hostname.strip().lower()
        if k and k not in hostname_original:
            hostname_original[k] = dev.switch_hostname.strip()
    if port_census:
        for hostname_key in port_census.keys():
            k = hostname_key.strip().lower()
            if k and k not in hostname_original:
                hostname_original[k] = hostname_key.strip()

    # Create stubs for missing switches
    for key, switch_ip in device_switches.items():
        if key not in switch_map:
            stub = VenueSwitch(
                venue_id=venue_id,
                hostname=hostname_original.get(key, key),
                mgmt_ip=switch_ip,
                online=True,
                source="discovered",
                first_seen_at=now,
                last_seen_at=now,
                last_crawl_job_id=job_id,
            )
            db.add(stub)
            db.flush()  # get stub.id for port FK
            switch_map[key] = stub
            log_created(db, venue_id, "switch", stub.id, job_id)
            logger.info("Created switch stub '%s' (%s) from discovery data", key, switch_ip)

    # --- Step 2: Consolidate by (switch_hostname, interface) ---
    # Prefer the record with matched_oui set
    consolidated: dict[tuple[str, str], object] = {}
    for dev in discovered_devices:
        key = (dev.switch_hostname.strip().lower(), dev.interface)
        if key not in consolidated:
            consolidated[key] = dev
        elif dev.matched_oui and not consolidated[key].matched_oui:
            consolidated[key] = dev

    # --- Step 3: Merge into VenuePort ---
    # Group by switch to batch-load existing ports
    by_switch: dict[str, list[tuple[str, object]]] = {}
    for (hostname_key, interface), dev in consolidated.items():
        by_switch.setdefault(hostname_key, []).append((interface, dev))

    new_count = 0
    updated_count = 0

    for hostname_key, port_devs in by_switch.items():
        switch = switch_map.get(hostname_key)
        if not switch:
            continue

        existing_ports = db.query(VenuePort).filter(
            VenuePort.switch_id == switch.id,
        ).all()
        port_map = {p.interface: p for p in existing_ports}

        for interface, dev in port_devs:
            # Extract port config fields only if discovery actually collected config
            pc = getattr(dev, "port_config", None)
            has_config = pc is not None

            if interface in port_map:
                row = port_map[interface]

                # Log field-level changes
                old_vals = {f: getattr(row, f) for f in _TRACKED_FIELDS}
                # Resolve IP: use discovered IP if available,
                # but discard stale cached IP when VLAN changed
                # (old IP is from a different subnet).
                new_ip = dev.ip_address if dev.ip_address and dev.ip_address != "unknown" else None
                vlan_changed = dev.vlan and row.vlan and dev.vlan != row.vlan
                if not new_ip and not vlan_changed:
                    new_ip = row.ip_address  # preserve only if VLAN didn't change

                new_vals = {
                    "mac_address": dev.mac_address or row.mac_address,
                    "ip_address": new_ip,
                    "vlan": dev.vlan or row.vlan,
                    "matched_oui": dev.matched_oui or row.matched_oui,
                    "notes": dev.notes or None,
                }
                log_changes(db, venue_id, "port", row.id, old_vals, new_vals, job_id)

                row.mac_address = new_vals["mac_address"]
                row.ip_address = new_vals["ip_address"]
                row.vlan = new_vals["vlan"]
                row.matched_oui = new_vals["matched_oui"]
                row.notes = new_vals["notes"]

                # Only overwrite config fields when discovery actually parsed
                # the running-config for this port. When port_config is None
                # (interface name mismatch, uplink port, failed SSH, etc.)
                # preserve whatever was already in the DB — including values
                # set by optimistic updates after a successful config push.
                if has_config:
                    row.has_portfast = pc.has_portfast
                    row.has_bpdu_guard = pc.has_bpdu_guard
                    row.has_storm_control = pc.has_storm_control
                    row.storm_control_level = pc.storm_control_level
                    row.port_description = pc.description
                    row.civic_location = pc.civic_location

                row.last_seen_at = now
                row.last_crawl_job_id = job_id
                updated_count += 1
            else:
                new_port = VenuePort(
                    switch_id=switch.id,
                    interface=interface,
                    mac_address=dev.mac_address,
                    ip_address=dev.ip_address,
                    vlan=dev.vlan,
                    matched_oui=dev.matched_oui,
                    notes=dev.notes or None,
                    has_portfast=pc.has_portfast if has_config else False,
                    has_bpdu_guard=pc.has_bpdu_guard if has_config else False,
                    has_storm_control=pc.has_storm_control if has_config else False,
                    storm_control_level=pc.storm_control_level if has_config else None,
                    port_description=pc.description if has_config else None,
                    civic_location=pc.civic_location if has_config else None,
                    source="discovered",
                    first_seen_at=now,
                    last_seen_at=now,
                    last_crawl_job_id=job_id,
                )
                db.add(new_port)
                db.flush()
                log_created(db, venue_id, "port", new_port.id, job_id)
                new_count += 1

    # --- Step 4: Propagate IPs across VSX/duplicate MAC entries ---
    # When a device appears on multiple switches (e.g., VSX pair), only one
    # gets a device record (resolved_macs dedup). Propagate the freshly
    # resolved IP to any other port in the venue with the same MAC.
    fresh_ips: dict[str, str] = {}
    for dev in consolidated.values():
        if dev.mac_address and dev.ip_address and dev.ip_address != "unknown":
            fresh_ips[dev.mac_address] = dev.ip_address

    if fresh_ips:
        all_venue_ports = (
            db.query(VenuePort)
            .join(VenueSwitch)
            .filter(VenueSwitch.venue_id == venue_id)
            .filter(VenuePort.mac_address.in_(list(fresh_ips.keys())))
            .all()
        )
        ip_propagated = 0
        for port in all_venue_ports:
            correct_ip = fresh_ips.get(port.mac_address)
            if correct_ip and port.ip_address != correct_ip:
                port.ip_address = correct_ip
                ip_propagated += 1
        if ip_propagated:
            logger.info("Propagated IP updates to %d duplicate-MAC ports", ip_propagated)

    # --- Step 5: Port census reconciliation ---
    # For each switch we actually visited, the engine emits a PortObservation
    # for every access port (single MAC, no switch/router neighbor). Use that
    # to refresh rows whose MAC changed to a non-tracked OUI, and to clear
    # rows on visited switches whose port is now empty. Compliance ignores
    # ports with empty matched_oui, so non-tracked devices are discovered
    # but not surfaced as suggestions.
    if port_census:
        # Load venue OUI list once for reverse lookup
        oui_entries = db.query(OUIEntry).filter(OUIEntry.venue_id == venue_id).all()
        normalized_oui_list = [
            normalize_oui_prefix(e.oui_prefix) for e in oui_entries if e.oui_prefix
        ]

        census_updated = 0
        census_cleared = 0
        census_new = 0

        for hostname_key_raw, observations in port_census.items():
            hostname_key = hostname_key_raw.strip().lower()
            switch = switch_map.get(hostname_key)
            if not switch:
                continue

            existing_ports = db.query(VenuePort).filter(
                VenuePort.switch_id == switch.id,
            ).all()
            port_map = {p.interface: p for p in existing_ports}

            observed_by_intf: dict[str, object] = {}
            for obs in observations:
                observed_by_intf[obs.interface] = obs

            # Update / create from observations
            for interface, obs in observed_by_intf.items():
                mac_cisco = normalize_mac_to_cisco(obs.mac_address) if obs.mac_address else ""
                matched = mac_matches_oui(mac_cisco, normalized_oui_list) if mac_cisco else None
                if interface in port_map:
                    row = port_map[interface]
                    # Skip if a device record already updated this row this run
                    # with a matched OUI — that path has richer data (IP, config).
                    if row.last_crawl_job_id == job_id and row.matched_oui:
                        continue
                    old_vals = {f: getattr(row, f) for f in _TRACKED_FIELDS}
                    vlan_changed = obs.vlan and row.vlan and obs.vlan != row.vlan
                    mac_changed = mac_cisco and row.mac_address and mac_cisco != row.mac_address
                    new_ip = row.ip_address
                    if vlan_changed or mac_changed:
                        new_ip = None  # stale
                    new_vals = {
                        "mac_address": mac_cisco or None,
                        "ip_address": new_ip,
                        "vlan": obs.vlan or None,
                        "matched_oui": matched or None,
                        "notes": row.notes,
                    }
                    log_changes(db, venue_id, "port", row.id, old_vals, new_vals, job_id)
                    row.mac_address = new_vals["mac_address"]
                    row.ip_address = new_vals["ip_address"]
                    row.vlan = new_vals["vlan"]
                    row.matched_oui = new_vals["matched_oui"]
                    row.last_seen_at = now
                    row.last_crawl_job_id = job_id
                    census_updated += 1
                else:
                    new_port = VenuePort(
                        switch_id=switch.id,
                        interface=interface,
                        mac_address=mac_cisco or None,
                        ip_address=None,
                        vlan=obs.vlan or None,
                        matched_oui=matched or None,
                        source="discovered",
                        first_seen_at=now,
                        last_seen_at=now,
                        last_crawl_job_id=job_id,
                    )
                    db.add(new_port)
                    db.flush()
                    log_created(db, venue_id, "port", new_port.id, job_id)
                    census_new += 1

            # Clear rows on visited switches whose interface is no longer
            # in the census (port empty now, or converted to trunk/uplink).
            # Only clear ports that weren't touched this run.
            for interface, row in port_map.items():
                if interface in observed_by_intf:
                    continue
                if row.last_crawl_job_id == job_id:
                    continue
                if not (row.mac_address or row.ip_address or row.matched_oui):
                    continue
                old_vals = {f: getattr(row, f) for f in _TRACKED_FIELDS}
                new_vals = {
                    "mac_address": None,
                    "ip_address": None,
                    "vlan": None,
                    "matched_oui": None,
                    "notes": row.notes,
                }
                log_changes(db, venue_id, "port", row.id, old_vals, new_vals, job_id)
                row.mac_address = None
                row.ip_address = None
                row.vlan = None
                row.matched_oui = None
                row.last_seen_at = now
                row.last_crawl_job_id = job_id
                census_cleared += 1

        logger.info(
            "Port census for venue %d: %d updated, %d new, %d cleared",
            venue_id, census_updated, census_new, census_cleared,
        )

    db.commit()
    logger.info(
        "Port merge for venue %d: %d devices consolidated, %d updated, %d new",
        venue_id,
        len(consolidated),
        updated_count,
        new_count,
    )
