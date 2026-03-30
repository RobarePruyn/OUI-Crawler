"""Merge discovered devices into the VenuePort table."""

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .changelog import log_changes, log_created
from .db_models import VenuePort, VenueSwitch

logger = logging.getLogger(__name__)

_TRACKED_FIELDS = ("mac_address", "ip_address", "vlan", "matched_oui", "notes")


def merge_discovered_ports(
    db: Session,
    venue_id: int,
    job_id: str,
    discovered_devices: list,
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

    if not discovered_devices:
        return

    # --- Step 1: Ensure switches exist ---
    existing_switches = db.query(VenueSwitch).filter(
        VenueSwitch.venue_id == venue_id,
    ).all()
    switch_map: dict[str, VenueSwitch] = {
        s.hostname.lower(): s for s in existing_switches
    }

    # Collect unique switches from discovered devices
    device_switches: dict[str, str] = {}  # hostname_lower → switch_ip
    for dev in discovered_devices:
        key = dev.switch_hostname.strip().lower()
        if key and key not in device_switches:
            device_switches[key] = dev.switch_ip

    # Build a reverse lookup for original-case hostnames
    hostname_original: dict[str, str] = {}
    for dev in discovered_devices:
        k = dev.switch_hostname.strip().lower()
        if k and k not in hostname_original:
            hostname_original[k] = dev.switch_hostname.strip()

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
            if interface in port_map:
                row = port_map[interface]

                # Log field-level changes
                old_vals = {f: getattr(row, f) for f in _TRACKED_FIELDS}
                new_vals = {
                    "mac_address": dev.mac_address or row.mac_address,
                    "ip_address": dev.ip_address or row.ip_address,
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
                    source="discovered",
                    first_seen_at=now,
                    last_seen_at=now,
                    last_crawl_job_id=job_id,
                )
                db.add(new_port)
                db.flush()
                log_created(db, venue_id, "port", new_port.id, job_id)
                new_count += 1

    db.commit()
    logger.info(
        "Port merge for venue %d: %d devices consolidated, %d updated, %d new",
        venue_id,
        len(consolidated),
        updated_count,
        new_count,
    )
