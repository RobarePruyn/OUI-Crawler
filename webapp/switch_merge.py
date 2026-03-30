"""Merge discovered switches into the VenueSwitch table."""

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .changelog import log_changes, log_created, log_offline
from .db_models import VenueSwitch

logger = logging.getLogger(__name__)

_TRACKED_FIELDS = ("mgmt_ip", "platform", "upstream_hostname", "upstream_ip", "upstream_interface")


def merge_discovered_switches(
    db: Session,
    venue_id: int,
    job_id: str,
    discovered_switches: list,
) -> None:
    """
    Merge discovered switches into persistent VenueSwitch records.

    1. Build hostname → SwitchRecord lookup from discovered list.
    2. For each discovered switch:
       - Exists → log changes, update fields, online=True, last_seen_at
       - New → create with source="discovered", log created
    3. Mark existing switches NOT in discovered set as online=False, log offline.
    """
    now = datetime.now(timezone.utc)

    # --- Step 1: Build lookup from discovered data ---
    discovered_map: dict[str, object] = {}
    for sw in discovered_switches:
        hostname = sw.switch_hostname.strip().lower()
        if hostname:
            discovered_map[hostname] = sw

    # --- Step 2: Merge into DB ---
    existing = db.query(VenueSwitch).filter(VenueSwitch.venue_id == venue_id).all()
    existing_map = {s.hostname.lower(): s for s in existing}
    discovered_keys = set(discovered_map.keys())

    for key, sw in discovered_map.items():
        if key in existing_map:
            row = existing_map[key]

            # Capture old values before update
            new_vals = {
                "mgmt_ip": sw.switch_ip or row.mgmt_ip,
                "platform": sw.platform or row.platform,
                "upstream_hostname": sw.upstream_hostname or "",
                "upstream_ip": sw.upstream_ip or "",
                "upstream_interface": sw.upstream_interface or "",
            }
            old_vals = {f: getattr(row, f) for f in _TRACKED_FIELDS}

            # Log if coming back online
            if not row.online:
                old_vals["online"] = "False"
                new_vals["online"] = "True"

            log_changes(db, venue_id, "switch", row.id, old_vals, new_vals, job_id)

            row.mgmt_ip = new_vals["mgmt_ip"]
            row.platform = new_vals["platform"]
            row.upstream_hostname = new_vals["upstream_hostname"]
            row.upstream_ip = new_vals["upstream_ip"]
            row.upstream_interface = new_vals["upstream_interface"]
            row.online = True
            row.last_seen_at = now
            row.last_crawl_job_id = job_id
        else:
            new_switch = VenueSwitch(
                venue_id=venue_id,
                hostname=sw.switch_hostname.strip(),
                mgmt_ip=sw.switch_ip,
                platform=sw.platform,
                upstream_hostname=sw.upstream_hostname or "",
                upstream_ip=sw.upstream_ip or "",
                upstream_interface=sw.upstream_interface or "",
                online=True,
                source="discovered",
                first_seen_at=now,
                last_seen_at=now,
                last_crawl_job_id=job_id,
            )
            db.add(new_switch)
            db.flush()  # get ID for changelog
            log_created(db, venue_id, "switch", new_switch.id, job_id)

    # --- Step 3: Mark missing switches offline ---
    for key, row in existing_map.items():
        if key not in discovered_keys:
            if row.online:
                row.online = False
                log_offline(db, venue_id, "switch", row.id, job_id)

    db.commit()
    logger.info(
        "Switch merge for venue %d: %d discovered, %d existing, %d new",
        venue_id,
        len(discovered_keys),
        len(existing_map),
        len(discovered_keys - set(existing_map.keys())),
    )
