"""Merge discovered switches into the VenueSwitch table.

Matching strategy (rename-safe, stack-aware):

  1. **Stack member overlap** — if any serial in the discovered
     stack_member_serials list also appears in an existing row's
     stack_member_serials, it's the same logical stack. This handles
     stack add/remove (members partially change) and stack active
     failover (primary serial changes).
  2. **Exact chassis serial** — discovered serial_number equals an
     existing serial_number.
  3. **Base MAC** — discovered base_mac equals an existing base_mac.
     Stable across renames; unique per chassis.
  4. **Hostname** (case-insensitive) — fallback for rows that predate
     hardware-identity collection.
  5. **Mgmt IP** — last-resort legacy fallback, only fires when *both*
     the discovered switch and the candidate row have no hardware
     identity. This auto-absorbs pre-identity duplicate rows created
     by hostname renames. Once either side has identity, IP is
     ignored (IPs can legitimately be reassigned).

When a match is found but the hostname differs, it's a **rename**:
the existing row is kept (preserving port FKs and history), hostname
is updated, and a "Switch renamed: OLD → NEW" entry is logged.
"""

import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .changelog import log_changes, log_created, log_offline
from .db_models import ChangeLog, VenueSwitch

logger = logging.getLogger(__name__)

_TRACKED_FIELDS = (
    "mgmt_ip", "platform",
    "upstream_hostname", "upstream_ip", "upstream_interface",
    "serial_number", "base_mac",
)


def _load_members(row: VenueSwitch) -> list[str]:
    if not row.stack_member_serials:
        return []
    try:
        val = json.loads(row.stack_member_serials)
        return [s for s in val if s] if isinstance(val, list) else []
    except (ValueError, TypeError):
        return []


def _find_match(
    sw,
    existing: list[VenueSwitch],
) -> tuple[VenueSwitch | None, str]:
    """Return (matched_row, reason) using the priority ladder.

    Reason is one of: "stack_overlap", "serial", "base_mac", "hostname",
    or "" if no match.
    """
    disc_serial = (getattr(sw, "serial_number", "") or "").strip()
    disc_base_mac = (getattr(sw, "base_mac", "") or "").strip().lower()
    disc_members = set(
        s for s in (getattr(sw, "stack_member_serials", None) or []) if s
    )
    disc_hostname = (sw.switch_hostname or "").strip().lower()

    # 1. Stack member overlap
    if disc_members:
        for row in existing:
            row_members = set(_load_members(row))
            if row_members and (disc_members & row_members):
                return row, "stack_overlap"

    # 2. Exact chassis serial
    if disc_serial:
        for row in existing:
            if row.serial_number and row.serial_number.strip() == disc_serial:
                return row, "serial"

    # 3. Base MAC
    if disc_base_mac:
        for row in existing:
            if row.base_mac and row.base_mac.strip().lower() == disc_base_mac:
                return row, "base_mac"

    # 4. Hostname fallback
    if disc_hostname:
        for row in existing:
            if row.hostname and row.hostname.strip().lower() == disc_hostname:
                return row, "hostname"

    return None, ""


def _row_has_identity(row: VenueSwitch) -> bool:
    return bool(
        (row.serial_number or "").strip()
        or (row.base_mac or "").strip()
        or _load_members(row)
    )


def _absorb_legacy_orphans(
    db: Session,
    venue_id: int,
    winner: VenueSwitch,
    existing: list[VenueSwitch],
    job_id: str,
) -> int:
    """Fold identity-less duplicate rows into `winner`.

    Called after a discovered switch has been matched to `winner` and
    `winner` has been updated with hardware identity. Any other row in
    the venue that (a) lacks identity and (b) shares mgmt_ip with
    `winner` is treated as a legacy duplicate — its ports are
    re-parented onto `winner` (dropping interface conflicts in favor
    of `winner`'s version) and the row is deleted.

    Returns the set of absorbed (and now deleted) row IDs.
    """
    from .db_models import ChangeLog, VenuePort

    absorbed: set[int] = set()
    if not _row_has_identity(winner):
        return absorbed
    winner_ip = (winner.mgmt_ip or "").strip()
    if not winner_ip:
        return absorbed

    winner_interfaces = {
        p.interface for p in db.query(VenuePort).filter(VenuePort.switch_id == winner.id).all()
    }
    for row in existing:
        if row.id == winner.id or row.id in absorbed:
            continue
        if _row_has_identity(row):
            continue
        if (row.mgmt_ip or "").strip() != winner_ip:
            continue

        # Re-parent ports, dropping interface conflicts
        for port in db.query(VenuePort).filter(VenuePort.switch_id == row.id).all():
            if port.interface in winner_interfaces:
                db.delete(port)
            else:
                port.switch_id = winner.id
                winner_interfaces.add(port.interface)

        db.add(ChangeLog(
            venue_id=venue_id,
            entity_type="switch",
            entity_id=winner.id,
            change_type="merged",
            field_name="hostname",
            old_value=row.hostname,
            new_value=winner.hostname,
            job_id=job_id,
        ))
        absorbed.add(row.id)
        db.delete(row)
        logger.info(
            "Absorbed legacy orphan switch %r (id=%d) into %r (id=%d) in venue %d",
            row.hostname, row.id, winner.hostname, winner.id, venue_id,
        )
    return absorbed


def _log_rename(
    db: Session,
    venue_id: int,
    switch_id: int,
    old_hostname: str,
    new_hostname: str,
    job_id: str,
) -> None:
    """Append a dedicated 'renamed' changelog entry (distinct from field
    diffs so it stands out in audit views)."""
    db.add(ChangeLog(
        venue_id=venue_id,
        entity_type="switch",
        entity_id=switch_id,
        change_type="renamed",
        field_name="hostname",
        old_value=old_hostname,
        new_value=new_hostname,
        job_id=job_id,
    ))


def merge_discovered_switches(
    db: Session,
    venue_id: int,
    job_id: str,
    discovered_switches: list,
) -> None:
    """Merge discovered switches into persistent VenueSwitch records.

    See module docstring for matching strategy.
    """
    now = datetime.now(timezone.utc)

    existing = db.query(VenueSwitch).filter(VenueSwitch.venue_id == venue_id).all()
    matched_ids: set[int] = set()
    absorbed_ids: set[int] = set()
    new_count = 0
    rename_count = 0
    absorbed_count = 0

    for sw in discovered_switches:
        if not (sw.switch_hostname or "").strip():
            continue

        row, reason = _find_match(sw, existing)
        disc_hostname = sw.switch_hostname.strip()
        disc_members = list(sw.stack_member_serials or [])
        members_json = json.dumps(sorted(set(disc_members))) if disc_members else None

        if row is not None:
            matched_ids.add(row.id)

            # Rename detection
            if row.hostname and row.hostname.strip().lower() != disc_hostname.lower():
                old_hostname = row.hostname
                _log_rename(db, venue_id, row.id, old_hostname, disc_hostname, job_id)
                row.hostname = disc_hostname
                rename_count += 1
                logger.info(
                    "Switch rename detected in venue %d via %s: %r -> %r",
                    venue_id, reason, old_hostname, disc_hostname,
                )

            new_vals = {
                "mgmt_ip": sw.switch_ip or row.mgmt_ip,
                "platform": sw.platform or row.platform,
                "upstream_hostname": sw.upstream_hostname or "",
                "upstream_ip": sw.upstream_ip or "",
                "upstream_interface": sw.upstream_interface or "",
                "serial_number": (getattr(sw, "serial_number", "") or row.serial_number or ""),
                "base_mac": (getattr(sw, "base_mac", "") or row.base_mac or ""),
            }
            old_vals = {f: getattr(row, f) for f in _TRACKED_FIELDS}

            if not row.online:
                old_vals["online"] = "False"
                new_vals["online"] = "True"

            log_changes(db, venue_id, "switch", row.id, old_vals, new_vals, job_id)

            row.mgmt_ip = new_vals["mgmt_ip"]
            row.platform = new_vals["platform"]
            row.upstream_hostname = new_vals["upstream_hostname"]
            row.upstream_ip = new_vals["upstream_ip"]
            row.upstream_interface = new_vals["upstream_interface"]
            row.serial_number = new_vals["serial_number"] or None
            row.base_mac = new_vals["base_mac"] or None
            if members_json is not None:
                row.stack_member_serials = members_json
            row.online = True
            row.last_seen_at = now
            row.last_crawl_job_id = job_id

            # Legacy-orphan absorption: if this row now has identity and
            # there are other identity-less rows in the venue sharing
            # mgmt_ip, they're duplicates from pre-identity renames.
            absorbed = _absorb_legacy_orphans(db, venue_id, row, existing, job_id)
            if absorbed:
                absorbed_ids.update(absorbed)
                absorbed_count += len(absorbed)
                db.flush()
        else:
            new_switch = VenueSwitch(
                venue_id=venue_id,
                hostname=disc_hostname,
                mgmt_ip=sw.switch_ip,
                platform=sw.platform,
                upstream_hostname=sw.upstream_hostname or "",
                upstream_ip=sw.upstream_ip or "",
                upstream_interface=sw.upstream_interface or "",
                serial_number=(getattr(sw, "serial_number", "") or None),
                base_mac=(getattr(sw, "base_mac", "") or None),
                stack_member_serials=members_json,
                online=True,
                source="discovered",
                first_seen_at=now,
                last_seen_at=now,
                last_crawl_job_id=job_id,
            )
            db.add(new_switch)
            db.flush()
            matched_ids.add(new_switch.id)
            log_created(db, venue_id, "switch", new_switch.id, job_id)
            new_count += 1

    # Mark unseen existing switches offline (skipping rows already
    # absorbed into a winner — they no longer exist)
    offline_count = 0
    for row in existing:
        if row.id in absorbed_ids:
            continue
        if row.id not in matched_ids and row.online:
            row.online = False
            log_offline(db, venue_id, "switch", row.id, job_id)
            offline_count += 1

    db.commit()
    logger.info(
        "Switch merge for venue %d: %d discovered, %d existing, %d new, "
        "%d renamed, %d absorbed (legacy), %d marked offline",
        venue_id, len(discovered_switches), len(existing),
        new_count, rename_count, absorbed_count, offline_count,
    )
