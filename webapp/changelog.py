"""Changelog utility — records field-level changes during merges and actions."""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .db_models import ChangeLog


def log_created(
    db: Session,
    venue_id: int,
    entity_type: str,
    entity_id: int,
    job_id: str | None = None,
) -> None:
    """Log that a new entity was created."""
    db.add(ChangeLog(
        venue_id=venue_id,
        entity_type=entity_type,
        entity_id=entity_id,
        change_type="created",
        job_id=job_id,
        created_at=datetime.now(timezone.utc),
    ))


def log_changes(
    db: Session,
    venue_id: int,
    entity_type: str,
    entity_id: int,
    old_vals: dict,
    new_vals: dict,
    job_id: str | None = None,
) -> int:
    """Compare old and new field values; log one ChangeLog row per changed field.

    Returns the number of changes logged.
    """
    now = datetime.now(timezone.utc)
    count = 0
    for field, new_val in new_vals.items():
        old_val = old_vals.get(field)
        # Normalize to strings for comparison
        old_str = str(old_val) if old_val is not None else None
        new_str = str(new_val) if new_val is not None else None
        if old_str != new_str:
            db.add(ChangeLog(
                venue_id=venue_id,
                entity_type=entity_type,
                entity_id=entity_id,
                change_type="updated",
                field_name=field,
                old_value=old_str,
                new_value=new_str,
                job_id=job_id,
                created_at=now,
            ))
            count += 1
    return count


def log_offline(
    db: Session,
    venue_id: int,
    entity_type: str,
    entity_id: int,
    job_id: str | None = None,
) -> None:
    """Log that an entity went offline / was not seen in latest crawl."""
    db.add(ChangeLog(
        venue_id=venue_id,
        entity_type=entity_type,
        entity_id=entity_id,
        change_type="offline",
        field_name="online",
        old_value="True",
        new_value="False",
        job_id=job_id,
        created_at=datetime.now(timezone.utc),
    ))
