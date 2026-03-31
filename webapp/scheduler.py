"""APScheduler integration for recurring venue jobs."""

import json
import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from .config import settings
from .crypto import decrypt_credential
from .database import SessionLocal
from .db_models import Job, OUIEntry, Schedule, Venue, _new_uuid

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()


def init_scheduler() -> None:
    """Load enabled schedules from the DB and start the scheduler."""
    if not settings.scheduler_enabled:
        logger.info("Scheduler disabled by config")
        return

    db = SessionLocal()
    try:
        schedules = db.query(Schedule).filter(Schedule.enabled == True).all()
        for sched in schedules:
            _add_apscheduler_job(sched)
        logger.info("Loaded %d active schedules", len(schedules))
    finally:
        db.close()

    scheduler.start()
    logger.info("Scheduler started")

    # Check for missed jobs on startup
    _catch_up_missed()


def shutdown_scheduler() -> None:
    """Gracefully shut down the scheduler."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler shut down")


def sync_schedule(schedule_id: int) -> None:
    """Add, update, or remove an APScheduler job to match the DB state."""
    job_id = f"schedule_{schedule_id}"

    db = SessionLocal()
    try:
        sched = db.query(Schedule).get(schedule_id)
        if not sched or not sched.enabled:
            # Remove if it exists
            if scheduler.get_job(job_id):
                scheduler.remove_job(job_id)
                logger.info("Removed scheduler job %s", job_id)
            return

        _add_apscheduler_job(sched)
    finally:
        db.close()


def _add_apscheduler_job(sched: Schedule) -> None:
    """Add or replace an APScheduler cron job for a schedule row."""
    job_id = f"schedule_{sched.id}"
    hour, minute = sched.time_of_day.split(":")

    # Replace if already exists
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    scheduler.add_job(
        _run_scheduled_job,
        trigger=CronTrigger(hour=int(hour), minute=int(minute)),
        id=job_id,
        args=[sched.id],
        name=f"{sched.job_type} for schedule {sched.id}",
        replace_existing=True,
        misfire_grace_time=3600,  # run if up to 1 hour late
        coalesce=True,            # collapse multiple missed fires into one
    )
    logger.info("Scheduled %s at %s (schedule_id=%d)", sched.job_type, sched.time_of_day, sched.id)


def _catch_up_missed() -> None:
    """Run any schedules whose time_of_day has passed today but never ran."""
    db = SessionLocal()
    try:
        now = datetime.now()  # local time, matching CronTrigger default
        schedules = db.query(Schedule).filter(Schedule.enabled == True).all()
        for sched in schedules:
            hour, minute = sched.time_of_day.split(":")
            scheduled_today = now.replace(hour=int(hour), minute=int(minute), second=0, microsecond=0)
            if now < scheduled_today:
                continue  # hasn't reached trigger time today yet

            # Check if it already ran today (last_run_at is UTC, convert to local date)
            if sched.last_run_at:
                last_run_local = sched.last_run_at.replace(tzinfo=timezone.utc).astimezone()
                if last_run_local.date() >= now.date():
                    continue

            logger.info(
                "Catch-up: schedule %d (%s at %s) missed today, running now",
                sched.id, sched.job_type, sched.time_of_day,
            )
            _run_scheduled_job(sched.id)
    except Exception:
        logger.exception("Catch-up check failed")
    finally:
        db.close()


def _run_scheduled_job(schedule_id: int) -> None:
    """Execute a scheduled discovery or inventory job."""
    db = SessionLocal()
    try:
        sched = db.query(Schedule).get(schedule_id)
        if not sched or not sched.enabled:
            return

        venue = db.query(Venue).get(sched.venue_id)
        if not venue:
            logger.error("Schedule %d references missing venue %d", schedule_id, sched.venue_id)
            return

        # Build params from venue config
        params = {
            "core_ip": venue.core_ip,
            "platform": venue.platform,
            "username": venue.ssh_username,
            "password": decrypt_credential(venue.ssh_password_enc),
            "enable_secret": decrypt_credential(venue.enable_secret_enc) if venue.enable_secret_enc else None,
            "mgmt_subnet": venue.mgmt_subnet,
            "fan_out": venue.fan_out,
            "workers": venue.workers,
            "mac_threshold": venue.mac_threshold,
        }

        # For discovery, include OUI list and track_vlans
        if sched.job_type == "discovery":
            oui_entries = db.query(OUIEntry).filter(OUIEntry.venue_id == venue.id).all()
            oui_list = [e.oui_prefix for e in oui_entries]
            if not oui_list:
                logger.warning("Scheduled discovery for venue '%s' skipped — no OUI entries", venue.name)
                return
            params["oui_list"] = oui_list

            all_vlans = set()
            for entry in oui_entries:
                if entry.candidate_vlans:
                    try:
                        all_vlans.update(json.loads(entry.candidate_vlans))
                    except (json.JSONDecodeError, TypeError):
                        pass
            if all_vlans:
                params["track_vlans"] = sorted(all_vlans)

        # Create job record
        job_id = _new_uuid()
        job = Job(
            id=job_id,
            job_type=sched.job_type,
            status="pending",
            core_ip=venue.core_ip,
            oui_list=json.dumps(params.get("oui_list", [])),
            params=json.dumps({k: v for k, v in params.items() if k not in ("password", "enable_secret")}),
            venue_id=venue.id,
        )
        db.add(job)
        db.commit()

        # Update schedule tracking
        sched.last_run_at = datetime.now(timezone.utc)
        sched.last_job_id = job_id
        db.commit()

        # Start the job via job_manager
        from .app import job_manager
        if sched.job_type == "discovery":
            job_manager.start_discovery(job_id, params)
        elif sched.job_type == "inventory":
            job_manager.start_inventory(job_id, params)

        logger.info("Scheduled %s job %s started for venue '%s'", sched.job_type, job_id, venue.name)

    except Exception:
        logger.exception("Failed to run scheduled job for schedule %d", schedule_id)
    finally:
        db.close()
