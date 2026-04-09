"""Background job runner — bridges web API and engine."""

from __future__ import annotations

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from oui_mapper_engine import (
    DeviceRecord,
    OUIPortMapper,
    ProgressEvent,
    SwitchRecord,
)
from .config import settings
from .database import SessionLocal
from .db_models import ActionLog, DeviceResult, Job, SwitchResult, Venue

logger = logging.getLogger(__name__)


class ProgressState:
    """In-memory snapshot of a running job's progress (fast polling)."""

    def __init__(self):
        self.switches_visited: int = 0
        self.devices_found: int = 0
        self.message: str = ""


class JobManager:
    """Manages background engine jobs via a thread pool."""

    def __init__(self):
        self._pool = ThreadPoolExecutor(max_workers=settings.max_concurrent_jobs)
        self._progress: dict[str, ProgressState] = {}
        self._mappers: dict[str, OUIPortMapper] = {}
        self._lock = threading.Lock()

    def get_progress(self, job_id: str) -> Optional[ProgressState]:
        with self._lock:
            return self._progress.get(job_id)

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            mapper = self._mappers.get(job_id)
        if mapper is None:
            return False
        mapper._cancelled = True
        return True

    # ── Discovery ────────────────────────────────────────────────────

    def start_discovery(self, job_id: str, params: dict) -> None:
        with self._lock:
            self._progress[job_id] = ProgressState()
        self._pool.submit(self._run_discovery, job_id, params)

    def _run_discovery(self, job_id: str, params: dict) -> None:
        db = SessionLocal()
        try:
            self._mark_running(db, job_id)
            progress = self._progress[job_id]

            def on_progress(event: ProgressEvent):
                progress.switches_visited = event.switches_visited
                progress.devices_found = event.devices_found
                progress.message = event.message or ""

            # Map webapp param names to engine param names
            platform = params.get("platform", "auto")
            forced_platform = None if platform == "auto" else platform

            # Full Scan = inventory phase (LLDP walk) + discovery phase
            # (OUI device hunt) against a single mapper instance so state
            # is shared. Venue-linked jobs run both; standalone (manual
            # core_ip) jobs skip inventory since there's nowhere to
            # persist the switch/VLAN data.
            job = db.query(Job).get(job_id)
            venue_id = job.venue_id if job else None

            mapper = OUIPortMapper(
                core_ip=params["core_ip"],
                username=params["username"],
                password=params["password"],
                enable_secret=params.get("enable_secret") or "",
                forced_platform=forced_platform,
                oui_list=params.get("oui_list", []),
                fan_out=params.get("fan_out", False),
                max_workers=params.get("workers", 10),
                mac_threshold=params.get("mac_threshold", 1),
                mgmt_subnet=params.get("mgmt_subnet") or "",
                track_vlans=params.get("track_vlans"),
                vlan_subnets=params.get("vlan_subnets"),
                discover_vlans=bool(venue_id),
                progress_callback=on_progress,
            )

            with self._lock:
                self._mappers[job_id] = mapper

            # Phase 1: inventory (LLDP topology walk). Populates
            # switch_inventory_records and discovered_vlans so the
            # subsequent device discovery runs against a fully-known
            # venue. Best-effort: failure here logs and proceeds.
            if venue_id:
                try:
                    progress.message = "Inventory phase: walking topology..."
                    mapper.discover_switches()
                except Exception:
                    logger.exception(
                        "Inventory phase failed for job %s; "
                        "continuing with device discovery", job_id,
                    )

            # Phase 2: device discovery (MAC/OUI hunt).
            progress.message = "Discovery phase: hunting devices..."
            devices = mapper.discover()

            # Store results
            for dev in devices:
                db.add(DeviceResult(
                    job_id=job_id,
                    switch_hostname=dev.switch_hostname,
                    switch_ip=dev.switch_ip,
                    interface=dev.interface,
                    mac_address=dev.mac_address,
                    matched_oui=dev.matched_oui,
                    ip_address=dev.ip_address,
                    vlan=dev.vlan,
                    switch_tracked_vlan=dev.switch_tracked_vlan,
                    notes=dev.notes,
                ))

            self._mark_completed(db, job_id, progress.switches_visited, progress.devices_found)

            # Merge discovered switches into venue state (must run BEFORE
            # port merge, since port merge needs the VenueSwitch rows to
            # exist and to have absorbed any legacy duplicates)
            if venue_id and mapper.switch_inventory_records:
                try:
                    from .switch_merge import merge_discovered_switches
                    merge_discovered_switches(
                        db, venue_id, job_id, mapper.switch_inventory_records,
                    )
                except Exception:
                    logger.exception("Switch merge failed for job %s", job_id)

            # Merge discovered VLANs (populated by the inventory phase)
            if venue_id and mapper.discovered_vlans:
                try:
                    from .vlan_merge import merge_discovered_vlans
                    merge_discovered_vlans(
                        db, venue_id, params["core_ip"], mapper.discovered_vlans,
                    )
                except Exception:
                    logger.exception("VLAN merge failed for job %s", job_id)

            # Merge discovered devices into venue port state
            if venue_id:
                try:
                    from .port_merge import merge_discovered_ports
                    merge_discovered_ports(db, venue_id, job_id, devices)
                except Exception:
                    logger.exception("Port merge failed for job %s", job_id)

            # Auto-run compliance if linked to a venue
            if venue_id:
                try:
                    from .compliance import check_vlan_compliance
                    check_vlan_compliance(db, job_id, venue_id)
                except Exception:
                    logger.exception("Auto job compliance check failed for job %s", job_id)
                try:
                    from .compliance import check_venue_compliance
                    check_venue_compliance(db, venue_id)
                except Exception:
                    logger.exception("Auto venue compliance check failed for job %s", job_id)
                try:
                    from .compliance import check_duplicate_switches
                    check_duplicate_switches(db, venue_id)
                except Exception:
                    logger.exception("Auto duplicate-switch check failed for job %s", job_id)

        except Exception as exc:
            logger.exception("Discovery job %s failed", job_id)
            self._mark_failed(db, job_id, str(exc))
        finally:
            with self._lock:
                self._mappers.pop(job_id, None)
            db.close()

    # ── Switch Inventory ─────────────────────────────────────────────

    def start_inventory(self, job_id: str, params: dict) -> None:
        with self._lock:
            self._progress[job_id] = ProgressState()
        self._pool.submit(self._run_inventory, job_id, params)

    def _run_inventory(self, job_id: str, params: dict) -> None:
        db = SessionLocal()
        try:
            self._mark_running(db, job_id)
            progress = self._progress[job_id]

            def on_progress(event: ProgressEvent):
                progress.switches_visited = event.switches_visited
                progress.message = event.message or ""

            platform = params.get("platform", "auto")
            forced_platform = None if platform == "auto" else platform

            # Enable VLAN discovery when job is linked to a venue
            job = db.query(Job).get(job_id)
            venue_id = job.venue_id if job else None

            mapper = OUIPortMapper(
                core_ip=params["core_ip"],
                username=params["username"],
                password=params["password"],
                enable_secret=params.get("enable_secret") or "",
                forced_platform=forced_platform,
                oui_list=[],
                max_workers=params.get("workers", 10),
                mgmt_subnet=params.get("mgmt_subnet") or "",
                discover_vlans=bool(venue_id),
                progress_callback=on_progress,
            )

            with self._lock:
                self._mappers[job_id] = mapper

            switches = mapper.discover_switches()

            for sw in switches:
                db.add(SwitchResult(
                    job_id=job_id,
                    hostname=sw.switch_hostname,
                    mgmt_ip=sw.switch_ip,
                    platform=sw.platform,
                    upstream_hostname=sw.upstream_hostname,
                    upstream_ip=sw.upstream_ip,
                    upstream_interface=sw.upstream_interface,
                ))

            # Merge discovered switches into venue state
            if venue_id and switches:
                try:
                    from .switch_merge import merge_discovered_switches
                    merge_discovered_switches(db, venue_id, job_id, switches)
                except Exception:
                    logger.exception("Switch merge failed for job %s", job_id)

            # Merge discovered VLANs into venue config
            if venue_id and mapper.discovered_vlans:
                try:
                    from .vlan_merge import merge_discovered_vlans
                    merge_discovered_vlans(
                        db, venue_id, params["core_ip"], mapper.discovered_vlans,
                    )
                except Exception:
                    logger.exception("VLAN merge failed for job %s", job_id)

            self._mark_completed(db, job_id, progress.switches_visited, 0)

        except Exception as exc:
            logger.exception("Inventory job %s failed", job_id)
            self._mark_failed(db, job_id, str(exc))
        finally:
            with self._lock:
                self._mappers.pop(job_id, None)
            db.close()

    # ── Actions ──────────────────────────────────────────────────────

    def start_action(self, job_id: str, source_job_id: str, params: dict) -> None:
        with self._lock:
            self._progress[job_id] = ProgressState()
        self._pool.submit(self._run_action, job_id, source_job_id, params)

    def _run_action(self, job_id: str, source_job_id: str, params: dict) -> None:
        db = SessionLocal()
        try:
            self._mark_running(db, job_id)
            progress = self._progress[job_id]

            # Load device records from source job
            rows = db.query(DeviceResult).filter(DeviceResult.job_id == source_job_id).all()
            devices = [
                DeviceRecord(
                    switch_hostname=r.switch_hostname or "",
                    switch_ip=r.switch_ip or "",
                    interface=r.interface or "",
                    mac_address=r.mac_address or "",
                    matched_oui=r.matched_oui or "",
                    ip_address=r.ip_address or "",
                    vlan=r.vlan or "",
                    notes=r.notes or "",
                )
                for r in rows
            ]

            def on_progress(event: ProgressEvent):
                progress.switches_visited = event.switches_visited
                progress.message = event.message or ""

            save_config = params.get("save_config", False)

            mapper = OUIPortMapper(
                core_ip="0.0.0.0",  # not used for CSV-based actions
                username=params["username"],
                password=params["password"],
                enable_secret=params.get("enable_secret") or "",
                oui_list=[],
                save_config=save_config,
                progress_callback=on_progress,
            )

            with self._lock:
                self._mappers[job_id] = mapper

            action = params["action"]
            dry_run = params.get("dry_run", False)

            if action == "shutdown":
                plan = mapper.plan_toggle(devices, action="shutdown")
                if not dry_run:
                    results = mapper.execute_toggle(plan.actionable, action="shutdown")
                else:
                    results = []
            elif action == "no_shutdown":
                plan = mapper.plan_toggle(devices, action="no shutdown")
                if not dry_run:
                    results = mapper.execute_toggle(plan.actionable, action="no shutdown")
                else:
                    results = []
            elif action == "port_cycle":
                plan = mapper.plan_toggle(devices, action="shutdown")
                if not dry_run:
                    results = mapper.execute_cycle(
                        plan.actionable,
                        delay_seconds=params.get("cycle_delay", 5),
                    )
                else:
                    results = []
            elif action == "vlan_assign":
                plan = mapper.plan_vlan_assign(devices)
                if not dry_run:
                    results = mapper.execute_vlan_assign(plan.actionable)
                else:
                    results = []
            elif action == "set_description":
                template = params.get("desc_template", "{mac} {ip}")
                plan = mapper.plan_set_descriptions(devices, template=template)
                if not dry_run:
                    results = mapper.execute_set_descriptions(plan.actionable)
                else:
                    results = []
            else:
                raise ValueError(f"Unknown action: {action}")

            # Store action logs
            for r in results:
                db.add(ActionLog(
                    job_id=job_id,
                    action_type=action,
                    switch_hostname=r.switch_hostname,
                    switch_ip=r.switch_ip,
                    interface=r.interface,
                    status=r.status,
                    detail=r.error or "",
                    dry_run=dry_run,
                ))

            self._mark_completed(db, job_id, progress.switches_visited, 0)

        except Exception as exc:
            logger.exception("Action job %s failed", job_id)
            self._mark_failed(db, job_id, str(exc))
        finally:
            with self._lock:
                self._mappers.pop(job_id, None)
            db.close()

    # ── DB helpers ───────────────────────────────────────────────────

    @staticmethod
    def _mark_running(db: Session, job_id: str) -> None:
        job = db.query(Job).get(job_id)
        if job:
            job.status = "running"
            job.started_at = datetime.now(timezone.utc)
            db.commit()

    @staticmethod
    def _mark_completed(db: Session, job_id: str, switches: int, devices: int) -> None:
        job = db.query(Job).get(job_id)
        if job:
            job.status = "completed"
            job.switches_visited = switches
            job.devices_found = devices
            job.completed_at = datetime.now(timezone.utc)
            db.commit()

    @staticmethod
    def _mark_failed(db: Session, job_id: str, error: str) -> None:
        job = db.query(Job).get(job_id)
        if job:
            job.status = "failed"
            job.error_message = error
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
