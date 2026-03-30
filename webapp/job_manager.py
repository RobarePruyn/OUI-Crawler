"""Background job runner — bridges web API and engine."""

from __future__ import annotations

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from ipaddress import IPv4Network
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
from .db_models import ActionLog, DeviceResult, Job, SwitchResult

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

            mapper = OUIPortMapper(
                core_ip=params["core_ip"],
                username=params["username"],
                password=params["password"],
                enable_secret=params.get("enable_secret"),
                platform=params.get("platform", "auto"),
                oui_list=params.get("oui_list", []),
                fan_out=params.get("fan_out", False),
                workers=params.get("workers", 10),
                mac_threshold=params.get("mac_threshold", 1),
                mgmt_subnet=IPv4Network(params["mgmt_subnet"]) if params.get("mgmt_subnet") else None,
                track_vlans=params.get("track_vlans"),
                progress_callback=on_progress,
            )

            with self._lock:
                self._mappers[job_id] = mapper

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
                    switch_tracked_vlan=getattr(dev, "switch_tracked_vlan", None),
                    notes=dev.notes,
                ))

            self._mark_completed(db, job_id, progress.switches_visited, progress.devices_found)

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

            mapper = OUIPortMapper(
                core_ip=params["core_ip"],
                username=params["username"],
                password=params["password"],
                enable_secret=params.get("enable_secret"),
                platform=params.get("platform", "auto"),
                oui_list=[],
                workers=params.get("workers", 10),
                mgmt_subnet=IPv4Network(params["mgmt_subnet"]) if params.get("mgmt_subnet") else None,
                progress_callback=on_progress,
            )

            with self._lock:
                self._mappers[job_id] = mapper

            switches = mapper.discover_switches()

            for sw in switches:
                db.add(SwitchResult(
                    job_id=job_id,
                    hostname=sw.hostname,
                    mgmt_ip=sw.mgmt_ip,
                    platform=sw.platform,
                    upstream_hostname=getattr(sw, "upstream_hostname", None),
                    upstream_ip=getattr(sw, "upstream_ip", None),
                    upstream_interface=getattr(sw, "upstream_interface", None),
                ))

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

            mapper = OUIPortMapper(
                core_ip="0.0.0.0",  # not used for CSV-based actions
                username=params["username"],
                password=params["password"],
                enable_secret=params.get("enable_secret"),
                oui_list=[],
                progress_callback=on_progress,
            )

            with self._lock:
                self._mappers[job_id] = mapper

            action = params["action"]
            dry_run = params.get("dry_run", False)
            save_config = params.get("save_config", False)

            if action == "shutdown":
                plan = mapper.plan_toggle(devices, shutdown=True)
                if not dry_run:
                    results = mapper.execute_toggle(plan.actionable, shutdown=True, save_config=save_config)
                else:
                    results = []
            elif action == "no_shutdown":
                plan = mapper.plan_toggle(devices, shutdown=False)
                if not dry_run:
                    results = mapper.execute_toggle(plan.actionable, shutdown=False, save_config=save_config)
                else:
                    results = []
            elif action == "port_cycle":
                plan = mapper.plan_toggle(devices, shutdown=True)
                if not dry_run:
                    results = mapper.execute_cycle(
                        plan.actionable,
                        cycle_delay=params.get("cycle_delay", 5),
                        save_config=save_config,
                    )
                else:
                    results = []
            elif action == "vlan_assign":
                plan = mapper.plan_vlan_assign(devices)
                if not dry_run:
                    results = mapper.execute_vlan_assign(plan.actionable, save_config=save_config)
                else:
                    results = []
            elif action == "set_description":
                plan = mapper.plan_set_descriptions(devices)
                if not dry_run:
                    template = params.get("desc_template", "{mac} {ip}")
                    results = mapper.execute_set_descriptions(plan.actionable, template=template, save_config=save_config)
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
