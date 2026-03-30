"""Port action API routes."""

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from oui_mapper_engine import DeviceRecord, OUIPortMapper

from ..auth import User, get_current_user
from ..database import get_db
from ..db_models import DeviceResult, Job
from ..schemas import ActionPreview, ActionRequest, DeviceResultOut, JobSummary

router = APIRouter(prefix="/api/actions", tags=["actions"])


def _load_devices(db: Session, job_id: str) -> list[DeviceRecord]:
    """Load DeviceRecords from a completed discovery job."""
    rows = db.query(DeviceResult).filter(DeviceResult.job_id == job_id).all()
    if not rows:
        raise HTTPException(status_code=404, detail="No device results for that job")
    return [
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


@router.post("/preview", response_model=ActionPreview)
def preview_action(
    req: ActionRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Compute the safety-filtered action plan without executing."""
    devices = _load_devices(db, req.job_id)

    mapper = OUIPortMapper(
        core_ip="0.0.0.0",
        username=req.username,
        password=req.password,
        oui_list=[],
    )

    if req.action in ("shutdown", "no_shutdown", "port_cycle"):
        plan = mapper.plan_toggle(devices, shutdown=(req.action != "no_shutdown"))
    elif req.action == "vlan_assign":
        plan = mapper.plan_vlan_assign(devices)
    elif req.action == "set_description":
        plan = mapper.plan_set_descriptions(devices)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown action: {req.action}")

    return ActionPreview(
        actionable_count=len(plan.actionable),
        skipped_notes=plan.skipped_notes,
        skipped_trunk=plan.skipped_trunk,
        skipped_bad_intf=plan.skipped_bad_intf,
        skipped_correct_vlan=getattr(plan, "skipped_correct_vlan", 0),
        skipped_ambiguous=getattr(plan, "skipped_ambiguous", 0),
        skipped_no_tracked=getattr(plan, "skipped_no_tracked", 0),
        actionable=[
            DeviceResultOut(
                switch_hostname=d.switch_hostname,
                switch_ip=d.switch_ip,
                interface=d.interface,
                mac_address=d.mac_address,
                ip_address=d.ip_address,
                vlan=d.vlan,
            )
            for d in plan.actionable
        ],
    )


@router.post("/execute", response_model=JobSummary)
def execute_action(
    req: ActionRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start an action job in the background."""
    from ..app import job_manager

    # Verify source job exists
    source = db.query(Job).get(req.job_id)
    if not source:
        raise HTTPException(status_code=404, detail="Source job not found")

    job = Job(
        id=str(uuid.uuid4()),
        job_type="action",
        status="pending",
        params=json.dumps({
            "username": req.username,
            "password": req.password,
            "enable_secret": req.enable_secret,
            "action": req.action,
            "cycle_delay": req.cycle_delay,
            "save_config": req.save_config,
            "desc_template": req.desc_template,
            "dry_run": req.dry_run,
        }),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    job_manager.start_action(job.id, req.job_id, json.loads(job.params))

    return job
