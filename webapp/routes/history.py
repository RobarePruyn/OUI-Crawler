"""Job history, status, and diff API routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from oui_mapper_engine import DeviceRecord, OUIPortMapper

from ..auth import User, get_current_user
from ..database import get_db
from ..db_models import ActionLog, DeviceResult, Job, SwitchResult
from ..schemas import (
    ActionLogOut,
    DeviceResultOut,
    DiffReport,
    DiffRequest,
    JobProgress,
    JobSummary,
    SwitchResultOut,
)

router = APIRouter(prefix="/api", tags=["history"])


@router.get("/jobs/{job_id}/status", response_model=JobProgress)
def job_status(
    job_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = db.query(Job).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    from ..app import job_manager
    progress = job_manager.get_progress(job_id)
    return JobProgress(
        id=job.id,
        status=job.status,
        switches_visited=progress.switches_visited if progress else job.switches_visited,
        devices_found=progress.devices_found if progress else job.devices_found,
        message=progress.message if progress else None,
        error_message=job.error_message,
    )


@router.get("/jobs/{job_id}/results", response_model=list[DeviceResultOut])
def job_results(
    job_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(DeviceResult).filter(DeviceResult.job_id == job_id).all()
    return rows


@router.get("/jobs/{job_id}/switches", response_model=list[SwitchResultOut])
def job_switches(
    job_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(SwitchResult).filter(SwitchResult.job_id == job_id).all()
    return rows


@router.get("/jobs/{job_id}/action-log", response_model=list[ActionLogOut])
def job_action_log(
    job_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(ActionLog).filter(ActionLog.job_id == job_id).all()
    return rows


@router.post("/jobs/{job_id}/cancel")
def cancel_job(
    job_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = db.query(Job).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "running":
        raise HTTPException(status_code=400, detail="Job is not running")
    from ..app import job_manager
    if job_manager.cancel(job_id):
        job.status = "cancelled"
        db.commit()
        return {"detail": "Cancellation requested"}
    raise HTTPException(status_code=400, detail="Could not cancel job")


@router.get("/history/jobs", response_model=list[JobSummary])
def list_jobs(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return db.query(Job).order_by(Job.created_at.desc()).limit(100).all()


@router.delete("/history/jobs/{job_id}")
def delete_job(
    job_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = db.query(Job).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status == "running":
        raise HTTPException(status_code=400, detail="Cannot delete a running job")
    db.delete(job)
    db.commit()
    return {"detail": "Job deleted"}


@router.post("/history/diff", response_model=DiffReport)
def diff_jobs(
    req: DiffRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    def _load(job_id: str) -> list[DeviceRecord]:
        rows = db.query(DeviceResult).filter(DeviceResult.job_id == job_id).all()
        if not rows:
            raise HTTPException(status_code=404, detail=f"No results for job {job_id}")
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

    old_devices = _load(req.old_job_id)
    new_devices = _load(req.new_job_id)

    result = OUIPortMapper.diff_records(old_devices, new_devices)

    return DiffReport(
        added=[DeviceResultOut(
            switch_hostname=d.switch_hostname, switch_ip=d.switch_ip,
            interface=d.interface, mac_address=d.mac_address,
            ip_address=d.ip_address, vlan=d.vlan,
        ) for d in result.added],
        removed=[DeviceResultOut(
            switch_hostname=d.switch_hostname, switch_ip=d.switch_ip,
            interface=d.interface, mac_address=d.mac_address,
            ip_address=d.ip_address, vlan=d.vlan,
        ) for d in result.removed],
        moved=[
            {"mac": m["mac"], "old_switch": m["old_switch"], "old_port": m["old_port"],
             "new_switch": m["new_switch"], "new_port": m["new_port"]}
            for m in result.moved
        ],
        unchanged_count=result.unchanged_count,
        old_count=result.old_count,
        new_count=result.new_count,
    )
