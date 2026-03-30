"""Discovery API routes."""

import json
import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import User, get_current_user
from ..database import get_db
from ..db_models import Job
from ..schemas import DiscoveryRequest, JobSummary

router = APIRouter(prefix="/api/discovery", tags=["discovery"])


@router.post("/start", response_model=JobSummary)
def start_discovery(
    req: DiscoveryRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from ..app import job_manager

    job = Job(
        id=str(uuid.uuid4()),
        job_type="discovery",
        status="pending",
        core_ip=req.core_ip,
        oui_list=json.dumps(req.oui_list),
        params=json.dumps({
            "core_ip": req.core_ip,
            "username": req.username,
            "password": req.password,
            "enable_secret": req.enable_secret,
            "platform": req.platform,
            "oui_list": req.oui_list,
            "fan_out": req.fan_out,
            "workers": req.workers,
            "mac_threshold": req.mac_threshold,
            "mgmt_subnet": req.mgmt_subnet,
            "track_vlans": req.track_vlans,
        }),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    job_manager.start_discovery(job.id, json.loads(job.params))

    return job
