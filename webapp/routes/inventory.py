"""Switch inventory API routes."""

import json
import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import User, get_current_user
from ..database import get_db
from ..db_models import Job
from ..schemas import InventoryRequest, JobSummary

router = APIRouter(prefix="/api/inventory", tags=["inventory"])


@router.post("/start", response_model=JobSummary)
def start_inventory(
    req: InventoryRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from ..app import job_manager

    job = Job(
        id=str(uuid.uuid4()),
        job_type="inventory",
        status="pending",
        core_ip=req.core_ip,
        params=json.dumps({
            "core_ip": req.core_ip,
            "username": req.username,
            "password": req.password,
            "enable_secret": req.enable_secret,
            "platform": req.platform,
            "workers": req.workers,
            "mgmt_subnet": req.mgmt_subnet,
        }),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    job_manager.start_inventory(job.id, json.loads(job.params))

    return job
