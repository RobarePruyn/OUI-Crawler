"""Schedule CRUD API routes (HTMX-friendly)."""

import re

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..auth import User, check_venue_access, get_current_user
from ..database import get_db
from ..db_models import Schedule, Venue
from ..scheduler import sync_schedule

router = APIRouter(tags=["schedules"], dependencies=[Depends(check_venue_access)])


@router.post("/api/venues/{venue_id}/schedules", response_class=HTMLResponse)
async def create_schedule(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    form = await request.form()
    job_type = form.get("job_type", "discovery")
    time_of_day = form.get("time_of_day", "06:00").strip()

    if job_type not in ("discovery", "inventory"):
        raise HTTPException(status_code=400, detail="Invalid job type")
    if not re.match(r"^\d{2}:\d{2}$", time_of_day):
        raise HTTPException(status_code=400, detail="Time must be HH:MM format")

    sched = Schedule(
        venue_id=venue_id,
        job_type=job_type,
        time_of_day=time_of_day,
        enabled=True,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)

    sync_schedule(sched.id)
    return _render_schedules_partial(request, db, venue)


@router.put("/api/venues/{venue_id}/schedules/{schedule_id}", response_class=HTMLResponse)
async def update_schedule(
    venue_id: int,
    schedule_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sched = db.query(Schedule).filter(Schedule.id == schedule_id, Schedule.venue_id == venue_id).first()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # Accept JSON or form data
    content_type = request.headers.get("content-type", "")
    if "json" in content_type:
        data = await request.json()
    else:
        form = await request.form()
        data = dict(form)

    if "enabled" in data:
        val = data["enabled"]
        sched.enabled = val in (True, "true", "True", "1")
    if "time_of_day" in data:
        sched.time_of_day = data["time_of_day"]
    if "job_type" in data:
        sched.job_type = data["job_type"]

    db.commit()
    sync_schedule(sched.id)

    venue = db.query(Venue).get(venue_id)
    return _render_schedules_partial(request, db, venue)


@router.delete("/api/venues/{venue_id}/schedules/{schedule_id}", response_class=HTMLResponse)
def delete_schedule(
    venue_id: int,
    schedule_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sched = db.query(Schedule).filter(Schedule.id == schedule_id, Schedule.venue_id == venue_id).first()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")

    sched_id = sched.id
    db.delete(sched)
    db.commit()
    sync_schedule(sched_id)

    venue = db.query(Venue).get(venue_id)
    return _render_schedules_partial(request, db, venue)


@router.post("/api/venues/{venue_id}/schedules/{schedule_id}/run-now")
def run_schedule_now(
    venue_id: int,
    schedule_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sched = db.query(Schedule).filter(Schedule.id == schedule_id, Schedule.venue_id == venue_id).first()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")

    from ..scheduler import _run_scheduled_job
    _run_scheduled_job(sched.id)

    # Refresh to get latest last_job_id
    db.refresh(sched)
    if sched.last_job_id:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(f"/jobs/{sched.last_job_id}", status_code=303)
    return {"detail": "Job started"}


# ── Helper ──────────────────────────────────────────────────────────

def _render_schedules_partial(request: Request, db: Session, venue: Venue) -> HTMLResponse:
    from ..templates_env import templates

    schedules = db.query(Schedule).filter(Schedule.venue_id == venue.id).all()
    return templates.TemplateResponse(request, "partials/schedules.html", {"venue": venue, "schedules": schedules})
