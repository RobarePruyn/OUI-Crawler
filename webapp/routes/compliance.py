"""Compliance check API routes and port policy CRUD."""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..auth import User, get_current_user
from ..compliance import check_port_policy_offline, check_vlan_compliance
from ..database import get_db
from ..db_models import ComplianceResult, Job, PortPolicy, Venue
from ..schemas import ComplianceResultOut, ComplianceSummary

router = APIRouter(tags=["compliance"])


# ── Compliance checks ───────────────────────────────────────────────

@router.post("/api/compliance/vlan-check/{job_id}", response_model=ComplianceSummary)
def run_vlan_check(
    job_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = db.query(Job).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if not job.venue_id:
        raise HTTPException(status_code=400, detail="Job is not linked to a venue")

    results = check_vlan_compliance(db, job_id, job.venue_id)
    return _build_summary(results)


@router.post("/api/compliance/port-policy/{job_id}", response_model=ComplianceSummary)
def run_port_policy_check(
    job_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = db.query(Job).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if not job.venue_id:
        raise HTTPException(status_code=400, detail="Job is not linked to a venue")

    results = check_port_policy_offline(db, job_id, job.venue_id)
    return _build_summary(results)


@router.get("/api/compliance/results/{job_id}", response_model=ComplianceSummary)
def get_compliance_results(
    job_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    results = db.query(ComplianceResult).filter(ComplianceResult.job_id == job_id).all()
    return _build_summary(results)


# ── Port policy CRUD (HTMX-friendly) ───────────────────────────────

@router.post("/api/venues/{venue_id}/policies", response_class=HTMLResponse)
async def create_port_policy(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    form = await request.form()
    policy = PortPolicy(
        venue_id=venue_id,
        vlan=form.get("vlan", "").strip(),
        bpdu_guard="bpdu_guard" in form,
        portfast="portfast" in form,
        storm_control="storm_control" in form,
        storm_control_level=form.get("storm_control_level", "1.00").strip(),
        description_template=form.get("description_template", "").strip() or None,
        notes=form.get("notes", "").strip() or None,
    )
    db.add(policy)
    db.commit()

    return _render_policies_partial(request, db, venue)


@router.delete("/api/venues/{venue_id}/policies/{policy_id}", response_class=HTMLResponse)
def delete_port_policy(
    venue_id: int,
    policy_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    policy = db.query(PortPolicy).filter(PortPolicy.id == policy_id, PortPolicy.venue_id == venue_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Port policy not found")
    db.delete(policy)
    db.commit()

    venue = db.query(Venue).get(venue_id)
    return _render_policies_partial(request, db, venue)


# ── Helpers ─────────────────────────────────────────────────────────

def _build_summary(results) -> ComplianceSummary:
    return ComplianceSummary(
        total=len(results),
        ok=sum(1 for r in results if r.severity == "ok"),
        warnings=sum(1 for r in results if r.severity == "warning"),
        critical=sum(1 for r in results if r.severity == "critical"),
        results=[ComplianceResultOut.model_validate(r) for r in results],
    )


def _render_policies_partial(request: Request, db: Session, venue: Venue) -> HTMLResponse:
    from ..templates_env import templates

    policies = db.query(PortPolicy).filter(PortPolicy.venue_id == venue.id).all()
    return templates.TemplateResponse(request, "partials/port_policies.html", {"venue": venue, "policies": policies})
