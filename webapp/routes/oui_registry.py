"""OUI entry CRUD and IEEE lookup API routes."""

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..auth import User, get_current_user
from ..database import get_db
from ..db_models import OUIEntry, Venue
from ..oui_lookup import lookup_manufacturer
from ..schemas import OUIEntryOut, OUILookupRequest, OUILookupResult

router = APIRouter(tags=["oui"])


# ── OUI CRUD (HTMX-friendly — returns partial HTML) ────────────────

@router.post("/api/venues/{venue_id}/oui", response_class=HTMLResponse)
async def add_oui_entry(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    form = await request.form()
    prefix = form.get("oui_prefix", "").strip()
    if not prefix:
        raise HTTPException(status_code=400, detail="OUI prefix is required")

    description = form.get("description", "").strip() or None
    manufacturer = form.get("manufacturer", "").strip() or None

    # Auto-lookup if no manufacturer provided
    if not manufacturer:
        manufacturer = lookup_manufacturer(prefix)

    # Parse comma-separated VLANs and IPs into JSON arrays
    vlans_raw = form.get("candidate_vlans", "").strip()
    vlans_json = json.dumps([v.strip() for v in vlans_raw.split(",") if v.strip()]) if vlans_raw else None

    ips_raw = form.get("expected_ips", "").strip()
    ips_json = json.dumps([ip.strip() for ip in ips_raw.split(",") if ip.strip()]) if ips_raw else None

    entry = OUIEntry(
        venue_id=venue_id,
        oui_prefix=prefix,
        description=description,
        manufacturer=manufacturer,
        candidate_vlans=vlans_json,
        expected_ips=ips_json,
    )
    db.add(entry)
    db.commit()

    # Return refreshed partial
    return _render_oui_partial(request, db, venue)


@router.put("/api/venues/{venue_id}/oui/{entry_id}", response_class=HTMLResponse)
async def update_oui_entry(
    venue_id: int,
    entry_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    entry = db.query(OUIEntry).filter(OUIEntry.id == entry_id, OUIEntry.venue_id == venue_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="OUI entry not found")

    form = await request.form()

    prefix = form.get("oui_prefix", "").strip()
    if prefix:
        entry.oui_prefix = prefix

    description = form.get("description")
    if description is not None:
        entry.description = description.strip() or None

    manufacturer = form.get("manufacturer")
    if manufacturer is not None:
        entry.manufacturer = manufacturer.strip() or None

    vlans_raw = form.get("candidate_vlans")
    if vlans_raw is not None:
        vlans_raw = vlans_raw.strip()
        entry.candidate_vlans = json.dumps([v.strip() for v in vlans_raw.split(",") if v.strip()]) if vlans_raw else None

    ips_raw = form.get("expected_ips")
    if ips_raw is not None:
        ips_raw = ips_raw.strip()
        entry.expected_ips = json.dumps([ip.strip() for ip in ips_raw.split(",") if ip.strip()]) if ips_raw else None

    db.commit()

    venue = db.query(Venue).get(venue_id)
    return _render_oui_partial(request, db, venue)


@router.delete("/api/venues/{venue_id}/oui/{entry_id}", response_class=HTMLResponse)
def delete_oui_entry(
    venue_id: int,
    entry_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    entry = db.query(OUIEntry).filter(OUIEntry.id == entry_id, OUIEntry.venue_id == venue_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="OUI entry not found")
    db.delete(entry)
    db.commit()

    venue = db.query(Venue).get(venue_id)
    return _render_oui_partial(request, db, venue)


# ── IEEE lookup endpoint ────────────────────────────────────────────

@router.post("/api/oui/lookup", response_model=OUILookupResult)
def oui_lookup(
    req: OUILookupRequest,
    user: User = Depends(get_current_user),
):
    mfr = lookup_manufacturer(req.oui_prefix)
    return OUILookupResult(
        oui_prefix=req.oui_prefix,
        manufacturer=mfr,
        found=mfr is not None,
    )


# ── Helper ──────────────────────────────────────────────────────────

def _render_oui_partial(request: Request, db: Session, venue: Venue) -> HTMLResponse:
    from pathlib import Path
    from fastapi.templating import Jinja2Templates

    templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
    templates.env.filters["fromjson"] = lambda s: json.loads(s) if s else []
    entries = db.query(OUIEntry).filter(OUIEntry.venue_id == venue.id).all()
    return templates.TemplateResponse(request, "partials/oui_registry.html", {"venue": venue, "entries": entries})
