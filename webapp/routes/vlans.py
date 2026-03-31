"""Venue VLAN CRUD API routes (HTMX partial pattern)."""

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..auth import User, get_current_user
from ..database import get_db
from ..db_models import Venue, VenueVlan
from ..templates_env import templates

router = APIRouter(tags=["vlans"])


def _render_vlan_partial(request: Request, db: Session, venue: Venue) -> HTMLResponse:
    vlans = (
        db.query(VenueVlan)
        .filter(VenueVlan.venue_id == venue.id)
        .order_by(VenueVlan.vlan_id)
        .all()
    )
    return templates.TemplateResponse(
        request, "partials/vlans.html", {"venue": venue, "vlans": vlans}
    )


@router.post("/api/venues/{venue_id}/vlans", response_class=HTMLResponse)
async def add_vlan(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    form = await request.form()
    vlan_id_raw = form.get("vlan_id", "").strip()
    if not vlan_id_raw or not vlan_id_raw.isdigit():
        raise HTTPException(status_code=400, detail="VLAN ID is required (2-4094)")

    vlan_id = int(vlan_id_raw)
    if vlan_id < 2 or vlan_id > 4094:
        raise HTTPException(status_code=400, detail="VLAN ID must be 2-4094")

    # Check for duplicate
    existing = (
        db.query(VenueVlan)
        .filter(VenueVlan.venue_id == venue_id, VenueVlan.vlan_id == vlan_id)
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail=f"VLAN {vlan_id} already exists for this venue")

    name = form.get("name", "").strip() or None
    ip_address = form.get("ip_address", "").strip() or None
    gateway_ip = form.get("gateway_ip", "").strip() or None
    gateway_mac = form.get("gateway_mac", "").strip() or None

    dhcp_raw = form.get("dhcp_servers", "").strip()
    dhcp_json = json.dumps([s.strip() for s in dhcp_raw.split(",") if s.strip()]) if dhcp_raw else None

    dns_raw = form.get("dns_servers", "").strip()
    dns_json = json.dumps([s.strip() for s in dns_raw.split(",") if s.strip()]) if dns_raw else None

    igmp = form.get("igmp_enable") == "on"
    pim = form.get("pim_sparse_enable") == "on"

    dark = form.get("dark_vlan") == "on"

    vlan = VenueVlan(
        venue_id=venue_id,
        vlan_id=vlan_id,
        name=name,
        dark_vlan=dark,
        ip_address=ip_address,
        gateway_ip=gateway_ip,
        gateway_mac=gateway_mac,
        dhcp_servers=dhcp_json,
        dns_servers=dns_json,
        igmp_enable=igmp,
        pim_sparse_enable=pim,
        source="manual",
    )
    db.add(vlan)
    db.commit()

    return _render_vlan_partial(request, db, venue)


@router.put("/api/venues/{venue_id}/vlans/{vlan_entry_id}", response_class=HTMLResponse)
async def update_vlan(
    venue_id: int,
    vlan_entry_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    vlan = (
        db.query(VenueVlan)
        .filter(VenueVlan.id == vlan_entry_id, VenueVlan.venue_id == venue_id)
        .first()
    )
    if not vlan:
        raise HTTPException(status_code=404, detail="VLAN entry not found")

    form = await request.form()

    name = form.get("name")
    if name is not None:
        vlan.name = name.strip() or None

    if form.get("dark_vlan") is not None:
        vlan.dark_vlan = form.get("dark_vlan") == "on"

    ip_address = form.get("ip_address")
    if ip_address is not None:
        vlan.ip_address = ip_address.strip() or None

    gateway_ip = form.get("gateway_ip")
    if gateway_ip is not None:
        vlan.gateway_ip = gateway_ip.strip() or None

    gateway_mac = form.get("gateway_mac")
    if gateway_mac is not None:
        vlan.gateway_mac = gateway_mac.strip() or None

    dhcp_raw = form.get("dhcp_servers")
    if dhcp_raw is not None:
        dhcp_raw = dhcp_raw.strip()
        vlan.dhcp_servers = json.dumps([s.strip() for s in dhcp_raw.split(",") if s.strip()]) if dhcp_raw else None

    dns_raw = form.get("dns_servers")
    if dns_raw is not None:
        dns_raw = dns_raw.strip()
        vlan.dns_servers = json.dumps([s.strip() for s in dns_raw.split(",") if s.strip()]) if dns_raw else None

    if form.get("igmp_enable") is not None:
        vlan.igmp_enable = form.get("igmp_enable") == "on"
    if form.get("pim_sparse_enable") is not None:
        vlan.pim_sparse_enable = form.get("pim_sparse_enable") == "on"

    # Overwrite flags
    if form.get("overwrite_name") is not None:
        vlan.overwrite_name = form.get("overwrite_name") == "on"
    if form.get("overwrite_svi") is not None:
        vlan.overwrite_svi = form.get("overwrite_svi") == "on"
    if form.get("overwrite_dhcp") is not None:
        vlan.overwrite_dhcp = form.get("overwrite_dhcp") == "on"
    if form.get("overwrite_dns") is not None:
        vlan.overwrite_dns = form.get("overwrite_dns") == "on"

    db.commit()

    venue = db.query(Venue).get(venue_id)
    return _render_vlan_partial(request, db, venue)


@router.delete("/api/venues/{venue_id}/vlans/{vlan_entry_id}", response_class=HTMLResponse)
def delete_vlan(
    venue_id: int,
    vlan_entry_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    vlan = (
        db.query(VenueVlan)
        .filter(VenueVlan.id == vlan_entry_id, VenueVlan.venue_id == venue_id)
        .first()
    )
    if not vlan:
        raise HTTPException(status_code=404, detail="VLAN entry not found")

    db.delete(vlan)
    db.commit()

    venue = db.query(Venue).get(venue_id)
    return _render_vlan_partial(request, db, venue)
