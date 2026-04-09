"""Venue CRUD and venue-triggered job API routes."""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import User, check_venue_access, get_current_user, get_user_venues
from ..crypto import decrypt_credential, encrypt_credential
from ..database import get_db
from ..db_models import Job, OUIEntry, Venue, VenueVlan, _new_uuid, _utcnow
from ..schemas import VenueCreate, VenueOut, VenueUpdate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/venues", tags=["venues"], dependencies=[Depends(check_venue_access)])


# ── CRUD ────────────────────────────────────────────────────────────

@router.post("", response_model=VenueOut)
def create_venue(
    req: VenueCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if db.query(Venue).filter(Venue.name == req.name).first():
        raise HTTPException(status_code=409, detail="Venue name already exists")

    venue = Venue(
        name=req.name,
        core_ip=req.core_ip,
        platform=req.platform,
        ssh_username=req.ssh_username,
        ssh_password_enc=encrypt_credential(req.ssh_password),
        enable_secret_enc=encrypt_credential(req.enable_secret) if req.enable_secret else None,
        mgmt_subnet=req.mgmt_subnet or None,
        fan_out=req.fan_out,
        workers=req.workers,
        mac_threshold=req.mac_threshold,
        default_dhcp_servers=json.dumps(req.default_dhcp_servers) if req.default_dhcp_servers else None,
        default_dns_servers=json.dumps(req.default_dns_servers) if req.default_dns_servers else None,
        default_gateway_mac=req.default_gateway_mac,
    )
    db.add(venue)
    db.commit()
    db.refresh(venue)
    return venue


@router.get("", response_model=list[VenueOut])
def list_venues(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_user_venues(db, user)


@router.get("/{venue_id}", response_model=VenueOut)
def get_venue(
    venue_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")
    return venue


@router.put("/{venue_id}", response_model=VenueOut)
def update_venue(
    venue_id: int,
    req: VenueUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    if req.name is not None:
        existing = db.query(Venue).filter(Venue.name == req.name, Venue.id != venue_id).first()
        if existing:
            raise HTTPException(status_code=409, detail="Venue name already exists")
        venue.name = req.name
    if req.core_ip is not None:
        venue.core_ip = req.core_ip
    if req.platform is not None:
        venue.platform = req.platform
    if req.ssh_username is not None:
        venue.ssh_username = req.ssh_username
    if req.ssh_password is not None:
        venue.ssh_password_enc = encrypt_credential(req.ssh_password)
    if req.enable_secret is not None:
        venue.enable_secret_enc = encrypt_credential(req.enable_secret) if req.enable_secret else None
    if req.mgmt_subnet is not None:
        venue.mgmt_subnet = req.mgmt_subnet or None
    if req.fan_out is not None:
        venue.fan_out = req.fan_out
    if req.workers is not None:
        venue.workers = req.workers
    if req.mac_threshold is not None:
        venue.mac_threshold = req.mac_threshold
    if req.default_dhcp_servers is not None:
        venue.default_dhcp_servers = json.dumps(req.default_dhcp_servers) if req.default_dhcp_servers else None
    if req.default_dns_servers is not None:
        venue.default_dns_servers = json.dumps(req.default_dns_servers) if req.default_dns_servers else None
    if req.default_gateway_mac is not None:
        venue.default_gateway_mac = req.default_gateway_mac or None

    db.commit()
    db.refresh(venue)
    return venue


@router.delete("/{venue_id}")
def delete_venue(
    venue_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")
    db.delete(venue)
    db.commit()
    return {"detail": "Venue deleted"}


# ── Venue prefill data (for discovery/inventory form population) ────

@router.get("/{venue_id}/prefill")
def venue_prefill(
    venue_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    oui_entries = db.query(OUIEntry).filter(OUIEntry.venue_id == venue_id).all()
    oui_list = [e.oui_prefix for e in oui_entries]

    # Collect candidate VLANs for track_vlans
    all_vlans = set()
    for entry in oui_entries:
        if entry.candidate_vlans:
            try:
                all_vlans.update(json.loads(entry.candidate_vlans))
            except (json.JSONDecodeError, TypeError):
                pass

    return {
        "name": venue.name,
        "core_ip": venue.core_ip,
        "platform": venue.platform,
        "ssh_username": venue.ssh_username,
        "mgmt_subnet": venue.mgmt_subnet or "",
        "fan_out": venue.fan_out,
        "workers": venue.workers,
        "mac_threshold": venue.mac_threshold,
        "oui_list": oui_list,
        "track_vlans": sorted(all_vlans) if all_vlans else [],
    }


# ── Connection test ─────────────────────────────────────────────────

@router.post("/{venue_id}/test")
def test_venue_connection(
    venue_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    from oui_mapper_engine.platforms import detect_platform
    password = decrypt_credential(venue.ssh_password_enc)
    enable = decrypt_credential(venue.enable_secret_enc) if venue.enable_secret_enc else password

    try:
        platform, conn = detect_platform(venue.core_ip, venue.ssh_username, password, enable, logger)
        if conn:
            conn.disconnect()
        return {"status": "ok", "platform": platform, "message": f"Connected to {venue.core_ip} ({platform})"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


# ── Venue-triggered jobs ────────────────────────────────────────────

def _venue_to_params(venue: Venue) -> dict:
    """Build a job params dict from a venue's stored config."""
    return {
        "core_ip": venue.core_ip,
        "platform": venue.platform,
        "username": venue.ssh_username,
        "password": decrypt_credential(venue.ssh_password_enc),
        "enable_secret": decrypt_credential(venue.enable_secret_enc) if venue.enable_secret_enc else None,
        "mgmt_subnet": venue.mgmt_subnet,
        "fan_out": venue.fan_out,
        "workers": venue.workers,
        "mac_threshold": venue.mac_threshold,
    }


@router.post("/{venue_id}/discover")
def venue_discover(
    venue_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    # Collect OUI prefixes from venue registry
    oui_entries = db.query(OUIEntry).filter(OUIEntry.venue_id == venue_id).all()
    oui_list = [e.oui_prefix for e in oui_entries]
    if not oui_list:
        raise HTTPException(status_code=400, detail="No OUI entries configured for this venue")

    params = _venue_to_params(venue)
    params["oui_list"] = oui_list

    # Collect candidate VLANs for track_vlans
    all_vlans = set()
    for entry in oui_entries:
        if entry.candidate_vlans:
            try:
                all_vlans.update(json.loads(entry.candidate_vlans))
            except (json.JSONDecodeError, TypeError):
                pass
    if all_vlans:
        params["track_vlans"] = sorted(all_vlans)

    # Build VLAN→subnet map from VenueVlan SVI config for ARP resolution
    venue_vlans = db.query(VenueVlan).filter(VenueVlan.venue_id == venue_id).all()
    vlan_subnets = {}
    for vv in venue_vlans:
        if vv.ip_address:  # CIDR like "10.2.1.1/24"
            vlan_subnets[str(vv.vlan_id)] = vv.ip_address
    if vlan_subnets:
        params["vlan_subnets"] = vlan_subnets

    job_id = _new_uuid()
    job = Job(
        id=job_id,
        job_type="discovery",
        status="pending",
        core_ip=venue.core_ip,
        oui_list=json.dumps(oui_list),
        params=json.dumps({k: v for k, v in params.items() if k != "password" and k != "enable_secret"}),
        venue_id=venue_id,
    )
    db.add(job)
    db.commit()

    from ..app import job_manager
    job_manager.start_discovery(job_id, params)

    return {"id": job_id, "status": "pending"}


@router.post("/{venue_id}/scan")
def venue_scan(
    venue_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    mode: str = "full",
):
    """Unified scan endpoint.

    mode=full       → inventory phase (LLDP walk) + discovery phase
                      (OUI device hunt) in one job. Default.
    mode=inventory  → inventory only (topology + VLANs, no device hunt).
    """
    if mode == "inventory":
        return venue_inventory(venue_id, user, db)
    return venue_discover(venue_id, user, db)


@router.post("/{venue_id}/inventory")
def venue_inventory(
    venue_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    params = _venue_to_params(venue)

    job_id = _new_uuid()
    job = Job(
        id=job_id,
        job_type="inventory",
        status="pending",
        core_ip=venue.core_ip,
        params=json.dumps({k: v for k, v in params.items() if k != "password" and k != "enable_secret"}),
        venue_id=venue_id,
    )
    db.add(job)
    db.commit()

    from ..app import job_manager
    job_manager.start_inventory(job_id, params)

    return {"id": job_id, "status": "pending"}
