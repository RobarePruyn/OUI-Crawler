"""CSV export endpoints for venue data."""

import csv
import io

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..auth import User, check_venue_access, get_current_user
from ..database import get_db
from ..db_models import ChangeLog, Venue, VenuePort, VenueSwitch, VenueVlan

router = APIRouter(tags=["exports"], dependencies=[Depends(check_venue_access)])


def _csv_response(rows: list[list[str]], headers: list[str], filename: str):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(headers)
    writer.writerows(rows)
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/venues/{venue_id}/switches/csv")
def export_switches_csv(
    venue_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404)
    switches = db.query(VenueSwitch).filter(VenueSwitch.venue_id == venue_id).order_by(VenueSwitch.hostname).all()
    headers = ["Hostname", "Mgmt IP", "Platform", "Online", "Upstream", "Port Count", "Source", "Last Seen"]
    rows = []
    for s in switches:
        rows.append([
            s.hostname, s.mgmt_ip or "", s.platform or "",
            "online" if s.online else "offline",
            s.upstream_hostname or "", str(len(s.ports)),
            s.source or "", str(s.last_seen_at or ""),
        ])
    return _csv_response(rows, headers, f"{venue.name}_switches.csv")


@router.get("/api/venues/{venue_id}/vlans/csv")
def export_vlans_csv(
    venue_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404)
    vlans = db.query(VenueVlan).filter(VenueVlan.venue_id == venue_id).order_by(VenueVlan.vlan_id).all()
    headers = ["VLAN ID", "Name", "SVI IP", "Location", "DHCP Servers", "STP", "Source", "Dark"]
    rows = []
    for v in vlans:
        rows.append([
            str(v.vlan_id), v.name or "", v.ip_address or "",
            v.svi_location or "", v.dhcp_servers or "",
            "Yes" if v.spanning_tree_enabled else "No",
            v.source or "", "Yes" if v.dark_vlan else "No",
        ])
    return _csv_response(rows, headers, f"{venue.name}_vlans.csv")


@router.get("/api/venues/{venue_id}/timeline/csv")
def export_timeline_csv(
    venue_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404)
    changes = (
        db.query(ChangeLog)
        .filter(ChangeLog.venue_id == venue_id)
        .order_by(ChangeLog.created_at.desc())
        .limit(5000)
        .all()
    )
    headers = ["Time", "Change Type", "Entity Type", "Entity ID", "Field", "Old Value", "New Value"]
    rows = []
    for c in changes:
        rows.append([
            str(c.created_at), c.change_type or "", c.entity_type or "",
            str(c.entity_id), c.field_name or "",
            c.old_value or "", c.new_value or "",
        ])
    return _csv_response(rows, headers, f"{venue.name}_timeline.csv")


@router.get("/api/venues/{venue_id}/switches/{switch_id}/ports/csv")
def export_ports_csv(
    venue_id: int,
    switch_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    switch = db.query(VenueSwitch).filter(
        VenueSwitch.id == switch_id, VenueSwitch.venue_id == venue_id,
    ).first()
    if not switch:
        raise HTTPException(status_code=404)
    ports = db.query(VenuePort).filter(VenuePort.switch_id == switch_id).order_by(VenuePort.interface).all()
    headers = ["Interface", "MAC", "IP", "VLAN", "OUI", "Notes", "Last Seen"]
    rows = []
    for p in ports:
        rows.append([
            p.interface, p.mac_address or "", p.ip_address or "",
            p.vlan or "", p.matched_oui or "", p.notes or "",
            str(p.last_seen_at or ""),
        ])
    venue = db.query(Venue).get(venue_id)
    return _csv_response(rows, headers, f"{switch.hostname}_ports.csv")
