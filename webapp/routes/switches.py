"""Venue switch CRUD and port action API routes."""

import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from netmiko import ConnectHandler
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from ..auth import User, get_current_user
from ..changelog import log_changes
from ..crypto import decrypt_credential
from ..database import get_db
from ..db_models import ActionLog, ChangeLog, Venue, VenuePort, VenueSwitch
from ..templates_env import templates

logger = logging.getLogger(__name__)

router = APIRouter(tags=["switches"])


def _render_switches_partial(request: Request, db: Session, venue: Venue) -> HTMLResponse:
    switches = (
        db.query(VenueSwitch)
        .filter(VenueSwitch.venue_id == venue.id)
        .order_by(VenueSwitch.hostname)
        .all()
    )
    return templates.TemplateResponse(
        request, "partials/switches.html", {"venue": venue, "switches": switches}
    )


@router.delete("/api/venues/{venue_id}/switches/{switch_id}", response_class=HTMLResponse)
def delete_switch(
    venue_id: int,
    switch_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    switch = (
        db.query(VenueSwitch)
        .filter(VenueSwitch.id == switch_id, VenueSwitch.venue_id == venue_id)
        .first()
    )
    if not switch:
        raise HTTPException(status_code=404, detail="Switch not found")

    db.delete(switch)
    db.commit()

    venue = db.query(Venue).get(venue_id)
    return _render_switches_partial(request, db, venue)


# ── Port Actions ───────────────────────────────────────────────────

class PortActionRequest(BaseModel):
    action: str           # shutdown, no_shutdown, port_cycle, vlan_assign
    vlan: Optional[str] = None
    save_config: bool = False
    cycle_delay: int = 5


@router.post("/api/venues/{venue_id}/ports/{port_id}/action")
def port_action(
    venue_id: int,
    port_id: int,
    req: PortActionRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    port = db.query(VenuePort).get(port_id)
    if not port:
        raise HTTPException(status_code=404, detail="Port not found")

    switch = db.query(VenueSwitch).get(port.switch_id)
    if not switch or switch.venue_id != venue_id:
        raise HTTPException(status_code=404, detail="Switch not found")

    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    password = decrypt_credential(venue.ssh_password_enc)
    enable = decrypt_credential(venue.enable_secret_enc) if venue.enable_secret_enc else password

    # Determine platform for Netmiko device_type
    platform = switch.platform or venue.platform or "cisco_ios"
    if platform == "auto":
        platform = "cisco_ios"

    from oui_mapper_engine.platforms import get_platform, PLATFORM_MAP
    if platform not in PLATFORM_MAP:
        raise HTTPException(status_code=400, detail=f"Unknown platform: {platform}")

    plat = get_platform(platform)

    try:
        conn = ConnectHandler(
            device_type=platform,
            host=switch.mgmt_ip,
            username=venue.ssh_username,
            password=password,
            secret=enable,
            timeout=15,
            read_timeout_override=30,
        )
        conn.enable()

        commands: list[str] = []
        action_label = req.action

        if req.action == "shutdown":
            commands = [f"interface {port.interface}", "shutdown"]
        elif req.action == "no_shutdown":
            commands = [f"interface {port.interface}", "no shutdown"]
        elif req.action == "port_cycle":
            shut_cmds = [f"interface {port.interface}", "shutdown"]
            conn.send_config_set(shut_cmds)
            time.sleep(req.cycle_delay)
            no_shut_cmds = [f"interface {port.interface}", "no shutdown"]
            conn.send_config_set(no_shut_cmds)
            commands = shut_cmds + ["! wait"] + no_shut_cmds
            action_label = "port_cycle"
        elif req.action == "vlan_assign":
            if not req.vlan:
                raise HTTPException(status_code=400, detail="VLAN required for vlan_assign")
            commands = plat.get_vlan_assign_commands(port.interface, req.vlan)
            action_label = f"vlan_assign ({req.vlan})"
        else:
            raise HTTPException(status_code=400, detail=f"Unknown action: {req.action}")

        # Send commands (port_cycle already sent above)
        if req.action != "port_cycle":
            conn.send_config_set(commands)

        if req.save_config:
            conn.send_command(plat.get_save_config_command(), read_timeout=30)

        conn.disconnect()

        # Log to ActionLog
        db.add(ActionLog(
            job_id=f"venue-{venue_id}",
            action_type=req.action,
            switch_hostname=switch.hostname,
            switch_ip=switch.mgmt_ip,
            interface=port.interface,
            mac_address=port.mac_address,
            status="ok",
            detail=action_label,
            dry_run=False,
        ))

        # Log VLAN change to changelog
        if req.action == "vlan_assign" and req.vlan:
            old_vlan = port.vlan
            log_changes(
                db, venue_id, "port", port.id,
                {"vlan": old_vlan},
                {"vlan": req.vlan},
            )
            port.vlan = req.vlan

        db.commit()

        return {
            "status": "ok",
            "message": f"{action_label} on {port.interface} ({switch.hostname})",
            "commands": commands,
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Port action failed: %s", exc)

        db.add(ActionLog(
            job_id=f"venue-{venue_id}",
            action_type=req.action,
            switch_hostname=switch.hostname,
            switch_ip=switch.mgmt_ip,
            interface=port.interface,
            mac_address=port.mac_address,
            status="error",
            detail=str(exc),
            dry_run=False,
        ))
        db.commit()

        return {
            "status": "error",
            "message": str(exc),
        }
