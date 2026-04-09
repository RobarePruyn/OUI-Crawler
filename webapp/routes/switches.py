"""Venue switch CRUD and port action API routes."""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from netmiko import ConnectHandler
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from ..auth import User, check_venue_access, get_current_user
from ..changelog import log_changes
from ..crypto import decrypt_credential
from ..database import get_db
from ..db_models import ActionLog, ChangeLog, PortPolicy, Venue, VenuePort, VenueSwitch, VenueVlan
from ..templates_env import templates

logger = logging.getLogger(__name__)

router = APIRouter(tags=["switches"], dependencies=[Depends(check_venue_access)])

# Error patterns that indicate a command was rejected by the switch.
# Checked case-insensitively against each output line.
_CMD_ERROR_PATTERNS = [
    "% invalid",
    "% ambiguous",
    "% incomplete",
    "% unknown",
    "% error",
    "% unrecognized",
    "% not supported",
    "% feature not enabled",
    "% failed",
    "% cannot",
    "command rejected",
    "command authorization failed",
    "insufficient privilege",
    "not authorized",
    "error:",
    "failed to apply",
]


def _check_config_output(output: str, commands: list[str]) -> list[str]:
    """Check send_config_set output for per-command errors.

    Walks the output line-by-line, correlating each error with the
    command that triggered it. Returns a list of "command -> error"
    strings (empty if all commands succeeded).
    """
    if not output:
        return []

    errors = []
    lines = output.splitlines()
    # Track the most recent command we saw echoed in the output
    last_cmd = ""

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Check if this line is a command echo (netmiko echoes each command)
        for cmd in commands:
            if stripped.endswith(cmd) or stripped == cmd:
                last_cmd = cmd
                break

        # Check for error patterns
        lower = stripped.lower()
        for pattern in _CMD_ERROR_PATTERNS:
            if pattern in lower:
                if last_cmd:
                    errors.append(f"{last_cmd} -> {stripped}")
                else:
                    errors.append(stripped)
                break

    return errors


def build_port_grids(switches: list[VenueSwitch]) -> dict[int, list[str]]:
    """Compute per-switch port status dots for the switches list mini-grid.

    Each port becomes one of: "uplink" (notes mention uplink/trunk),
    "matched" (has an OUI match), or "empty" (MAC seen but unmatched).
    Ports with no MAC are omitted.
    """
    port_grids: dict[int, list[str]] = {}
    for sw in switches:
        dots = []
        for p in sw.ports:
            notes = (p.notes or "").lower()
            if "uplink" in notes or "trunk" in notes:
                dots.append("uplink")
            elif p.matched_oui:
                dots.append("matched")
            elif p.mac_address:
                dots.append("empty")
        port_grids[sw.id] = dots
    return port_grids


def _render_switches_partial(request: Request, db: Session, venue: Venue) -> HTMLResponse:
    switches = (
        db.query(VenueSwitch)
        .filter(VenueSwitch.venue_id == venue.id)
        .order_by(VenueSwitch.hostname)
        .all()
    )
    return templates.TemplateResponse(
        request,
        "partials/switches.html",
        {"venue": venue, "switches": switches, "port_grids": build_port_grids(switches)},
    )


@router.delete("/api/venues/{venue_id}/switches", response_class=HTMLResponse)
def delete_all_switches(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user.role != "super_admin":
        raise HTTPException(status_code=403, detail="Super admin only")
    switches = db.query(VenueSwitch).filter(VenueSwitch.venue_id == venue_id).all()
    count = len(switches)
    for sw in switches:
        db.delete(sw)
    db.commit()
    logger.info("Deleted all %d switches in venue %d (by %s)",
                count, venue_id, user.username)
    venue = db.query(Venue).get(venue_id)
    return _render_switches_partial(request, db, venue)


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
    action: str           # shutdown, no_shutdown, port_cycle, poe_cycle, vlan_assign, port_config_push
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

    from netcaster_engine.platforms import get_platform, PLATFORM_MAP
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
        elif req.action == "poe_cycle":
            poe_off = plat.get_poe_off_command(port.interface)
            conn.send_config_set(poe_off)
            time.sleep(req.cycle_delay)
            poe_on = plat.get_poe_on_command(port.interface)
            conn.send_config_set(poe_on)
            commands = poe_off + ["! wait"] + poe_on
            action_label = "poe_cycle"
        elif req.action == "vlan_assign":
            if not req.vlan:
                raise HTTPException(status_code=400, detail="VLAN required for vlan_assign")
            # Pre-create the VLAN on the switch (idempotent on Cisco, required on Aruba)
            vlan_record = db.query(VenueVlan).filter(
                VenueVlan.venue_id == venue_id,
                VenueVlan.vlan_id == int(req.vlan),
            ).first()
            vlan_name = vlan_record.name if vlan_record else ""
            vlan_create_cmds = plat.get_vlan_create_commands(int(req.vlan), vlan_name)
            if vlan_create_cmds:
                conn.send_config_set(vlan_create_cmds)
            commands = plat.get_vlan_assign_commands(port.interface, req.vlan)
            conn.send_config_set(commands)
            # Bounce port so device re-DHCPs on the new VLAN
            conn.send_config_set([f"interface {port.interface}", "shutdown"])
            time.sleep(2)
            conn.send_config_set([f"interface {port.interface}", "no shutdown"])
            commands += [f"interface {port.interface}", "shutdown", "! wait 2s", "no shutdown"]
            # Clear stale IP — device will get a new one via DHCP
            port.ip_address = None
            port.vlan = req.vlan
            action_label = f"vlan_assign ({req.vlan})"
        elif req.action == "port_config_push":
            device_vlan = (port.vlan or "").strip()
            if not device_vlan:
                raise HTTPException(status_code=400, detail="Port has no VLAN assigned")
            policy = db.query(PortPolicy).filter(
                PortPolicy.venue_id == venue_id,
                PortPolicy.vlan == device_vlan,
            ).first()
            if not policy:
                raise HTTPException(status_code=400, detail=f"No port policy for VLAN {device_vlan}")
            # Render description template
            rendered_desc = None
            if policy.description_template:
                from ..compliance import _render_description
                rendered_desc = _render_description(policy.description_template, port, switch)
            commands = plat.get_port_config_commands(
                port.interface,
                bpdu_guard=policy.bpdu_guard,
                portfast=policy.portfast,
                storm_control=policy.storm_control,
                storm_control_level=policy.storm_control_level or "1.00",
                description=rendered_desc,
            )
            action_label = f"port_config_push (VLAN {device_vlan})"
        else:
            raise HTTPException(status_code=400, detail=f"Unknown action: {req.action}")

        # Send commands (port_cycle and vlan_assign already sent above)
        cmd_warnings = []
        if req.action not in ("port_cycle", "poe_cycle", "vlan_assign"):
            output = conn.send_config_set(commands)
            cmd_warnings = _check_config_output(output, commands)
            if cmd_warnings:
                logger.warning("Command warnings on %s:%s: %s",
                               switch.hostname, port.interface, cmd_warnings)

        if req.save_config:
            conn.send_command(plat.get_save_config_command(), read_timeout=30)

        conn.disconnect()

        # Log to ActionLog
        status = "ok" if not cmd_warnings else "warning"
        detail = action_label
        if cmd_warnings:
            detail += " [WARNINGS: " + "; ".join(cmd_warnings) + "]"
        db.add(ActionLog(
            job_id=f"venue-{venue_id}",
            action_type=req.action,
            switch_hostname=switch.hostname,
            switch_ip=switch.mgmt_ip,
            interface=port.interface,
            mac_address=port.mac_address,
            status=status,
            detail=detail,
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

        # Optimistic update after successful port config push
        if req.action == "port_config_push":
            if cmd_warnings:
                port.last_config_error = "; ".join(cmd_warnings)
            else:
                port.last_config_error = None
                port.has_portfast = policy.portfast
                port.has_bpdu_guard = policy.bpdu_guard
                port.has_storm_control = policy.storm_control
                if policy.storm_control:
                    port.storm_control_level = policy.storm_control_level
                if rendered_desc:
                    port.port_description = rendered_desc

        db.commit()

        return {
            "status": "ok" if not cmd_warnings else "warning",
            "message": f"{action_label} on {port.interface} ({switch.hostname})",
            "commands": commands,
            "warnings": cmd_warnings,
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


# ── Batch Port Actions ────────────────────────────────────────────

class BatchPortAction(BaseModel):
    port_id: int
    action: str          # vlan_assign, port_config_push
    vlan: Optional[str] = None  # for vlan_assign


class BatchPortActionRequest(BaseModel):
    actions: list[BatchPortAction]


@router.post("/api/venues/{venue_id}/batch-port-action")
def batch_port_action(
    venue_id: int,
    req: BatchPortActionRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Execute port actions grouped by switch.

    For each switch: one SSH session, pre-create VLANs, configure all
    ports, write memory once, then trigger a re-discovery to verify.
    """
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    password = decrypt_credential(venue.ssh_password_enc)
    enable = decrypt_credential(venue.enable_secret_enc) if venue.enable_secret_enc else password

    # Load all referenced ports and group by switch
    port_ids = [a.port_id for a in req.actions]
    ports = db.query(VenuePort).filter(VenuePort.id.in_(port_ids)).all()
    port_map = {p.id: p for p in ports}

    switches_cache: dict[int, VenueSwitch] = {}
    for p in ports:
        if p.switch_id not in switches_cache:
            switches_cache[p.switch_id] = db.query(VenueSwitch).get(p.switch_id)

    # Group actions by switch
    by_switch: dict[int, list[BatchPortAction]] = {}
    for action in req.actions:
        port = port_map.get(action.port_id)
        if not port:
            continue
        by_switch.setdefault(port.switch_id, []).append(action)

    # Load policies and VLANs for lookups
    policies = db.query(PortPolicy).filter(PortPolicy.venue_id == venue_id).all()
    policy_map = {p.vlan: p for p in policies}
    venue_vlans = db.query(VenueVlan).filter(VenueVlan.venue_id == venue_id).all()
    vlan_name_map = {str(v.vlan_id): v.name or "" for v in venue_vlans}

    from netcaster_engine.platforms import get_platform, PLATFORM_MAP
    from ..compliance import _render_description

    results_lock = threading.Lock()
    results = {"ok": 0, "fail": 0, "warnings": 0, "errors": [],
               "switches_touched": [], "actions_log": [], "vlans_created": []}
    # Collect DB operations from threads to apply on main thread
    db_ops: list[dict] = []
    db_ops_lock = threading.Lock()

    def _process_switch(switch_id: int, switch_actions: list[BatchPortAction]):
        """Process all actions for one switch in a single SSH session."""
        switch = switches_cache.get(switch_id)
        if not switch:
            return

        platform_name = switch.platform or venue.platform or "cisco_ios"
        if platform_name == "auto":
            platform_name = "cisco_ios"
        if platform_name not in PLATFORM_MAP:
            with results_lock:
                results["errors"].append(f"Unknown platform {platform_name} for {switch.hostname}")
                results["fail"] += len(switch_actions)
            return

        plat = get_platform(platform_name)
        local_ok = 0
        local_fail = 0
        local_warnings = 0
        local_errors = []
        local_db_ops = []
        local_actions_log = []
        local_vlans_created = []

        try:
            conn = ConnectHandler(
                device_type=platform_name,
                host=switch.mgmt_ip,
                username=venue.ssh_username,
                password=password,
                secret=enable,
                timeout=15,
                read_timeout_override=30,
            )
            conn.enable()

            # Collect VLANs that need pre-creation on this switch
            vlans_to_create: set[str] = set()
            for action in switch_actions:
                if action.action == "vlan_assign" and action.vlan:
                    vlans_to_create.add(action.vlan)

            # Pre-create all needed VLANs (idempotent)
            for vlan_id in vlans_to_create:
                vlan_name = vlan_name_map.get(vlan_id, "")
                vlan_cmds = plat.get_vlan_create_commands(int(vlan_id), vlan_name)
                if vlan_cmds:
                    conn.send_config_set(vlan_cmds)
                    local_vlans_created.append(
                        f"VLAN {vlan_id}" + (f" ({vlan_name})" if vlan_name else "") +
                        f" on {switch.hostname}"
                    )

            # Execute each port action
            for action in switch_actions:
                port = port_map.get(action.port_id)
                if not port:
                    local_fail += 1
                    continue

                try:
                    commands: list[str] = []
                    action_label = action.action

                    if action.action == "vlan_assign" and action.vlan:
                        commands = plat.get_vlan_assign_commands(port.interface, action.vlan)
                        # Bounce port so device re-DHCPs on the new VLAN
                        commands += [f"interface {port.interface}", "shutdown"]
                        action_label = f"vlan_assign ({action.vlan})"
                    elif action.action == "port_config_push":
                        device_vlan = (port.vlan or "").strip()
                        policy = policy_map.get(device_vlan)
                        if not policy:
                            local_fail += 1
                            local_errors.append(f"No policy for VLAN {device_vlan} on {port.interface}")
                            continue
                        rendered_desc = None
                        if policy.description_template:
                            rendered_desc = _render_description(policy.description_template, port, switch)
                        commands = plat.get_port_config_commands(
                            port.interface,
                            bpdu_guard=policy.bpdu_guard,
                            portfast=policy.portfast,
                            storm_control=policy.storm_control,
                            storm_control_level=policy.storm_control_level or "1.00",
                            description=rendered_desc,
                        )
                        action_label = f"port_config_push (VLAN {device_vlan})"

                    cmd_warnings = []
                    if commands:
                        output = conn.send_config_set(commands)
                        cmd_warnings = _check_config_output(output, commands)
                        if cmd_warnings:
                            logger.warning("Command warnings on %s:%s: %s",
                                           switch.hostname, port.interface, cmd_warnings)
                        # Bring port back up after VLAN assign (shut was in commands)
                        if action.action == "vlan_assign":
                            time.sleep(2)
                            conn.send_config_set([f"interface {port.interface}", "no shutdown"])

                    detail = action_label
                    if cmd_warnings:
                        detail += " [WARNINGS: " + "; ".join(cmd_warnings) + "]"

                    # Queue DB operations for main thread
                    local_db_ops.append({
                        "type": "action_log",
                        "job_id": f"venue-{venue_id}",
                        "action_type": action.action,
                        "switch_hostname": switch.hostname,
                        "switch_ip": switch.mgmt_ip,
                        "interface": port.interface,
                        "mac_address": port.mac_address,
                        "detail": detail,
                        "status": "warning" if cmd_warnings else "ok",
                    })

                    if action.action == "vlan_assign" and action.vlan:
                        local_db_ops.append({
                            "type": "vlan_update",
                            "port_id": port.id,
                            "old_vlan": port.vlan,
                            "new_vlan": action.vlan,
                        })
                        # Update in-memory so subsequent port_config_push
                        # for the same port finds the correct policy
                        port.vlan = action.vlan
                        local_actions_log.append(
                            f"{switch.hostname} {port.interface}: VLAN {port.vlan} → {action.vlan}"
                        )
                    elif action.action == "port_config_push":
                        log_msg = f"{switch.hostname} {port.interface}: applied port policy"
                        if cmd_warnings:
                            log_msg += " [WARNINGS: " + "; ".join(cmd_warnings) + "]"
                            local_db_ops.append({
                                "type": "port_config_error",
                                "port_id": port.id,
                                "error": "; ".join(cmd_warnings),
                            })
                        else:
                            # Optimistically update VenuePort config fields
                            local_db_ops.append({
                                "type": "port_config_update",
                                "port_id": port.id,
                                "policy_vlan": device_vlan,
                            })
                        local_actions_log.append(log_msg)

                    if cmd_warnings:
                        local_warnings += 1
                    local_ok += 1

                except Exception as port_exc:
                    local_fail += 1
                    local_errors.append(f"{switch.hostname}:{port.interface}: {port_exc}")
                    logger.error("Batch action failed on %s:%s: %s",
                                 switch.hostname, port.interface, port_exc)

            # Write memory once for this switch
            try:
                conn.send_command(plat.get_save_config_command(), read_timeout=30)
            except Exception as save_exc:
                logger.warning("Write memory failed on %s: %s", switch.hostname, save_exc)
                local_errors.append(f"Write memory failed on {switch.hostname}: {save_exc}")

            conn.disconnect()

            with results_lock:
                results["ok"] += local_ok
                results["fail"] += local_fail
                results["warnings"] += local_warnings
                results["errors"].extend(local_errors)
                results["switches_touched"].append(switch.hostname)
                results["actions_log"].extend(local_actions_log)
                results["vlans_created"].extend(local_vlans_created)
            with db_ops_lock:
                db_ops.extend(local_db_ops)

        except Exception as conn_exc:
            logger.error("Batch: failed to connect to %s: %s", switch.hostname, conn_exc)
            with results_lock:
                results["fail"] += len(switch_actions)
                results["errors"].append(f"Connection to {switch.hostname} failed: {conn_exc}")

    # Run one thread per switch, up to 20 concurrent
    max_workers = min(20, len(by_switch))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_process_switch, sid, actions): sid
            for sid, actions in by_switch.items()
        }
        for future in as_completed(futures):
            exc = future.exception()
            if exc:
                sid = futures[future]
                sw = switches_cache.get(sid)
                hostname = sw.hostname if sw else f"switch-{sid}"
                logger.error("Thread exception for %s: %s", hostname, exc)
                with results_lock:
                    results["errors"].append(f"Thread error for {hostname}: {exc}")

    # Apply DB operations on main thread (SQLite is not thread-safe)
    for op in db_ops:
        if op["type"] == "action_log":
            db.add(ActionLog(
                job_id=op["job_id"],
                action_type=op["action_type"],
                switch_hostname=op["switch_hostname"],
                switch_ip=op["switch_ip"],
                interface=op["interface"],
                mac_address=op["mac_address"],
                status=op.get("status", "ok"),
                detail=op["detail"],
                dry_run=False,
            ))
        elif op["type"] == "vlan_update":
            port = port_map.get(op["port_id"])
            if port:
                log_changes(db, venue_id, "port", port.id,
                            {"vlan": op["old_vlan"]}, {"vlan": op["new_vlan"]})
                port.vlan = op["new_vlan"]
                port.ip_address = None  # clear stale IP — device will re-DHCP
        elif op["type"] == "port_config_error":
            # Record the error so compliance view can show it
            port = port_map.get(op["port_id"])
            if port:
                port.last_config_error = op["error"]
        elif op["type"] == "port_config_update":
            # Optimistic update — mark port config as matching policy
            # so compliance passes immediately. Re-discovery will verify.
            port = port_map.get(op["port_id"])
            policy = policy_map.get(op.get("policy_vlan", ""))
            if port and policy:
                port.last_config_error = None  # clear any prior error
                port.has_portfast = policy.portfast
                port.has_bpdu_guard = policy.bpdu_guard
                port.has_storm_control = policy.storm_control
                port.storm_control_level = policy.storm_control_level if policy.storm_control else port.storm_control_level
                if policy.description_template:
                    sw = switches_cache.get(port.switch_id)
                    from ..compliance import _render_description
                    rendered = _render_description(policy.description_template, port, sw)
                    if rendered:
                        port.port_description = rendered

    db.commit()

    # Trigger re-discovery on touched switches to verify config stuck
    rediscovery_job_id = None
    if results["switches_touched"]:
        try:
            rediscovery_job_id = _trigger_rediscovery(db, venue, results["switches_touched"])
        except Exception as exc:
            logger.warning("Re-discovery trigger failed: %s", exc)

    return {
        "status": "ok" if results["fail"] == 0 and results["warnings"] == 0 else "partial",
        "ok": results["ok"],
        "fail": results["fail"],
        "warnings": results["warnings"],
        "errors": results["errors"][:10],
        "switches_touched": results["switches_touched"],
        "actions_log": results["actions_log"],
        "vlans_created": results["vlans_created"],
        "rediscovery_job_id": rediscovery_job_id,
    }


def _trigger_rediscovery(db: Session, venue: Venue, switch_hostnames: list[str]):
    """Trigger a discovery crawl for the venue to re-read switch state."""
    from ..crypto import decrypt_credential
    from ..app import job_manager
    from ..db_models import Job, OUIEntry
    import json
    import uuid

    oui_entries = db.query(OUIEntry).filter(OUIEntry.venue_id == venue.id).all()
    oui_list = []
    for e in oui_entries:
        prefix = (e.oui_prefix or "").replace(":", "").replace("-", "").replace(".", "").upper()
        if prefix:
            oui_list.append(prefix)

    job_id = str(uuid.uuid4())
    job = Job(
        id=job_id,
        job_type="discovery",
        status="pending",
        venue_id=venue.id,
        params=json.dumps({"trigger": "post_batch_push", "switches": switch_hostnames}),
    )
    db.add(job)
    db.commit()

    password = decrypt_credential(venue.ssh_password_enc)
    enable = decrypt_credential(venue.enable_secret_enc) if venue.enable_secret_enc else password

    params = {
        "core_ip": venue.core_ip,
        "username": venue.ssh_username,
        "password": password,
        "enable_secret": enable,
        "platform": venue.platform,
        "oui_list": oui_list,
        "fan_out": venue.fan_out,
        "workers": venue.workers,
        "mac_threshold": venue.mac_threshold,
        "mgmt_subnet": venue.mgmt_subnet,
    }
    job_manager.start_discovery(job_id, params)
    logger.info("Triggered post-push re-discovery job %s for venue %s (%s)",
                job_id, venue.name, ", ".join(switch_hostnames))
    return job_id
