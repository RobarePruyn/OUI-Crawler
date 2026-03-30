"""HTML page routes — Jinja2 + HTMX."""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..auth import User, authenticate_user, get_current_user, hash_password, verify_password
from ..database import get_db
from ..db_models import ChangeLog, ComplianceResult, DeviceResult, Job, OUIEntry, PortPolicy, Schedule, SwitchResult, ActionLog, Venue, VenuePort, VenueSwitch, VenueVlan
from ..db_models import User as UserModel

import json as _json

router = APIRouter(tags=["pages"])

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
templates.env.filters["fromjson"] = lambda s: _json.loads(s) if s else []


def _render(request: Request, template: str, context: dict = None, status_code: int = 200):
    ctx = context or {}
    return templates.TemplateResponse(request, template, ctx, status_code=status_code)


# ── Auth pages ───────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return _render(request, "login.html", {"error": None})


@router.post("/login-action")
async def login_action(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")
    user = authenticate_user(db, username, password)
    if not user:
        return _render(request, "login.html", {"error": "Invalid credentials"}, status_code=401)
    request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=303)


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ── Dashboard ────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    jobs = db.query(Job).order_by(Job.created_at.desc()).limit(20).all()
    return _render(request, "dashboard.html", {"user": user, "jobs": jobs})


# ── Discovery ────────────────────────────────────────────────────────

@router.get("/discovery", response_class=HTMLResponse)
def discovery_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venues = db.query(Venue).order_by(Venue.name).all()
    return _render(request, "discovery.html", {"user": user, "venues": venues})


# ── Inventory ────────────────────────────────────────────────────────

@router.get("/inventory", response_class=HTMLResponse)
def inventory_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venues = db.query(Venue).order_by(Venue.name).all()
    return _render(request, "inventory.html", {"user": user, "venues": venues})


# ── Device Lookup ───────────────────────────────────────────────────

@router.get("/lookup", response_class=HTMLResponse)
def lookup_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venues = db.query(Venue).order_by(Venue.name).all()
    return _render(request, "lookup.html", {"user": user, "venues": venues})


# ── Job Detail ───────────────────────────────────────────────────────

@router.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_detail_page(
    job_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = db.query(Job).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    devices = db.query(DeviceResult).filter(DeviceResult.job_id == job_id).all()
    switches = db.query(SwitchResult).filter(SwitchResult.job_id == job_id).all()
    action_logs = db.query(ActionLog).filter(ActionLog.job_id == job_id).all()
    return _render(request, "job_detail.html", {
        "user": user, "job": job,
        "devices": devices, "switches": switches, "action_logs": action_logs,
    })


# ── HTMX partials ───────────────────────────────────────────────────

@router.get("/partials/job-progress/{job_id}", response_class=HTMLResponse)
def job_progress_partial(
    job_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from ..app import job_manager

    job = db.query(Job).get(job_id)
    if not job:
        raise HTTPException(status_code=404)
    progress = job_manager.get_progress(job_id)
    return _render(request, "partials/progress.html", {"job": job, "progress": progress})


# ── Actions ──────────────────────────────────────────────────────────

@router.get("/actions/{job_id}", response_class=HTMLResponse)
def actions_page(
    job_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = db.query(Job).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _render(request, "actions.html", {"user": user, "job": job})


# ── Diff ─────────────────────────────────────────────────────────────

@router.get("/diff", response_class=HTMLResponse)
def diff_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    discovery_jobs = (
        db.query(Job)
        .filter(Job.job_type == "discovery", Job.status == "completed")
        .order_by(Job.created_at.desc())
        .all()
    )
    return _render(request, "diff.html", {"user": user, "jobs": discovery_jobs})


# ── Venues ───────────────────────────────────────────────────────────

@router.get("/venues", response_class=HTMLResponse)
def venues_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venues = db.query(Venue).order_by(Venue.name).all()
    return _render(request, "venues.html", {"user": user, "venues": venues})


@router.get("/venues/new", response_class=HTMLResponse)
def venue_new_page(
    request: Request,
    user: User = Depends(get_current_user),
):
    return _render(request, "venue_detail.html", {"user": user, "venue": None})


@router.post("/venues", response_class=HTMLResponse)
async def venue_create_action(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from ..crypto import encrypt_credential
    form = await request.form()

    name = form.get("name", "").strip()
    if not name:
        return _render(request, "venue_detail.html", {"user": user, "venue": None, "message": "Name is required.", "error": True})

    if db.query(Venue).filter(Venue.name == name).first():
        return _render(request, "venue_detail.html", {"user": user, "venue": None, "message": f"Venue '{name}' already exists.", "error": True})

    ssh_password = form.get("ssh_password", "")
    if not ssh_password:
        return _render(request, "venue_detail.html", {"user": user, "venue": None, "message": "SSH password is required.", "error": True})

    enable_secret = form.get("enable_secret", "").strip()

    dhcp_raw = form.get("default_dhcp_servers", "").strip()
    dns_raw = form.get("default_dns_servers", "").strip()

    venue = Venue(
        name=name,
        core_ip=form.get("core_ip", "").strip(),
        platform=form.get("platform", "auto"),
        ssh_username=form.get("ssh_username", "").strip(),
        ssh_password_enc=encrypt_credential(ssh_password),
        enable_secret_enc=encrypt_credential(enable_secret) if enable_secret else None,
        mgmt_subnet=form.get("mgmt_subnet", "").strip() or None,
        fan_out="fan_out" in form,
        workers=int(form.get("workers", 10)),
        mac_threshold=int(form.get("mac_threshold", 1)),
        default_dhcp_servers=_json.dumps([s.strip() for s in dhcp_raw.split(",") if s.strip()]) if dhcp_raw else None,
        default_dns_servers=_json.dumps([s.strip() for s in dns_raw.split(",") if s.strip()]) if dns_raw else None,
        default_gateway_mac=form.get("default_gateway_mac", "").strip() or None,
    )
    db.add(venue)
    db.commit()
    db.refresh(venue)
    return RedirectResponse(f"/venues/{venue.id}", status_code=303)


@router.get("/venues/{venue_id}", response_class=HTMLResponse)
def venue_detail_page(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")
    return _render(request, "venue_detail.html", {"user": user, "venue": venue})


@router.post("/venues/{venue_id}", response_class=HTMLResponse)
async def venue_update_action(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from ..crypto import encrypt_credential
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    form = await request.form()
    name = form.get("name", "").strip()

    if name and name != venue.name:
        if db.query(Venue).filter(Venue.name == name, Venue.id != venue_id).first():
            return _render(request, "venue_detail.html", {"user": user, "venue": venue, "message": f"Venue '{name}' already exists.", "error": True})
        venue.name = name

    venue.core_ip = form.get("core_ip", venue.core_ip).strip()
    venue.platform = form.get("platform", venue.platform)
    venue.ssh_username = form.get("ssh_username", venue.ssh_username).strip()
    venue.mgmt_subnet = form.get("mgmt_subnet", "").strip() or None
    venue.fan_out = "fan_out" in form
    venue.workers = int(form.get("workers", venue.workers))
    venue.mac_threshold = int(form.get("mac_threshold", venue.mac_threshold))

    # Default SVI settings
    dhcp_raw = form.get("default_dhcp_servers", "").strip()
    venue.default_dhcp_servers = _json.dumps([s.strip() for s in dhcp_raw.split(",") if s.strip()]) if dhcp_raw else None
    dns_raw = form.get("default_dns_servers", "").strip()
    venue.default_dns_servers = _json.dumps([s.strip() for s in dns_raw.split(",") if s.strip()]) if dns_raw else None
    venue.default_gateway_mac = form.get("default_gateway_mac", "").strip() or None

    ssh_password = form.get("ssh_password", "").strip()
    if ssh_password:
        venue.ssh_password_enc = encrypt_credential(ssh_password)

    enable_secret = form.get("enable_secret", "").strip()
    if enable_secret:
        venue.enable_secret_enc = encrypt_credential(enable_secret)

    db.commit()
    return _render(request, "venue_detail.html", {"user": user, "venue": venue, "message": "Venue updated."})


@router.post("/venues/{venue_id}/delete")
def venue_delete_action(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")
    db.delete(venue)
    db.commit()
    return RedirectResponse("/venues", status_code=303)


# ── Venue partials (OUI, Schedules, Policies) ───────────────────────

@router.get("/partials/oui-registry/{venue_id}", response_class=HTMLResponse)
def oui_registry_partial(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404)
    entries = db.query(OUIEntry).filter(OUIEntry.venue_id == venue_id).all()
    return _render(request, "partials/oui_registry.html", {"venue": venue, "entries": entries})


@router.get("/partials/schedules/{venue_id}", response_class=HTMLResponse)
def schedules_partial(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404)
    schedules = db.query(Schedule).filter(Schedule.venue_id == venue_id).all()
    return _render(request, "partials/schedules.html", {"venue": venue, "schedules": schedules})


@router.get("/partials/port-policies/{venue_id}", response_class=HTMLResponse)
def port_policies_partial(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404)
    policies = db.query(PortPolicy).filter(PortPolicy.venue_id == venue_id).all()
    return _render(request, "partials/port_policies.html", {"venue": venue, "policies": policies})


@router.get("/partials/vlans/{venue_id}", response_class=HTMLResponse)
def vlans_partial(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404)
    vlans = db.query(VenueVlan).filter(VenueVlan.venue_id == venue_id).order_by(VenueVlan.vlan_id).all()
    return _render(request, "partials/vlans.html", {"venue": venue, "vlans": vlans})


@router.get("/partials/switches/{venue_id}", response_class=HTMLResponse)
def switches_partial(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404)
    switches = (
        db.query(VenueSwitch)
        .filter(VenueSwitch.venue_id == venue_id)
        .order_by(VenueSwitch.hostname)
        .all()
    )
    return _render(request, "partials/switches.html", {"venue": venue, "switches": switches})


@router.get("/partials/switches/{venue_id}/{switch_id}/ports", response_class=HTMLResponse)
def switch_ports_partial(
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
        raise HTTPException(status_code=404)
    ports = (
        db.query(VenuePort)
        .filter(VenuePort.switch_id == switch_id)
        .order_by(VenuePort.interface)
        .all()
    )
    vlans = db.query(VenueVlan).filter(VenueVlan.venue_id == venue_id).order_by(VenueVlan.vlan_id).all()
    return _render(request, "partials/switch_ports.html", {"switch": switch, "ports": ports, "venue_id": venue_id, "vlans": vlans})


@router.get("/partials/timeline/{venue_id}", response_class=HTMLResponse)
def timeline_partial(
    venue_id: int,
    request: Request,
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
        .limit(200)
        .all()
    )

    # Enrich with entity labels for display
    switch_names: dict[int, str] = {}
    port_labels: dict[int, str] = {}
    vlan_labels: dict[int, str] = {}

    for c in changes:
        if c.entity_type == "switch" and c.entity_id not in switch_names:
            sw = db.query(VenueSwitch).get(c.entity_id)
            switch_names[c.entity_id] = sw.hostname if sw else f"(deleted #{c.entity_id})"
        elif c.entity_type == "port" and c.entity_id not in port_labels:
            port = db.query(VenuePort).get(c.entity_id)
            if port:
                sw = db.query(VenueSwitch).get(port.switch_id)
                port_labels[c.entity_id] = f"{port.interface} on {sw.hostname}" if sw else port.interface
            else:
                port_labels[c.entity_id] = f"(deleted #{c.entity_id})"
        elif c.entity_type == "vlan" and c.entity_id not in vlan_labels:
            vlan = db.query(VenueVlan).get(c.entity_id)
            vlan_labels[c.entity_id] = f"VLAN {vlan.vlan_id}" if vlan else f"(deleted #{c.entity_id})"

    for c in changes:
        if c.entity_type == "switch":
            c._entity_label = switch_names.get(c.entity_id, "")
        elif c.entity_type == "port":
            c._entity_label = port_labels.get(c.entity_id, "")
        elif c.entity_type == "vlan":
            c._entity_label = vlan_labels.get(c.entity_id, "")
        else:
            c._entity_label = ""

    return _render(request, "partials/timeline.html", {"venue": venue, "changes": changes})


# ── Compliance ──────────────────────────────────────────────────────

@router.get("/compliance/{job_id}", response_class=HTMLResponse)
def compliance_page(
    job_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = db.query(Job).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    results = db.query(ComplianceResult).filter(ComplianceResult.job_id == job_id).all()
    ok_count = sum(1 for r in results if r.severity == "ok")
    warn_count = sum(1 for r in results if r.severity == "warning")
    crit_count = sum(1 for r in results if r.severity == "critical")
    return _render(request, "compliance.html", {
        "user": user, "job": job, "results": results,
        "ok_count": ok_count, "warn_count": warn_count, "crit_count": crit_count,
    })


@router.get("/venues/{venue_id}/compliance", response_class=HTMLResponse)
def venue_compliance_page(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404)
    results = db.query(ComplianceResult).filter(
        ComplianceResult.venue_id == venue_id,
        ComplianceResult.job_id.is_(None),
    ).all()
    ok_count = sum(1 for r in results if r.severity == "ok")
    warn_count = sum(1 for r in results if r.severity == "warning")
    return _render(request, "venue_compliance.html", {
        "user": user, "venue": venue, "results": results,
        "ok_count": ok_count, "warn_count": warn_count,
    })


@router.post("/api/venues/{venue_id}/compliance")
def run_venue_compliance(
    venue_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404)
    from ..compliance import check_venue_compliance
    results = check_venue_compliance(db, venue_id)
    return {"ok": True, "count": len(results)}


# ── Settings ─────────────────────────────────────────────────────────

@router.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    users = db.query(UserModel).order_by(UserModel.username).all() if user.role == "admin" else []
    return _render(request, "settings.html", {"user": user, "users": users})


@router.post("/settings/change-password")
async def change_password(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    form = await request.form()
    current = form.get("current_password", "")
    new_pw = form.get("new_password", "")
    confirm = form.get("confirm_password", "")

    users = db.query(UserModel).order_by(UserModel.username).all() if user.role == "admin" else []
    ctx = {"user": user, "users": users}

    if not verify_password(current, user.password_hash):
        return _render(request, "settings.html", {**ctx, "message": "Current password is incorrect.", "error": True})

    if new_pw != confirm:
        return _render(request, "settings.html", {**ctx, "message": "New passwords do not match.", "error": True})

    if len(new_pw) < 8:
        return _render(request, "settings.html", {**ctx, "message": "Password must be at least 8 characters.", "error": True})

    user.password_hash = hash_password(new_pw)
    db.commit()
    return _render(request, "settings.html", {**ctx, "message": "Password changed successfully."})


@router.post("/settings/create-user")
async def create_user(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "")
    role = form.get("role", "operator")

    users = db.query(UserModel).order_by(UserModel.username).all()
    ctx = {"user": user, "users": users}

    if not username:
        return _render(request, "settings.html", {**ctx, "message": "Username is required.", "error": True})

    if len(password) < 8:
        return _render(request, "settings.html", {**ctx, "message": "Password must be at least 8 characters.", "error": True})

    if db.query(UserModel).filter(UserModel.username == username).first():
        return _render(request, "settings.html", {**ctx, "message": f"User '{username}' already exists.", "error": True})

    new_user = UserModel(
        username=username,
        password_hash=hash_password(password),
        role=role,
    )
    db.add(new_user)
    db.commit()

    users = db.query(UserModel).order_by(UserModel.username).all()
    return _render(request, "settings.html", {"user": user, "users": users, "message": f"User '{username}' created."})


@router.post("/settings/delete-user/{user_id}")
def delete_user(
    user_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    target = db.query(UserModel).get(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if target.id == user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    db.delete(target)
    db.commit()
    return RedirectResponse("/settings", status_code=303)
