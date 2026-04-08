"""HTML page routes — Jinja2 + HTMX."""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..auth import User, authenticate_user, get_current_user, get_user_venues, require_venue_access, hash_password, verify_password
from ..database import SessionLocal, get_db
from ..db_models import ChangeLog, ComplianceResult, DeviceResult, Job, OUIEntry, PortPolicy, Schedule, SwitchResult, ActionLog, Venue, VenuePort, VenueSwitch, VenueVlan
from ..db_models import User as UserModel
from ..templates_env import templates

router = APIRouter(tags=["pages"])


def _render(request: Request, template: str, context: dict = None, status_code: int = 200):
    ctx = context or {}
    # Inject venue nav context for base.html
    user = ctx.get("user")
    if user and "nav_venues" not in ctx:
        db = SessionLocal()
        try:
            ctx["nav_venues"] = get_user_venues(db, user)
            selected_id = request.session.get("selected_venue_id")
            ctx["selected_venue_id"] = selected_id
            ctx["selected_venue"] = next((v for v in ctx["nav_venues"] if v.id == selected_id), None)
        finally:
            db.close()
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
    # Auto-select the first venue the user has access to
    venues = get_user_venues(db, user)
    if venues:
        request.session["selected_venue_id"] = venues[0].id
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
    venues = get_user_venues(db, user)
    selected_id = request.session.get("selected_venue_id")
    venue = None

    if selected_id:
        venue = db.query(Venue).get(selected_id)

    # If no valid selection, pick first available
    if not venue and venues:
        venue = venues[0]
        request.session["selected_venue_id"] = venue.id

    ctx = {"user": user, "venues": venues, "venue": venue}

    if venue:
        # Last completed scan (discovery or inventory)
        last_scan = (
            db.query(Job)
            .filter(Job.venue_id == venue.id, Job.job_type.in_(["discovery", "inventory"]), Job.status == "completed")
            .order_by(Job.completed_at.desc())
            .first()
        )
        # Compliance summary
        compliance = db.query(ComplianceResult).filter(
            ComplianceResult.venue_id == venue.id,
            ComplianceResult.job_id == f"venue-{venue.id}",
        ).all()
        compliance_ok = sum(1 for r in compliance if r.severity == "ok")
        compliance_warn = sum(1 for r in compliance if r.severity != "ok")

        # Recent jobs for this venue
        jobs = db.query(Job).filter(Job.venue_id == venue.id).order_by(Job.created_at.desc()).limit(15).all()

        # Switch/port counts
        switch_count = db.query(VenueSwitch).filter(VenueSwitch.venue_id == venue.id).count()
        port_count = db.query(VenuePort).join(VenueSwitch).filter(VenueSwitch.venue_id == venue.id).count()

        ctx.update({
            "last_scan": last_scan,
            "compliance_ok": compliance_ok,
            "compliance_warn": compliance_warn,
            "jobs": jobs,
            "switch_count": switch_count,
            "port_count": port_count,
        })
    else:
        ctx["jobs"] = []

    return _render(request, "dashboard.html", ctx)


# ── Discovery ────────────────────────────────────────────────────────

@router.get("/discovery", response_class=HTMLResponse)
def discovery_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venues = get_user_venues(db, user)
    return _render(request, "discovery.html", {"user": user, "venues": venues})


# ── Inventory (redirect to unified discovery page) ──────────────────

@router.get("/inventory")
def inventory_redirect():
    return RedirectResponse("/discovery", status_code=301)


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


@router.get("/partials/venue-job/{job_id}", response_class=HTMLResponse)
def venue_job_banner_partial(
    job_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Inline job progress banner for the venue detail page."""
    from ..app import job_manager

    job = db.query(Job).get(job_id)
    if not job:
        raise HTTPException(status_code=404)
    progress = job_manager.get_progress(job_id)
    return _render(request, "partials/venue_job_banner.html", {"job": job, "progress": progress})


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


# ── Venue Selection ──────────────────────────────────────────────────

@router.get("/api/set-venue/{venue_id}")
def set_venue(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from ..auth import require_venue_access
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")
    require_venue_access(user, venue_id, db)
    request.session["selected_venue_id"] = venue_id
    return {"ok": True, "venue_id": venue_id, "venue_name": venue.name}


# ── Venues ───────────────────────────────────────────────────────────

@router.get("/venues", response_class=HTMLResponse)
def venues_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venues = get_user_venues(db, user)
    # Compliance counts per venue
    venue_compliance: dict[int, dict] = {}
    for v in venues:
        sentinel = f"venue-{v.id}"
        results = db.query(ComplianceResult).filter(
            ComplianceResult.venue_id == v.id,
            ComplianceResult.job_id == sentinel,
        ).all()
        if results:
            venue_compliance[v.id] = {
                "ok": sum(1 for r in results if r.severity == "ok"),
                "warn": sum(1 for r in results if r.severity != "ok"),
            }
    return _render(request, "venues.html", {
        "user": user, "venues": venues, "venue_compliance": venue_compliance,
    })


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
    require_venue_access(user, venue_id, db)
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
    require_venue_access(user, venue_id, db)
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


@router.post("/venues/{venue_id}/duplicate")
def venue_duplicate_action(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_venue_access(user, venue_id, db)
    src = db.query(Venue).get(venue_id)
    if not src:
        raise HTTPException(status_code=404, detail="Venue not found")

    new_venue = Venue(
        name=f"{src.name} (copy)",
        core_ip="",
        platform=src.platform,
        ssh_username=src.ssh_username,
        ssh_password_enc=src.ssh_password_enc,
        enable_secret_enc=src.enable_secret_enc,
        mgmt_subnet=src.mgmt_subnet,
        fan_out=src.fan_out,
        workers=src.workers,
        mac_threshold=src.mac_threshold,
        default_dhcp_servers=src.default_dhcp_servers,
        default_dns_servers=src.default_dns_servers,
        default_gateway_mac=src.default_gateway_mac,
    )
    db.add(new_venue)
    db.flush()

    # Copy OUI entries
    for oui in db.query(OUIEntry).filter(OUIEntry.venue_id == venue_id).all():
        db.add(OUIEntry(
            venue_id=new_venue.id,
            oui_prefix=oui.oui_prefix,
            manufacturer=oui.manufacturer,
            description=oui.description,
            candidate_vlans=oui.candidate_vlans,
            expected_ips=oui.expected_ips,
        ))

    # Copy VLANs
    for vlan in db.query(VenueVlan).filter(VenueVlan.venue_id == venue_id).all():
        db.add(VenueVlan(
            venue_id=new_venue.id,
            vlan_id=vlan.vlan_id,
            name=vlan.name,
            ip_address=vlan.ip_address,
            gateway_ip=vlan.gateway_ip,
            gateway_mac=vlan.gateway_mac,
            dhcp_servers=vlan.dhcp_servers,
            dns_servers=vlan.dns_servers,
        ))

    # Copy port policies
    for pol in db.query(PortPolicy).filter(PortPolicy.venue_id == venue_id).all():
        db.add(PortPolicy(
            venue_id=new_venue.id,
            vlan=pol.vlan,
            portfast=pol.portfast,
            bpdu_guard=pol.bpdu_guard,
            storm_control=pol.storm_control,
            storm_control_level=pol.storm_control_level,
            description_template=pol.description_template,
            notes=pol.notes,
        ))

    db.commit()
    return RedirectResponse(f"/venues/{new_venue.id}", status_code=303)


@router.post("/venues/{venue_id}/delete")
def venue_delete_action(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_venue_access(user, venue_id, db)
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
    # Look up last job status for each schedule
    schedule_statuses = {}
    for s in schedules:
        if s.last_job_id:
            last_job = db.query(Job).get(s.last_job_id)
            schedule_statuses[s.id] = last_job.status if last_job else None
    return _render(request, "partials/schedules.html", {
        "venue": venue, "schedules": schedules, "schedule_statuses": schedule_statuses,
    })


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
    from .switches import build_port_grids
    return _render(request, "partials/switches.html", {
        "venue": venue, "switches": switches, "port_grids": build_port_grids(switches),
    })


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

    # Per-port compliance status
    compliance_results = db.query(ComplianceResult).filter(
        ComplianceResult.venue_id == venue_id,
        ComplianceResult.job_id == f"venue-{venue_id}",
        ComplianceResult.switch_hostname == switch.hostname,
    ).all()
    port_compliance: dict[str, str] = {}  # interface → severity
    port_compliance_detail: dict[str, str] = {}  # interface → detail
    for cr in compliance_results:
        port_compliance[cr.interface] = cr.severity
        if cr.severity != "ok":
            port_compliance_detail[cr.interface] = cr.detail or ""

    return _render(request, "partials/switch_ports.html", {
        "switch": switch, "ports": ports, "venue_id": venue_id, "vlans": vlans,
        "port_compliance": port_compliance, "port_compliance_detail": port_compliance_detail,
    })


@router.get("/partials/timeline/{venue_id}", response_class=HTMLResponse)
def timeline_partial(
    venue_id: int,
    request: Request,
    page: int = 1,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404)
    per_page = 50
    changes = (
        db.query(ChangeLog)
        .filter(ChangeLog.venue_id == venue_id)
        .order_by(ChangeLog.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page + 1)
        .all()
    )
    has_more = len(changes) > per_page
    if has_more:
        changes = changes[:per_page]

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

    template = "partials/timeline.html" if page == 1 else "partials/timeline_rows.html"
    return _render(request, template, {
        "venue": venue, "changes": changes,
        "page": page, "has_more": has_more,
    })


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
    require_venue_access(user, venue_id, db)
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404)
    results = db.query(ComplianceResult).filter(
        ComplianceResult.venue_id == venue_id,
        ComplianceResult.job_id == f"venue-{venue_id}",
    ).all()

    # Build port ID lookup for violations that can be remediated
    switches = db.query(VenueSwitch).filter(VenueSwitch.venue_id == venue_id).all()
    switch_id_map = {s.hostname: s.id for s in switches}
    port_lookup: dict[tuple, int] = {}
    for s in switches:
        for p in s.ports:
            port_lookup[(s.hostname, p.interface)] = p.id

    # Enrich results with port_id for actionable violations
    for r in results:
        r._port_id = port_lookup.get((r.switch_hostname, r.interface))

    vlan_results = [r for r in results if r.check_type == "vlan_compliance"]
    config_results = [r for r in results if r.check_type == "port_config"]
    ok_count = sum(1 for r in vlan_results if r.severity == "ok")
    warn_count = sum(1 for r in vlan_results if r.severity == "warning")
    config_count = sum(1 for r in config_results if r.severity == "warning")
    return _render(request, "venue_compliance.html", {
        "user": user, "venue": venue, "results": results,
        "ok_count": ok_count, "warn_count": warn_count, "config_count": config_count,
    })


@router.get("/partials/compliance/{venue_id}", response_class=HTMLResponse)
def compliance_tab_partial(
    venue_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Compliance tab content for venue detail page."""
    venue = db.query(Venue).get(venue_id)
    if not venue:
        raise HTTPException(status_code=404)
    results = db.query(ComplianceResult).filter(
        ComplianceResult.venue_id == venue_id,
        ComplianceResult.job_id == f"venue-{venue_id}",
    ).all()

    # Build port ID lookup for actionable violations
    switches = db.query(VenueSwitch).filter(VenueSwitch.venue_id == venue_id).all()
    port_lookup: dict[tuple, int] = {}
    for s in switches:
        for p in s.ports:
            port_lookup[(s.hostname, p.interface)] = p.id
    for r in results:
        r._port_id = port_lookup.get((r.switch_hostname, r.interface))

    vlan_results = [r for r in results if r.check_type == "vlan_compliance"]
    config_results = [r for r in results if r.check_type == "port_config"]
    ok_count = sum(1 for r in vlan_results if r.severity == "ok")
    warn_count = sum(1 for r in vlan_results if r.severity == "warning")
    config_count = sum(1 for r in config_results if r.severity == "warning")
    return _render(request, "partials/venue_compliance_tab.html", {
        "venue": venue, "results": results,
        "ok_count": ok_count, "warn_count": warn_count, "config_count": config_count,
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
    from ..compliance import check_venue_compliance, check_port_config_compliance
    vlan_results = check_venue_compliance(db, venue_id)
    config_results = check_port_config_compliance(db, venue_id)
    return {"ok": True, "count": len(vlan_results) + len(config_results)}


# ── Settings ─────────────────────────────────────────────────────────

@router.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from ..app_settings import get_timezone, TIMEZONE_CHOICES
    users = db.query(UserModel).order_by(UserModel.username).all() if user.role == "super_admin" else []
    all_venues = db.query(Venue).order_by(Venue.name).all() if user.role == "super_admin" else []
    return _render(request, "settings.html", {
        "user": user, "users": users, "all_venues": all_venues,
        "current_tz": get_timezone(db),
        "timezone_choices": TIMEZONE_CHOICES,
    })


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

    from ..app_settings import get_timezone, TIMEZONE_CHOICES
    users = db.query(UserModel).order_by(UserModel.username).all() if user.role == "super_admin" else []
    ctx = {"user": user, "users": users, "current_tz": get_timezone(db), "timezone_choices": TIMEZONE_CHOICES}

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
    if user.role != "super_admin":
        raise HTTPException(status_code=403, detail="Admin only")

    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "")
    role = form.get("role", "site_admin")
    venue_ids = [int(v) for v in form.getlist("venue_ids") if v]

    from ..app_settings import get_timezone, TIMEZONE_CHOICES
    users = db.query(UserModel).order_by(UserModel.username).all()
    all_venues = db.query(Venue).order_by(Venue.name).all()
    ctx = {"user": user, "users": users, "all_venues": all_venues, "current_tz": get_timezone(db), "timezone_choices": TIMEZONE_CHOICES}

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
    db.flush()

    # Assign venues for site_admin
    if role == "site_admin" and venue_ids:
        for vid in venue_ids:
            v = db.query(Venue).get(vid)
            if v:
                new_user.venues.append(v)

    db.commit()

    users = db.query(UserModel).order_by(UserModel.username).all()
    all_venues = db.query(Venue).order_by(Venue.name).all()
    return _render(request, "settings.html", {
        "user": user, "users": users, "all_venues": all_venues,
        "message": f"User '{username}' created.",
        "current_tz": get_timezone(db), "timezone_choices": TIMEZONE_CHOICES,
    })


@router.post("/settings/delete-user/{user_id}")
def delete_user(
    user_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user.role != "super_admin":
        raise HTTPException(status_code=403, detail="Admin only")

    target = db.query(UserModel).get(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if target.id == user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    db.delete(target)
    db.commit()
    return RedirectResponse("/settings", status_code=303)


@router.post("/settings/user-venues/{user_id}")
async def update_user_venues(
    user_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user.role != "super_admin":
        raise HTTPException(status_code=403, detail="Admin only")

    target = db.query(UserModel).get(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    form = await request.form()
    venue_ids = [int(v) for v in form.getlist("venue_ids") if v]

    # Replace all venue assignments
    target.venues.clear()
    for vid in venue_ids:
        v = db.query(Venue).get(vid)
        if v:
            target.venues.append(v)
    db.commit()

    return RedirectResponse("/settings", status_code=303)


@router.post("/settings/timezone")
async def set_timezone_route(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user.role != "super_admin":
        raise HTTPException(status_code=403, detail="Admin only")

    form = await request.form()
    tz_name = form.get("timezone", "UTC").strip()

    from ..app_settings import set_timezone
    set_timezone(db, tz_name)

    return RedirectResponse("/settings", status_code=303)
