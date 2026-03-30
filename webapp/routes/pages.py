"""HTML page routes — Jinja2 + HTMX."""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..auth import User, authenticate_user, get_current_user, hash_password, verify_password
from ..database import get_db
from ..db_models import DeviceResult, Job, SwitchResult, ActionLog
from ..db_models import User as UserModel

router = APIRouter(tags=["pages"])

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


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
):
    return _render(request, "discovery.html", {"user": user})


# ── Inventory ────────────────────────────────────────────────────────

@router.get("/inventory", response_class=HTMLResponse)
def inventory_page(
    request: Request,
    user: User = Depends(get_current_user),
):
    return _render(request, "inventory.html", {"user": user})


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
