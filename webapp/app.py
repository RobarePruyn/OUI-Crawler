"""FastAPI application factory."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .database import SessionLocal, init_db
from .auth import ensure_default_admin
from .job_manager import JobManager


job_manager = JobManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()

    from .oui_lookup import load_oui_database
    load_oui_database()

    db = SessionLocal()

    # Schema migrations for existing databases
    from sqlalchemy import inspect as sa_inspect, text
    inspector = sa_inspect(db.bind)
    venue_port_cols = {c["name"] for c in inspector.get_columns("venue_ports")}
    if "last_config_error" not in venue_port_cols:
        db.execute(text("ALTER TABLE venue_ports ADD COLUMN last_config_error TEXT"))
        db.commit()
        print("  Added venue_ports.last_config_error column")

    # Hardware identity columns on venue_switches (rename/merge matching)
    venue_switch_cols = {c["name"] for c in inspector.get_columns("venue_switches")}
    if "serial_number" not in venue_switch_cols:
        db.execute(text("ALTER TABLE venue_switches ADD COLUMN serial_number VARCHAR(64)"))
        db.execute(text("CREATE INDEX IF NOT EXISTS ix_venue_switches_serial_number ON venue_switches(serial_number)"))
        db.commit()
        print("  Added venue_switches.serial_number column")
    if "base_mac" not in venue_switch_cols:
        db.execute(text("ALTER TABLE venue_switches ADD COLUMN base_mac VARCHAR(17)"))
        db.execute(text("CREATE INDEX IF NOT EXISTS ix_venue_switches_base_mac ON venue_switches(base_mac)"))
        db.commit()
        print("  Added venue_switches.base_mac column")
    if "stack_member_serials" not in venue_switch_cols:
        db.execute(text("ALTER TABLE venue_switches ADD COLUMN stack_member_serials TEXT"))
        db.commit()
        print("  Added venue_switches.stack_member_serials column")

    # Mark any jobs left in running/pending as failed — their threads are gone
    from .db_models import Job
    from datetime import datetime, timezone
    stale = db.query(Job).filter(Job.status.in_(["running", "pending"])).all()
    for j in stale:
        j.status = "failed"
        j.error_message = "Stale: app restarted while job was in progress"
        j.completed_at = datetime.now(timezone.utc)
    if stale:
        db.commit()
        print(f"  Cleaned up {len(stale)} stale job(s)")

    # Migrate legacy "admin" role to "super_admin"
    from .db_models import User as UserModel
    legacy = db.query(UserModel).filter(UserModel.role == "admin").all()
    for u in legacy:
        u.role = "super_admin"
    if legacy:
        db.commit()
        print(f"  Migrated {len(legacy)} user(s) from 'admin' to 'super_admin'")

    password = ensure_default_admin(db)
    if password:
        import sys
        print(f"\n{'='*50}")
        print(f"  Default admin account created")
        print(f"  Username: admin")
        print(f"  Password: {password}")
        print(f"  Change this after first login!")
        print(f"{'='*50}\n")
        sys.stdout.flush()
    from .app_settings import load_timezone
    load_timezone(db)

    db.close()

    from .scheduler import init_scheduler, shutdown_scheduler
    init_scheduler()

    from .updates import start_background_checker
    start_background_checker()

    yield
    # Shutdown
    shutdown_scheduler()
    job_manager._pool.shutdown(wait=False)


def _read_version() -> str:
    from pathlib import Path
    vf = Path(__file__).resolve().parent.parent / "VERSION"
    if vf.exists():
        return vf.read_text(encoding="utf-8").strip()
    return "2.0"


def create_app() -> FastAPI:
    app = FastAPI(title="NetCaster", version=_read_version(), lifespan=lifespan)

    app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)

    # Mount static files
    from pathlib import Path
    static_dir = Path(__file__).parent / "static"
    static_dir.mkdir(exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Register routes
    from .routes import discovery, inventory, actions, history, venues, oui_registry, schedules, compliance, lookup, vlans, switches, exports, pages
    app.include_router(discovery.router)
    app.include_router(inventory.router)
    app.include_router(actions.router)
    app.include_router(history.router)
    app.include_router(venues.router)
    app.include_router(oui_registry.router)
    app.include_router(schedules.router)
    app.include_router(compliance.router)
    app.include_router(lookup.router)
    app.include_router(vlans.router)
    app.include_router(switches.router)
    app.include_router(exports.router)
    app.include_router(pages.router)

    # Redirect unauthenticated HTML requests to login page
    from fastapi.exceptions import HTTPException as FastAPIHTTPException
    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.exception_handler(StarletteHTTPException)
    async def auth_redirect(request: Request, exc: StarletteHTTPException):
        if exc.status_code == 401 and "text/html" in request.headers.get("accept", ""):
            return RedirectResponse("/login", status_code=303)
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return app
