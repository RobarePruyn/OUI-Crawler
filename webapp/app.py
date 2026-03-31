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
    password = ensure_default_admin(db)
    if password:
        print(f"\n{'='*50}")
        print(f"  Default admin account created")
        print(f"  Username: admin")
        print(f"  Password: {password}")
        print(f"  Change this after first login!")
        print(f"{'='*50}\n")
    from .app_settings import load_timezone
    load_timezone(db)

    db.close()

    from .scheduler import init_scheduler, shutdown_scheduler
    init_scheduler()

    yield
    # Shutdown
    shutdown_scheduler()
    job_manager._pool.shutdown(wait=False)


def create_app() -> FastAPI:
    app = FastAPI(title="OUI Port Mapper", version="4.0", lifespan=lifespan)

    app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)

    # Mount static files
    from pathlib import Path
    static_dir = Path(__file__).parent / "static"
    static_dir.mkdir(exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Register routes
    from .routes import discovery, inventory, actions, history, venues, oui_registry, schedules, compliance, lookup, vlans, switches, pages
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
