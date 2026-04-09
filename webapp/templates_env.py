"""Shared Jinja2 templates instance with all custom filters."""

import json
from pathlib import Path

from fastapi.templating import Jinja2Templates

from .app_settings import localtime

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.filters["fromjson"] = lambda s: json.loads(s) if s else []
templates.env.filters["localtime"] = localtime


def _job_label(job_type: str) -> str:
    """Display name for a job_type DB value.

    Single source of truth so templates don't each reimplement the
    "discovery → Full Scan" translation.
    """
    return {
        "discovery": "Full Scan",
        "inventory": "Inventory",
        "action": "Action",
    }.get((job_type or "").lower(), (job_type or "").title())


templates.env.filters["job_label"] = _job_label
