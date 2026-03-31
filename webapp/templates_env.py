"""Shared Jinja2 templates instance with all custom filters."""

import json
from pathlib import Path

from fastapi.templating import Jinja2Templates

from .app_settings import localtime

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.filters["fromjson"] = lambda s: json.loads(s) if s else []
templates.env.filters["localtime"] = localtime
