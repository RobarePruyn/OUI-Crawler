"""App-level settings stored in the database (timezone, etc.)."""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from .db_models import AppSetting

# Common US/world timezones for the picker
TIMEZONE_CHOICES = [
    "US/Eastern",
    "US/Central",
    "US/Mountain",
    "US/Pacific",
    "US/Alaska",
    "US/Hawaii",
    "UTC",
    "Europe/London",
    "Europe/Paris",
    "Europe/Berlin",
    "Asia/Tokyo",
    "Asia/Shanghai",
    "Australia/Sydney",
]

_DEFAULT_TIMEZONE = "UTC"

# Cached timezone to avoid DB hit on every template render
_cached_tz: ZoneInfo | None = None


def get_setting(db: Session, key: str, default: str = "") -> str:
    row = db.query(AppSetting).get(key)
    return row.value if row else default


def set_setting(db: Session, key: str, value: str) -> None:
    row = db.query(AppSetting).get(key)
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=key, value=value))
    db.commit()


def get_timezone(db: Session) -> str:
    return get_setting(db, "timezone", _DEFAULT_TIMEZONE)


def set_timezone(db: Session, tz_name: str) -> None:
    global _cached_tz
    set_setting(db, "timezone", tz_name)
    try:
        _cached_tz = ZoneInfo(tz_name)
    except (KeyError, Exception):
        _cached_tz = ZoneInfo("UTC")


def load_timezone(db: Session) -> None:
    """Load timezone from DB into cache. Called at startup."""
    global _cached_tz
    tz_name = get_timezone(db)
    try:
        _cached_tz = ZoneInfo(tz_name)
    except (KeyError, Exception):
        _cached_tz = ZoneInfo("UTC")


def localtime(dt, fmt="%Y-%m-%d %H:%M"):
    """Jinja2 filter: convert a UTC datetime to the configured app timezone."""
    if dt is None:
        return "-"
    global _cached_tz
    tz = _cached_tz or ZoneInfo("UTC")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(tz).strftime(fmt)
