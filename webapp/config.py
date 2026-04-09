"""Application configuration via pydantic-settings."""

import os
from pathlib import Path
from pydantic_settings import BaseSettings


_BASE = Path(__file__).resolve().parent.parent
_DEFAULT_DB = _BASE / "netcaster.db"
_LEGACY_DB = _BASE / "oui_mapper.db"

# Auto-rename legacy DB on first import if the new name doesn't exist yet.
# This only fires when there's no explicit DB path override.
if not os.environ.get("NETCASTER_DB_PATH") and not os.environ.get("OUI_MAPPER_DB_PATH"):
    if _LEGACY_DB.exists() and not _DEFAULT_DB.exists():
        try:
            _LEGACY_DB.rename(_DEFAULT_DB)
            # Also move WAL/SHM sidecar files if present
            for suffix in ("-wal", "-shm"):
                legacy_side = _LEGACY_DB.with_name(_LEGACY_DB.name + suffix)
                if legacy_side.exists():
                    legacy_side.rename(_DEFAULT_DB.with_name(_DEFAULT_DB.name + suffix))
        except OSError:
            pass

# Backward compatibility: honor legacy OUI_MAPPER_* env vars if the
# new NETCASTER_* variants aren't set.
for legacy, new in (
    ("OUI_MAPPER_SECRET_KEY", "NETCASTER_SECRET_KEY"),
    ("OUI_MAPPER_DB_PATH",    "NETCASTER_DB_PATH"),
):
    if legacy in os.environ and new not in os.environ:
        os.environ[new] = os.environ[legacy]


class Settings(BaseSettings):
    """All configuration knobs for the web application."""

    # Paths
    base_dir: Path = _BASE
    db_path: Path = _DEFAULT_DB

    # Security
    secret_key: str = "change-me-in-production"

    # Job runner
    max_concurrent_jobs: int = 3

    # Session
    session_expire_minutes: int = 480  # 8 hours

    # OUI database
    oui_csv_path: Path = Path(__file__).resolve().parent.parent / "data" / "oui.csv"

    # Scheduler
    scheduler_enabled: bool = True

    model_config = {"env_prefix": "NETCASTER_"}


settings = Settings()
