"""Application configuration via pydantic-settings."""

from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All configuration knobs for the web application."""

    # Paths
    base_dir: Path = Path(__file__).resolve().parent.parent
    db_path: Path = Path(__file__).resolve().parent.parent / "oui_mapper.db"

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

    model_config = {"env_prefix": "OUI_MAPPER_"}


settings = Settings()
