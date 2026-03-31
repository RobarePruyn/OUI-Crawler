"""SQLAlchemy engine, session, and base model for SQLite."""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


engine = create_engine(
    f"sqlite:///{settings.db_path}",
    connect_args={"check_same_thread": False},
    echo=False,
)


@event.listens_for(engine, "connect")
def _set_sqlite_wal(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    """Create all tables that don't exist yet, and run lightweight migrations."""
    Base.metadata.create_all(bind=engine)
    _migrate(engine)


def _migrate(eng) -> None:
    """Add columns that create_all() can't add to existing tables."""
    import sqlite3
    with eng.connect() as conn:
        raw = conn.connection.connection  # unwrap to sqlite3 connection
        cursor = raw.cursor()
        # Check if jobs.venue_id exists
        cols = [row[1] for row in cursor.execute("PRAGMA table_info(jobs)").fetchall()]
        if "venue_id" not in cols:
            cursor.execute("ALTER TABLE jobs ADD COLUMN venue_id INTEGER REFERENCES venues(id)")
            raw.commit()

        # Venue defaults for VLAN management
        venue_cols = [row[1] for row in cursor.execute("PRAGMA table_info(venues)").fetchall()]
        for col, col_type in [
            ("default_dhcp_servers", "TEXT"),
            ("default_dns_servers", "TEXT"),
            ("default_gateway_mac", "VARCHAR(17)"),
        ]:
            if col not in venue_cols:
                cursor.execute(f"ALTER TABLE venues ADD COLUMN {col} {col_type}")
        raw.commit()

        # VenueVlan columns added after initial table creation
        vlan_cols = [row[1] for row in cursor.execute("PRAGMA table_info(venue_vlans)").fetchall()]
        for col, col_type in [
            ("dark_vlan", "BOOLEAN NOT NULL DEFAULT 0"),
            ("igmp_enable", "BOOLEAN NOT NULL DEFAULT 0"),
            ("pim_sparse_enable", "BOOLEAN NOT NULL DEFAULT 0"),
        ]:
            if col not in vlan_cols:
                cursor.execute(f"ALTER TABLE venue_vlans ADD COLUMN {col} {col_type}")
        raw.commit()

        # ActionLog.job_id and ComplianceResult.job_id made nullable
        # (SQLite can't alter column nullability, but new rows work fine)

        cursor.close()


def get_db():
    """FastAPI dependency that yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
