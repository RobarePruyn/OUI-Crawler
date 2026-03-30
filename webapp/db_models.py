"""SQLAlchemy ORM models."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


# ── Users ────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), nullable=False, default="admin")
    created_at = Column(DateTime, nullable=False, default=_utcnow)


# ── Jobs ─────────────────────────────────────────────────────────────

class Job(Base):
    __tablename__ = "jobs"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    job_type = Column(String(32), nullable=False)  # discovery, inventory, action
    status = Column(String(16), nullable=False, default="pending")  # pending, running, completed, failed, cancelled
    core_ip = Column(String(64))
    oui_list = Column(Text)       # JSON array of OUI prefixes
    params = Column(Text)         # JSON blob of all job parameters
    progress_json = Column(Text)  # JSON blob: latest ProgressEvent
    switches_visited = Column(Integer, default=0)
    devices_found = Column(Integer, default=0)
    error_message = Column(Text)
    created_at = Column(DateTime, nullable=False, default=_utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)

    device_results = relationship("DeviceResult", back_populates="job", cascade="all, delete-orphan")
    switch_results = relationship("SwitchResult", back_populates="job", cascade="all, delete-orphan")
    action_logs = relationship("ActionLog", back_populates="job", cascade="all, delete-orphan")


# ── Device Results ───────────────────────────────────────────────────

class DeviceResult(Base):
    __tablename__ = "device_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(36), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False, index=True)

    switch_hostname = Column(String(128))
    switch_ip = Column(String(64))
    interface = Column(String(64))
    mac_address = Column(String(14))
    matched_oui = Column(String(6))
    ip_address = Column(String(64))
    vlan = Column(String(16))
    switch_tracked_vlan = Column(String(16))
    notes = Column(Text)

    job = relationship("Job", back_populates="device_results")


# ── Switch Results ───────────────────────────────────────────────────

class SwitchResult(Base):
    __tablename__ = "switch_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(36), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False, index=True)

    hostname = Column(String(128))
    mgmt_ip = Column(String(64))
    platform = Column(String(32))
    upstream_hostname = Column(String(128))
    upstream_ip = Column(String(64))
    upstream_interface = Column(String(64))

    job = relationship("Job", back_populates="switch_results")


# ── Action Logs ──────────────────────────────────────────────────────

class ActionLog(Base):
    __tablename__ = "action_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(36), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False, index=True)

    action_type = Column(String(32), nullable=False)  # shutdown, no_shutdown, port_cycle, vlan_assign, set_description
    switch_hostname = Column(String(128))
    switch_ip = Column(String(64))
    interface = Column(String(64))
    mac_address = Column(String(14))
    detail = Column(Text)
    status = Column(String(16), nullable=False)  # ok, error
    dry_run = Column(Boolean, nullable=False, default=False)
    executed_at = Column(DateTime, nullable=False, default=_utcnow)

    job = relationship("Job", back_populates="action_logs")
