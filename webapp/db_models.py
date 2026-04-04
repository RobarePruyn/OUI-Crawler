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
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


# ── App Settings ────────────────────────────────────────────────────

class AppSetting(Base):
    __tablename__ = "app_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False)


# ── User-Venue Association ──────────────────────────────────────────

user_venue = Table(
    "user_venues",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("venue_id", Integer, ForeignKey("venues.id", ondelete="CASCADE"), primary_key=True),
)


# ── Users ────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), nullable=False, default="super_admin")
    created_at = Column(DateTime, nullable=False, default=_utcnow)

    venues = relationship("Venue", secondary=user_venue, backref="users")


# ── Jobs ─────────────────────────────────────────────────────────────

class Job(Base):
    __tablename__ = "jobs"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    job_type = Column(String(32), nullable=False)  # discovery, inventory, action
    status = Column(String(16), nullable=False, default="pending")  # pending, running, completed, failed, cancelled
    venue_id = Column(Integer, ForeignKey("venues.id", ondelete="SET NULL"), nullable=True)
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

    venue = relationship("Venue", back_populates="jobs")
    device_results = relationship("DeviceResult", back_populates="job", cascade="all, delete-orphan")
    switch_results = relationship("SwitchResult", back_populates="job", cascade="all, delete-orphan")
    action_logs = relationship("ActionLog", back_populates="job", cascade="all, delete-orphan")
    compliance_results = relationship("ComplianceResult", back_populates="job", cascade="all, delete-orphan")


# ── Device Results ───────────────────────────────────────────────────

class DeviceResult(Base):
    __tablename__ = "device_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(36), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False, index=True)

    switch_hostname = Column(String(128))
    switch_ip = Column(String(64))
    interface = Column(String(64))
    mac_address = Column(String(14))
    matched_oui = Column(String(12))  # hex-only, up to full MAC length
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
    job_id = Column(String(36), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=True, index=True)

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


# ── Venues ──────────────────────────────────────────────────────────

class Venue(Base):
    __tablename__ = "venues"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    core_ip = Column(String(64), nullable=False)
    platform = Column(String(32), nullable=False, default="auto")
    ssh_username = Column(String(128), nullable=False)
    ssh_password_enc = Column(Text, nullable=False)
    enable_secret_enc = Column(Text)
    mgmt_subnet = Column(String(64))
    fan_out = Column(Boolean, nullable=False, default=False)
    workers = Column(Integer, nullable=False, default=10)
    mac_threshold = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime, nullable=False, default=_utcnow)
    updated_at = Column(DateTime, nullable=False, default=_utcnow, onupdate=_utcnow)

    default_dhcp_servers = Column(Text)    # JSON array: ["10.1.1.10", "10.1.1.11"]
    default_dns_servers = Column(Text)     # JSON array: ["10.1.1.10"]
    default_gateway_mac = Column(String(17))  # Aruba active-gateway MAC

    oui_entries = relationship("OUIEntry", back_populates="venue", cascade="all, delete-orphan")
    schedules = relationship("Schedule", back_populates="venue", cascade="all, delete-orphan")
    port_policies = relationship("PortPolicy", back_populates="venue", cascade="all, delete-orphan")
    vlans = relationship("VenueVlan", back_populates="venue", cascade="all, delete-orphan")
    switches = relationship("VenueSwitch", back_populates="venue", cascade="all, delete-orphan")
    jobs = relationship("Job", back_populates="venue")


# ── OUI Entries ─────────────────────────────────────────────────────

class OUIEntry(Base):
    __tablename__ = "oui_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    venue_id = Column(Integer, ForeignKey("venues.id", ondelete="CASCADE"), nullable=False, index=True)
    oui_prefix = Column(String(23), nullable=False)  # up to full MAC: 00:1A:2B:3C:4D:5E
    description = Column(String(256))
    manufacturer = Column(String(256))
    candidate_vlans = Column(Text)   # JSON array of VLAN IDs
    expected_ips = Column(Text)      # JSON array of IP ranges
    created_at = Column(DateTime, nullable=False, default=_utcnow)

    venue = relationship("Venue", back_populates="oui_entries")


# ── Schedules ───────────────────────────────────────────────────────

class Schedule(Base):
    __tablename__ = "schedules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    venue_id = Column(Integer, ForeignKey("venues.id", ondelete="CASCADE"), nullable=False, index=True)
    job_type = Column(String(32), nullable=False)  # discovery, inventory
    enabled = Column(Boolean, nullable=False, default=True)
    time_of_day = Column(String(5), nullable=False)  # "HH:MM"
    last_run_at = Column(DateTime)
    last_job_id = Column(String(36))
    created_at = Column(DateTime, nullable=False, default=_utcnow)

    venue = relationship("Venue", back_populates="schedules")


# ── Port Policies ───────────────────────────────────────────────────

class PortPolicy(Base):
    __tablename__ = "port_policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    venue_id = Column(Integer, ForeignKey("venues.id", ondelete="CASCADE"), nullable=False, index=True)
    vlan = Column(String(16), nullable=False)
    bpdu_guard = Column(Boolean, nullable=False, default=True)
    portfast = Column(Boolean, nullable=False, default=True)
    storm_control = Column(Boolean, nullable=False, default=False)
    storm_control_level = Column(String(16), default="1.00")
    description_template = Column(String(256))
    notes = Column(Text)
    created_at = Column(DateTime, nullable=False, default=_utcnow)

    venue = relationship("Venue", back_populates="port_policies")


# ── Compliance Results ──────────────────────────────────────────────

class ComplianceResult(Base):
    __tablename__ = "compliance_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(36), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=True, index=True)
    venue_id = Column(Integer, ForeignKey("venues.id", ondelete="SET NULL"), nullable=True)
    check_type = Column(String(32), nullable=False)  # vlan_compliance, port_policy
    switch_hostname = Column(String(128))
    switch_ip = Column(String(64))
    interface = Column(String(64))
    mac_address = Column(String(14))
    current_value = Column(String(128))
    expected_value = Column(String(128))
    severity = Column(String(16), nullable=False, default="warning")  # ok, warning, critical
    detail = Column(Text)
    created_at = Column(DateTime, nullable=False, default=_utcnow)

    job = relationship("Job", back_populates="compliance_results")


# ── Venue VLANs ────────────────────────────────────────────────────

class VenueVlan(Base):
    __tablename__ = "venue_vlans"
    __table_args__ = (
        UniqueConstraint("venue_id", "vlan_id", name="uq_venue_vlan"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    venue_id = Column(Integer, ForeignKey("venues.id", ondelete="CASCADE"), nullable=False, index=True)
    vlan_id = Column(Integer, nullable=False)
    name = Column(String(128))

    # SVI
    ip_address = Column(String(64))         # CIDR: "10.1.21.1/24"
    gateway_ip = Column(String(64))         # Aruba active-gateway IP
    gateway_mac = Column(String(17))        # Aruba active-gateway MAC

    # Services (JSON arrays)
    dhcp_servers = Column(Text)             # ["10.1.1.10", "10.1.1.11"]
    dns_servers = Column(Text)              # ["10.1.1.10"]

    # SVI options
    dark_vlan = Column(Boolean, nullable=False, default=False)  # No SVI expected on network
    igmp_enable = Column(Boolean, nullable=False, default=False)
    pim_sparse_enable = Column(Boolean, nullable=False, default=False)

    # Discovery state
    svi_location = Column(String(16))       # "core" / "edge" / "off-net" / "unknown"
    svi_switch_hostname = Column(String(128))
    discovered_on_switches = Column(Text)   # JSON array of hostnames
    spanning_tree_enabled = Column(Boolean, nullable=False, default=False)

    # Overwrite flags (checked = crawl overwrites manual value)
    overwrite_name = Column(Boolean, nullable=False, default=True)
    overwrite_svi = Column(Boolean, nullable=False, default=True)
    overwrite_dhcp = Column(Boolean, nullable=False, default=True)
    overwrite_dns = Column(Boolean, nullable=False, default=True)

    source = Column(String(16), nullable=False, default="manual")  # "manual" / "discovered"
    created_at = Column(DateTime, nullable=False, default=_utcnow)
    updated_at = Column(DateTime, nullable=False, default=_utcnow, onupdate=_utcnow)

    venue = relationship("Venue", back_populates="vlans")


# ── Venue Switches ─────────────────────────────────────────────────

class VenueSwitch(Base):
    __tablename__ = "venue_switches"
    __table_args__ = (
        UniqueConstraint("venue_id", "hostname", name="uq_venue_switch"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    venue_id = Column(Integer, ForeignKey("venues.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname = Column(String(128), nullable=False)
    mgmt_ip = Column(String(64))
    platform = Column(String(32))

    # Topology
    upstream_hostname = Column(String(128))
    upstream_ip = Column(String(64))
    upstream_interface = Column(String(64))

    # State
    online = Column(Boolean, nullable=False, default=True)
    source = Column(String(16), nullable=False, default="discovered")  # "manual" / "discovered"
    first_seen_at = Column(DateTime, nullable=False, default=_utcnow)
    last_seen_at = Column(DateTime, nullable=False, default=_utcnow)
    last_crawl_job_id = Column(String(36))

    venue = relationship("Venue", back_populates="switches")
    ports = relationship("VenuePort", back_populates="switch", cascade="all, delete-orphan")


# ── Venue Ports ────────────────────────────────────────────────────

class VenuePort(Base):
    __tablename__ = "venue_ports"
    __table_args__ = (
        UniqueConstraint("switch_id", "interface", name="uq_venue_port"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    switch_id = Column(Integer, ForeignKey("venue_switches.id", ondelete="CASCADE"), nullable=False, index=True)
    interface = Column(String(64), nullable=False)

    # Current device state from last discovery
    mac_address = Column(String(14))
    ip_address = Column(String(64))
    vlan = Column(String(16))
    matched_oui = Column(String(12))
    notes = Column(Text)

    # Port config state from last discovery (show running-config)
    has_portfast = Column(Boolean, default=False)
    has_bpdu_guard = Column(Boolean, default=False)
    has_storm_control = Column(Boolean, default=False)
    storm_control_level = Column(String(16))
    port_description = Column(String(256))
    civic_location = Column(String(256))

    # Last config push error (None = no error or never pushed)
    last_config_error = Column(Text)

    # State
    source = Column(String(16), nullable=False, default="discovered")
    first_seen_at = Column(DateTime, nullable=False, default=_utcnow)
    last_seen_at = Column(DateTime, nullable=False, default=_utcnow)
    last_crawl_job_id = Column(String(36))

    switch = relationship("VenueSwitch", back_populates="ports")


# ── Change Log ─────────────────────────────────────────────────────

class ChangeLog(Base):
    __tablename__ = "changelog"

    id = Column(Integer, primary_key=True, autoincrement=True)
    venue_id = Column(Integer, ForeignKey("venues.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_type = Column(String(16), nullable=False)   # "switch" / "port" / "vlan"
    entity_id = Column(Integer, nullable=False)         # FK to VenueSwitch/VenuePort/VenueVlan
    change_type = Column(String(16), nullable=False)    # "created" / "updated" / "offline" / "deleted"
    field_name = Column(String(64))                     # e.g. "vlan", "mac_address", null for create
    old_value = Column(Text)
    new_value = Column(Text)
    job_id = Column(String(36))                         # crawl job or null for manual actions
    created_at = Column(DateTime, nullable=False, default=_utcnow)
