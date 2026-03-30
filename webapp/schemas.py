"""Pydantic request/response models for the API."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ── Requests ─────────────────────────────────────────────────────────

class DiscoveryRequest(BaseModel):
    core_ip: str
    username: str
    password: str
    enable_secret: Optional[str] = None
    platform: str = "auto"
    oui_list: list[str] = Field(default_factory=list, description="OUI prefixes (e.g. ['00:0F:44','90:AC:3F'])")
    fan_out: bool = False
    workers: int = 10
    mac_threshold: int = 1
    mgmt_subnet: Optional[str] = None
    track_vlans: Optional[str] = None


class InventoryRequest(BaseModel):
    core_ip: str
    username: str
    password: str
    enable_secret: Optional[str] = None
    platform: str = "auto"
    workers: int = 10
    mgmt_subnet: Optional[str] = None


class ActionRequest(BaseModel):
    job_id: str = Field(description="Source discovery job ID")
    username: str
    password: str
    enable_secret: Optional[str] = None
    action: str = Field(description="shutdown | no_shutdown | port_cycle | vlan_assign | set_description")
    cycle_delay: int = 5
    save_config: bool = False
    desc_template: str = "{mac} {ip}"
    dry_run: bool = False


class DiffRequest(BaseModel):
    old_job_id: str
    new_job_id: str


# ── Responses ────────────────────────────────────────────────────────

class JobSummary(BaseModel):
    id: str
    job_type: str
    status: str
    core_ip: Optional[str] = None
    switches_visited: int = 0
    devices_found: int = 0
    error_message: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class JobProgress(BaseModel):
    id: str
    status: str
    switches_visited: int = 0
    devices_found: int = 0
    message: Optional[str] = None
    error_message: Optional[str] = None


class DeviceResultOut(BaseModel):
    switch_hostname: Optional[str] = None
    switch_ip: Optional[str] = None
    interface: Optional[str] = None
    mac_address: Optional[str] = None
    matched_oui: Optional[str] = None
    ip_address: Optional[str] = None
    vlan: Optional[str] = None
    switch_tracked_vlan: Optional[str] = None
    notes: Optional[str] = None

    model_config = {"from_attributes": True}


class SwitchResultOut(BaseModel):
    hostname: Optional[str] = None
    mgmt_ip: Optional[str] = None
    platform: Optional[str] = None
    upstream_hostname: Optional[str] = None
    upstream_ip: Optional[str] = None
    upstream_interface: Optional[str] = None

    model_config = {"from_attributes": True}


class ActionLogOut(BaseModel):
    action_type: str
    switch_hostname: Optional[str] = None
    switch_ip: Optional[str] = None
    interface: Optional[str] = None
    mac_address: Optional[str] = None
    detail: Optional[str] = None
    status: str
    dry_run: bool = False
    executed_at: datetime

    model_config = {"from_attributes": True}


class ActionPreview(BaseModel):
    actionable_count: int
    skipped_notes: int
    skipped_trunk: int
    skipped_bad_intf: int
    skipped_correct_vlan: int = 0
    skipped_ambiguous: int = 0
    skipped_no_tracked: int = 0
    actionable: list[DeviceResultOut]


class DiffReport(BaseModel):
    added: list[DeviceResultOut]
    removed: list[DeviceResultOut]
    moved: list[dict]
    unchanged_count: int
    old_count: int
    new_count: int
