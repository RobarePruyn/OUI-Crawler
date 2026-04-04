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


# ── Venue ───────────────────────────────────────────────────────────

class VenueCreate(BaseModel):
    name: str
    core_ip: str
    platform: str = "auto"
    ssh_username: str
    ssh_password: str
    enable_secret: Optional[str] = None
    mgmt_subnet: Optional[str] = None
    fan_out: bool = False
    workers: int = 10
    mac_threshold: int = 1
    default_dhcp_servers: list[str] = Field(default_factory=list)
    default_dns_servers: list[str] = Field(default_factory=list)
    default_gateway_mac: Optional[str] = None


class VenueUpdate(BaseModel):
    name: Optional[str] = None
    core_ip: Optional[str] = None
    platform: Optional[str] = None
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    enable_secret: Optional[str] = None
    mgmt_subnet: Optional[str] = None
    fan_out: Optional[bool] = None
    workers: Optional[int] = None
    mac_threshold: Optional[int] = None
    default_dhcp_servers: Optional[list[str]] = None
    default_dns_servers: Optional[list[str]] = None
    default_gateway_mac: Optional[str] = None


class VenueOut(BaseModel):
    id: int
    name: str
    core_ip: str
    platform: str
    ssh_username: str
    mgmt_subnet: Optional[str] = None
    fan_out: bool = False
    workers: int = 10
    mac_threshold: int = 1
    default_dhcp_servers: Optional[str] = None  # JSON string from DB
    default_dns_servers: Optional[str] = None   # JSON string from DB
    default_gateway_mac: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── OUI Entry ───────────────────────────────────────────────────────

class OUIEntryCreate(BaseModel):
    oui_prefix: str
    description: Optional[str] = None
    candidate_vlans: list[str] = Field(default_factory=list)
    expected_ips: list[str] = Field(default_factory=list)


class OUIEntryUpdate(BaseModel):
    oui_prefix: Optional[str] = None
    description: Optional[str] = None
    candidate_vlans: Optional[list[str]] = None
    expected_ips: Optional[list[str]] = None


class OUIEntryOut(BaseModel):
    id: int
    venue_id: int
    oui_prefix: str
    description: Optional[str] = None
    manufacturer: Optional[str] = None
    candidate_vlans: Optional[str] = None  # JSON string from DB
    expected_ips: Optional[str] = None     # JSON string from DB
    created_at: datetime

    model_config = {"from_attributes": True}


class OUILookupRequest(BaseModel):
    oui_prefix: str


class OUILookupResult(BaseModel):
    oui_prefix: str
    manufacturer: Optional[str] = None
    found: bool


# ── Schedule ────────────────────────────────────────────────────────

class ScheduleCreate(BaseModel):
    job_type: str = Field(description="discovery or inventory")
    time_of_day: str = Field(description="HH:MM in 24h format")
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    job_type: Optional[str] = None
    time_of_day: Optional[str] = None
    enabled: Optional[bool] = None


class ScheduleOut(BaseModel):
    id: int
    venue_id: int
    job_type: str
    enabled: bool
    time_of_day: str
    last_run_at: Optional[datetime] = None
    last_job_id: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Port Policy ─────────────────────────────────────────────────────

class PortPolicyCreate(BaseModel):
    vlan: str
    bpdu_guard: bool = True
    portfast: bool = True
    storm_control: bool = False
    storm_control_level: str = "1.00"
    description_template: Optional[str] = None
    notes: Optional[str] = None


class PortPolicyUpdate(BaseModel):
    vlan: Optional[str] = None
    bpdu_guard: Optional[bool] = None
    portfast: Optional[bool] = None
    storm_control: Optional[bool] = None
    storm_control_level: Optional[str] = None
    description_template: Optional[str] = None
    notes: Optional[str] = None


class PortPolicyOut(BaseModel):
    id: int
    venue_id: int
    vlan: str
    bpdu_guard: bool
    portfast: bool
    storm_control: bool
    storm_control_level: Optional[str] = None
    description_template: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Venue VLANs ────────────────────────────────────────────────────

class VenueVlanCreate(BaseModel):
    vlan_id: int = Field(ge=2, le=4094)
    name: Optional[str] = None
    dark_vlan: bool = False
    ip_address: Optional[str] = None
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    dhcp_servers: list[str] = Field(default_factory=list)
    dns_servers: list[str] = Field(default_factory=list)
    igmp_enable: bool = False
    pim_sparse_enable: bool = False


class VenueVlanUpdate(BaseModel):
    name: Optional[str] = None
    dark_vlan: Optional[bool] = None
    ip_address: Optional[str] = None
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    dhcp_servers: Optional[list[str]] = None
    dns_servers: Optional[list[str]] = None
    igmp_enable: Optional[bool] = None
    pim_sparse_enable: Optional[bool] = None
    overwrite_name: Optional[bool] = None
    overwrite_svi: Optional[bool] = None
    overwrite_dhcp: Optional[bool] = None
    overwrite_dns: Optional[bool] = None


class VenueVlanOut(BaseModel):
    id: int
    venue_id: int
    vlan_id: int
    name: Optional[str] = None
    dark_vlan: bool = False
    ip_address: Optional[str] = None
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    dhcp_servers: Optional[str] = None   # JSON string from DB
    dns_servers: Optional[str] = None    # JSON string from DB
    igmp_enable: bool = False
    pim_sparse_enable: bool = False
    svi_location: Optional[str] = None
    svi_switch_hostname: Optional[str] = None
    discovered_on_switches: Optional[str] = None  # JSON string from DB
    spanning_tree_enabled: bool = False
    overwrite_name: bool = True
    overwrite_svi: bool = True
    overwrite_dhcp: bool = True
    overwrite_dns: bool = True
    source: str = "manual"
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── Compliance ──────────────────────────────────────────────────────

class ComplianceResultOut(BaseModel):
    id: int
    job_id: str
    venue_id: Optional[int] = None
    check_type: str
    switch_hostname: Optional[str] = None
    switch_ip: Optional[str] = None
    interface: Optional[str] = None
    mac_address: Optional[str] = None
    current_value: Optional[str] = None
    expected_value: Optional[str] = None
    severity: str
    detail: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ComplianceSummary(BaseModel):
    total: int = 0
    ok: int = 0
    warnings: int = 0
    critical: int = 0
    results: list[ComplianceResultOut] = Field(default_factory=list)


# ── Device Lookup ───────────────────────────────────────────────────

class LookupRequest(BaseModel):
    venue_id: int
    search_term: str = Field(description="MAC address or IP address")


class InterfaceStats(BaseModel):
    status: Optional[str] = None
    protocol_status: Optional[str] = None
    description: Optional[str] = None
    input_rate_30sec: Optional[str] = None
    output_rate_30sec: Optional[str] = None
    input_rate_5min: Optional[str] = None
    output_rate_5min: Optional[str] = None
    input_errors: Optional[int] = None
    output_errors: Optional[int] = None
    crc_errors: Optional[int] = None
    input_packets: Optional[int] = None
    output_packets: Optional[int] = None


class LookupHop(BaseModel):
    switch_hostname: str
    switch_ip: str
    port: str
    reason: str


class OUIMatch(BaseModel):
    oui_prefix: str
    description: Optional[str] = None
    manufacturer: Optional[str] = None
    candidate_vlans: list[str] = Field(default_factory=list)


class PortPolicyInfo(BaseModel):
    vlan: str
    bpdu_guard: bool = True
    portfast: bool = True
    storm_control: bool = False
    storm_control_level: Optional[str] = None
    description_template: Optional[str] = None
    notes: Optional[str] = None


class LookupResponse(BaseModel):
    mac_address: Optional[str] = None
    ip_address: Optional[str] = None
    switch_hostname: Optional[str] = None
    switch_ip: Optional[str] = None
    interface: Optional[str] = None
    vlan: Optional[str] = None
    platform: Optional[str] = None
    interface_config: Optional[str] = None
    interface_stats: Optional[InterfaceStats] = None
    hops: list[LookupHop] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    oui_match: Optional[OUIMatch] = None
    port_policies: list[PortPolicyInfo] = Field(default_factory=list)
    venue_vlans: list[str] = Field(default_factory=list)


class VlanPushRequest(BaseModel):
    venue_id: int
    switch_ip: str
    interface: str
    vlan: str
    platform: str
    save_config: bool = False


class LookupPortActionRequest(BaseModel):
    venue_id: int
    switch_ip: str
    interface: str
    platform: str
    action: str  # shutdown, no_shutdown, port_cycle
