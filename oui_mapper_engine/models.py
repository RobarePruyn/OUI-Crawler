"""
Data models for OUI Port Mapper engine.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional, Any


@dataclass
class DeviceRecord:
    """One discovered device pinned to a specific switch port."""
    switch_hostname: str
    switch_ip: str
    interface: str
    mac_address: str
    ip_address: str
    vlan: str
    matched_oui: str
    platform: str = ""
    discovery_depth: int = 0
    notes: str = ""
    switch_tracked_vlan: str = ""


@dataclass
class Neighbor:
    """A CDP or LLDP neighbor learned on a local interface."""
    local_interface: str
    neighbor_hostname: str
    neighbor_ip: str
    neighbor_platform: str
    neighbor_interface: str
    protocol: str
    capabilities: str = ""


@dataclass
class MacEntry:
    """A single MAC address table entry."""
    vlan: str
    mac_address: str
    entry_type: str
    interface: str


@dataclass
class SwitchRecord:
    """A switch discovered via CDP/LLDP neighbor crawl."""
    switch_hostname: str
    switch_ip: str
    platform: str
    discovery_depth: int = 0
    upstream_hostname: str = ""
    upstream_ip: str = ""
    upstream_interface: str = ""


@dataclass
class ProgressEvent:
    """Progress event emitted by the engine during discovery."""
    event_type: str          # "switch_start", "switch_done", "device_found", "error", "complete"
    switch_ip: str = ""
    switch_hostname: str = ""
    switches_visited: int = 0
    devices_found: int = 0
    message: str = ""
    detail: Optional[Any] = None  # DeviceRecord or SwitchRecord when relevant


@dataclass
class ActionPlan:
    """Result of planning a port action (safety filter applied)."""
    actionable: list = field(default_factory=list)  # list[DeviceRecord] or list[tuple[DeviceRecord, str]]
    skipped_notes: int = 0
    skipped_trunk: int = 0
    skipped_bad_intf: int = 0
    skipped_correct_vlan: int = 0
    skipped_ambiguous: int = 0
    skipped_no_tracked: int = 0


@dataclass
class ActionResult:
    """Result of executing a single port action."""
    switch_hostname: str
    switch_ip: str
    interface: str
    action: str
    status: str = ""     # "success" or "failed"
    error: str = ""


@dataclass
class VlanInfo:
    """VLAN discovered from a switch during inventory crawl."""
    vlan_id: int
    name: str = ""
    status: str = ""
    switch_hostname: str = ""
    switch_ip: str = ""
    has_svi: bool = False
    svi_ip_address: str = ""        # CIDR
    svi_status: str = ""
    dhcp_helpers: list[str] = field(default_factory=list)
    vsx_sync: bool = False          # Aruba
    active_gateway_ip: str = ""     # Aruba
    active_gateway_mac: str = ""    # Aruba
    spanning_tree_enabled: bool = False  # Aruba
    igmp_enabled: bool = False
    pim_sparse_enabled: bool = False


@dataclass
class DiffResult:
    """Result of comparing two sets of DeviceRecords."""
    added: list = field(default_factory=list)       # list[dict] - new devices
    removed: list = field(default_factory=list)     # list[dict] - missing devices
    moved: list = field(default_factory=list)       # list[tuple[str, dict, dict]] - (mac, old, new)
    unchanged_count: int = 0
    old_count: int = 0
    new_count: int = 0
