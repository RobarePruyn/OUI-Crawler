"""
NetCaster Engine — shared automation logic.

This package contains the core discovery and automation engine
used by the NetCaster web application.
"""
from .models import (
    DeviceRecord,
    SwitchRecord,
    Neighbor,
    MacEntry,
    PortObservation,
    ProgressEvent,
    ActionPlan,
    ActionResult,
    DiffResult,
    VlanInfo,
)
from .mac_utils import normalize_mac_to_cisco, normalize_oui_prefix, mac_matches_oui
from .platforms import (
    SwitchPlatform,
    CiscoIOSPlatform,
    CiscoNXOSPlatform,
    ArubaAOSCXPlatform,
    PLATFORM_MAP,
    detect_platform,
    get_platform,
)
from .engine import NetCasterEngine
from .lookup import LookupResult, lookup_device
