"""
Platform abstraction layer for OUI Port Mapper.
"""
import logging
import re
from abc import ABC, abstractmethod
from typing import Optional

from netmiko import ConnectHandler
from netmiko.ssh_autodetect import SSHDetect

from ..models import MacEntry, Neighbor, PortConfig, VlanInfo


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------

class SwitchPlatform(ABC):
    """
    Abstract base class for platform-specific command syntax and output
    parsing.  Each supported platform (Cisco IOS, Aruba AOS-CX, etc.)
    subclasses this and implements the abstract methods.
    """

    # Human-readable platform name for logging and CSV output
    platform_name: str = "unknown"

    # netmiko device_type string
    netmiko_device_type: str = "autodetect"

    @abstractmethod
    def get_arp_command(self) -> str:
        """Return the CLI command to display the ARP table."""
        ...

    @abstractmethod
    def get_mac_table_command(self) -> str:
        """Return the CLI command to display the MAC address table."""
        ...

    @abstractmethod
    def get_neighbor_command(self) -> str:
        """Return the CLI command to display CDP/LLDP neighbor detail."""
        ...

    @abstractmethod
    def get_shutdown_commands(self, interface: str) -> list[str]:
        """Return config commands to shut down an interface."""
        ...

    @abstractmethod
    def get_no_shutdown_commands(self, interface: str) -> list[str]:
        """Return config commands to enable an interface."""
        ...

    @abstractmethod
    def get_vlan_assign_commands(self, interface: str, vlan: str) -> list[str]:
        """Return config commands to set an access port's VLAN."""
        ...

    def get_port_config_commands(
        self,
        interface: str,
        *,
        bpdu_guard: bool = True,
        portfast: bool = True,
        storm_control: bool = False,
        storm_control_level: str = "1.00",
        description: str | None = None,
    ) -> list[str]:
        """Return config commands to apply port policy settings.

        Subclasses override for platform-specific syntax.
        """
        return []

    def get_save_config_command(self) -> str:
        """Return the exec command to save running-config to startup."""
        return "write memory"

    @abstractmethod
    def parse_mac_table(self, raw_output: str) -> list[MacEntry]:
        """Parse MAC address table output into MacEntry objects."""
        ...

    @abstractmethod
    def parse_arp_table(self, raw_output: str) -> dict[str, str]:
        """Parse ARP table output into a MAC→IP lookup dict."""
        ...

    @abstractmethod
    def parse_neighbors(self, raw_output: str) -> list[Neighbor]:
        """Parse CDP/LLDP neighbor detail into Neighbor objects."""
        ...

    @abstractmethod
    def normalize_interface(self, raw_name: str) -> str:
        """Normalize an interface name to its full canonical form."""
        ...

    def get_port_channel_command(self) -> str:
        """
        Return the CLI command to display port-channel/LAG membership.
        Used to map logical port-channel interfaces to their physical
        member interfaces, which is critical for correlating MAC table
        entries (learned on port-channel) with CDP/LLDP neighbors
        (reported on physical members).
        """
        return ""  # Override in subclasses

    def parse_port_channel_members(self, raw_output: str) -> dict[str, list[str]]:
        """
        Parse port-channel summary output into a mapping of
        port-channel name → list of physical member interfaces.

        Returns:
            {"Port-channel1": ["GigabitEthernet1/0/49", "GigabitEthernet1/0/50"],
             "Port-channel2": ["GigabitEthernet1/0/51"]}
        """
        return {}  # Override in subclasses

    def get_interface_config_command(self, interface: str) -> str:
        """Return CLI command for 'show running-config interface X'."""
        return ""  # Override in subclasses

    def get_all_interface_configs_command(self) -> str:
        """Return CLI command to retrieve all interface running-configs at once."""
        return ""  # Override in subclasses

    def parse_interface_configs(self, raw_output: str) -> dict[str, PortConfig]:
        """Parse bulk interface config output into per-interface PortConfig.

        Returns a dict of normalized interface name → PortConfig.
        """
        return {}  # Override in subclasses

    def get_civic_location_command(self) -> str:
        """Return CLI command to retrieve civic location definitions."""
        return ""  # Override in subclasses

    def parse_civic_locations(self, raw_output: str) -> dict[str, str]:
        """Parse civic location output into id → location name/description.

        Returns a dict of location_id → human-readable location string.
        """
        return {}  # Override in subclasses

    def enrich_civic_locations(
        self,
        intf_configs: dict[str, PortConfig],
        civic_map: dict[str, str],
    ) -> None:
        """Populate civic_location on PortConfig entries using civic_map.

        Default implementation does nothing — platforms that support civic
        location override parse_interface_configs to store the location ID
        in civic_location, then this method resolves IDs to names.
        """
        for pc in intf_configs.values():
            if pc.civic_location and pc.civic_location in civic_map:
                pc.civic_location = civic_map[pc.civic_location]

    def get_interface_stats_command(self, interface: str) -> str:
        """Return CLI command for 'show interface X' (detailed stats)."""
        return ""  # Override in subclasses

    def parse_interface_stats(self, raw_output: str) -> dict:
        """Parse 'show interface X' output into a structured dict."""
        return {}  # Override in subclasses

    # ── VLAN discovery ──────────────────────────────────────────────

    def get_vlan_brief_command(self) -> str:
        """Return CLI command to list VLANs."""
        return ""

    def get_svi_config_command(self) -> str:
        """Return CLI command to show SVI running-config sections."""
        return ""

    def get_spanning_tree_vlan_command(self) -> str:
        """Return CLI command to show spanning-tree VLAN info."""
        return ""

    def parse_vlan_brief(self, raw_output: str, hostname: str = "", ip: str = "") -> list[VlanInfo]:
        """Parse VLAN brief output into VlanInfo objects."""
        return []

    def parse_svi_config(self, raw_output: str, vlan_map: dict[int, VlanInfo]) -> dict[int, VlanInfo]:
        """Parse SVI config and enrich the vlan_map with SVI details."""
        return vlan_map

    def parse_spanning_tree_vlans(self, raw_output: str) -> set[int]:
        """Parse spanning-tree output and return set of VLAN IDs with STP enabled."""
        return set()

    # ── VLAN provisioning ───────────────────────────────────────────

    def get_vlan_create_commands(self, vlan_id: int, name: str = "") -> list[str]:
        """Return config commands to create a VLAN definition."""
        return []

    def get_svi_create_commands(
        self,
        vlan_id: int,
        ip_address: str = "",
        gateway_ip: str = "",
        gateway_mac: str = "",
        dhcp_servers: list[str] | None = None,
        igmp: bool = False,
        pim_sparse: bool = False,
    ) -> list[str]:
        """Return config commands to create an SVI for a VLAN."""
        return []

    def get_spanning_tree_vlan_commands(self, vlan_id: int) -> list[str]:
        """Return config commands to add a VLAN to spanning-tree."""
        return []

    def get_hostname(self, connection) -> str:
        """Extract the switch hostname from the netmiko prompt."""
        prompt = connection.find_prompt()
        return re.sub(r'[#>]\s*$', '', prompt)


# ---------------------------------------------------------------------------
# Platform implementations
# ---------------------------------------------------------------------------

from .cisco_ios import CiscoIOSPlatform
from .cisco_nxos import CiscoNXOSPlatform
from .aruba_aoscx import ArubaAOSCXPlatform


# ---------------------------------------------------------------------------
# Platform detection and factory
# ---------------------------------------------------------------------------

# Map netmiko device_type strings to our platform classes
PLATFORM_MAP: dict[str, type[SwitchPlatform]] = {
    "cisco_ios":      CiscoIOSPlatform,
    "cisco_xe":       CiscoIOSPlatform,   # IOS-XE uses same syntax as IOS
    "cisco_nxos":     CiscoNXOSPlatform,
    "aruba_aoscx":     ArubaAOSCXPlatform,
    "aruba_osswitch": ArubaAOSCXPlatform, # SSHDetect sometimes returns this for AOS-CX
    "aruba_os":       ArubaAOSCXPlatform, # SSHDetect may also return this
}

# SSHDetect returns netmiko device_type strings that may not be the correct
# driver for the actual hardware.  In particular, AOS-CX switches are often
# detected as "aruba_osswitch" (legacy ArubaOS) which uses a different
# netmiko SSH driver and mangles output.  This table remaps to the correct
# netmiko device_type for the SSH connection while PLATFORM_MAP still picks
# the right parser class.
DEVICE_TYPE_REMAP: dict[str, str] = {
    "aruba_osswitch": "aruba_aoscx",
    "aruba_os":       "aruba_aoscx",
}

# Patterns in 'show version' output to identify platform
VERSION_FINGERPRINTS: list[tuple[str, str]] = [
    (r'Cisco IOS Software',    "cisco_ios"),
    (r'Cisco IOS XE Software', "cisco_ios"),
    (r'Cisco IOS-XE',         "cisco_ios"),
    (r'Cisco Nexus',          "cisco_nxos"),
    (r'ArubaOS-CX',           "aruba_aoscx"),
    (r'Aruba.*CX',            "aruba_aoscx"),
    (r'AOS-CX',               "aruba_aoscx"),
    (r'HP.*Aruba',            "aruba_aoscx"),
]


def _fingerprint_via_show_version(
    host: str,
    username: str,
    password: str,
    enable_secret: str,
    log: logging.Logger,
    hint: Optional[str] = None,
) -> tuple[Optional[str], Optional[object]]:
    """
    Connect to a device, run 'show version', and fingerprint the output.

    If hint is provided, that device_type is tried first (likely to
    succeed if the fabric is homogeneous). Returns (device_type,
    connection) where connection is kept open if we connected with
    the matching type, or (device_type, None) if a reconnect is needed.
    """
    # Build try order: hint first (if valid), then the standard types
    standard_types = ["cisco_ios", "cisco_nxos", "aruba_aoscx"]
    if hint and hint in standard_types:
        try_order = [hint] + [t for t in standard_types if t != hint]
    else:
        try_order = standard_types

    for try_type in try_order:
        try:
            conn_params = {
                "device_type": try_type,
                "host": host,
                "username": username,
                "password": password,
                "secret": enable_secret,
                "timeout": 15,
                "read_timeout_override": 15,
            }
            conn = ConnectHandler(**conn_params)
            conn.enable()

            version_output = conn.send_command("show version")

            for pattern, device_type in VERSION_FINGERPRINTS:
                if re.search(pattern, version_output, re.IGNORECASE):
                    log.info(
                        f"Fingerprinted {host} as {device_type} "
                        f"via 'show version' (connected as {try_type})"
                    )
                    # If we connected with the right type, return the
                    # live connection so the caller doesn't have to reconnect
                    if try_type == device_type:
                        return device_type, conn
                    else:
                        conn.disconnect()
                        return device_type, None

            # No fingerprint matched but we got a working session
            log.warning(
                f"Could not fingerprint {host} from show version; "
                f"falling back to {try_type}"
            )
            return try_type, conn

        except Exception as exc:
            log.debug(f"Connection as {try_type} to {host} failed: {exc}")
            continue

    return None, None


def detect_platform(
    host: str,
    username: str,
    password: str,
    enable_secret: str,
    log: logging.Logger,
    hint: Optional[str] = None,
) -> tuple[Optional[str], Optional[object]]:
    """
    Auto-detect the platform of a network device.

    Strategy (fast to slow):
      1. Connect and fingerprint 'show version' output. If hint is
         provided (last successful platform), try that type first so
         homogeneous fabrics get a single SSH session per switch.
      2. Fall back to netmiko SSHDetect as a last resort.

    Returns (device_type, active_connection) or (None, None) on failure.
    The connection is returned still open when we connected with the
    matching type, saving a reconnect.
    """
    log.info(f"Auto-detecting platform for {host}...")

    # --- Attempt 1: show version fingerprint (fast path) ---
    device_type, conn = _fingerprint_via_show_version(
        host, username, password, enable_secret, log, hint=hint,
    )
    if device_type:
        return device_type, conn

    # --- Attempt 2: SSHDetect as last resort ---
    log.info(f"Show version fingerprint failed for {host}; trying SSHDetect...")
    try:
        detect_params = {
            "device_type": "autodetect",
            "host": host,
            "username": username,
            "password": password,
            "secret": enable_secret,
            "timeout": 30,
        }
        detector = SSHDetect(**detect_params)
        best_match = detector.autodetect()
        log.info(f"SSHDetect result for {host}: {best_match}")
        detector.connection.disconnect()

        if best_match and best_match in PLATFORM_MAP:
            remapped = DEVICE_TYPE_REMAP.get(best_match, best_match)
            if remapped != best_match:
                log.info(
                    f"Remapping SSHDetect result '{best_match}' → "
                    f"'{remapped}' for {host}"
                )
            return remapped, None

    except Exception as exc:
        log.debug(f"SSHDetect failed for {host}: {exc}")

    log.error(f"Platform auto-detection failed for {host}")
    return None, None


def get_platform(device_type: str) -> SwitchPlatform:
    """
    Factory: return a SwitchPlatform instance for the given netmiko
    device_type string. Falls back to CiscoIOSPlatform if unknown.
    """
    platform_class = PLATFORM_MAP.get(device_type, CiscoIOSPlatform)
    return platform_class()
