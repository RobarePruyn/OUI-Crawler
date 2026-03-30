"""
Platform abstraction layer for OUI Port Mapper.
"""
import logging
import re
from abc import ABC, abstractmethod
from typing import Optional

from netmiko import ConnectHandler
from netmiko.ssh_autodetect import SSHDetect

from ..models import MacEntry, Neighbor


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


def detect_platform(
    host: str,
    username: str,
    password: str,
    enable_secret: str,
    log: logging.Logger,
) -> tuple[Optional[str], Optional[object]]:
    """
    Auto-detect the platform of a network device by SSH fingerprinting.

    Uses netmiko's SSHDetect first, then validates with 'show version'
    output if needed. Returns (device_type, active_connection) or
    (None, None) on failure.

    The connection is returned still open so the caller doesn't have to
    reconnect after detection.
    """
    log.info(f"Auto-detecting platform for {host}...")

    # --- Attempt 1: netmiko SSHDetect ---
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

        if best_match and best_match in PLATFORM_MAP:
            # SSHDetect's internal connection is not fully set up for
            # reliable command execution, so disconnect and let the
            # caller reconnect with the proper device_type.
            # Remap to the correct netmiko driver if needed (e.g.,
            # SSHDetect returns aruba_osswitch for AOS-CX hardware).
            remapped = DEVICE_TYPE_REMAP.get(best_match, best_match)
            if remapped != best_match:
                log.info(
                    f"Remapping SSHDetect result '{best_match}' → "
                    f"'{remapped}' for {host}"
                )
            detector.connection.disconnect()
            return remapped, None

        if best_match:
            log.debug(
                f"SSHDetect returned '{best_match}' which is not in "
                f"our platform map; trying show version fingerprint"
            )
            detector.connection.disconnect()

    except Exception as exc:
        log.debug(f"SSHDetect failed for {host}: {exc}")

    # --- Attempt 2: Connect generic, run 'show version', fingerprint ---
    for try_type in ["cisco_ios", "cisco_nxos", "aruba_aoscx"]:
        try:
            conn_params = {
                "device_type": try_type,
                "host": host,
                "username": username,
                "password": password,
                "secret": enable_secret,
                "timeout": 30,
                "read_timeout_override": 30,
            }
            conn = ConnectHandler(**conn_params)
            conn.enable()

            version_output = conn.send_command("show version")

            for pattern, device_type in VERSION_FINGERPRINTS:
                if re.search(pattern, version_output, re.IGNORECASE):
                    log.info(
                        f"Fingerprinted {host} as {device_type} "
                        f"via 'show version'"
                    )
                    # If we connected with the right type, return the
                    # live connection so the caller doesn't have to reconnect
                    if try_type == device_type or (
                        try_type == "cisco_ios"
                        and device_type == "cisco_ios"
                    ):
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

    log.error(f"Platform auto-detection failed for {host}")
    return None, None


def get_platform(device_type: str) -> SwitchPlatform:
    """
    Factory: return a SwitchPlatform instance for the given netmiko
    device_type string. Falls back to CiscoIOSPlatform if unknown.
    """
    platform_class = PLATFORM_MAP.get(device_type, CiscoIOSPlatform)
    return platform_class()
