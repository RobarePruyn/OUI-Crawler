"""
MAC address and OUI normalization utilities.
"""
import re
from typing import Optional


def normalize_mac_to_cisco(raw_mac: str) -> str:
    """
    Convert any MAC format to Cisco dotted notation: xxxx.xxxx.xxxx

    Accepts:
      00:1A:2B:3C:4D:5E   (colon-separated)
      00-1A-2B-3C-4D-5E   (dash-separated)
      001a.2b3c.4d5e      (Cisco dotted)
      001A2B3C4D5E        (bare hex)

    Returns:
      001a.2b3c.4d5e
    """
    hex_only = re.sub(r'[^0-9a-fA-F]', '', raw_mac).lower()
    if len(hex_only) != 12:
        return raw_mac.lower()
    return f"{hex_only[0:4]}.{hex_only[4:8]}.{hex_only[8:12]}"


def normalize_oui_prefix(raw_oui: str) -> str:
    """
    Normalize an OUI to hex-only lowercase for prefix matching.
    '00:1A:2B' -> '001a2b',  '001A2B' -> '001a2b'
    """
    return re.sub(r'[^0-9a-fA-F]', '', raw_oui).lower()


def mac_matches_oui(mac_cisco: str, normalized_oui_list: list[str]) -> Optional[str]:
    """
    Check if a Cisco-format MAC matches any OUI prefix in the list.
    Returns the matched OUI string if found, None otherwise.
    """
    mac_hex = mac_cisco.replace('.', '')
    for oui_prefix in normalized_oui_list:
        if mac_hex.startswith(oui_prefix):
            return oui_prefix
    return None
