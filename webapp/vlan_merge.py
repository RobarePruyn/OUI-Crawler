"""Merge discovered VLANs into the VenueVlan table."""

import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .changelog import log_changes, log_created
from .db_models import VenueVlan

logger = logging.getLogger(__name__)


def merge_discovered_vlans(
    db: Session,
    venue_id: int,
    core_ip: str,
    discovered_vlans: dict[str, list],
) -> None:
    """
    Merge discovered VLANs into the VenueVlan table for a venue.

    1. Consolidate across switches: vlan_id -> best SVI data + list of switch hostnames.
       - SVI on switch matching core_ip -> svi_location="core"
       - SVI on any other switch -> svi_location="edge"
       - VLAN defined but no SVI anywhere -> svi_location="off-net"
    2. For each consolidated VLAN:
       - Exists in VenueVlan -> update only where overwrite flag is True
       - New -> create with source="discovered", overwrite flags all True
    3. Existing VenueVlans not found in discovery:
       - If previously had SVI -> set svi_location="off-net"
       - Do NOT delete (may be manually added for provisioning)
    """
    # --- Step 1: Consolidate across all switches ---
    consolidated: dict[int, dict] = {}

    for hostname, vlan_list in discovered_vlans.items():
        for vinfo in vlan_list:
            vid = vinfo.vlan_id
            if vid not in consolidated:
                consolidated[vid] = {
                    "name": vinfo.name,
                    "switches": [],
                    "svi": None,
                    "svi_hostname": None,
                    "svi_is_core": False,
                    "spanning_tree_enabled": False,
                }

            consolidated[vid]["switches"].append(hostname)

            # Track spanning-tree (any switch having it counts)
            if vinfo.spanning_tree_enabled:
                consolidated[vid]["spanning_tree_enabled"] = True

            # Pick best SVI: prefer core switch, then first found
            if vinfo.has_svi:
                is_core = vinfo.switch_ip == core_ip
                existing_svi = consolidated[vid]["svi"]
                if existing_svi is None or (is_core and not consolidated[vid]["svi_is_core"]):
                    consolidated[vid]["svi"] = vinfo
                    consolidated[vid]["svi_hostname"] = hostname
                    consolidated[vid]["svi_is_core"] = is_core

    # --- Step 2: Merge into DB ---
    existing = db.query(VenueVlan).filter(VenueVlan.venue_id == venue_id).all()
    existing_map = {v.vlan_id: v for v in existing}
    discovered_vids = set(consolidated.keys())

    for vid, data in consolidated.items():
        svi = data["svi"]
        switches_json = json.dumps(data["switches"])

        # Determine SVI location
        if svi:
            svi_location = "core" if data["svi_is_core"] else "edge"
        else:
            svi_location = "off-net"

        if vid in existing_map:
            # Update existing record, respecting overwrite flags
            row = existing_map[vid]

            # Capture old values for changelog
            old_vals = {
                "name": row.name,
                "svi_location": row.svi_location,
                "ip_address": row.ip_address,
                "dhcp_servers": row.dhcp_servers,
                "spanning_tree_enabled": str(row.spanning_tree_enabled),
            }

            if row.overwrite_name and data["name"]:
                row.name = data["name"]

            if row.overwrite_svi:
                row.svi_location = svi_location
                row.svi_switch_hostname = data["svi_hostname"] or ""
                if svi:
                    row.ip_address = svi.svi_ip_address or row.ip_address
                    row.gateway_ip = svi.active_gateway_ip or row.gateway_ip
                    row.gateway_mac = svi.active_gateway_mac or row.gateway_mac
                    row.igmp_enable = svi.igmp_enabled
                    row.pim_sparse_enable = svi.pim_sparse_enabled
                row.spanning_tree_enabled = data["spanning_tree_enabled"]

            if row.overwrite_dhcp and svi and svi.dhcp_helpers:
                row.dhcp_servers = json.dumps(svi.dhcp_helpers)

            row.discovered_on_switches = switches_json
            row.source = "discovered" if row.source != "manual" else row.source
            row.updated_at = datetime.now(timezone.utc)

            # Log field-level changes
            new_vals = {
                "name": row.name,
                "svi_location": row.svi_location,
                "ip_address": row.ip_address,
                "dhcp_servers": row.dhcp_servers,
                "spanning_tree_enabled": str(row.spanning_tree_enabled),
            }
            log_changes(db, venue_id, "vlan", row.id, old_vals, new_vals)
        else:
            # Create new record
            new_vlan = VenueVlan(
                venue_id=venue_id,
                vlan_id=vid,
                name=data["name"],
                svi_location=svi_location,
                svi_switch_hostname=data["svi_hostname"] or "",
                spanning_tree_enabled=data["spanning_tree_enabled"],
                discovered_on_switches=switches_json,
                source="discovered",
            )
            if svi:
                new_vlan.ip_address = svi.svi_ip_address
                new_vlan.gateway_ip = svi.active_gateway_ip
                new_vlan.gateway_mac = svi.active_gateway_mac
                if svi.dhcp_helpers:
                    new_vlan.dhcp_servers = json.dumps(svi.dhcp_helpers)
                new_vlan.igmp_enable = svi.igmp_enabled
                new_vlan.pim_sparse_enable = svi.pim_sparse_enabled
            db.add(new_vlan)
            db.flush()
            log_created(db, venue_id, "vlan", new_vlan.id)

    # --- Step 3: Mark missing VLANs as off-net ---
    for vid, row in existing_map.items():
        if vid not in discovered_vids:
            if row.svi_location and row.svi_location != "off-net":
                row.svi_location = "off-net"
                row.updated_at = datetime.now(timezone.utc)

    db.commit()
    logger.info(
        "VLAN merge for venue %d: %d discovered, %d existing, %d new",
        venue_id,
        len(discovered_vids),
        len(existing_map),
        len(discovered_vids - set(existing_map.keys())),
    )
