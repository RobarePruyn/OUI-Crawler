"""Device lookup and VLAN push API routes."""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from netmiko import ConnectHandler
from sqlalchemy.orm import Session

from ..auth import User, get_current_user
from ..crypto import decrypt_credential
from ..database import get_db
from ..db_models import OUIEntry, PortPolicy, Venue, VenueVlan
from ..schemas import (
    InterfaceStats,
    LookupHop,
    LookupRequest,
    LookupResponse,
    OUIMatch,
    PortPolicyInfo,
    VlanPushRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/lookup", tags=["lookup"])


def _match_oui(mac_address: str, oui_entries: list[OUIEntry]) -> OUIEntry | None:
    """Find the most specific OUI entry whose prefix matches the given MAC.
    Longest-prefix-match: e4:30:22:b8 beats e4:30:22."""
    if not mac_address:
        return None
    mac_hex = mac_address.replace('.', '').replace(':', '').replace('-', '').lower()
    best_entry = None
    best_len = 0
    for entry in oui_entries:
        prefix_hex = entry.oui_prefix.replace(':', '').replace('-', '').replace('.', '').lower()
        if mac_hex.startswith(prefix_hex) and len(prefix_hex) > best_len:
            best_entry = entry
            best_len = len(prefix_hex)
    return best_entry


def _parse_json_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []


@router.post("", response_model=LookupResponse)
def device_lookup(
    req: LookupRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(req.venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    password = decrypt_credential(venue.ssh_password_enc)
    enable = decrypt_credential(venue.enable_secret_enc) if venue.enable_secret_enc else password

    from oui_mapper_engine.lookup import lookup_device

    result = lookup_device(
        search_term=req.search_term,
        core_ip=venue.core_ip,
        username=venue.ssh_username,
        password=password,
        enable_secret=enable,
        platform_hint=venue.platform,
        mgmt_subnet=venue.mgmt_subnet,
        logger=logger,
    )

    # --- OUI match + port policies ---
    oui_entries = db.query(OUIEntry).filter(OUIEntry.venue_id == req.venue_id).all()
    policies = db.query(PortPolicy).filter(PortPolicy.venue_id == req.venue_id).all()

    # Collect all candidate VLANs across venue OUI entries
    all_vlans = set()
    for entry in oui_entries:
        for v in _parse_json_list(entry.candidate_vlans):
            all_vlans.add(str(v))

    # Check if device MAC matches a registered OUI
    oui_match = None
    matched_entry = _match_oui(result.mac_address, oui_entries)
    if matched_entry:
        candidate_vlans = _parse_json_list(matched_entry.candidate_vlans)
        oui_match = OUIMatch(
            oui_prefix=matched_entry.oui_prefix,
            description=matched_entry.description,
            manufacturer=matched_entry.manufacturer,
            candidate_vlans=[str(v) for v in candidate_vlans],
        )

    # Collect port policies for candidate VLANs
    policy_map = {p.vlan: p for p in policies}
    port_policies = []
    target_vlans = oui_match.candidate_vlans if oui_match else sorted(all_vlans)
    for vlan in target_vlans:
        policy = policy_map.get(str(vlan))
        if policy:
            port_policies.append(PortPolicyInfo(
                vlan=policy.vlan,
                bpdu_guard=policy.bpdu_guard,
                portfast=policy.portfast,
                storm_control=policy.storm_control,
                storm_control_level=policy.storm_control_level,
                description_template=policy.description_template,
                notes=policy.notes,
            ))

    return LookupResponse(
        mac_address=result.mac_address or None,
        ip_address=result.ip_address or None,
        switch_hostname=result.switch_hostname or None,
        switch_ip=result.switch_ip or None,
        interface=result.interface or None,
        vlan=result.vlan or None,
        platform=result.platform or None,
        interface_config=result.interface_config or None,
        interface_stats=InterfaceStats(**result.interface_stats) if result.interface_stats else None,
        hops=[LookupHop(**h) for h in result.hops],
        warnings=result.warnings,
        oui_match=oui_match,
        port_policies=port_policies,
        venue_vlans=sorted(all_vlans),
    )


@router.post("/vlan-push")
def vlan_push(
    req: VlanPushRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    venue = db.query(Venue).get(req.venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    password = decrypt_credential(venue.ssh_password_enc)
    enable = decrypt_credential(venue.enable_secret_enc) if venue.enable_secret_enc else password

    from oui_mapper_engine.platforms import get_platform, PLATFORM_MAP

    if req.platform not in PLATFORM_MAP:
        raise HTTPException(status_code=400, detail=f"Unknown platform: {req.platform}")

    platform = get_platform(req.platform)
    all_commands: list[str] = []
    provisioned_on: list[str] = []

    try:
        # Connect to the target (edge) switch
        conn = ConnectHandler(
            device_type=req.platform,
            host=req.switch_ip,
            username=venue.ssh_username,
            password=password,
            secret=enable,
            timeout=15,
            read_timeout_override=30,
        )
        conn.enable()

        # Check if VLAN exists on this switch
        vlan_cmd = platform.get_vlan_brief_command()
        vlan_exists = True
        if vlan_cmd:
            vlan_output = conn.send_command(vlan_cmd)
            existing_vlans = platform.parse_vlan_brief(vlan_output)
            existing_ids = {v.vlan_id for v in existing_vlans}
            vlan_exists = int(req.vlan) in existing_ids

        if not vlan_exists:
            # Look up VenueVlan for SVI config
            venue_vlan = (
                db.query(VenueVlan)
                .filter(VenueVlan.venue_id == req.venue_id, VenueVlan.vlan_id == int(req.vlan))
                .first()
            )
            vlan_name = venue_vlan.name if venue_vlan else ""

            is_edge = req.switch_ip != venue.core_ip

            # Create VLAN on core switch first (if this is an edge switch)
            if is_edge:
                try:
                    core_conn = ConnectHandler(
                        device_type=req.platform,
                        host=venue.core_ip,
                        username=venue.ssh_username,
                        password=password,
                        secret=enable,
                        timeout=15,
                        read_timeout_override=30,
                    )
                    core_conn.enable()

                    core_cmds = platform.get_vlan_create_commands(int(req.vlan), vlan_name)

                    # SVI on core (if venue_vlan has SVI config, skip for dark VLANs)
                    if venue_vlan and venue_vlan.ip_address and not venue_vlan.dark_vlan:
                        dhcp = json.loads(venue_vlan.dhcp_servers) if venue_vlan.dhcp_servers else []
                        core_cmds += platform.get_svi_create_commands(
                            int(req.vlan),
                            ip_address=venue_vlan.ip_address or "",
                            gateway_ip=venue_vlan.gateway_ip or "",
                            gateway_mac=venue_vlan.gateway_mac or "",
                            dhcp_servers=dhcp,
                            igmp=venue_vlan.igmp_enable,
                            pim_sparse=venue_vlan.pim_sparse_enable,
                        )

                    # Aruba spanning-tree
                    core_cmds += platform.get_spanning_tree_vlan_commands(int(req.vlan))

                    if core_cmds:
                        core_conn.send_config_set(core_cmds)
                        all_commands.extend([f"[core] {c}" for c in core_cmds])
                        provisioned_on.append(f"core ({venue.core_ip})")

                    if req.save_config:
                        core_conn.send_command(platform.get_save_config_command(), read_timeout=30)

                    core_conn.disconnect()
                except Exception as exc:
                    logger.warning(f"Failed to provision VLAN {req.vlan} on core: {exc}")

            # Create VLAN on edge switch (no SVI)
            edge_cmds = platform.get_vlan_create_commands(int(req.vlan), vlan_name)
            edge_cmds += platform.get_spanning_tree_vlan_commands(int(req.vlan))

            # If this IS the core, also create SVI here (skip for dark VLANs)
            if not is_edge and venue_vlan and venue_vlan.ip_address and not venue_vlan.dark_vlan:
                dhcp = json.loads(venue_vlan.dhcp_servers) if venue_vlan.dhcp_servers else []
                edge_cmds += platform.get_svi_create_commands(
                    int(req.vlan),
                    ip_address=venue_vlan.ip_address or "",
                    gateway_ip=venue_vlan.gateway_ip or "",
                    gateway_mac=venue_vlan.gateway_mac or "",
                    dhcp_servers=dhcp,
                    igmp=venue_vlan.igmp_enable,
                    pim_sparse=venue_vlan.pim_sparse_enable,
                )

            if edge_cmds:
                conn.send_config_set(edge_cmds)
                all_commands.extend(edge_cmds)
                provisioned_on.append(f"edge ({req.switch_ip})" if is_edge else f"core ({req.switch_ip})")

        # Now push the port VLAN assignment
        port_commands = platform.get_vlan_assign_commands(req.interface, req.vlan)
        conn.send_config_set(port_commands)
        all_commands.extend(port_commands)

        if req.save_config:
            save_cmd = platform.get_save_config_command()
            conn.send_command(save_cmd, read_timeout=30)

        conn.disconnect()

        message = f"VLAN {req.vlan} assigned to {req.interface} on {req.switch_ip}"
        if provisioned_on:
            message += f" (VLAN created on {', '.join(provisioned_on)})"

        return {
            "status": "ok",
            "commands": all_commands,
            "message": message,
        }
    except Exception as exc:
        logger.error(f"VLAN push failed: {exc}")
        return {
            "status": "error",
            "message": str(exc),
        }
