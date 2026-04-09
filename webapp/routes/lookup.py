"""Device lookup and VLAN push API routes."""

import json
import logging
import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import APIRouter, Depends, HTTPException
from netmiko import ConnectHandler
from sqlalchemy.orm import Session

from ..auth import User, get_current_user
from ..crypto import decrypt_credential
from ..database import get_db
from ..db_models import OUIEntry, PortPolicy, Venue, VenuePort, VenueSwitch, VenueVlan
from ..schemas import (
    BulkPortActionRequest,
    InterfaceStats,
    LookupHop,
    LookupPortActionRequest,
    LookupRequest,
    LookupResponse,
    OUIMatch,
    PortPolicyInfo,
    VlanPushRequest,
)

logger = logging.getLogger(__name__)

_LAG_RE = re.compile(r'^(lag\d|port-channel\d|po\d|ae\d|bond\d|loopback|vlan)', re.IGNORECASE)

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

    from netcaster_engine.lookup import lookup_device

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


@router.post("/search")
def device_search(
    req: LookupRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Search VenuePort DB for partial MAC or IP matches."""
    venue = db.query(Venue).get(req.venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    term = req.search_term.strip().lower()
    if len(term) < 3:
        raise HTTPException(status_code=400, detail="Search term must be at least 3 characters")

    # Normalize: strip colons/dots/dashes for MAC matching
    term_normalized = term.replace(":", "").replace(".", "").replace("-", "")

    # Query ports for this venue with partial match
    ports = (
        db.query(VenuePort, VenueSwitch)
        .join(VenueSwitch, VenuePort.switch_id == VenueSwitch.id)
        .filter(VenueSwitch.venue_id == req.venue_id)
        .filter(VenuePort.mac_address.isnot(None))
        .all()
    )

    results = []
    for port, switch in ports:
        mac_norm = (port.mac_address or "").replace(".", "").replace(":", "").replace("-", "").lower()
        ip = (port.ip_address or "").lower()

        # Skip LAGs, port-channels, loopbacks, SVIs — only edge ports
        if _LAG_RE.match(port.interface or ""):
            continue

        if term_normalized in mac_norm or term in ip or term in (port.matched_oui or "").lower():
            results.append({
                "port_id": port.id,
                "switch_hostname": switch.hostname,
                "switch_ip": switch.mgmt_ip,
                "interface": port.interface,
                "mac_address": port.mac_address,
                "ip_address": port.ip_address,
                "vlan": port.vlan,
                "matched_oui": port.matched_oui,
                "platform": switch.platform or venue.platform,
            })

    return {"results": results, "count": len(results)}


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

    from netcaster_engine.platforms import get_platform, PLATFORM_MAP

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

        # Bounce port so device re-DHCPs on the new VLAN
        conn.send_config_set([f"interface {req.interface}", "shutdown"])
        time.sleep(2)
        conn.send_config_set([f"interface {req.interface}", "no shutdown"])
        all_commands.extend([f"interface {req.interface}", "shutdown", "! wait 2s", "no shutdown"])

        if req.save_config:
            save_cmd = platform.get_save_config_command()
            conn.send_command(save_cmd, read_timeout=30)

        conn.disconnect()

        message = f"VLAN {req.vlan} assigned to {req.interface} on {req.switch_ip} (port bounced)"
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


@router.post("/port-action")
def lookup_port_action(
    req: LookupPortActionRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Shut / no-shut / cycle a port directly from the lookup page."""
    if req.action not in ("shutdown", "no_shutdown", "port_cycle", "poe_cycle"):
        raise HTTPException(status_code=400, detail="Invalid action")

    venue = db.query(Venue).get(req.venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    password = decrypt_credential(venue.ssh_password_enc)
    enable = decrypt_credential(venue.enable_secret_enc) if venue.enable_secret_enc else password

    try:
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

        from netcaster_engine.platforms import get_platform
        plat = get_platform(req.platform)

        if req.action == "shutdown":
            cmds = [f"interface {req.interface}", "shutdown"]
            conn.send_config_set(cmds)
        elif req.action == "no_shutdown":
            cmds = [f"interface {req.interface}", "no shutdown"]
            conn.send_config_set(cmds)
        elif req.action == "port_cycle":
            conn.send_config_set([f"interface {req.interface}", "shutdown"])
            time.sleep(3)
            conn.send_config_set([f"interface {req.interface}", "no shutdown"])
            cmds = [f"interface {req.interface}", "shutdown", "! wait 3s", "no shutdown"]
        elif req.action == "poe_cycle":
            poe_off = plat.get_poe_off_command(req.interface)
            conn.send_config_set(poe_off)
            time.sleep(3)
            poe_on = plat.get_poe_on_command(req.interface)
            conn.send_config_set(poe_on)
            cmds = poe_off + ["! wait 3s"] + poe_on

        conn.disconnect()

        label = req.action.replace("_", " ").title()
        return {
            "status": "ok",
            "commands": cmds,
            "message": f"{label} on {req.interface} ({req.switch_ip})",
        }
    except Exception as exc:
        logger.error(f"Port action failed: {exc}")
        return {"status": "error", "message": str(exc)}


@router.post("/bulk-action")
def bulk_port_action(
    req: BulkPortActionRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Run a port action on multiple devices, grouped by switch for efficiency."""
    if req.action not in ("shutdown", "no_shutdown", "port_cycle", "poe_cycle"):
        raise HTTPException(status_code=400, detail="Invalid action")

    venue = db.query(Venue).get(req.venue_id)
    if not venue:
        raise HTTPException(status_code=404, detail="Venue not found")

    password = decrypt_credential(venue.ssh_password_enc)
    enable = decrypt_credential(venue.enable_secret_enc) if venue.enable_secret_enc else password

    # Group targets by switch
    by_switch: dict[str, list] = defaultdict(list)
    platform_map: dict[str, str] = {}
    for t in req.targets:
        by_switch[t.switch_ip].append(t.interface)
        platform_map[t.switch_ip] = t.platform

    results: list[dict] = []

    def _process_switch(switch_ip: str, interfaces: list[str]) -> list[dict]:
        """SSH once per switch, run action on all its interfaces."""
        local_results = []
        platform = platform_map[switch_ip]
        try:
            conn = ConnectHandler(
                device_type=platform,
                host=switch_ip,
                username=venue.ssh_username,
                password=password,
                secret=enable,
                timeout=15,
                read_timeout_override=30,
            )
            conn.enable()

            from netcaster_engine.platforms import get_platform
            plat = get_platform(platform)

            for intf in interfaces:
                try:
                    if req.action == "shutdown":
                        conn.send_config_set([f"interface {intf}", "shutdown"])
                    elif req.action == "no_shutdown":
                        conn.send_config_set([f"interface {intf}", "no shutdown"])
                    elif req.action == "port_cycle":
                        conn.send_config_set([f"interface {intf}", "shutdown"])
                        time.sleep(2)
                        conn.send_config_set([f"interface {intf}", "no shutdown"])
                    elif req.action == "poe_cycle":
                        conn.send_config_set(plat.get_poe_off_command(intf))
                        time.sleep(2)
                        conn.send_config_set(plat.get_poe_on_command(intf))
                    local_results.append({"switch_ip": switch_ip, "interface": intf, "status": "ok"})
                except Exception as exc:
                    local_results.append({"switch_ip": switch_ip, "interface": intf, "status": "error", "error": str(exc)})

            conn.disconnect()
        except Exception as exc:
            # SSH connection failed — all interfaces on this switch fail
            for intf in interfaces:
                local_results.append({"switch_ip": switch_ip, "interface": intf, "status": "error", "error": str(exc)})
        return local_results

    # Run switches in parallel (one thread per switch, sequential ports within)
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {
            pool.submit(_process_switch, sw_ip, intfs): sw_ip
            for sw_ip, intfs in by_switch.items()
        }
        for future in as_completed(futures):
            results.extend(future.result())

    ok = sum(1 for r in results if r["status"] == "ok")
    failed = [r for r in results if r["status"] != "ok"]

    return {
        "ok": ok,
        "failed": len(failed),
        "total": len(results),
        "errors": failed,
    }
