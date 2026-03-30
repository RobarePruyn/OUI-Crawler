"""VLAN compliance and port policy checking engine."""

import ipaddress
import json
import logging
from typing import Optional

from sqlalchemy.orm import Session

from .db_models import ComplianceResult, DeviceResult, OUIEntry, PortPolicy, Venue, VenuePort, VenueSwitch

logger = logging.getLogger(__name__)


# ── VLAN/subnet pair data structure ─────────────────────────────────

class VlanSubnetPair:
    """A VLAN paired with its expected subnet (positional from OUI entry)."""

    def __init__(self, vlan: str, subnet: Optional[str] = None):
        self.vlan = vlan
        self.subnet = subnet
        self._network = None
        if subnet:
            try:
                self._network = ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                pass

    def ip_in_subnet(self, ip_str: str) -> bool:
        """Check if an IP address falls within this pair's subnet."""
        if not self._network or not ip_str:
            return True  # no subnet to check against
        try:
            return ipaddress.ip_address(ip_str) in self._network
        except ValueError:
            return True  # unparseable IP — don't flag


def _build_oui_map(oui_entries: list[OUIEntry]) -> dict[str, list[VlanSubnetPair]]:
    """Build a lookup from normalized OUI prefix to paired VLAN/subnet list."""
    oui_map: dict[str, list[VlanSubnetPair]] = {}
    for entry in oui_entries:
        prefix = (entry.oui_prefix or "").replace(":", "").replace("-", "").replace(".", "").upper()[:6]
        if not prefix or not entry.candidate_vlans:
            continue
        try:
            vlans = json.loads(entry.candidate_vlans)
        except (json.JSONDecodeError, TypeError):
            continue
        if not vlans:
            continue

        # Parse subnets (positionally paired with VLANs)
        subnets = []
        if entry.expected_ips:
            try:
                subnets = json.loads(entry.expected_ips)
            except (json.JSONDecodeError, TypeError):
                pass

        pairs = []
        for i, vlan in enumerate(vlans):
            subnet = subnets[i] if i < len(subnets) else None
            pairs.append(VlanSubnetPair(vlan, subnet))

        oui_map[prefix] = pairs
    return oui_map


def check_vlan_compliance(db: Session, job_id: str, venue_id: int) -> list[ComplianceResult]:
    """Compare discovered device VLANs and IPs against venue OUI registry expectations.

    VLANs and expected subnets are paired by position in the OUI entry.
    Checks both: is the device on a valid VLAN, and does its IP fall in
    the expected subnet for that VLAN?
    """
    devices = db.query(DeviceResult).filter(DeviceResult.job_id == job_id).all()
    if not devices:
        return []

    oui_entries = db.query(OUIEntry).filter(OUIEntry.venue_id == venue_id).all()
    oui_map = _build_oui_map(oui_entries)
    if not oui_map:
        return []

    # Clear existing results
    db.query(ComplianceResult).filter(
        ComplianceResult.job_id == job_id,
        ComplianceResult.check_type == "vlan_compliance",
    ).delete()

    results = []
    for dev in devices:
        matched = (dev.matched_oui or "").replace(":", "").replace("-", "").replace(".", "").upper()[:6]
        if matched not in oui_map:
            continue

        pairs = oui_map[matched]
        device_vlan = (dev.vlan or "").strip()
        device_ip = (dev.ip_address or "").strip()
        valid_vlans = [p.vlan for p in pairs]

        if not device_vlan:
            severity = "warning"
            detail = f"No VLAN detected; expected one of: {', '.join(valid_vlans)}"
            expected = valid_vlans[0]
        elif device_vlan in valid_vlans:
            # VLAN matches — now check subnet
            pair = next(p for p in pairs if p.vlan == device_vlan)
            if pair.subnet and device_ip and not pair.ip_in_subnet(device_ip):
                severity = "warning"
                detail = f"VLAN {device_vlan} is correct, but IP {device_ip} is outside expected subnet {pair.subnet}"
                expected = f"VLAN {device_vlan} / {pair.subnet}"
            else:
                severity = "ok"
                detail = f"VLAN {device_vlan} matches expected"
                if pair.subnet and device_ip:
                    detail += f", IP {device_ip} in {pair.subnet}"
                expected = device_vlan
        else:
            # Wrong VLAN — suggest the first candidate
            suggested = pairs[0]
            severity = "warning"
            detail = f"Device on VLAN {device_vlan} but expected one of: {', '.join(valid_vlans)}. Suggest VLAN {suggested.vlan}"
            if suggested.subnet:
                detail += f" ({suggested.subnet})"
            expected = suggested.vlan

        cr = ComplianceResult(
            job_id=job_id,
            venue_id=venue_id,
            check_type="vlan_compliance",
            switch_hostname=dev.switch_hostname,
            switch_ip=dev.switch_ip,
            interface=dev.interface,
            mac_address=dev.mac_address,
            current_value=f"VLAN {device_vlan or '?'}" + (f" / {device_ip}" if device_ip else ""),
            expected_value=expected,
            severity=severity,
            detail=detail,
        )
        db.add(cr)
        results.append(cr)

    db.commit()
    logger.info("VLAN compliance check for job %s: %d results (%d warnings)",
                job_id, len(results), sum(1 for r in results if r.severity == "warning"))
    return results


def check_port_policy_offline(db: Session, job_id: str, venue_id: int) -> list[ComplianceResult]:
    """Check device VLANs against port policies (no SSH required).

    This checks whether devices on certain VLANs have a port policy defined.
    Full port-config compliance (bpdu guard, portfast, etc.) requires SSH
    and runs as a background job via check_port_policy_live().
    """
    devices = db.query(DeviceResult).filter(DeviceResult.job_id == job_id).all()
    policies = db.query(PortPolicy).filter(PortPolicy.venue_id == venue_id).all()

    if not devices or not policies:
        return []

    policy_map = {p.vlan: p for p in policies}

    # Clear existing port_policy results
    db.query(ComplianceResult).filter(
        ComplianceResult.job_id == job_id,
        ComplianceResult.check_type == "port_policy",
    ).delete()

    results = []
    for dev in devices:
        device_vlan = (dev.vlan or "").strip()
        if not device_vlan or device_vlan not in policy_map:
            continue

        policy = policy_map[device_vlan]
        # Record that this port has a policy — detailed checks need SSH
        cr = ComplianceResult(
            job_id=job_id,
            venue_id=venue_id,
            check_type="port_policy",
            switch_hostname=dev.switch_hostname,
            switch_ip=dev.switch_ip,
            interface=dev.interface,
            mac_address=dev.mac_address,
            current_value=f"VLAN {device_vlan}",
            expected_value=_policy_summary(policy),
            severity="ok",
            detail=f"Port policy defined for VLAN {device_vlan}. SSH check required for full compliance.",
        )
        db.add(cr)
        results.append(cr)

    db.commit()
    return results


def check_venue_compliance(db: Session, venue_id: int) -> list[ComplianceResult]:
    """Check persistent VenuePort state against venue OUI registry expectations.

    Same logic as check_vlan_compliance but reads from VenuePort instead of
    DeviceResult, and stores results with venue_id only (no job_id).
    """
    oui_entries = db.query(OUIEntry).filter(OUIEntry.venue_id == venue_id).all()
    oui_map = _build_oui_map(oui_entries)
    if not oui_map:
        return []

    # Load all venue ports via switches
    switches = db.query(VenueSwitch).filter(VenueSwitch.venue_id == venue_id).all()
    switch_map = {s.id: s for s in switches}
    ports = db.query(VenuePort).filter(
        VenuePort.switch_id.in_([s.id for s in switches])
    ).all() if switches else []

    if not ports:
        return []

    # Clear existing venue-level compliance (job_id is NULL)
    db.query(ComplianceResult).filter(
        ComplianceResult.venue_id == venue_id,
        ComplianceResult.job_id.is_(None),
    ).delete()

    results = []
    for port in ports:
        matched = (port.matched_oui or "").replace(":", "").replace("-", "").replace(".", "").upper()[:6]
        if matched not in oui_map:
            continue

        switch = switch_map.get(port.switch_id)
        pairs = oui_map[matched]
        device_vlan = (port.vlan or "").strip()
        device_ip = (port.ip_address or "").strip()
        valid_vlans = [p.vlan for p in pairs]

        if not device_vlan:
            severity = "warning"
            detail = f"No VLAN detected; expected one of: {', '.join(valid_vlans)}"
            expected = valid_vlans[0]
        elif device_vlan in valid_vlans:
            pair = next(p for p in pairs if p.vlan == device_vlan)
            if pair.subnet and device_ip and not pair.ip_in_subnet(device_ip):
                severity = "warning"
                detail = f"VLAN {device_vlan} is correct, but IP {device_ip} is outside expected subnet {pair.subnet}"
                expected = f"VLAN {device_vlan} / {pair.subnet}"
            else:
                severity = "ok"
                detail = f"VLAN {device_vlan} matches expected"
                if pair.subnet and device_ip:
                    detail += f", IP {device_ip} in {pair.subnet}"
                expected = device_vlan
        else:
            suggested = pairs[0]
            severity = "warning"
            detail = f"Device on VLAN {device_vlan} but expected one of: {', '.join(valid_vlans)}. Suggest VLAN {suggested.vlan}"
            if suggested.subnet:
                detail += f" ({suggested.subnet})"
            expected = suggested.vlan

        cr = ComplianceResult(
            job_id=None,
            venue_id=venue_id,
            check_type="vlan_compliance",
            switch_hostname=switch.hostname if switch else "",
            switch_ip=switch.mgmt_ip if switch else "",
            interface=port.interface,
            mac_address=port.mac_address,
            current_value=f"VLAN {device_vlan or '?'}" + (f" / {device_ip}" if device_ip else ""),
            expected_value=expected,
            severity=severity,
            detail=detail,
        )
        db.add(cr)
        results.append(cr)

    db.commit()
    logger.info("Venue compliance check for venue %d: %d results (%d warnings)",
                venue_id, len(results), sum(1 for r in results if r.severity == "warning"))
    return results


def _policy_summary(policy: PortPolicy) -> str:
    """Build a human-readable summary of a port policy."""
    parts = []
    if policy.bpdu_guard:
        parts.append("bpdu-guard")
    if policy.portfast:
        parts.append("portfast")
    if policy.storm_control:
        parts.append(f"storm-control {policy.storm_control_level}%")
    return ", ".join(parts) if parts else "no requirements"
