"""Export and import venue configurations between NetCaster instances.

Usage:
    Export (on source machine):
        python venue_transfer.py export venues.json

    Import (on destination machine):
        python venue_transfer.py import venues.json

Credentials are decrypted for export and re-encrypted on import using
each instance's SECRET_KEY. Delete the JSON file after import -- it
contains plaintext SSH credentials.
"""

import json
import sys
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from webapp.config import settings
from webapp.database import SessionLocal, init_db
from webapp.crypto import decrypt_credential, encrypt_credential
from webapp.db_models import (
    OUIEntry,
    PortPolicy,
    Schedule,
    Venue,
    VenueVlan,
)


def export_venues(out_path: str):
    init_db()
    db = SessionLocal()
    venues = db.query(Venue).all()

    if not venues:
        print("No venues found in database.")
        return

    data = []
    for v in venues:
        # Decrypt credentials for portable export
        try:
            ssh_password = decrypt_credential(v.ssh_password_enc)
        except Exception:
            ssh_password = ""
            print(f"  WARNING: could not decrypt SSH password for {v.name}")

        enable_secret = ""
        if v.enable_secret_enc:
            try:
                enable_secret = decrypt_credential(v.enable_secret_enc)
            except Exception:
                print(f"  WARNING: could not decrypt enable secret for {v.name}")

        venue_data = {
            "name": v.name,
            "core_ip": v.core_ip,
            "platform": v.platform,
            "ssh_username": v.ssh_username,
            "ssh_password": ssh_password,
            "enable_secret": enable_secret,
            "mgmt_subnet": v.mgmt_subnet,
            "fan_out": v.fan_out,
            "workers": v.workers,
            "mac_threshold": v.mac_threshold,
            "default_dhcp_servers": json.loads(v.default_dhcp_servers) if v.default_dhcp_servers else [],
            "default_dns_servers": json.loads(v.default_dns_servers) if v.default_dns_servers else [],
            "default_gateway_mac": v.default_gateway_mac or "",
            "oui_entries": [],
            "port_policies": [],
            "vlans": [],
            "schedules": [],
        }

        for o in v.oui_entries:
            venue_data["oui_entries"].append({
                "oui_prefix": o.oui_prefix,
                "description": o.description or "",
                "manufacturer": o.manufacturer or "",
                "candidate_vlans": json.loads(o.candidate_vlans) if o.candidate_vlans else [],
                "expected_ips": json.loads(o.expected_ips) if o.expected_ips else [],
            })

        for p in v.port_policies:
            venue_data["port_policies"].append({
                "vlan": p.vlan,
                "bpdu_guard": p.bpdu_guard,
                "portfast": p.portfast,
                "storm_control": p.storm_control,
                "storm_control_level": p.storm_control_level or "1.00",
                "description_template": p.description_template or "",
                "notes": p.notes or "",
            })

        for vl in v.vlans:
            venue_data["vlans"].append({
                "vlan_id": vl.vlan_id,
                "name": vl.name or "",
                "ip_address": vl.ip_address or "",
                "gateway_ip": vl.gateway_ip or "",
                "gateway_mac": vl.gateway_mac or "",
                "dhcp_servers": json.loads(vl.dhcp_servers) if vl.dhcp_servers else [],
                "dns_servers": json.loads(vl.dns_servers) if vl.dns_servers else [],
                "dark_vlan": vl.dark_vlan,
                "igmp_enable": vl.igmp_enable,
                "pim_sparse_enable": vl.pim_sparse_enable,
                "source": vl.source,
            })

        for s in v.schedules:
            venue_data["schedules"].append({
                "job_type": s.job_type,
                "enabled": s.enabled,
                "time_of_day": s.time_of_day,
            })

        data.append(venue_data)

    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Exported {len(data)} venue(s) to {out_path}")
    print("WARNING: this file contains plaintext credentials. Delete it after import.")


def import_venues(in_path: str):
    init_db()
    db = SessionLocal()

    with open(in_path) as f:
        data = json.load(f)

    created = 0
    skipped = 0

    for v in data:
        existing = db.query(Venue).filter(Venue.name == v["name"]).first()
        if existing:
            print(f"  SKIP: {v['name']} (already exists)")
            skipped += 1
            continue

        venue = Venue(
            name=v["name"],
            core_ip=v["core_ip"],
            platform=v.get("platform", "auto"),
            ssh_username=v["ssh_username"],
            ssh_password_enc=encrypt_credential(v["ssh_password"]),
            enable_secret_enc=encrypt_credential(v["enable_secret"]) if v.get("enable_secret") else None,
            mgmt_subnet=v.get("mgmt_subnet"),
            fan_out=v.get("fan_out", False),
            workers=v.get("workers", 10),
            mac_threshold=v.get("mac_threshold", 1),
            default_dhcp_servers=json.dumps(v["default_dhcp_servers"]) if v.get("default_dhcp_servers") else None,
            default_dns_servers=json.dumps(v["default_dns_servers"]) if v.get("default_dns_servers") else None,
            default_gateway_mac=v.get("default_gateway_mac") or None,
        )
        db.add(venue)
        db.flush()  # get venue.id

        for o in v.get("oui_entries", []):
            db.add(OUIEntry(
                venue_id=venue.id,
                oui_prefix=o["oui_prefix"],
                description=o.get("description") or None,
                manufacturer=o.get("manufacturer") or None,
                candidate_vlans=json.dumps(o["candidate_vlans"]) if o.get("candidate_vlans") else None,
                expected_ips=json.dumps(o["expected_ips"]) if o.get("expected_ips") else None,
            ))

        for p in v.get("port_policies", []):
            db.add(PortPolicy(
                venue_id=venue.id,
                vlan=p["vlan"],
                bpdu_guard=p.get("bpdu_guard", True),
                portfast=p.get("portfast", True),
                storm_control=p.get("storm_control", False),
                storm_control_level=p.get("storm_control_level", "1.00"),
                description_template=p.get("description_template") or None,
                notes=p.get("notes") or None,
            ))

        for vl in v.get("vlans", []):
            db.add(VenueVlan(
                venue_id=venue.id,
                vlan_id=vl["vlan_id"],
                name=vl.get("name") or None,
                ip_address=vl.get("ip_address") or None,
                gateway_ip=vl.get("gateway_ip") or None,
                gateway_mac=vl.get("gateway_mac") or None,
                dhcp_servers=json.dumps(vl["dhcp_servers"]) if vl.get("dhcp_servers") else None,
                dns_servers=json.dumps(vl["dns_servers"]) if vl.get("dns_servers") else None,
                dark_vlan=vl.get("dark_vlan", False),
                igmp_enable=vl.get("igmp_enable", False),
                pim_sparse_enable=vl.get("pim_sparse_enable", False),
                source=vl.get("source", "manual"),
            ))

        for s in v.get("schedules", []):
            db.add(Schedule(
                venue_id=venue.id,
                job_type=s["job_type"],
                enabled=s.get("enabled", True),
                time_of_day=s["time_of_day"],
            ))

        created += 1
        print(f"  OK: {v['name']} ({len(v.get('oui_entries', []))} OUIs, {len(v.get('vlans', []))} VLANs, {len(v.get('port_policies', []))} policies)")

    db.commit()
    db.close()
    print(f"\nImported {created} venue(s), skipped {skipped}.")


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in ("export", "import"):
        print("Usage:")
        print("  python venue_transfer.py export venues.json")
        print("  python venue_transfer.py import venues.json")
        sys.exit(1)

    action = sys.argv[1]
    filepath = sys.argv[2]

    if action == "export":
        export_venues(filepath)
    else:
        if not Path(filepath).exists():
            print(f"File not found: {filepath}")
            sys.exit(1)
        import_venues(filepath)
