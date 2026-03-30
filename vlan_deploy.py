#!/usr/bin/env python3
"""
MFP VLAN Deployment — Shift4 (VLAN 615) & VisioLab/DraftServ (VLAN 617)

Creates VLANs 615 and 617 on the core and edge switches, then assigns
access ports per the VLAN_Port_Configs spreadsheet. Aruba AOS-CX only.

Author: Robare Pruyn
Copyright: Mediacast Network Solutions, Inc. 2026

Usage:
  # Dry run (shows plan, no changes)
  python3 vlan_deploy.py --user admin --dry-run

  # Live deploy
  python3 vlan_deploy.py --user admin

  # Live deploy with write-memory
  python3 vlan_deploy.py --user admin --save-config
"""

import argparse
import getpass
import sys
import time
from collections import defaultdict

try:
    from netmiko import ConnectHandler
except ImportError:
    print("ERROR: netmiko is required.  Install with:  pip install netmiko")
    sys.exit(1)


# -----------------------------------------------------------------------
# VLAN definitions — L2 only, no SVI
# -----------------------------------------------------------------------

VLANS_TO_CREATE = {
    "615": "Shift4",
    "617": "VisioLab-DrftSrv",
}


# -----------------------------------------------------------------------
# Switch inventory — management IPs
# -----------------------------------------------------------------------

CORE_SWITCH = {
    "hostname": "mfp-core-01",
    "ip": "10.10.0.2",
}

EDGE_SWITCHES = {
    "CL152-46":  "10.10.0.46",
    "CL178-47":  "10.10.0.47",
    "EL207-38":  "10.10.0.38",
    "EL239-39":  "10.10.0.39",
    "MC109-41":  "10.10.0.41",
    "MC137-42":  "10.10.0.42",
    "MC162-43":  "10.10.0.43",
    "MC178-44":  "10.10.0.44",
    "MC204-45":  "10.10.0.45",
}


# -----------------------------------------------------------------------
# Port → VLAN assignments from VLAN_Port_Configs.xlsx
# -----------------------------------------------------------------------

PORT_ASSIGNMENTS = [
    # (switch_hostname, interface, vlan_id)

    # --- VLAN 615 — Shift4 ---
    ("CL178-47", "1/1/15", "615"),
    ("CL178-47", "1/1/13", "615"),
    ("CL178-47", "1/1/9",  "615"),
    ("CL178-47", "1/1/11", "615"),

    ("CL152-46", "1/1/10", "615"),
    ("CL152-46", "1/1/8",  "615"),
    ("CL152-46", "1/1/4",  "615"),

    ("EL239-39", "4/1/29", "615"),
    ("EL239-39", "4/1/19", "615"),
    ("EL239-39", "4/1/23", "615"),
    ("EL239-39", "4/1/25", "615"),
    ("EL239-39", "4/1/17", "615"),
    ("EL239-39", "4/1/27", "615"),
    ("EL239-39", "4/1/21", "615"),
    ("EL239-39", "4/1/15", "615"),
    ("EL239-39", "4/1/31", "615"),
    ("EL239-39", "4/1/39", "615"),
    ("EL239-39", "4/1/43", "615"),
    ("EL239-39", "4/1/35", "615"),
    ("EL239-39", "4/1/45", "615"),
    ("EL239-39", "4/1/41", "615"),
    ("EL239-39", "4/1/33", "615"),

    ("EL207-38", "7/1/24", "615"),
    ("EL207-38", "7/1/30", "615"),
    ("EL207-38", "7/1/32", "615"),
    ("EL207-38", "7/1/34", "615"),
    ("EL207-38", "7/1/40", "615"),
    ("EL207-38", "7/1/42", "615"),
    ("EL207-38", "7/1/45", "615"),
    ("EL207-38", "8/1/1",  "615"),
    ("EL207-38", "8/1/5",  "615"),
    ("EL207-38", "8/1/11", "615"),
    ("EL207-38", "8/1/13", "615"),
    ("EL207-38", "8/1/19", "615"),

    ("MC109-41", "2/1/11", "615"),
    ("MC109-41", "2/1/13", "615"),
    ("MC109-41", "2/1/17", "615"),
    ("MC109-41", "2/1/19", "615"),
    ("MC109-41", "1/1/19", "615"),

    ("MC137-42", "1/1/30", "615"),
    ("MC137-42", "1/1/28", "615"),
    ("MC137-42", "1/1/32", "615"),
    ("MC137-42", "1/1/26", "615"),

    ("MC162-43", "2/1/5",  "615"),
    ("MC162-43", "2/1/9",  "615"),
    ("MC162-43", "2/1/7",  "615"),
    ("MC162-43", "2/1/11", "615"),
    ("MC162-43", "1/1/3",  "615"),
    ("MC162-43", "2/1/10", "615"),
    ("MC162-43", "2/1/12", "615"),
    ("MC162-43", "2/1/6",  "615"),

    ("MC178-44", "1/1/1",  "615"),
    ("MC178-44", "1/1/3",  "615"),
    ("MC178-44", "1/1/5",  "615"),
    ("MC178-44", "1/1/7",  "615"),
    ("MC178-44", "1/1/34", "615"),
    ("MC178-44", "1/1/36", "615"),
    ("MC178-44", "1/1/38", "615"),
    ("MC178-44", "1/1/40", "615"),

    ("MC204-45", "1/1/6",  "615"),
    ("MC204-45", "1/1/8",  "615"),

    # --- VLAN 617 — VisioLab/DraftServ ---
    ("MC178-44", "3/1/22", "617"),
    ("MC178-44", "3/1/24", "617"),
    ("MC178-44", "3/1/18", "617"),
    ("MC178-44", "3/1/20", "617"),

    ("MC204-45", "3/1/25", "617"),
    ("MC204-45", "3/1/27", "617"),

    ("MC162-43", "2/1/40", "617"),

    ("MC137-42", "1/1/5",  "617"),

    ("MC109-41", "2/1/22", "617"),
    ("MC109-41", "2/1/24", "617"),
]


# -----------------------------------------------------------------------
# Aruba AOS-CX config command builders
# -----------------------------------------------------------------------

def build_vlan_create_commands() -> list[str]:
    """Build AOS-CX commands to create VLANs (L2 only, no SVI) with RPVST+."""
    commands = []
    for vlan_id, vlan_name in VLANS_TO_CREATE.items():
        commands.append(f"vlan {vlan_id}")
        commands.append(f"name {vlan_name}")
    # Enable RPVST+ spanning-tree instances for the new VLANs
    vlan_list = ",".join(VLANS_TO_CREATE.keys())
    commands.append(f"spanning-tree vlan {vlan_list}")
    return commands


def build_port_commands(interface: str, vlan_id: str) -> list[str]:
    """Build AOS-CX commands to configure an access port with STP hardening."""
    return [
        f"interface {interface}",
        "no routing",
        f"vlan access {vlan_id}",
        "spanning-tree bpdu-guard",
        "spanning-tree port-type admin-edge",
    ]


# -----------------------------------------------------------------------
# SSH connection helper
# -----------------------------------------------------------------------

def connect_switch(ip: str, username: str, password: str):
    """Open an SSH connection to an Aruba AOS-CX switch."""
    device = {
        "device_type": "aruba_aoscx",
        "host": ip,
        "username": username,
        "password": password,
    }
    return ConnectHandler(**device)


# -----------------------------------------------------------------------
# Main deployment logic
# -----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="MFP VLAN Deployment — Shift4 (615) & VisioLab (617)"
    )
    parser.add_argument("--user", help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show planned changes without executing"
    )
    parser.add_argument(
        "--save-config", action="store_true",
        help="Save running-config to startup-config after changes"
    )
    args = parser.parse_args()

    username = args.user or input("SSH Username: ")
    password = args.password or getpass.getpass("SSH Password: ")

    # --- Group port assignments by switch ---
    ports_by_switch: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for switch_hostname, interface, vlan_id in PORT_ASSIGNMENTS:
        ports_by_switch[switch_hostname].append((interface, vlan_id))

    # --- Display the plan ---
    print(f"\n{'='*80}")
    print(f"  MFP VLAN DEPLOYMENT PLAN")
    print(f"{'='*80}")
    print()
    print(f"  VLANs to create:")
    for vlan_id, vlan_name in VLANS_TO_CREATE.items():
        print(f"    VLAN {vlan_id} — {vlan_name} (L2 only, no SVI)")
    vlan_list = ",".join(VLANS_TO_CREATE.keys())
    print(f"    spanning-tree vlan {vlan_list} (RPVST+)")
    print()

    # All switches that need VLAN creation (core + all edge switches with ports)
    vlan_create_targets = [
        (CORE_SWITCH["hostname"], CORE_SWITCH["ip"])
    ] + [
        (hostname, EDGE_SWITCHES[hostname])
        for hostname in sorted(ports_by_switch.keys())
    ]

    print(f"  VLAN creation on {len(vlan_create_targets)} switches:")
    for hostname, ip in vlan_create_targets:
        print(f"    {hostname:20s} ({ip})")
    print()

    print(f"  Port assignments: {len(PORT_ASSIGNMENTS)} total")
    for switch_hostname in sorted(ports_by_switch.keys()):
        port_list = ports_by_switch[switch_hostname]
        ip = EDGE_SWITCHES[switch_hostname]
        vlan_615_count = sum(1 for _, v in port_list if v == "615")
        vlan_617_count = sum(1 for _, v in port_list if v == "617")
        parts = []
        if vlan_615_count:
            parts.append(f"{vlan_615_count}×VLAN 615")
        if vlan_617_count:
            parts.append(f"{vlan_617_count}×VLAN 617")
        print(
            f"    {switch_hostname:20s} ({ip})  "
            f"{len(port_list):2d} ports  ({', '.join(parts)})"
        )
    print()

    print(f"  Per-port commands (Aruba AOS-CX):")
    print(f"    interface X/X/X")
    print(f"    no routing")
    print(f"    vlan access <615|617>")
    print(f"    spanning-tree bpdu-guard")
    print(f"    spanning-tree port-type admin-edge")
    print()
    print(f"  Save config: {'YES' if args.save_config else 'NO (running-config only)'}")
    print(f"{'='*80}\n")

    if args.dry_run:
        print("[DRY RUN] No changes will be made.")
        return

    confirm = input(
        f"Type 'YES' to deploy VLANs and configure "
        f"{len(PORT_ASSIGNMENTS)} ports: "
    )
    if confirm != "YES":
        print("Aborted. No changes made.")
        return

    # --- Phase 1: Create VLANs on all target switches ---
    vlan_commands = build_vlan_create_commands()

    print(f"\n--- Phase 1: Creating VLANs ---\n")
    for hostname, ip in vlan_create_targets:
        print(f"  {hostname} ({ip})...", end=" ", flush=True)
        try:
            conn = connect_switch(ip, username, password)
            output = conn.send_config_set(vlan_commands)
            if args.save_config:
                conn.send_command_timing(
                    "write memory",
                    strip_command=False,
                    strip_prompt=False,
                )
            conn.disconnect()
            print("OK")
        except Exception as exc:
            print(f"FAILED: {exc}")

    # --- Phase 2: Configure ports on edge switches ---
    print(f"\n--- Phase 2: Configuring {len(PORT_ASSIGNMENTS)} ports ---\n")

    for switch_hostname in sorted(ports_by_switch.keys()):
        port_list = ports_by_switch[switch_hostname]
        ip = EDGE_SWITCHES[switch_hostname]

        print(f"  {switch_hostname} ({ip}) — {len(port_list)} ports...")
        try:
            conn = connect_switch(ip, username, password)

            # Build all port config commands for this switch
            config_commands = []
            for interface, vlan_id in port_list:
                config_commands.extend(
                    build_port_commands(interface, vlan_id)
                )
                vlan_name = VLANS_TO_CREATE[vlan_id]
                print(
                    f"    {interface:10s} → VLAN {vlan_id} ({vlan_name})"
                )

            output = conn.send_config_set(config_commands)

            if args.save_config:
                print(f"    Saving config...", end=" ", flush=True)
                conn.send_command_timing(
                    "write memory",
                    strip_command=False,
                    strip_prompt=False,
                )
                print("OK")

            conn.disconnect()
            print(f"    Done.")

        except Exception as exc:
            print(f"    FAILED: {exc}")

    print(f"\n{'='*80}")
    print(f"  Deployment complete.")
    print(f"  VLANs created: {', '.join(VLANS_TO_CREATE.keys())}")
    print(f"  Ports configured: {len(PORT_ASSIGNMENTS)}")
    if not args.save_config:
        print(f"  WARNING: Changes are running-config only.")
        print(f"  Run with --save-config to persist, or manually 'write memory'.")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    main()
