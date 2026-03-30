# OUI Port Mapper

**Author:** Robare Pruyn  
**Copyright:** Mediacast Network Solutions, Inc. 2026

Multi-platform network automation tool that locates devices by OUI prefix across a campus switching fabric. Supports Cisco IOS/IOS-XE, Cisco NX-OS, and Aruba AOS-CX with automatic platform detection.

## Features

- **Automatic platform detection** via SSH fingerprinting (IOS, NX-OS, AOS-CX)
- **Recursive MAC tracing** through CDP/LLDP neighbors and port-channel members
- **Fan-out mode** for routed-access designs where endpoint VLANs are L3-terminated at edge switches
- **Concurrent threading** at all recursion depths for parallel SSH sessions
- **Hostname-based dedup** prevents revisiting the same switch via different VRF sub-interface IPs
- **Access-port-only safety filter** for all port operations
- **Port-cycle operation** (shut → wait → no-shut) with a single confirmation prompt
- **VLAN reassignment** (`--vlan-assign`) moves ports to their correct VLAN with platform-aware STP edge hardening
- **VLAN tracking** (`--track-vlans`) determines which monitored VLANs are active per switch
- **MAC threshold** (`--mac-threshold`) handles dual-NIC devices (e.g., VITEC encoders)
- **Management subnet filter** (`--mgmt-subnet`) prevents recursion into LLDP-advertising endpoints
- **Save config** (`--save-config`) persists changes to startup-config
- **Switch inventory** (`--switch-inventory`) crawls the fabric via CDP/LLDP and lists every reachable switch with hostname, management IP, platform, and upstream link — no OUI list required
- **Port status check** (`--port-status`) verifies current operational state (up/down/err-disabled) of all ports in a CSV
- **Interface descriptions** (`--set-description`) pushes port descriptions from discovery data with customizable templates
- **CSV diff** (`--diff`) compares two exports to show new, missing, and moved devices between runs
- **CSV export** with MAC deduplication (clean finds prioritized over uplink records)

## Requirements

```
pip install netmiko
```

## Quick Start

### Switch inventory (list all switches in the fabric)
```bash
python3 oui_port_mapper_v4.0.py --core 10.1.1.1 --user admin --switch-inventory --output switches.csv
```

### Discovery (normal mode)
```bash
python3 oui_port_mapper_v4.0.py --core 10.1.1.1 --user admin --oui 00:1A:2B --output discovery.csv
```

### Discovery (fan-out mode for routed-access)
```bash
python3 oui_port_mapper_v4.0.py --core 10.1.1.1 --user admin --oui-file target_ouis.txt --fan-out --workers 10 --output discovery.csv
```

### Discovery with VLAN tracking and endpoint filtering
```bash
python3 oui_port_mapper_v4.0.py --core 10.10.0.2 --user admin --oui 4C:A0:03 \
  --platform aruba_aoscx --mac-threshold 2 --mgmt-subnet 10.10.0.0/25 \
  --track-vlans 21,22,23,24,25 --output discovery.csv
```

### VLAN reassignment from CSV
```bash
# Dry run first
python3 oui_port_mapper_v4.0.py --from-csv discovery.csv --user admin --vlan-assign --dry-run

# Live with save to startup
python3 oui_port_mapper_v4.0.py --from-csv discovery.csv --user admin --vlan-assign --save-config
```

### Port-cycle from CSV
```bash
# Dry run first
python3 oui_port_mapper_v4.0.py --from-csv discovery.csv --user admin --port-cycle --cycle-delay 5 --dry-run

# Live
python3 oui_port_mapper_v4.0.py --from-csv discovery.csv --user admin --port-cycle --cycle-delay 5
```

### Port status check from CSV
```bash
python3 oui_port_mapper_v4.0.py --from-csv discovery.csv --user admin --port-status
```

### Push interface descriptions from CSV
```bash
# Dry run first
python3 oui_port_mapper_v4.0.py --from-csv discovery.csv --user admin --set-description --desc-template "{mac} {ip}" --dry-run

# Live with save
python3 oui_port_mapper_v4.0.py --from-csv discovery.csv --user admin --set-description --desc-template "{mac} {ip}" --save-config
```

### Compare two discovery runs
```bash
python3 oui_port_mapper_v4.0.py --diff old_discovery.csv new_discovery.csv
```

## OUI File Format

One OUI per line, `#` comments supported:
```
# Cisco DMP-4310
00:0F:44
00:22:BD
74:26:AC
# BrightSign
90:AC:3F
```

## Safety

Port actions (shutdown, no-shutdown, port-cycle, vlan-assign) only operate on **clean access-port finds**. Records are automatically excluded if they have:
- Notes (multi-MAC, uplink, not-resolved downstream)
- Port-channel, LAG, or vPC interface names
- Unknown or missing interface names

All changes are **running-config only** by default — a reload reverts them. Use `--save-config` to persist. A `YES` confirmation prompt (exact, case-sensitive) is required before any changes are applied.

## Version History

| Version | Changes |
|---------|---------|
| v4.0 | Concurrent recursion at all depths, `--save-config`, `--vlan-assign` with platform STP hardening, `--mac-threshold`, `--mgmt-subnet`, `--switch-inventory`, `--port-status`, `--set-description`, `--diff` |
| v3.0 | Fan-out mode, concurrent fan-out threading, hostname dedup, safety filter, port-cycle, VLAN tracking, CSV dedup |
| v2.0 | Multi-platform support (IOS, NX-OS, AOS-CX), port-channel traversal, NX-OS parser fixes, recursive discovery |
| v1.0 | Initial single-hop core-only discovery |
