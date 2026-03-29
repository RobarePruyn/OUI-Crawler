# OUI Port Mapper

**Author:** Robare Pruyn  
**Copyright:** Mediacast Network Solutions, Inc. 2026

Multi-platform network automation tool that locates devices by OUI prefix across a campus switching fabric. Supports Cisco IOS/IOS-XE, Cisco NX-OS, and Aruba AOS-CX with automatic platform detection.

## Features

- **Automatic platform detection** via SSH fingerprinting (IOS, NX-OS, AOS-CX)
- **Recursive MAC tracing** through CDP/LLDP neighbors and port-channel members
- **Fan-out mode** for routed-access designs where endpoint VLANs are L3-terminated at edge switches
- **Concurrent threading** for parallel SSH sessions during fan-out discovery
- **Hostname-based dedup** prevents revisiting the same switch via different VRF sub-interface IPs
- **Access-port-only safety filter** for shut/no-shut/port-cycle operations
- **Port-cycle operation** (shut → wait → no-shut) with a single confirmation prompt
- **CSV export** with MAC deduplication

## Requirements

```
pip install netmiko
```

## Quick Start

### Discovery (normal mode)
```bash
python3 oui_port_mapper_v3.0.py --core 10.1.1.1 --user admin --oui 00:1A:2B --output discovery.csv
```

### Discovery (fan-out mode for routed-access)
```bash
python3 oui_port_mapper_v3.0.py --core 10.1.1.1 --user admin --oui-file target_ouis.txt --fan-out --workers 10 --output discovery.csv
```

### Port-cycle from CSV
```bash
# Dry run first
python3 oui_port_mapper_v3.0.py --from-csv discovery.csv --user admin --port-cycle --cycle-delay 5 --dry-run

# Live
python3 oui_port_mapper_v3.0.py --from-csv discovery.csv --user admin --port-cycle --cycle-delay 5
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

Port actions (shutdown, no-shutdown, port-cycle) only operate on **clean access-port finds**. Records are automatically excluded if they have:
- Notes (multi-MAC, uplink, not-resolved downstream)
- Port-channel, LAG, or vPC interface names
- Unknown or missing interface names

All changes are **running-config only** — a reload reverts them. A `YES` confirmation prompt (exact, case-sensitive) is required before any changes are applied.

## Version History

| Version | Changes |
|---------|---------|
| v3.0 | Fan-out mode (depth-0 only), concurrent threading, hostname dedup, access-port-only safety filter, port-cycle operation, MAC dedup in CSV export |
| v2.0 | Multi-platform support (IOS, NX-OS, AOS-CX), port-channel traversal, NX-OS `~~~` age field fix, recursive discovery |
| v1.0 | Initial single-hop core-only discovery |
