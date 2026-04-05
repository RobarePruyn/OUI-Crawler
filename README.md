# NetCaster

**Author:** Robare Pruyn  
**Copyright:** Mediacast Network Solutions, Inc. 2026

Venue-centric network management platform for AV and enterprise campus networks. Automates device discovery, OUI-based identification, compliance enforcement, and port configuration across Cisco IOS/IOS-XE, Cisco NX-OS, and Aruba AOS-CX switching fabrics.

## Features

### Web Application
- **Venue management** — organize switches, VLANs, port policies, and compliance rules per venue
- **Network scanning** — full discovery (OUI + neighbors + inventory), discovery-only, or inventory-only modes
- **Compliance dashboard** — VLAN mismatches, port config drift, wrong-subnet detection with one-click remediation
- **Device lookup** — partial MAC/IP search with bulk port actions (shutdown, cycle, PoE cycle, VLAN assign)
- **Port policy enforcement** — push portfast, BPDU guard, storm control, and descriptions in one batch
- **SVI-aware ARP resolution** — resolves IPs using VLAN-to-subnet mapping for multi-VLAN environments
- **VSX/StackWise support** — propagates resolved IPs across duplicate-MAC entries on redundant switch pairs
- **Scheduled scans** — cron-based discovery and inventory with job history
- **Role-based access** — super admin (all venues) and site admin (assigned venues only)

### Engine
- **Automatic platform detection** via SSH fingerprinting (IOS, NX-OS, AOS-CX)
- **Recursive MAC tracing** through CDP/LLDP neighbors and port-channel members
- **Fan-out mode** for routed-access designs where endpoint VLANs are L3-terminated at edge switches
- **Concurrent threading** at all recursion depths for parallel SSH sessions
- **Hostname-based dedup** prevents revisiting the same switch via different VRF sub-interface IPs

## Requirements

```
pip install -r requirements.txt
```

## Quick Start

```bash
# Start the web application
python run.py
```

Then open `http://localhost:8000`, create an admin account, and add your first venue.

## Deployment

### Windows Service
```powershell
# From an elevated PowerShell prompt
.\deploy-windows.ps1
```

## Legacy CLI

The original standalone CLI script (`oui_port_mapper_v4.1.py`) is preserved in this repo but is no longer under active development. New features and bug fixes target the web application only. The CLI will be archived to a separate repository.

## Safety

Port actions (shutdown, no-shutdown, port-cycle, VLAN-assign, PoE cycle) only operate on **clean access-port finds**. LAGs, port-channels, and infrastructure interfaces are automatically excluded. All bulk operations require confirmation and report per-device results with error details.
