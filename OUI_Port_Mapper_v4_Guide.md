# OUI Port Mapper v4.0 — Setup & Usage Guide

**Author:** Robare Pruyn
**Copyright:** Mediacast Network Solutions, Inc. 2026

## Part 1: Installing Python

### macOS

macOS ships with a system Python but you should never use it for tool installs. Use a standalone Python from python.org.

**Step 1 — Download the installer**

Go to [https://www.python.org/downloads/](https://www.python.org/downloads/) and click the yellow "Download Python 3.x.x" button. This downloads a `.pkg` file.

**Step 2 — Run the installer**

Double-click the `.pkg` file. Click through the prompts. On the "Install" screen, click Install and authenticate with your Mac password. The defaults are fine — it installs to `/Library/Frameworks/Python.framework/` and adds itself to your PATH.

**Step 3 — Verify**

Open Terminal (Cmd+Space, type "Terminal", Enter) and run:

```
python3 --version
```

You should see something like `Python 3.12.x` or `Python 3.13.x`. If you get "command not found," close and reopen Terminal — the PATH update requires a new shell session.

> **Note:** On macOS, the command is `python3` and `pip3`, not `python` and `pip`. This is because the system still ships a legacy Python 2 stub on some versions.

**Step 4 — Upgrade pip**

```
python3 -m pip install --upgrade pip
```

---

### Windows

**Step 1 — Download the installer**

Go to [https://www.python.org/downloads/](https://www.python.org/downloads/) and click the yellow "Download Python 3.x.x" button. This downloads a `.exe` installer.

**Step 2 — Run the installer**

Double-click the `.exe` file. **CRITICAL: On the very first screen of the installer, check the box that says "Add python.exe to PATH."** This is not checked by default and without it, `python` and `pip` won't work from the command line. Then click "Install Now."

**Step 3 — Verify**

Open a **new** Command Prompt or PowerShell window (Win+R, type `cmd`, Enter) and run:

```
python --version
```

You should see `Python 3.12.x` or `Python 3.13.x`. If you get "'python' is not recognized," the PATH checkbox was missed. Uninstall and reinstall with it checked, or manually add `C:\Users\<you>\AppData\Local\Programs\Python\Python3xx\` and its `Scripts\` subdirectory to your system PATH.

**Step 4 — Upgrade pip**

```
python -m pip install --upgrade pip
```

---

## Part 2: Installing netmiko

netmiko is the only external dependency. It handles SSH transport to Cisco, Aruba, and other vendor network devices.

### macOS

```
pip3 install netmiko
```

If you get a permissions error, use the `--user` flag:

```
pip3 install --user netmiko
```

### Windows

```
pip install netmiko
```

### Verify the install

```
python3 -c "import netmiko; print(netmiko.__version__)"
```

(On Windows, use `python` instead of `python3`.)

You should see a version string like `4.x.x`. If you get an ImportError, pip installed to a different Python than the one you're running. Run `which python3` (Mac) or `where python` (Windows) and `pip3 show netmiko` (Mac) or `pip show netmiko` (Windows) to confirm they match.

---

## Part 3: How the Tool Works

### Platform Support

The tool supports three switching platforms:

**Cisco IOS / IOS-XE** — Catalyst 9000, 3850, 3650, 2960, and similar. Uses CDP as the primary neighbor discovery protocol, with LLDP as a secondary source. MAC addresses in Cisco dotted notation (xxxx.xxxx.xxxx). Interface names like GigabitEthernet1/0/1.

**Cisco NX-OS** — Nexus 9000, 7000, 5000 series. Uses CDP by default (LLDP also supported). Same Cisco dotted MAC notation. Interface names like Ethernet1/1 and port-channel1. The MAC address table has extra columns compared to IOS (age, Secure, NTFY flags) which the tool's NX-OS parser handles. NX-OS 7.3 uses `~~~` in the age column instead of numeric values — the parser handles this.

**Aruba AOS-CX** — CX 6300, 6400, 8320, 8325, 8400, 10000. Uses LLDP natively (CDP is off by default on Aruba). MAC addresses in colon-separated notation (00:1a:2b:3c:4d:5e), which the tool normalizes to Cisco format internally. Interface names like 1/1/1.

**Ubiquiti UniFi** is not supported. UniFi switches are controller-managed and don't expose a usable CLI over SSH.

### Platform Auto-Detection

By default (`--platform auto`), the tool auto-detects each switch it connects to. This means you can traverse a mixed Cisco/Aruba fabric without specifying anything. The detection works in two stages:

1. **netmiko SSHDetect** — fingerprints the device based on SSH banner and prompt behavior.
2. **`show version` fingerprinting** — if SSHDetect is inconclusive, the tool connects, runs `show version`, and pattern-matches the output against known platform signatures.

Auto-detection adds a few seconds per switch on the first connection. If your entire fabric is one platform, `--platform cisco_ios`, `--platform cisco_nxos`, or `--platform aruba_oscx` skips detection and is faster.

### Discovery Modes

#### Normal Mode (default)

Follow OUI-matching MACs through the switching fabric via CDP/LLDP neighbors. This works when target device VLANs are trunked L2 from the edge switches back to the starting switch. The starting switch can "see" the target MACs in its own MAC address table and the tool traces them downstream to the access port.

#### Fan-Out Mode (`--fan-out`)

Visit ALL CDP/LLDP neighbors from the starting switch, regardless of whether any matching MACs are visible at the starting switch. This is required for **routed-access designs** where endpoint VLANs have SVIs on the edge switches and are NOT trunked L2 back to the core. In these designs, the core switch never sees the target MACs — they only exist in the edge switch's local MAC and ARP tables.

Fan-out only occurs at depth 0 (the starting switch). Edge switches discovered via fan-out use normal MAC-tracing recursion from that point forward. This prevents runaway recursion through datacenter infrastructure (distribution switches, IDS sensors, storage fabric switches, etc.) that have zero endpoints.

Fan-out mode uses concurrent threading (`--workers`, default 10) to SSH to multiple edge switches in parallel.

### Discovery Workflow

**Step 1 — Connect to the starting switch.** Auto-detect or use the forced platform.

**Step 2 — Pull ARP table.** Builds a MAC→IP lookup. This is merged globally across all switches visited, so ARP data from deeper in the fabric is available for earlier hops. In routed-access designs, the edge switch's ARP table contains the SVI-learned IP addresses for locally-switched VLANs.

**Step 3 — Pull MAC address table.** Every entry is tested against your OUI prefix list. Only prefix matches proceed.

**Step 4 — Pull CDP/LLDP neighbors.** On Cisco, both CDP and LLDP are queried. On Aruba, LLDP only. Neighbors are deduplicated.

**Step 5 — Classify each matching MAC.** Three outcomes:

- **Access port** — Single MAC on the port, no CDP/LLDP neighbor. This is an endpoint. Record it.
- **Known uplink** — CDP/LLDP neighbor on the port. The MAC is behind another switch. Queue for recursion.
- **Unknown uplink** — Multiple MACs on the port but no CDP/LLDP neighbor. Record here with a note.

**Step 6 — Recurse or Fan-Out.** In normal mode, recurse into downstream switches where matching MACs were found on uplinks. In fan-out mode (depth 0 only), visit ALL neighbors concurrently, then switch to normal recursion from depth 1+. In both modes, all downstream switches at a given hop are queried in parallel using `--workers` threads.

**Step 7 — Export.** All results written to CSV with MAC deduplication.

### Hostname-Based Dedup

In large fabrics, the same switch can appear via multiple management IPs (VRF sub-interfaces, loopback addresses, etc.). The tool tracks visited hostnames (case-insensitive) in addition to IPs. After connecting and reading the switch prompt, if the hostname has been seen before, the connection is dropped immediately. This prevents wasting time re-querying the same switch through a different IP.

### Concurrent Threading

Both fan-out mode and normal recursion dispatch downstream switches using a `ThreadPoolExecutor`. The `--workers` flag (default: 10) controls how many SSH sessions run in parallel. All switches at the same hop depth are queried concurrently, regardless of discovery mode.

### MAC Threshold (`--mac-threshold`)

By default, any port with more than 1 MAC is treated as a trunk/uplink. Some endpoint devices (e.g., VITEC EP6 encoders) present 2 MACs on their access port — the data NIC plus an LLDP-advertised management MAC. Use `--mac-threshold 2` to treat ports with ≤2 MACs as access ports.

### Management Subnet Filter (`--mgmt-subnet`)

Some endpoints advertise LLDP (e.g., VITEC encoders). Without filtering, the tool tries to SSH into them, wastes time on auth failures, and misclassifies their ports as uplinks. Use `--mgmt-subnet 10.10.0.0/25` to restrict recursion to neighbors whose management IP falls within the switch management subnet. Neighbors outside this subnet are treated as endpoints for classification purposes — their ports fall through to the MAC count heuristic.

### The Multi-MAC Heuristic

Instead of relying solely on CDP/LLDP to identify uplinks, the tool counts how many total MACs are learned on each port:

- **1 MAC on the port** → access port. An endpoint device directly connected.
- **>1 MAC on the port** → trunk/uplink. Multiple devices behind this port.

When a multi-MAC port also has a CDP/LLDP neighbor, the tool recurses to that neighbor. When it doesn't, it records the MAC at the current switch with a note.

---

## Part 4: Command Reference

### Basic discovery — auto-detect platform

```
python3 oui_port_mapper_v4.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:1A:2B
```

### Fan-out discovery (routed-access venues)

```
python3 oui_port_mapper_v4.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui-file target_ouis.txt \
  --fan-out \
  --workers 10 \
  --output discovery.csv
```

### Force a specific platform

```
python3 oui_port_mapper_v4.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:1A:2B \
  --platform aruba_oscx
```

### Multiple OUIs / OUIs from file

```
python3 oui_port_mapper_v4.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:60:35 \
  --oui 00:10:7F \
  --oui 00:0E:DD
```

```
python3 oui_port_mapper_v4.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui-file av_vendor_ouis.txt
```

### Custom output filename

```
python3 oui_port_mapper_v4.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:60:35 \
  --output qsc_inventory_2026-03-27.csv
```

### Limit recursion depth

```
# Only check the starting switch, no recursion
python3 oui_port_mapper_v4.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:60:35 \
  --max-depth 0
```

### Control concurrency

```
# 20 concurrent SSH sessions (faster, more management plane load)
python3 oui_port_mapper_v4.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui-file target_ouis.txt \
  --fan-out \
  --workers 20
```

### Verbose / debug output

```
python3 oui_port_mapper_v4.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:60:35 \
  --verbose
```

---

## Part 5: Port Actions (Shutdown / No Shutdown / Port Cycle)

### Safety Filter

All port actions apply a strict **access-port-only safety filter**. A record is only acted on if ALL of these are true:

- Interface is a real port name (not "unknown" or "not found")
- Interface is not a port-channel, LAG, vPC, or other aggregate interface
- Notes field is empty (clean find — single MAC, access port)

Records with notes are **automatically excluded**. The tool reports how many were filtered.

### Dry-run first (always)

```
python3 oui_port_mapper_v4.0.py \
  --from-csv discovery.csv \
  --user admin \
  --shutdown \
  --dry-run
```

### Live shutdown

```
python3 oui_port_mapper_v4.0.py \
  --from-csv discovery.csv \
  --user admin \
  --shutdown
```

### Re-enable ports

```
python3 oui_port_mapper_v4.0.py \
  --from-csv discovery.csv \
  --user admin \
  --no-shutdown
```

### Port cycle (shut → wait → no-shut)

```
# Dry run
python3 oui_port_mapper_v4.0.py \
  --from-csv discovery.csv \
  --user admin \
  --port-cycle \
  --cycle-delay 5 \
  --dry-run

# Live
python3 oui_port_mapper_v4.0.py \
  --from-csv discovery.csv \
  --user admin \
  --port-cycle \
  --cycle-delay 5
```

Single confirmation prompt. Shuts down all matched access ports, waits `--cycle-delay` seconds (default 5), then re-enables them.

### Two-step workflow (recommended for production)

**Step 1 — Discover and export:**

```
python3 oui_port_mapper_v4.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui-file target_ouis.txt \
  --fan-out \
  --output discovery.csv
```

**Step 2 — Review the CSV.** The `notes` column shows which records the safety filter will exclude. Records with empty notes are the ones that will be acted on.

**Step 3 — Act on the CSV:**

```
python3 oui_port_mapper_v4.0.py \
  --from-csv discovery.csv \
  --user admin \
  --port-cycle \
  --cycle-delay 5
```

### VLAN Reassignment (`--vlan-assign`)

Moves access ports to their correct VLAN based on `--track-vlans` data from the discovery run. Only changes ports where the current VLAN differs from the tracked VLAN for that switch.

```
# Dry run
python3 oui_port_mapper_v4.0.py \
  --from-csv discovery.csv \
  --user admin \
  --vlan-assign \
  --dry-run

# Live
python3 oui_port_mapper_v4.0.py \
  --from-csv discovery.csv \
  --user admin \
  --vlan-assign
```

The tool skips records where:
- The device is already on the correct VLAN
- The tracked VLAN is ambiguous (e.g., core switch with multiple VLANs active)
- The tracked VLAN field is empty

Platform-aware commands are pushed per port:

| Platform | Commands |
|---|---|
| Cisco IOS/IOS-XE | `switchport access vlan N`, `spanning-tree portfast`, `spanning-tree bpduguard enable` |
| Cisco NX-OS | `switchport access vlan N`, `spanning-tree port type edge`, `spanning-tree bpduguard enable` |
| Aruba AOS-CX | `no routing`, `vlan access N`, `spanning-tree bpdu-guard`, `spanning-tree port-type admin-edge` |

### Saving Configuration (`--save-config`)

By default, all changes are **running-config only** — a switch reload reverts them. Add `--save-config` to persist changes to startup-config after each switch is configured.

```
python3 oui_port_mapper_v4.0.py \
  --from-csv discovery.csv \
  --user admin \
  --vlan-assign \
  --save-config
```

The tool runs `write memory` on each switch after applying changes. This works with `--shutdown`, `--no-shutdown`, `--port-cycle`, and `--vlan-assign`.

---

## Part 6: CSV Output Format

| Column | Description |
|---|---|
| `switch_hostname` | Hostname of the switch where the device port lives. |
| `switch_ip` | Management IP of that switch. |
| `interface` | Physical port (e.g., `GigabitEthernet1/0/15` or `1/1/15`). |
| `mac_address` | Device MAC in Cisco dotted notation (xxxx.xxxx.xxxx). |
| `ip_address` | IP from ARP. "unknown" if no ARP entry found. |
| `vlan` | VLAN the MAC was learned on. |
| `matched_oui` | Which OUI prefix triggered the match (hex-only). |
| `platform` | Detected platform of the switch (cisco_ios, cisco_nxos, aruba_oscx). |
| `discovery_depth` | Hop count from the starting switch (0 = starting switch). |
| `notes` | Context flags. Empty = clean find, safe for port actions. |
| `switch_tracked_vlan` | Active tracked VLAN(s) on this switch (from `--track-vlans`). Single value = the VLAN this IDF uses. |

### Notes column values

- **(empty)** — Clean access-port find. Safe for port actions.
- **"multi-MAC port (N MACs), no CDP/LLDP neighbor"** — Unmanaged switch, hub, or disabled discovery protocols. Excluded from port actions.
- **"on uplink, not resolved downstream"** — MAC on uplink, downstream visited but MAC not found there. Excluded from port actions.
- **"not found on downstream X; recorded at uplink"** — MAC aged out on downstream switch. Excluded from port actions.
- **"downstream already visited"** — Switch already visited via different path. Excluded from port actions.

---

## Part 7: OUI Format Reference

The tool accepts any common OUI format:

| Input | Interpreted as |
|---|---|
| `00:1A:2B` | `001a2b` |
| `00-1A-2B` | `001a2b` |
| `001A2B` | `001a2b` |
| `001a.2b` | `001a2b` |

---

## Part 8: Common AV/Media OUIs

```
# av_vendor_ouis.txt
# QSC (Q-SYS)         00:60:35
# Crestron             00:10:7F
# Shure                00:0E:DD
# Audinate (Dante)     00:1D:C1
# Biamp                00:90:5A
# Extron               00:05:A6
# AMX (Harman)         00:60:9F
# Barco                00:0F:B5
# Samsung displays     00:07:AB / F4:42:8F
# LG displays          00:E0:91 / A8:23:FE
# BrightSign           00:24:A4
# Ross Video           00:1E:2A
```

Verify OUIs against the IEEE database at [https://standards-oui.ieee.org/](https://standards-oui.ieee.org/).

---

## Part 9: Troubleshooting

**"Platform auto-detection failed"** — SSH not responding or unsupported platform. Use `--platform` to force.

**"No matching devices found"** — Confirm OUI is correct. If VLANs are L3-terminated at edge, use `--fan-out`.

**"No OUI matches here, but fan-out mode will check neighbors"** — Normal in fan-out mode. The core doesn't see the MACs; edge switches will.

**"Already visited X via different IP, skipping"** — Hostname dedup working correctly. Same switch, different VRF IP.

**"Safety filter: N total → M actionable"** — Expected. Records with notes are auto-excluded from port actions.

**"Authentication failed"** — Wrong credentials for that switch. Same creds used for all switches.

**"Connection timed out"** — Management IP unreachable. Common for datacenter infra discovered via fan-out.

**IP shows "unknown"** — No ARP entry on any visited switch. Device may be powered off or ARP timed out.

**NX-OS age column shows `~~~`** — Normal for NX-OS 7.3+. Parser handles it.

**Fan-out slower than expected** — Adjust `--workers`. Lower = gentler, higher = faster.

---

## Part 10: Windows-Specific Notes

On Windows, use `python` instead of `python3`:

```
python oui_port_mapper_v4.0.py --core 10.1.1.1 --user admin --oui 00:60:35
```

PowerShell line continuation uses backtick:

```powershell
python oui_port_mapper_v4.0.py `
  --core 10.1.1.1 `
  --user admin `
  --oui-file target_ouis.txt `
  --fan-out `
  --workers 10 `
  --output results.csv
```

---

## Part 11: Architecture Notes

### Nexus Core + Catalyst Edge (most common venue topology)

The tool connects to the Nexus, auto-detects NX-OS, and uses the NX-OS parser. CDP identifies downstream Catalyst switches. In fan-out mode, all edge switches are queried concurrently with the correct IOS parser.

### Cisco Core + Aruba Edge

The core gets Cisco commands; Aruba switches get AOS-CX commands. Inter-switch links need LLDP on both sides.

### Any Mix with Unmanaged Switches

Multi-MAC ports with no CDP/LLDP neighbor get recorded with a note. The tool can't traverse unmanaged devices. These records are automatically excluded from port actions.

---

## Part 12: Version History

| Version | Changes |
|---------|---------|
| v4.0 | Concurrent recursion at all depths, `--save-config` to persist to startup, `--vlan-assign` for VLAN reassignment with platform-correct STP edge hardening, `--mac-threshold` for dual-NIC devices, `--mgmt-subnet` filter for LLDP-advertising endpoints |
| v3.0 | Fan-out mode (depth-0 only), concurrent fan-out threading, hostname dedup, access-port-only safety filter, port-cycle operation, MAC dedup in CSV export, VLAN tracking |
| v2.0 | Multi-platform support (IOS, NX-OS, AOS-CX), port-channel traversal, NX-OS `~~~` age field fix, recursive discovery |
| v1.0 | Initial single-hop core-only discovery |
