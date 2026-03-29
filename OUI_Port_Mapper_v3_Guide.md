# OUI Port Mapper v3.0 — Setup & Usage Guide

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

**Cisco NX-OS** — Nexus 9000, 7000, 5000 series. Uses CDP by default (LLDP also supported). Same Cisco dotted MAC notation. Interface names like Ethernet1/1 and port-channel1. The MAC address table has extra columns compared to IOS (age, Secure, NTFY flags) which the tool's NX-OS parser handles. NX-OS 7.3 uses `~~~` in the age column instead of digits — the parser handles this correctly. Common topology: Nexus core/distribution with Catalyst access switches — auto-detection handles this mixed fabric seamlessly.

**Aruba AOS-CX** — CX 6300, 6400, 8320, 8325, 8400, 10000. Uses LLDP natively (CDP is off by default on Aruba). MAC addresses in colon-separated notation (00:1a:2b:3c:4d:5e), which the tool normalizes to Cisco format internally. Interface names like 1/1/1.

**Ubiquiti UniFi** is not supported. UniFi switches are controller-managed and don't expose a usable CLI over SSH. The EdgeSwitch line (discontinued) had a CLI, but current UniFi gear requires hitting the UniFi Controller REST API, which is a fundamentally different integration pattern.

### Platform Auto-Detection

By default (`--platform auto`), the tool auto-detects each switch it connects to. This means you can traverse a mixed Cisco/Aruba fabric without specifying anything. The detection works in two stages:

1. **netmiko SSHDetect** — fingerprints the device based on SSH banner and prompt behavior.
2. **`show version` fingerprinting** — if SSHDetect is inconclusive, the tool connects, runs `show version`, and pattern-matches the output against known platform signatures.

Auto-detection adds a few seconds per switch on the first connection. If your entire fabric is one platform, `--platform cisco_ios`, `--platform cisco_nxos`, or `--platform aruba_oscx` skips detection and is faster.

### Discovery Modes

#### Normal Mode (default)

The tool starts at the core switch, finds OUI-matching MACs, and follows them downstream through CDP/LLDP neighbors. This works when the target device VLANs are trunked L2 all the way back to the starting switch — the core sees the MACs in its MAC address table and the tool can trace them.

#### Fan-Out Mode (`--fan-out`)

In routed-access designs, many device VLANs are L3-terminated at the edge switch with an SVI. These VLANs are NOT trunked L2 back to the core — traffic is routed via EIGRP/OSPF sub-interfaces. The core never sees those MACs in its MAC table.

Fan-out mode solves this by visiting **every** CDP/LLDP neighbor from the starting switch, regardless of whether any OUI-matching MACs are visible at the core. Each edge switch's local MAC table and ARP table are queried directly. Since the SVIs live on the edge switch, the ARP table there provides IP resolution for locally-switched devices.

Fan-out only triggers at depth 0 (the starting switch). Edge switches use normal MAC-tracing recursion — they do NOT fan out to their own neighbors. This prevents runaway recursion through datacenter infrastructure (IDS, DCS, SFS devices) that have no endpoints.

### Discovery Workflow

**Step 1 — Connect to the starting switch.** Auto-detect or use the forced platform.

**Step 2 — Pull ARP table.** Builds a MAC→IP lookup. This is merged globally across all switches visited, so ARP data from deeper in the fabric is available for earlier hops. In fan-out mode, each edge switch's ARP table captures locally-switched VLAN entries.

**Step 3 — Pull MAC address table.** Every entry is tested against your OUI prefix list. Only prefix matches proceed.

**Step 4 — Pull CDP/LLDP neighbors.** On Cisco, both CDP and LLDP are queried (some mixed-vendor links only run LLDP). On Aruba, LLDP only. Neighbors are deduplicated — if the same neighbor appears via both protocols, the CDP entry is preferred (it typically has richer data).

**Step 5 — Classify each matching MAC.** Three outcomes:

- **Access port** — Single MAC on the port, no CDP/LLDP neighbor. This is an endpoint. Record it.
- **Known uplink** — CDP/LLDP neighbor on the port. The MAC is behind another switch. Queue for recursion.
- **Unknown uplink** — Multiple MACs on the port but no CDP/LLDP neighbor. Likely an unmanaged switch, hub, or a link with discovery protocols disabled. Record here with a note, because we can't determine a management IP to recurse into.

**Step 6 — Recurse or fan-out.** In normal mode, recurse into downstream switches where matching MACs were found. In fan-out mode (depth 0 only), visit all CDP/LLDP neighbors concurrently using `--workers` threads.

**Step 7 — Export.** All results written to CSV with MAC deduplication.

### Hostname-Based Deduplication

In many campus networks, the same switch is reachable via multiple management IPs (VRF sub-interfaces, different EIGRP adjacencies). Without dedup, the tool would SSH to the same physical switch multiple times.

v3.0 tracks visited switches by hostname (case-insensitive) in addition to IP. After connecting and reading the switch prompt, if the hostname was already visited via a different IP, the tool disconnects immediately and skips that switch. This dramatically reduces SSH sessions in routed-access designs — at Yankee Stadium, this cut 118 sessions down to ~45.

### Concurrent Threading

Fan-out mode dispatches edge switch queries using a `ThreadPoolExecutor`. The `--workers` flag (default: 10) controls how many SSH sessions run in parallel. With 45 switches at ~2 minutes each:

- Sequential: ~90 minutes
- 10 workers: ~10 minutes

The thread pool only applies to fan-out at depth 0. Normal MAC-tracing recursion at deeper levels is sequential (by design — each hop depends on the previous).

### The Multi-MAC Heuristic

Instead of relying solely on CDP/LLDP to identify uplinks (which fails when discovery protocols are disabled), the tool counts how many total MACs are learned on each port:

- **1 MAC on the port** → access port. An endpoint device directly connected.
- **>1 MAC on the port** → trunk/uplink. Multiple devices behind this port, meaning it connects to another switch, hub, or segment.

When a multi-MAC port also has a CDP/LLDP neighbor, the tool recurses to that neighbor. When it doesn't (no neighbor data), it records the MAC at the current switch with a note explaining why it couldn't trace further.

### Recursion Depth

The `--max-depth` flag (default: 10) limits how many hops from the starting switch the tool will traverse. In practice, venue topologies rarely exceed 3 hops (core → dist → access), so the default is generous. Set to 0 to query only the starting switch with no recursion.

---

## Part 4: Command Reference

### Basic discovery — auto-detect platform

```
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:1A:2B
```

Connects to 10.1.1.1, auto-detects whether it's Cisco or Aruba, discovers all MACs starting with `001a2b`, recursively traces them through the fabric, and exports to `oui_port_inventory.csv`.

### Fan-out discovery for routed-access designs

```
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui-file target_ouis.txt \
  --fan-out \
  --workers 10 \
  --output discovery.csv
```

Connects to the core, pulls its CDP/LLDP neighbor table, then SSHs to every edge switch in parallel (10 at a time) and searches each one's local MAC and ARP tables. Use this when device VLANs are L3-terminated at the edge.

### Force a specific platform

```
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:1A:2B \
  --platform aruba_oscx
```

Skips auto-detection and uses Aruba AOS-CX commands on ALL switches. Use this when your fabric is homogeneous and you want to skip the detection overhead.

### Multiple OUIs

```
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:60:35 \
  --oui 00:10:7F \
  --oui 00:0E:DD
```

### OUIs from a file

```
# av_vendor_ouis.txt
# QSC (Q-SYS)
00:60:35
# Crestron
00:10:7F
# Shure
00:0E:DD
# Audinate (Dante)
00:1D:C1
```

```
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui-file av_vendor_ouis.txt
```

### Custom output filename

```
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:60:35 \
  --output qsc_inventory_2026-03-27.csv
```

### Limit recursion depth

```
# Only check the starting switch, no recursion
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:60:35 \
  --max-depth 0

# Allow up to 3 hops (core → dist → access)
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:60:35 \
  --max-depth 3
```

### Verbose / debug output

```
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:60:35 \
  --verbose
```

Shows per-MAC classification decisions, raw command outputs, neighbor deduplication details, and connection timing. Extremely useful for debugging "why isn't this MAC showing up" problems. Note: verbose includes paramiko SSH debug logging, which is very noisy. Omit `--verbose` for normal operation — INFO-level logging still shows switch visits, MAC counts, and device finds.

### Adjust concurrent workers

```
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui-file target_ouis.txt \
  --fan-out \
  --workers 20
```

Default is 10 concurrent SSH sessions. Higher values are faster but put more load on the management plane. For older switching fabrics with limited CPU, use `--workers 5`.

### Passing the password inline (for scripting)

```
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --password 'YourPasswordHere' \
  --oui 00:60:35
```

Be aware the password is visible in shell history. For production automation, pull credentials from environment variables or a vault.

---

## Part 5: Port Actions (Shutdown / No Shutdown / Port Cycle)

### Safety Filter

v3.0 applies a strict access-port-only safety filter to ALL port actions. A port is only acted on if ALL of these are true:

- Interface is a real port name (not "unknown", "not found", etc.)
- Interface is NOT a port-channel, LAG, vPC, or aggregate interface
- Notes field is empty (clean single-MAC access-port find)

Any record with notes (multi-MAC, uplink, not-resolved, downstream-already-visited) is automatically excluded. The tool reports how many records were filtered and why.

### Dry-run first (always)

```
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:60:35 \
  --shutdown \
  --dry-run
```

Runs full discovery, exports CSV, prints the list of ports that *would* be shut down, but makes no changes.

### Live shutdown

```
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:60:35 \
  --shutdown
```

After discovery, the tool prints every port it's about to act on and asks you to type `YES` (exact, case-sensitive). It then SSHs to each switch and pushes the config.

### Re-enable ports

```
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui 00:60:35 \
  --no-shutdown
```

### Port Cycle (shut → wait → no-shut)

Single operation with one confirmation prompt. Shuts down all matched access ports, waits the specified delay, then re-enables them.

```
# Dry run
python3 oui_port_mapper_v3.0.py \
  --from-csv discovery.csv \
  --user admin \
  --port-cycle \
  --cycle-delay 5 \
  --dry-run

# Live
python3 oui_port_mapper_v3.0.py \
  --from-csv discovery.csv \
  --user admin \
  --port-cycle \
  --cycle-delay 5
```

The `--cycle-delay` flag controls seconds between shutdown and no-shutdown (default: 5). You confirm once for the shutdown phase; the no-shutdown phase runs automatically after the delay.

### Two-step workflow (recommended for production)

**Step 1 — Discover and export:**

```
python3 oui_port_mapper_v3.0.py \
  --core 10.1.1.1 \
  --user admin \
  --oui-file target_ouis.txt \
  --fan-out \
  --output devices.csv
```

**Step 2 — Review the CSV.** Open in Excel/Numbers. The safety filter handles multi-MAC and uplink records automatically, but you may want to remove specific devices you don't want to touch. Save.

**Step 3 — Act on the CSV:**

```
python3 oui_port_mapper_v3.0.py \
  --from-csv devices.csv \
  --user admin \
  --port-cycle \
  --cycle-delay 5
```

Loads records from CSV, applies the safety filter (only clean access-port finds pass), and cycles the ports. The `platform` column in the CSV tells the tool which command syntax to use for each switch.

### Running-config only

All port changes are applied to running-config ONLY. A switch reload reverts them. If persistence is needed, manually run `copy running-config startup-config` on each affected switch.

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
| `notes` | Context flags. Empty for clean access-port finds. Populated for edge cases — see below. |

### Notes column values

- **(empty)** — Clean find. MAC is on an access port with a single device. **This is the only category eligible for port actions.**
- **"multi-MAC port (N MACs), no CDP/LLDP neighbor"** — Port has multiple MACs but no neighbor data. Could be an unmanaged switch, hub, or a link with discovery protocols disabled. The MAC is recorded at this switch because the tool can't trace further. **Excluded from port actions by the safety filter.**
- **"on uplink, not resolved downstream"** — The MAC was visible on a switch's uplink to a downstream neighbor, but when the tool checked the downstream switch, the MAC wasn't resolved to an access port. **Excluded from port actions.**
- **"not found on downstream X; recorded at uplink"** — The MAC was visible on the core/dist switch's uplink to switch X, but when the tool checked switch X's MAC table, the MAC had aged out or wasn't present. **Excluded from port actions.**
- **"downstream already visited"** — The MAC's uplink port points to a switch that was already visited via a different path. **Excluded from port actions.**

### MAC Deduplication

The CSV export deduplicates by MAC address. If the same MAC appears at multiple points in the fabric (e.g., visible at both the core uplink and the edge access port), only the first-recorded entry is kept. Threading race conditions can occasionally produce duplicates; the export handles this automatically.

---

## Part 7: OUI Format Reference

The tool accepts any common OUI format:

| Input | Interpreted as |
|---|---|
| `00:1A:2B` | `001a2b` |
| `00-1A-2B` | `001a2b` |
| `001A2B` | `001a2b` |
| `001a.2b` | `001a2b` |

Matching is strictly prefix-based. A 3-byte OUI (6 hex chars) matches the first half of the MAC. Shorter or longer prefixes also work.

---

## Part 8: Common AV/Media OUIs

```
# av_vendor_ouis.txt

# QSC (Q-SYS)
00:60:35

# Crestron
00:10:7F

# Shure (MXA microphones, etc.)
00:0E:DD

# Audinate (Dante — many OEMs use Audinate's OUI)
00:1D:C1

# Biamp
00:90:5A

# Extron
00:05:A6

# AMX (Harman)
00:60:9F

# Barco
00:0F:B5

# Samsung displays
00:07:AB
F4:42:8F

# LG displays
00:E0:91
A8:23:FE

# BrightSign
00:24:A4

# Ross Video
00:1E:2A
```

Verify OUIs against the IEEE database at [https://standards-oui.ieee.org/](https://standards-oui.ieee.org/) for the specific hardware you're targeting. Some vendors use multiple OUI blocks across product lines.

---

## Part 9: Troubleshooting

**"Platform auto-detection failed for 10.x.x.x"**

- The tool tried both SSHDetect and `show version` fingerprinting and couldn't identify the platform. This usually means SSH isn't responding or the device isn't a supported platform. Use `--platform` to force a type, or check that SSH is enabled on the device.

**"No matching devices found"**

- Confirm the OUI is correct. Manually check a known device's MAC.
- The device may not have active traffic (MAC aged out). Ping the device and re-run.
- In normal mode, verify the starting switch has L2 visibility to the target VLANs. If device VLANs are L3-terminated at the edge, use `--fan-out`.

**"No OUI matches here, but fan-out mode will check neighbors"**

- This is normal in fan-out mode. The starting switch has no matching MACs in its MAC table (because the VLANs are routed at the edge), but fan-out will visit each edge switch and search their local tables.

**"Authentication failed for 10.x.x.x"**

- Credentials don't work on that switch. The tool uses the same username/password for all switches in the fabric. If an edge switch has different credentials, it will fail on that hop and record the MACs with a note.

**"Connection timed out for 10.x.x.x"**

- Management IP from CDP/LLDP is unreachable. Check routing, ACLs, and verify the IP is correct.

**"Already visited <hostname> via different IP, skipping"**

- Normal behavior. The same switch was reachable via multiple VRF sub-interface IPs. Hostname dedup correctly identified it and skipped the duplicate connection.

**IP shows "unknown"**

- The starting switch isn't the L3 gateway for that VLAN.
- In fan-out mode, the edge switch's ARP table should have the entry. If it's still unknown, the device may not have active traffic — ping it and re-run.

**"multi-MAC port, no CDP/LLDP neighbor" in notes**

- The MAC is on a port with multiple devices but no neighbor discovery data. This is the tool saying "I think there's another switch here but I can't reach it." Possible causes: unmanaged switch, CDP/LLDP disabled on that link, or a device acting as a bridge (e.g., a wireless AP in bridge mode). **These records are automatically excluded from port actions by the safety filter.**

**"on uplink, not resolved downstream" in notes**

- The MAC was on the upstream switch's MAC table pointing toward a downstream switch, but the tool couldn't pin it to an access port on the downstream switch. Usually a timing issue — the MAC aged out between queries. Re-run after pinging the device. **These records are automatically excluded from port actions.**

**Discovery takes too long**

- Use `--fan-out` with `--workers 10` (or higher) for concurrent SSH sessions.
- Without fan-out, the tool runs sequentially. Fan-out mode with 10 workers typically completes a 40+ switch venue in under 10 minutes.
- If `--verbose` is enabled, paramiko's SSH debug logging adds significant overhead to the log output. Remove `--verbose` for production runs.

**Safety filter excluded too many ports**

- The filter is deliberately strict. Only records with an empty `notes` field pass. If you need to act on a "multi-MAC" record, manually verify it in the CSV, then edit the notes column to empty and re-run from the CSV.

**Aruba: no neighbors found**

- CDP is off by default on AOS-CX. The tool uses LLDP for Aruba. Make sure LLDP is enabled globally (`lldp enable`) and on the relevant interfaces.

**Mixed vendor: Cisco core can't see Aruba edge via CDP**

- Aruba doesn't run CDP by default. If LLDP is enabled on both sides, the tool picks it up — on Cisco, it queries both CDP and LLDP.

**NX-OS: MAC table returns 0 entries**

- Some NX-OS versions require `show mac address-table dynamic` instead of `show mac address-table`. The current parser uses the base command. If you're getting empty results on a Nexus that you know has MAC entries, run the command manually and check the output format.

**NX-OS: gateway/supervisor MACs showing up**

- The NX-OS parser explicitly filters out entries with `sup-eth` in the port name and `(R)` routed flag. If you're still seeing internal/supervisor MACs in the output, check `--verbose` to see what's being parsed.

---

## Part 10: Windows-Specific Notes

On Windows, use `python` instead of `python3` in all commands:

```
python oui_port_mapper_v3.0.py --core 10.1.1.1 --user admin --oui 00:60:35
```

In PowerShell, multi-line commands use backtick (`` ` ``) for line continuation:

```powershell
python oui_port_mapper_v3.0.py `
  --core 10.1.1.1 `
  --user admin `
  --oui-file target_ouis.txt `
  --fan-out `
  --workers 10 `
  --output results.csv
```

Windows may trigger a firewall prompt the first time netmiko opens an outbound SSH connection. Allow it.

---

## Part 11: Architecture Notes for Mixed-Vendor Fabrics

Platform detection happens per-switch, so any supported combination works transparently.

### Nexus Core + Catalyst Edge (most common venue topology)

The tool connects to the Nexus 9300/9500/7700, auto-detects NX-OS, and uses the NX-OS MAC table parser (which handles the `*`/`+`/`G` flags, age/Secure/NTFY columns, and `~~~` age fields). CDP on the Nexus identifies downstream Catalyst 9200/9300 switches. In fan-out mode, the tool SSHs to each Catalyst concurrently, detects IOS-XE, and switches to the IOS parser. CDP is native on both platforms, so no additional configuration is needed on the inter-switch links.

### Cisco Core + Aruba Edge

The core gets Cisco commands (`show cdp neighbors detail`, `show mac address-table`), and when it follows a neighbor to an Aruba switch, it re-detects and switches to Aruba commands (`show lldp neighbors-detail`, `show mac-address-table`). For this to work across a Cisco↔Aruba boundary, LLDP must be enabled on both sides.

### Routed-Access Designs

When device VLANs have SVIs on the edge switch (not trunked to core), use `--fan-out`. The core's CDP table identifies all edge switches; fan-out visits each one and queries its local MAC/ARP tables. The edge switch's ARP table provides IP resolution since it owns the SVIs.

### Any Mix with Unmanaged Switches

When the tool hits a port with multiple MACs but no CDP/LLDP neighbor, it records the device at that port with a note. The tool can't traverse through unmanaged devices but it tells you exactly where the trail went cold. The safety filter prevents port actions on these ambiguous records.

---

## Version History

| Version | Changes |
|---------|---------|
| v3.0 | Fan-out mode (depth-0 only), concurrent threading, hostname dedup, access-port-only safety filter, port-cycle operation, MAC dedup in CSV export |
| v2.0 | Multi-platform support (IOS, NX-OS, AOS-CX), port-channel traversal, NX-OS `~~~` age field fix, recursive discovery |
| v1.0 | Initial single-hop core-only discovery |
