# OUI Port Mapper v3.0 — Runbook
# Cisco DMP-4310 + BrightSign Discovery & Port Control

**Author:** Robare Pruyn
**Copyright:** Mediacast Network Solutions, Inc. 2026

This document walks you through everything from zero to running the tool.
Follow each step in order. Do not skip steps.

---

## FILES YOU NEED

You should have received these files. Put them all in the same folder
(e.g., C:\Users\YourName\oui_mapper\ or ~/oui_mapper/):

    oui_port_mapper_v3.0.py   ← the script
    target_ouis.txt           ← the OUI list (Cisco DMP-4310 + BrightSign)
    RUNBOOK.md                ← this file

---

## ONE-TIME SETUP (only do this once)

### Step 1: Install Python

1. Go to https://www.python.org/downloads/
2. Click the big yellow "Download Python 3.x.x" button
3. Run the downloaded installer
4. **WINDOWS ONLY — IMPORTANT: On the VERY FIRST screen, check the
   box that says "Add python.exe to PATH" — it is NOT checked by default**
5. Click "Install Now"
6. Wait for it to finish, then close the installer

### Step 2: Verify Python installed correctly

Open a NEW terminal window and type:

    python3 --version        (Mac/Linux)
    python --version         (Windows)

You should see something like "Python 3.13.x"

### Step 3: Install netmiko

In the same terminal window:

    pip3 install netmiko     (Mac/Linux)
    pip install netmiko      (Windows)

Wait for "Successfully installed" to appear. This only needs to be done once.

---

## RUNNING THE TOOL

Before you run any commands below, open a terminal and navigate to
the folder where you put the files:

    cd ~/oui_mapper                              (Mac/Linux)
    cd C:\Users\YourName\oui_mapper              (Windows)


### TASK 1: DISCOVER ALL DMP-4310 AND BRIGHTSIGN DEVICES

This finds every matching device on the network and saves the results
to a CSV file. It does NOT shut anything down.

Mac/Linux:

    python3 oui_port_mapper_v3.0.py \
      --core CORE_SWITCH_IP \
      --user SSH_USERNAME \
      --oui-file target_ouis.txt \
      --fan-out \
      --workers 10 \
      --output discovery_results.csv

Windows (one line):

    python oui_port_mapper_v3.0.py --core CORE_SWITCH_IP --user SSH_USERNAME --oui-file target_ouis.txt --fan-out --workers 10 --output discovery_results.csv

Replace CORE_SWITCH_IP with the management IP of the core switch
(e.g., 32.21.168.1). Replace SSH_USERNAME with your SSH login username.

You will be prompted for your SSH password. It will not show on screen
as you type — that's normal.

**Why --fan-out?** The DMP and BrightSign devices are on VLANs that are
L3-terminated at the edge switches and NOT trunked to the core. Without
fan-out, the core switch can't see those MACs in its MAC table and will
find nothing. Fan-out tells the tool to visit every CDP neighbor from
the core and check each edge switch's local tables.

**What does --workers 10 do?** Runs up to 10 SSH sessions in parallel
for faster discovery. Adjust down (5) if switches are slow to respond,
or up (20) if you want to go faster.

When it finishes, open discovery_results.csv in Excel and review it.
Each row is one device found on the network.

Key columns:
  - switch_hostname  → which switch the device is plugged into
  - interface        → which port on that switch
  - mac_address      → the device's MAC
  - ip_address       → the device's IP (or "unknown" if not in ARP)
  - notes            → if empty, it's a clean find on an access port.
                        if populated, that device is automatically
                        excluded from shut/no-shut operations.


### TASK 2: PORT CYCLE (SHUT DOWN AND RE-ENABLE ALL DEVICES)

This is the most common operation. It shuts down every discovered
access port, waits a few seconds, then brings them all back up.
Useful for forcing DMP/BrightSign reboots or DHCP re-acquisition.

**Do Task 1 first.** Then:

Dry run (see what WOULD happen, no changes made):

    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --port-cycle --cycle-delay 5 --dry-run

Live (actually does it):

    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --port-cycle --cycle-delay 5

(On Windows, use `python` instead of `python3`.)

The tool will:
  1. Apply the safety filter (only clean access-port finds proceed)
  2. Show every port it will act on
  3. Ask you to type YES (all caps, exact) to confirm
  4. Shut down all ports
  5. Wait 5 seconds (or whatever --cycle-delay you set)
  6. Re-enable all ports

**You only confirm once.** The no-shut phase happens automatically
after the delay.

**SAFETY:** The tool automatically excludes ports that have notes
(multi-MAC, uplink, not-resolved, etc.), port-channel/LAG interfaces,
and unknown interfaces. You don't need to manually edit the CSV.


### TASK 3: SHUT DOWN ONLY (without re-enabling)

    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --shutdown --dry-run

Review the dry run, then run for real (remove --dry-run):

    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --shutdown

Same YES confirmation prompt. Same safety filter.


### TASK 4: RE-ENABLE ONLY (without shutting down first)

    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --no-shutdown --dry-run

Review the dry run, then for real:

    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --no-shutdown


### TASK 5: DISCOVER AND PORT-CYCLE IN ONE PASS (if you're in a hurry)

This discovers and immediately offers to port-cycle in a single run.
No CSV review step. Use only if you're confident the OUI list is
targeting the right devices.

    python3 oui_port_mapper_v3.0.py \
      --core CORE_SWITCH_IP \
      --user SSH_USERNAME \
      --oui-file target_ouis.txt \
      --fan-out \
      --workers 10 \
      --port-cycle \
      --cycle-delay 5

You still get the YES confirmation prompt before anything happens.

---

## IMPORTANT NOTES

**Changes are running-config only.** A switch reload will revert
all shut/no-shut changes. If you need to make them permanent,
manually log into each switch and run:

    copy running-config startup-config

**The safety filter protects you.** The tool will NOT shut down:
  - Ports with multiple MACs (likely trunks or uplinks)
  - Port-channels, LAGs, or vPC interfaces
  - Ports where the device couldn't be fully traced
  - Anything with a non-empty "notes" field

Only clean, single-MAC, access-port finds are acted on.

---

## QUICK REFERENCE (copy-paste commands)

All commands below assume you're in the folder with the files.
Replace CORE_SWITCH_IP and SSH_USERNAME every time.
On Windows, use `python` instead of `python3`.

    # Discover only (fan-out mode)
    python3 oui_port_mapper_v3.0.py --core CORE_SWITCH_IP --user SSH_USERNAME --oui-file target_ouis.txt --fan-out --workers 10 --output discovery_results.csv

    # Port cycle from CSV (dry run first)
    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --port-cycle --cycle-delay 5 --dry-run

    # Port cycle from CSV (for real)
    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --port-cycle --cycle-delay 5

    # Shut down from CSV (dry run first)
    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --shutdown --dry-run

    # Shut down from CSV (for real)
    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --shutdown

    # Re-enable from CSV (dry run first)
    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --no-shutdown --dry-run

    # Re-enable from CSV (for real)
    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --no-shutdown

---

## TROUBLESHOOTING

**"python is not recognized"**
→ Python isn't in your PATH. Uninstall, reinstall, check the PATH box.

**"No module named netmiko"**
→ Run: pip install netmiko

**"Authentication failed for 10.x.x.x"**
→ Wrong username or password for that switch. Verify your credentials.

**"Connection timed out for 10.x.x.x"**
→ Can't reach that switch's management IP from your machine.
  Check that you're on the right network/VPN. Some datacenter
  infrastructure discovered via CDP may be intentionally unreachable
  — these errors are harmless.

**"No matching devices found"**
→ No devices with those OUIs are in the MAC table right now.
  The devices may be powered off or the MACs may have aged out.
  If not using --fan-out, add it — the devices may be on VLANs
  that aren't trunked to the core.

**CSV shows ip_address as "unknown"**
→ The device doesn't have an ARP entry on any switch visited.
  In fan-out mode, edge switch ARP tables are checked (where
  SVIs live), so most IPs resolve. Remaining unknowns are
  powered-off devices or timed-out ARP entries.

**"Safety filter: N total → M actionable"**
→ This is normal and expected. The safety filter excluded records
  that aren't clean access-port finds. Only safe ports are acted on.

**A port shows notes like "multi-MAC port, no CDP/LLDP neighbor"**
→ The device is behind an unmanaged switch or a link without
  neighbor discovery. The recorded port is the last known point
  in the managed fabric. Automatically excluded from port actions.
