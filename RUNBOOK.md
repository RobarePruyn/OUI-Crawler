# OUI Port Mapper v3.0 — Runbook
# Cisco DMP-4310 + BrightSign Discovery & Port Control

Author: Robare Pruyn
Copyright: Mediacast Network Solutions, Inc. 2026

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
4. **IMPORTANT (Windows only): On the VERY FIRST screen, check the box
   that says "Add python.exe to PATH" — it is NOT checked by default**
5. Click "Install Now"
6. Wait for it to finish, then close the installer

### Step 2: Verify Python installed correctly

1. Open a NEW terminal window:
   - Mac: Terminal (Cmd+Space, type "Terminal", Enter)
   - Windows: Command Prompt (Win+R, type cmd, press Enter)
2. Type this and press Enter:

       python3 --version       (Mac)
       python --version        (Windows)

3. You should see something like "Python 3.13.x"
4. If you get "not recognized" / "command not found", close the window,
   uninstall Python, and redo Step 1 — you missed the PATH checkbox

### Step 3: Install netmiko

1. In the same terminal window, type this and press Enter:

       pip3 install netmiko    (Mac)
       pip install netmiko     (Windows)

2. Wait for it to finish. You'll see "Successfully installed" when done.
3. This only needs to be done once.

---

## RUNNING THE TOOL

Before you run any commands below, open your terminal and navigate to
the folder where you put the files:

    cd ~/oui_mapper                              (Mac)
    cd C:\Users\YourName\oui_mapper              (Windows)

Replace paths as needed for your actual folder location.

NOTE: On Mac, use python3. On Windows, use python.
All examples below use python3 (Mac). Windows users: substitute python.


### TASK 1: DISCOVER ALL DMP-4310 AND BRIGHTSIGN DEVICES

This finds every matching device on the network and saves the results
to a CSV file. It does NOT shut anything down.

    python3 oui_port_mapper_v3.0.py \
      --core CORE_SWITCH_IP \
      --user SSH_USERNAME \
      --oui-file target_ouis.txt \
      --fan-out \
      --workers 10 \
      --output discovery_results.csv

Replace CORE_SWITCH_IP with the management IP of the core switch
(e.g., 32.21.168.1). Replace SSH_USERNAME with your SSH login username.

The --fan-out flag is REQUIRED for venues where device VLANs are
L3-terminated at the edge switches (not trunked to core). This visits
every edge switch and checks its local MAC/ARP tables.

The --workers 10 flag runs 10 SSH sessions in parallel. Adjust down
to 5 for older hardware, or up to 20 for faster runs.

You will be prompted for your SSH password. It will not show on screen
as you type — that's normal.

Expected runtime: 5-15 minutes depending on the number of switches.

When it finishes, open discovery_results.csv in Excel and review it.
Each row is one device found on the network.

Key columns:
  - switch_hostname  → which switch the device is plugged into
  - interface        → which port on that switch
  - mac_address      → the device's MAC
  - ip_address       → the device's IP (or "unknown" if not in ARP)
  - notes            → if empty, it's a clean find on an access port.
                        if populated, read it — it explains edge cases.
                        ONLY rows with empty notes are eligible for
                        port actions (shut/no-shut/port-cycle).


### TASK 2: SHUT DOWN ALL DISCOVERED PORTS

**Do Task 1 first.** Review the CSV. Remove any rows you do NOT want
to shut down. Save the CSV.

Then run a dry run first:

    python3 oui_port_mapper_v3.0.py \
      --from-csv discovery_results.csv \
      --user SSH_USERNAME \
      --shutdown \
      --dry-run

This shows what WOULD be shut down but makes no changes. The safety
filter automatically excludes multi-MAC ports, uplinks, and any record
with notes. Only clean access-port finds are shown.

When you're satisfied, run it for real (remove --dry-run):

    python3 oui_port_mapper_v3.0.py \
      --from-csv discovery_results.csv \
      --user SSH_USERNAME \
      --shutdown

It will show every port it's about to shut down and ask you to type
YES (all caps, exact). Type YES and press Enter to proceed, or
anything else to abort.

**Changes are in running-config only.** A switch reload will revert
them. If you need to make them permanent, manually log into each
switch and run: copy running-config startup-config


### TASK 3: RE-ENABLE (NO SHUT) ALL PORTS

Same as Task 2, but with --no-shutdown instead of --shutdown:

    python3 oui_port_mapper_v3.0.py \
      --from-csv discovery_results.csv \
      --user SSH_USERNAME \
      --no-shutdown \
      --dry-run

Review the dry run, then run for real:

    python3 oui_port_mapper_v3.0.py \
      --from-csv discovery_results.csv \
      --user SSH_USERNAME \
      --no-shutdown

Same YES confirmation prompt. Same running-config-only behavior.


### TASK 4: PORT CYCLE (SHUT → WAIT → NO-SHUT)

This is a single operation that shuts down all matched access ports,
waits a configurable number of seconds, then re-enables them. You
only confirm once.

Dry run first:

    python3 oui_port_mapper_v3.0.py \
      --from-csv discovery_results.csv \
      --user SSH_USERNAME \
      --port-cycle \
      --cycle-delay 5 \
      --dry-run

Live:

    python3 oui_port_mapper_v3.0.py \
      --from-csv discovery_results.csv \
      --user SSH_USERNAME \
      --port-cycle \
      --cycle-delay 5

The --cycle-delay flag sets the number of seconds between shutdown and
no-shutdown (default: 5). You type YES once for the shutdown phase;
the no-shutdown phase runs automatically after the delay.


### TASK 5: DISCOVER AND ACT IN ONE PASS (if you're in a hurry)

This discovers and immediately offers to act in a single run.
No CSV review step. Use only if you're confident the OUI list is
targeting the right devices.

    python3 oui_port_mapper_v3.0.py \
      --core CORE_SWITCH_IP \
      --user SSH_USERNAME \
      --oui-file target_ouis.txt \
      --fan-out \
      --port-cycle \
      --cycle-delay 5

You still get the YES confirmation prompt before anything is shut down.
The safety filter still applies — only clean access-port finds are acted on.

---

## QUICK REFERENCE (copy-paste commands)

All commands below assume you're in the folder with the files.
Replace CORE_SWITCH_IP and SSH_USERNAME every time.

    # Discover only (fan-out, 10 workers)
    python3 oui_port_mapper_v3.0.py --core CORE_SWITCH_IP --user SSH_USERNAME --oui-file target_ouis.txt --fan-out --workers 10 --output discovery_results.csv

    # Port cycle from CSV (dry run)
    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --port-cycle --cycle-delay 5 --dry-run

    # Port cycle from CSV (live)
    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --port-cycle --cycle-delay 5

    # Shut down from CSV (dry run)
    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --shutdown --dry-run

    # Shut down from CSV (live)
    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --shutdown

    # Re-enable from CSV (dry run)
    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --no-shutdown --dry-run

    # Re-enable from CSV (live)
    python3 oui_port_mapper_v3.0.py --from-csv discovery_results.csv --user SSH_USERNAME --no-shutdown

---

## SAFETY FEATURES

The tool has multiple layers of protection:

1. **Access-port-only filter** — Port actions (shutdown, no-shutdown,
   port-cycle) only act on records with an empty notes field. Multi-MAC
   ports, uplinks, port-channels, and unresolved records are automatically
   excluded. You cannot accidentally shut down a trunk port.

2. **YES confirmation** — You must type YES (exact, case-sensitive)
   before any changes are made. Anything else aborts.

3. **Dry-run mode** — Use --dry-run to see exactly what would happen
   without making any changes.

4. **Running-config only** — Changes are NOT saved to startup-config.
   A switch reload reverts all changes.

5. **Hostname dedup** — The tool won't waste time revisiting the same
   switch via different management IPs.

---

## TROUBLESHOOTING

**"python is not recognized" / "command not found"**
→ Python isn't in your PATH. Uninstall, reinstall, check the PATH box.

**"No module named netmiko"**
→ Run: pip3 install netmiko (Mac) or pip install netmiko (Windows)

**"Authentication failed for 10.x.x.x"**
→ Wrong username or password for that switch. Verify your credentials.

**"Connection timed out for 10.x.x.x"**
→ Can't reach that switch's management IP from your machine.
  Check that you're on the right network/VPN.

**"No matching devices found"**
→ No devices with those OUIs are in the MAC table right now.
  The devices may be powered off or the MACs may have aged out.
  If using normal mode (no --fan-out), the devices may be on
  VLANs that aren't trunked to the core. Try adding --fan-out.

**"No OUI matches here, but fan-out mode will check neighbors"**
→ This is normal. The core switch doesn't have the MACs in its
  table (because VLANs are routed at the edge). Fan-out will
  visit each edge switch and find them there.

**"Already visited <hostname> via different IP, skipping"**
→ Normal. The same switch was reachable via two different IPs.
  The tool correctly skipped the duplicate.

**CSV shows ip_address as "unknown"**
→ The device doesn't have an ARP entry on any visited switch.
  This can happen for L2-only devices or if the MAC aged out
  of ARP. The port info is still accurate.

**"multi-MAC port, no CDP/LLDP neighbor" in notes**
→ The device is behind an unmanaged switch or a link without
  neighbor discovery. The tool found the MAC but couldn't trace
  it to the exact access port. The recorded port is the last
  known point in the managed fabric.
  These records are automatically excluded from port actions.

**Safety filter excluded ports I wanted to act on**
→ The filter is strict by design. Only records with empty notes
  pass. If you're sure a filtered record is safe, edit the CSV
  to clear its notes column and re-run from the CSV.

**Discovery is slow**
→ Make sure you're using --fan-out --workers 10. Without these,
  the tool runs sequentially and follows every CDP path.
