"""One-off diagnostic: inspect the CL152-46 2/1/26 port row and related state.

Run from the project root:
    .venv\\Scripts\\python.exe scripts\\check_port.py
"""
import sqlite3
import sys
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / "netcaster.db"
if not DB.exists():
    sys.exit(f"DB not found: {DB}")

c = sqlite3.connect(str(DB))
c.row_factory = sqlite3.Row


def dump(title, rows):
    print(f"=== {title} ===")
    rows = list(rows)
    if not rows:
        print("(no rows)")
    for r in rows:
        print(dict(r))
    print()


# 1. Exact match
dump(
    "exact (CL152-46, 2/1/26)",
    c.execute(
        "SELECT p.interface, p.mac_address, p.vlan, p.matched_oui, "
        "p.last_crawl_job_id, p.last_seen_at "
        "FROM venue_ports p JOIN venue_switches s ON p.switch_id=s.id "
        "WHERE s.hostname=? AND p.interface=?",
        ("CL152-46", "2/1/26"),
    ),
)

# 2. Any row carrying the stale MAC
dump(
    "any row with 90ac.3f05.1038",
    c.execute(
        "SELECT s.hostname, p.interface, p.mac_address, p.vlan, "
        "p.last_crawl_job_id "
        "FROM venue_ports p JOIN venue_switches s ON p.switch_id=s.id "
        "WHERE p.mac_address LIKE '%90ac%'"
    ),
)

# 3. All ports on CL152-46 (to see interface naming conventions)
dump(
    "all CL152-46 ports",
    c.execute(
        "SELECT p.interface, p.mac_address, p.vlan, p.last_crawl_job_id "
        "FROM venue_ports p JOIN venue_switches s ON p.switch_id=s.id "
        "WHERE s.hostname=? ORDER BY p.interface",
        ("CL152-46",),
    ),
)

# 4. Is CL152-46 even in venue_switches?
dump(
    "CL152-46 switch row",
    c.execute(
        "SELECT id, hostname, mgmt_ip, online, last_seen_at, "
        "last_crawl_job_id FROM venue_switches WHERE hostname=?",
        ("CL152-46",),
    ),
)

# 5. Most recent jobs (to correlate last_crawl_job_id)
dump(
    "last 5 jobs",
    c.execute(
        "SELECT id, job_type, status, created_at, completed_at "
        "FROM jobs ORDER BY created_at DESC LIMIT 5"
    ),
)
