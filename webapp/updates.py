"""Self-update check against the GitHub repository.

Lightweight by design: on-prem NetCaster will eventually be replaced by
a thin Rust connector, so we deliberately avoid building a full update
provider framework here. This module just answers two questions:

  1. What version am I running? (from VERSION file at repo root)
  2. Is there a newer commit on origin/main?  (via GitHub public API)

The "apply update" path is a flag file at C:\\NetCaster\\update.flag
watched by a Scheduled Task running update.ps1.  See scripts/update.ps1.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# --- Configuration ---------------------------------------------------

GITHUB_OWNER = "RobarePruyn"
GITHUB_REPO = "NetCaster"
CHECK_INTERVAL_SECONDS = 15 * 60   # 15 minutes
HTTP_TIMEOUT_SECONDS = 10
UPDATE_FLAG_PATH = Path(os.environ.get("NETCASTER_UPDATE_FLAG", r"C:\NetCaster\update.flag"))
LAST_UPDATE_STATUS_PATH = Path(
    os.environ.get("NETCASTER_UPDATE_STATUS", r"C:\NetCaster\logs\last-update-status.txt")
)


# --- State ------------------------------------------------------------

@dataclass
class UpdateState:
    current_version: str = "unknown"
    current_sha: str = ""
    latest_version: str = ""
    latest_sha: str = ""
    latest_message: str = ""
    checked_at: float = 0.0
    error: str = ""
    last_update_status: str = ""

    @property
    def update_available(self) -> bool:
        if not self.latest_sha or not self.current_sha:
            return False
        return self.latest_sha != self.current_sha


_state = UpdateState()
_state_lock = threading.Lock()
_worker_started = False


def get_state() -> UpdateState:
    """Return a snapshot of the current update state (thread-safe read).

    The dataclass is simple enough that returning the live object is
    fine for read-only template use; callers must not mutate it.
    """
    with _state_lock:
        # Refresh last-update-status on every read — it's written by
        # update.ps1 and we want the UI to reflect a failed update
        # immediately after the service comes back up.
        try:
            if LAST_UPDATE_STATUS_PATH.exists():
                _state.last_update_status = LAST_UPDATE_STATUS_PATH.read_text(encoding="utf-8").strip()
        except Exception:
            pass
        return _state


def _read_version_file() -> str:
    """Read VERSION from the repo root."""
    root = Path(__file__).resolve().parent.parent
    version_file = root / "VERSION"
    if version_file.exists():
        return version_file.read_text(encoding="utf-8").strip()
    return "unknown"


def _read_current_sha() -> str:
    """Read the current git HEAD sha, if the deployment is a git checkout."""
    root = Path(__file__).resolve().parent.parent
    head_file = root / ".git" / "HEAD"
    if not head_file.exists():
        return ""
    try:
        head = head_file.read_text(encoding="utf-8").strip()
        if head.startswith("ref:"):
            ref_path = root / ".git" / head.split(" ", 1)[1]
            if ref_path.exists():
                return ref_path.read_text(encoding="utf-8").strip()
        else:
            return head  # detached HEAD
    except Exception as exc:
        logger.debug("Could not read git HEAD: %s", exc)
    return ""


def _fetch_latest_from_github() -> tuple[str, str, str]:
    """Return (sha, short_version, commit_message) for origin/main.

    Uses the unauthenticated GitHub API — 60 req/hour is ample for a
    15-minute poll interval. Returns ("", "", "") on any failure.
    """
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/commits/main"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"NetCaster/{_state.current_version}",
        },
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    sha = payload.get("sha", "")
    message = (payload.get("commit", {}).get("message") or "").splitlines()[0]
    short = sha[:7] if sha else ""
    return sha, short, message


def check_now() -> UpdateState:
    """Perform one update check and store the result."""
    with _state_lock:
        _state.current_version = _read_version_file()
        _state.current_sha = _read_current_sha()
        try:
            sha, short, message = _fetch_latest_from_github()
            _state.latest_sha = sha
            _state.latest_version = short
            _state.latest_message = message
            _state.error = ""
        except Exception as exc:
            _state.error = str(exc)
            logger.info("Update check failed: %s", exc)
        _state.checked_at = time.time()
    return _state


def _background_loop() -> None:
    while True:
        try:
            check_now()
        except Exception:
            logger.exception("Update checker crashed")
        time.sleep(CHECK_INTERVAL_SECONDS)


def start_background_checker() -> None:
    """Launch the polling thread once per process."""
    global _worker_started
    if _worker_started:
        return
    _worker_started = True
    # Prime state synchronously so the first page load has data
    try:
        _state.current_version = _read_version_file()
        _state.current_sha = _read_current_sha()
    except Exception:
        pass
    t = threading.Thread(target=_background_loop, name="netcaster-update-checker", daemon=True)
    t.start()
    logger.info("Update checker started (interval=%ds)", CHECK_INTERVAL_SECONDS)


def request_update() -> bool:
    """Write the update flag file that the scheduled task watches.

    Returns True on success, False if the flag directory doesn't exist
    or isn't writable.
    """
    try:
        UPDATE_FLAG_PATH.parent.mkdir(parents=True, exist_ok=True)
        UPDATE_FLAG_PATH.write_text(
            f"requested_at={int(time.time())}\n"
            f"current_sha={_state.current_sha}\n"
            f"target_sha={_state.latest_sha}\n",
            encoding="utf-8",
        )
        logger.info("Update flag written to %s", UPDATE_FLAG_PATH)
        return True
    except Exception as exc:
        logger.error("Could not write update flag: %s", exc)
        return False
