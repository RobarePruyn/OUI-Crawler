"""IEEE OUI database loader and manufacturer lookup."""

import csv
import logging
from pathlib import Path
from typing import Optional

from .config import settings

logger = logging.getLogger(__name__)

_OUI_DB: dict[str, str] = {}


def _normalize_prefix(prefix: str) -> str:
    """Normalize an OUI prefix to uppercase hex without separators."""
    return prefix.replace(":", "").replace("-", "").replace(".", "").upper()[:6]


def load_oui_database(csv_path: Optional[Path] = None) -> int:
    """Load the IEEE OUI CSV into memory. Returns count of entries loaded."""
    global _OUI_DB
    path = csv_path or settings.oui_csv_path

    if not path.exists():
        logger.warning("IEEE OUI CSV not found at %s — manufacturer lookup disabled", path)
        return 0

    count = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                return 0

            for row in reader:
                if len(row) >= 3:
                    assignment = row[1].strip()
                    org_name = row[2].strip()
                    if assignment and org_name:
                        _OUI_DB[assignment.upper()[:6]] = org_name
                        count += 1
    except Exception:
        logger.exception("Failed to load IEEE OUI CSV from %s", path)
        return 0

    logger.info("Loaded %d OUI entries from IEEE database", count)
    return count


def lookup_manufacturer(oui_prefix: str) -> Optional[str]:
    """Look up a manufacturer name from a 3-byte OUI prefix."""
    normalized = _normalize_prefix(oui_prefix)
    if len(normalized) < 6:
        return None
    return _OUI_DB.get(normalized)
