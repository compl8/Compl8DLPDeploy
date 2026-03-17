"""Shared utilities for the DLP data pipeline Python scripts."""

import json
from pathlib import Path


def find_spreadsheet(project_root, explicit_path=None):
    """Find the input spreadsheet.

    Priority:
      1. Explicit path (--xls argument)
      2. inputSpreadsheet from config/settings.json
      3. First *.xlsx in project root (excluding temp files)

    Returns Path or None.
    """
    if explicit_path:
        p = Path(explicit_path).resolve()
        if p.exists():
            return p
        return None

    # Check settings.json
    settings_path = Path(project_root) / "config" / "settings.json"
    if settings_path.exists():
        try:
            with open(settings_path, encoding="utf-8") as f:
                settings = json.load(f)
            name = settings.get("inputSpreadsheet", "")
            if name:
                p = Path(project_root) / name
                if p.exists():
                    return p
        except (json.JSONDecodeError, KeyError):
            pass

    # Glob fallback — any xlsx in project root, newest first
    candidates = sorted(Path(project_root).glob("*.xlsx"), key=lambda p: p.stat().st_mtime, reverse=True)
    candidates = [c for c in candidates if not c.name.startswith("~$")]
    if candidates:
        return candidates[0]

    return None
