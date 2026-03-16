#!/usr/bin/env python3
"""Sync the SIT Risk Analysis spreadsheet with testpattern.dev's current catalogue.

Compares the spreadsheet's SIT entries against testpattern.dev's pattern list
and reports:
  - New patterns on testpattern.dev not in the spreadsheet
  - Spreadsheet entries whose slugs no longer exist on testpattern.dev
  - Slug or name changes

Usage:
  python scripts/sync-spreadsheet.py                      # report only
  python scripts/sync-spreadsheet.py --update              # update spreadsheet
  python scripts/sync-spreadsheet.py --jurisdiction au     # filter by jurisdiction
"""

import argparse
import json
import sys
import urllib.request
from pathlib import Path


def load_spreadsheet_slugs(xls_path):
    """Load all TestPattern slugs from the spreadsheet."""
    import openpyxl
    wb = openpyxl.load_workbook(str(xls_path), read_only=True, data_only=True)
    ws = wb["SIT Risk Analysis"]

    entries = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not row[0]:
            continue
        name = str(row[0]).strip()
        slug = str(row[1] or "").strip()
        source = str(row[14] or "").strip()
        if source == "TestPattern" and slug:
            entries[slug] = {"name": name, "source": source}

    wb.close()
    return entries


def fetch_testpattern_catalogue(jurisdiction=None):
    """Fetch the full pattern catalogue from testpattern.dev."""
    url = "https://testpattern.dev/api/patterns"
    if jurisdiction:
        url += f"?jurisdiction={jurisdiction}"
    req = urllib.request.Request(url, headers={"User-Agent": "Compl8DLPDeploy/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if isinstance(data, list):
                return {p["slug"]: p for p in data if "slug" in p}
            elif isinstance(data, dict) and "patterns" in data:
                return {p["slug"]: p for p in data["patterns"] if "slug" in p}
            else:
                print(f"Unexpected API response format", file=sys.stderr)
                return {}
    except Exception as e:
        print(f"Failed to fetch catalogue: {e}", file=sys.stderr)
        return {}


def main():
    parser = argparse.ArgumentParser(description="Sync spreadsheet with testpattern.dev")
    parser.add_argument("--xls", default=None, help="Path to spreadsheet")
    parser.add_argument("--jurisdiction", default=None, help="Filter by jurisdiction (e.g. au)")
    parser.add_argument("--update", action="store_true", help="Update spreadsheet (add new patterns)")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent

    if args.xls:
        xls_path = Path(args.xls).resolve()
    else:
        candidates = sorted(project_root.glob("SIT-Risk-Analysis-v*.xlsx"), reverse=True)
        if not candidates:
            sys.exit("ERROR: No SIT-Risk-Analysis-v*.xlsx found")
        xls_path = candidates[0]

    print(f"  Spreadsheet: {xls_path.name}")

    # Load current spreadsheet state
    spreadsheet_slugs = load_spreadsheet_slugs(xls_path)
    print(f"  Spreadsheet TestPattern entries: {len(spreadsheet_slugs)}")

    # Fetch testpattern.dev catalogue
    print(f"  Fetching testpattern.dev catalogue...")
    catalogue = fetch_testpattern_catalogue(args.jurisdiction)
    if not catalogue:
        sys.exit("ERROR: Could not fetch catalogue")
    print(f"  TestPattern catalogue: {len(catalogue)} patterns")

    # Compare
    spreadsheet_set = set(spreadsheet_slugs.keys())
    catalogue_set = set(catalogue.keys())

    new_patterns = catalogue_set - spreadsheet_set
    removed_patterns = spreadsheet_set - catalogue_set
    common = spreadsheet_set & catalogue_set

    # Report
    print(f"\n=== Sync Report ===")
    print(f"  In both: {len(common)}")
    print(f"  New on testpattern.dev: {len(new_patterns)}")
    print(f"  In spreadsheet but not on testpattern.dev: {len(removed_patterns)}")

    if new_patterns:
        print(f"\n  --- New Patterns ({len(new_patterns)}) ---")
        print(f"  These exist on testpattern.dev but are not in the spreadsheet:")
        for slug in sorted(new_patterns)[:30]:
            p = catalogue[slug]
            name = p.get("name", slug)
            print(f"    {slug}: {name}")
        if len(new_patterns) > 30:
            print(f"    ... and {len(new_patterns) - 30} more")

    if removed_patterns:
        print(f"\n  --- Removed Patterns ({len(removed_patterns)}) ---")
        print(f"  These are in the spreadsheet but not on testpattern.dev:")
        for slug in sorted(removed_patterns)[:20]:
            entry = spreadsheet_slugs[slug]
            print(f"    {slug}: {entry['name']}")
        if len(removed_patterns) > 20:
            print(f"    ... and {len(removed_patterns) - 20} more")

    if not new_patterns and not removed_patterns:
        print(f"\n  Spreadsheet is in sync with testpattern.dev.")

    if args.update and new_patterns:
        print(f"\n  --update not yet implemented. New patterns listed above need manual addition to spreadsheet.")
        # TODO: Auto-add new patterns to spreadsheet with default tier/label assignments


if __name__ == "__main__":
    main()
