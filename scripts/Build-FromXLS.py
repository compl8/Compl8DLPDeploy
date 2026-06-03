#!/usr/bin/env python3
"""
Build-FromXLS.py -- Generates DLP config from SIT Risk Analysis spreadsheet.

Reads the SIT Risk Analysis Excel workbook and generates:
  - config/classifiers.json (classifier -> label code mapping for DLP rules)
  - config/labels.json updates (validates label definitions match label sheet)
  - Gap report (classifiers needing XML packages, GUID resolution issues)

Automatically fetches TestPattern XML bundles from testpattern.dev API for any
TestPattern-sourced entries that lack GUIDs. Use --skip-fetch to disable.

Usage:
  python scripts/Build-FromXLS.py                                    # defaults
  python scripts/Build-FromXLS.py --xls SIT-Risk-Analysis-v11.xlsx   # specify file
  python scripts/Build-FromXLS.py --tier large                       # deployment tier
  python scripts/Build-FromXLS.py --dry-run                          # report only, no writes
  python scripts/Build-FromXLS.py --skip-fetch                       # skip testpattern.dev fetch
  python scripts/Build-FromXLS.py --label-sheet QGISCFDLM            # specify label sheet name
  python scripts/Build-FromXLS.py --scope tenant --env <env>         # per-tenant config
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Ensure sibling modules resolve regardless of CWD
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

from _bfx_loaders import (
    GUID_RE,
    load_spreadsheet,
    load_label_sheet,
    fetch_testpattern_bundles,
    build_xml_guid_lookup,
    build_existing_classifier_lookup,
    load_labels_json,
)
from _bfx_analysis import (
    filter_by_tier,
    build_classifiers_json,
    validate_labels,
    print_report,
)


def main():
    parser = argparse.ArgumentParser(
        description="Build DLP config from SIT Risk Analysis spreadsheet"
    )
    parser.add_argument(
        "--xls",
        default=None,
        help="Path to SIT Risk Analysis Excel file (default: auto-detect in project root)",
    )
    parser.add_argument(
        "--config-dir",
        default="config",
        help="Path to config directory (default: config/)",
    )
    parser.add_argument(
        "--scope",
        choices=["global", "tenant"],
        default="global",
        help="Write to global config/ or a per-tenant config/tenants/<env>/ (default: global)",
    )
    parser.add_argument(
        "--env",
        default=None,
        help="Tenant environment key (required when --scope tenant)",
    )
    parser.add_argument(
        "--xml-dir",
        default="xml",
        help="Path to XML packages directory (default: xml/)",
    )
    parser.add_argument(
        "--tier",
        choices=["small", "medium", "large"],
        default="large",
        help="Deployment tier to build for (default: large)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report only, don't write config files",
    )
    parser.add_argument(
        "--skip-fetch",
        action="store_true",
        help="Skip fetching TestPattern XML bundles from testpattern.dev",
    )
    parser.add_argument(
        "--include-unresolved",
        action="store_true",
        help="Include unresolved entries (slug as ID) in classifiers.json",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output path for classifiers.json (default: config/classifiers.json)",
    )
    parser.add_argument(
        "--label-sheet",
        default="QGISCFDLM",
        help="Name of the label definition sheet in the workbook (default: QGISCFDLM)",
    )

    args = parser.parse_args()

    if args.scope == "tenant":
        if not args.env:
            parser.error("--scope tenant requires --env <environment>")
        tenant_dir = os.path.join("config", "tenants", args.env)
        if not os.path.isdir(tenant_dir):
            parser.error(
                f"Tenant config not found: {tenant_dir}. "
                f"Seed it first: pwsh scripts/New-TenantConfig.ps1 -Environment {args.env}"
            )
        args.config_dir = tenant_dir

    # Resolve project root
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent
    config_dir = (project_root / args.config_dir).resolve()
    xml_dir = (project_root / args.xml_dir).resolve()

    # Auto-detect XLS file
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from pipeline_utils import find_spreadsheet
    xls_path = find_spreadsheet(project_root, args.xls)
    if not xls_path:
        print("ERROR: No input spreadsheet found. Specify with --xls or set inputSpreadsheet in settings.json", file=sys.stderr)
        sys.exit(1)

    print(f"  Source XLS:     {xls_path.name}")
    print(f"  Config dir:     {config_dir}")
    print(f"  XML dir:        {xml_dir}")
    print(f"  Tier:           {args.tier}")
    print(f"  TestPattern:    {'skip' if args.skip_fetch else 'fetch from testpattern.dev'}")

    # Load data sources
    print(f"\n  Loading spreadsheet...")
    all_entries = load_spreadsheet(str(xls_path))
    print(f"    {len(all_entries)} total entries")

    entries = filter_by_tier(all_entries, args.tier)
    print(f"    {len(entries)} entries for tier '{args.tier}'")

    # Fetch TestPattern XML bundles
    if not args.skip_fetch:
        tp_count = sum(1 for e in entries if e["source"] == "TestPattern" and not GUID_RE.match(e["guid_slug"]))
        if tp_count > 0:
            print(f"\n  Fetching TestPattern XML bundles ({tp_count} entries)...")
            fetched = fetch_testpattern_bundles(entries, str(xml_dir))
            print(f"    {fetched} bundles fetched")

    print(f"\n  Loading XML packages...")
    xml_lookup = build_xml_guid_lookup(str(xml_dir))
    print(f"    {len(xml_lookup)} entities from XML")

    print(f"  Loading existing classifiers.json...")
    classifier_lookup = build_existing_classifier_lookup(str(config_dir))
    print(f"    {len(classifier_lookup)} existing entries")

    # Load label definitions for validation
    label_sheet_data = load_label_sheet(str(xls_path), args.label_sheet)
    labels_json = load_labels_json(str(config_dir))
    label_issues = validate_labels(labels_json, label_sheet_data, args.label_sheet)

    # Build classifiers.json
    classifiers, stats = build_classifiers_json(
        entries, xml_lookup, classifier_lookup,
    )

    # Strip unresolved entries unless --include-unresolved
    if not args.include_unresolved:
        unresolved_names = {u["name"] for u in stats["unresolved"]}
        for label_code in list(classifiers.keys()):
            filtered = [e for e in classifiers[label_code] if e["name"] not in unresolved_names]
            if filtered:
                classifiers[label_code] = filtered
            else:
                del classifiers[label_code]

    # Print report
    print_report(stats, label_issues, len(entries), args.tier)

    # Count final output
    total_entries_out = sum(len(v) for v in classifiers.values())
    unique_names_out = len({e["name"] for v in classifiers.values() for e in v})
    print(f"\n  Output classifiers.json:")
    print(f"    {len(classifiers)} label codes")
    print(f"    {total_entries_out} total entries ({unique_names_out} unique classifiers)")
    for lc in classifiers:
        print(f"      {lc:12s}: {len(classifiers[lc]):4d}")

    if args.dry_run:
        print(f"\n  [DRY RUN] No files written.")
        return

    # Write classifiers.json
    output_path = Path(args.output) if args.output else config_dir / "classifiers.json"
    # Back up existing file
    if output_path.exists():
        import shutil
        backup_path = output_path.with_suffix(".json.bak")
        print(f"\n  Backing up existing: {output_path.name} -> {backup_path.name}")
        shutil.copy2(str(output_path), str(backup_path))

    with open(str(output_path), "w", encoding="utf-8") as f:
        json.dump(classifiers, f, indent=4, ensure_ascii=False)
    print(f"  Written: {output_path}")

    # Write unresolved report
    if stats["unresolved"]:
        report_path = config_dir / "classifiers-unresolved.json"
        with open(str(report_path), "w", encoding="utf-8") as f:
            json.dump(stats["unresolved"], f, indent=4, ensure_ascii=False)
        print(f"  Written: {report_path} ({len(stats['unresolved'])} entries needing XML)")
    else:
        # Clean up stale unresolved file
        report_path = config_dir / "classifiers-unresolved.json"
        if report_path.exists():
            report_path.unlink()
            print(f"  Removed: {report_path} (all entries resolved)")

    print(f"\n  Done.")


if __name__ == "__main__":
    main()
