#!/usr/bin/env python3
"""Refresh the SIT Risk Analysis spreadsheet from testpattern.dev's catalogue.

Report-only by default; --update appends new (enriched) patterns and syncs freshness
provenance, writing to --out. Never overwrites the input or curated values.
See docs/superpowers/specs/2026-06-27-catalog-refresh-design.md.

  python scripts/sync-spreadsheet.py                                  # report only
  python scripts/sync-spreadsheet.py --update --out SIT-...-v14.xlsx   # append new rows
"""
import argparse, csv, json, sys, urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import catalog_refresh as cr
from pipeline_utils import find_spreadsheet

CATALOG_URL = "https://testpattern.dev/patterns.json"
SHEET = "SIT Risk Analysis"


def fetch_catalog(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Compl8DLPDeploy/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    pats = data["patterns"] if isinstance(data, dict) and "patterns" in data else data
    if not isinstance(pats, list):
        raise ValueError("Unexpected catalogue response shape")
    return pats


def load_sheet_rows(xls_path):
    import openpyxl
    wb = openpyxl.load_workbook(str(xls_path), read_only=True, data_only=True)
    ws = wb[SHEET]
    rows = [list(r) for r in ws.iter_rows(min_row=2, values_only=True)]
    wb.close()
    return rows


def build_change_report(patterns, sheet_rows):
    skipped = sum(1 for p in patterns if cr.is_microsoft(p))
    catalog = cr.index_catalog(patterns)
    sheet = cr.index_sheet_rows(sheet_rows)
    added, removed, common = cr.reconcile(catalog, sheet)
    drift, tuned = [], []
    for s in common:
        ch = cr.detect_changes(catalog[s], sheet[s])
        if ch["drift"]:
            drift.append((s, ch["drift"]))
        if ch["tuned"]:
            tuned.append(s)
    return {"added": added, "removed": removed, "drift": drift,
            "tuned": tuned, "skipped_microsoft": skipped, "_catalog": catalog}


def write_report(report_dir, report):
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    with open(report_dir / "changes.csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["change", "slug", "detail"])
        for s in report["added"]:
            w.writerow(["added", s, ""])
        for s in report["removed"]:
            w.writerow(["removed", s, ""])
        for s, fields in report["drift"]:
            w.writerow(["drift", s, "; ".join(fields)])
        for s in report["tuned"]:
            w.writerow(["tuned", s, "version bump"])
    md = ["# Catalog refresh report", "",
          f"- Added: {len(report['added'])}",
          f"- Removed: {len(report['removed'])}",
          f"- Drifted: {len(report['drift'])}",
          f"- Tuned (version bump): {len(report['tuned'])}",
          f"- Skipped (source=microsoft replicas): {report['skipped_microsoft']}", ""]
    if report["added"]:
        md += ["## Added — need curation (tier + classification)", ""]
        md += [f"- `{s}`" for s in report["added"]]
    (report_dir / "report.md").write_text("\n".join(md), encoding="utf-8")


def _versioned_out(xls_path):
    p = Path(xls_path)
    return p.with_name(p.stem + ".refreshed" + p.suffix)


def main():
    ap = argparse.ArgumentParser(description="Refresh spreadsheet from testpattern.dev")
    ap.add_argument("--xls", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--catalog-url", default=CATALOG_URL)
    ap.add_argument("--report", default="reports/catalog-refresh")
    ap.add_argument("--update", action="store_true")
    ap.add_argument("--refresh-metadata", action="store_true")
    ap.add_argument("--in-place", action="store_true")
    ap.add_argument("--jurisdiction", default=None,
                    help="report-only: filter the catalogue to one jurisdiction (e.g. au)")
    args = ap.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    xls_path = find_spreadsheet(project_root, args.xls)
    if not xls_path:
        sys.exit("ERROR: no input spreadsheet (set --xls or settings.json inputSpreadsheet)")

    print(f"  Spreadsheet: {Path(xls_path).name}")
    patterns = fetch_catalog(args.catalog_url)
    print(f"  Catalogue patterns: {len(patterns)}")
    cr.assert_catalog_sane(patterns)
    if args.jurisdiction and args.update:
        sys.exit("ERROR: --jurisdiction is report-only (it would mark all other-region rows as removed); drop --update or --jurisdiction.")
    patterns = cr.filter_by_jurisdiction(patterns, args.jurisdiction)
    rows = load_sheet_rows(xls_path)
    report = build_change_report(patterns, rows)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_dir = Path(args.report) / stamp
    write_report(report_dir, report)
    print(f"  Added {len(report['added'])} | Removed {len(report['removed'])} | "
          f"Drift {len(report['drift'])} | Tuned {len(report['tuned'])} | "
          f"Skipped-MS {report['skipped_microsoft']}")
    print(f"  Report: {report_dir}")

    if not args.update:
        print("  (report only; pass --update to write the refreshed spreadsheet)")
        return

    from catalog_update import apply_update   # Task 5
    out_path = Path(args.out) if args.out else _versioned_out(xls_path)
    apply_update(xls_path, out_path, report["_catalog"], report["added"],
                 report["removed"], args.refresh_metadata, args.in_place)
    print(f"  Wrote: {out_path if not args.in_place else xls_path}")


if __name__ == "__main__":
    main()
