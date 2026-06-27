"""Pure logic for refreshing the SIT Risk Analysis spreadsheet from testpattern.dev's
catalog. No I/O (no HTTP, no file writes) so it is unit-testable; the CLI wrapper
(sync-spreadsheet.py) does fetching, openpyxl reads/writes, and reporting.
See docs/superpowers/specs/2026-06-27-catalog-refresh-design.md.
"""
from __future__ import annotations

# 0-based column indices on the "SIT Risk Analysis" sheet.
COL_NAME, COL_SLUG, COL_CATEGORY, COL_RISK_DESC, COL_RISK_RATING, COL_REF_URL = 0, 1, 2, 3, 4, 5
COL_CLASSIFIER_TYPE, COL_SOURCE, COL_JURISDICTIONS, COL_SCOPE, COL_CONFIDENCE, COL_REGULATIONS = 13, 14, 15, 16, 17, 18
COL_CREATED, COL_UPDATED, COL_VERSION = 24, 25, 26   # appended (sheet currently ends at 23)
SHEET_WIDTH = 27

MICROSOFT_SOURCE = "microsoft"
QLD_SOURCE_CATALOG = "qld-custom"
SOURCE_QLD, SOURCE_TESTPATTERN = "QLD-Custom", "TestPattern"
SHEET_SOURCES = (SOURCE_TESTPATTERN, SOURCE_QLD)
MIN_CATALOG_SIZE = 500


def _join(value):
    if isinstance(value, (list, tuple)):
        return "; ".join(str(v) for v in value if v not in (None, ""))
    return "" if value is None else str(value)


def is_microsoft(pattern):
    return str(pattern.get("source") or "").strip().lower() == MICROSOFT_SOURCE


def derive_source(catalog_source):
    if str(catalog_source or "").strip().lower() == QLD_SOURCE_CATALOG:
        return SOURCE_QLD
    return SOURCE_TESTPATTERN


def index_catalog(patterns):
    out = {}
    for p in patterns:
        slug = str(p.get("slug") or "").strip()
        if not slug or is_microsoft(p):
            continue
        out[slug] = p
    return out


def index_sheet_rows(rows):
    out = {}
    for row in rows:
        if not row or len(row) <= COL_SOURCE or not row[COL_NAME]:
            continue
        source = str(row[COL_SOURCE] or "").strip()
        slug = str(row[COL_SLUG] or "").strip()
        if source in SHEET_SOURCES and slug:
            out[slug] = row
    return out


def reconcile(catalog_index, sheet_index):
    cat, sheet = set(catalog_index), set(sheet_index)
    return sorted(cat - sheet), sorted(sheet - cat), sorted(cat & sheet)


def assert_catalog_sane(patterns):
    if len(patterns) < MIN_CATALOG_SIZE:
        raise ValueError(
            f"Catalog has only {len(patterns)} patterns (< {MIN_CATALOG_SIZE} floor); "
            "refusing to diff against a possibly-degraded API.")
