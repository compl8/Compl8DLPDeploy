#!/usr/bin/env python3
"""Build deployment packages by fetching right-sized batches from testpattern.dev.

Fetches entities in batches from testpattern.dev's purview-bundle API with
dictionary placeholders, strips whitespace, and writes directly as UTF-8.
No XML parsing or reassembly — preserves the API's valid XML exactly.

If a batch exceeds 150KB, it's split in half and re-fetched.

Usage:
  python scripts/build-deploy-packages.py --tier medium
  python scripts/build-deploy-packages.py --tier medium --max-terms 5
  python scripts/build-deploy-packages.py --tier medium --dry-run
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

MAX_PACKAGE_UTF16 = 150 * 1024        # 153600 — Purview/testpattern hard cap, measured UTF-16LE
PREFERRED_PACKAGE_UTF16 = 148 * 1024  # 151552 — working budget under the cap
MAX_PACKAGES = 9                      # automated build cap; 10th tenant slot reserved for manual adds
TESTPATTERN_API = "https://testpattern.dev/api/export/purview-bundle"
TIER_COLS = {"small": 9, "medium": 10, "large": 11}


def utf16_len(text):
    return len(text.encode("utf-16-le"))


def ffd_assign(slug_sizes, wrapper, budget, max_packages):
    """First-Fit-Decreasing: place largest slugs first into bins of (budget - wrapper) capacity.
    Returns (bins, dropped). A slug exceeding an empty bin, or not fitting within max_packages, is dropped."""
    cap = budget - wrapper
    order = sorted(slug_sizes, key=lambda s: (-slug_sizes[s], s))
    bins, fills, dropped = [], [], []
    for slug in order:
        sz = slug_sizes[slug]
        placed = False
        for i in range(len(bins)):
            if fills[i] + sz <= cap:
                bins[i].append(slug); fills[i] += sz; placed = True; break
        if placed:
            continue
        if len(bins) < max_packages and sz <= cap:
            bins.append([slug]); fills.append(sz)
        else:
            dropped.append(slug)
    return bins, dropped


def load_slugs(xls_path, tier):
    """Load TestPattern slugs for the requested tier."""
    import openpyxl
    tier_col = TIER_COLS[tier]
    wb = openpyxl.load_workbook(str(xls_path), read_only=True, data_only=True)
    ws = wb["SIT Risk Analysis"]
    slugs = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not row[0]:
            continue
        slug = str(row[1] or "").strip()
        source = str(row[14] or "").strip()
        in_tier = str(row[TIER_COLS[tier]] or "").strip().upper() == "Y"
        is_uuid = (
            len(slug) == 36
            and slug.count("-") == 4
            and all(c in "0123456789abcdef-" for c in slug.lower())
        )
        if in_tier and source == "TestPattern" and slug and not is_uuid:
            slugs.append(slug)
    wb.close()
    return slugs


def load_settings(project_root):
    """Load prefix and publisher from settings.json."""
    path = os.path.join(str(project_root), "config", "settings.json")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("namingPrefix", "DLP"), data.get("publisher", "")
    return "DLP", ""


def fetch_bundle(slugs, name):
    """Fetch a purview-bundle XML from testpattern.dev with dictionaries."""
    slug_param = ",".join(slugs)
    url = f"{TESTPATTERN_API}?slugs={slug_param}&name={name}&dictionaries=true"
    req = urllib.request.Request(url, headers={"User-Agent": "Compl8DLPDeploy/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = resp.read()
    # The API serves UTF-16 LE with BOM (testpattern's native encoding); older responses
    # were UTF-8. The toolkit's recorded encoding decision is UTF-8, so transcode here and
    # normalise the declaration — the "modulo declared encoding decision" of the design's
    # Stage 3 parity rule.
    if raw.startswith(b"\xff\xfe"):
        text = raw.decode("utf-16-le").lstrip("﻿")
    else:
        text = raw.decode("utf-8")
    return text.replace(
        '<?xml version="1.0" encoding="utf-16"?>',
        '<?xml version="1.0" encoding="utf-8"?>',
        1,
    )


def optimise(xml_text, publisher):
    """Strip whitespace/comments and patch publisher. Preserves raw XML structure."""
    xml_text = re.sub(r"<!--.*?-->", "", xml_text, flags=re.DOTALL)
    xml_text = re.sub(r">\s+<", ">\n<", xml_text)
    if publisher:
        xml_text = re.sub(
            r"<PublisherName>[^<]*</PublisherName>",
            f"<PublisherName>{publisher}</PublisherName>",
            xml_text,
        )
    return xml_text


def count_entities(xml_text):
    return len(re.findall(r'<Entity\s+id="', xml_text))


def main():
    parser = argparse.ArgumentParser(description="Build deployment packages from testpattern.dev")
    parser.add_argument("--tier", choices=["small", "medium", "large"], default="medium")
    parser.add_argument("--xls", default=None)
    parser.add_argument("--output-dir", default="xml/deploy")
    parser.add_argument("--batch-size", type=int, default=35, help="Slugs per API call")
    parser.add_argument("--prefix", default=None, help="Package name prefix (default: from settings.json)")
    parser.add_argument("--publisher", default=None, help="Publisher name (default: from settings.json)")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--delay", type=float, default=1.0)
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    output_dir = str((project_root / args.output_dir).resolve())

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from pipeline_utils import find_spreadsheet
    xls_path = find_spreadsheet(project_root, args.xls)
    if not xls_path:
        print("ERROR: No input spreadsheet found. Specify with --xls or set inputSpreadsheet in settings.json", file=sys.stderr)
        sys.exit(1)

    cfg_prefix, cfg_publisher = load_settings(project_root)
    prefix = args.prefix or cfg_prefix
    publisher = args.publisher or cfg_publisher

    print(f"  Source: {xls_path.name}")
    print(f"  Tier: {args.tier}")
    print(f"  Batch size: {args.batch_size}")
    print(f"  Prefix: {prefix}")

    # Load slugs
    slugs = load_slugs(xls_path, args.tier)
    print(f"  Slugs: {len(slugs)}")

    # Exclude verified Microsoft built-ins from PACKING — they're referenced by GUID in the DLP
    # rules (Build-FromXLS), already exist in the tenant, and don't count toward our package limit.
    from _bfx_loaders import load_builtin_map
    builtin_map = load_builtin_map(os.path.join(str(project_root), "tenant-sits-full.csv"))
    if builtin_map:
        import openpyxl
        _wb = openpyxl.load_workbook(str(xls_path), read_only=True, data_only=True)
        _ws = _wb["SIT Risk Analysis"]
        name_by_slug = {str(r[1]).strip(): str(r[0]).strip()
                        for r in _ws.iter_rows(min_row=2, values_only=True) if r[0] and r[1]}
        _wb.close()
        _norm = lambda n: "".join(c for c in str(n or "").lower() if c.isalnum())
        before = len(slugs)
        slugs = [s for s in slugs if _norm(name_by_slug.get(s, "")) not in builtin_map]
        print(f"  Excluded {before - len(slugs)} Microsoft built-ins from packing (referenced by GUID instead)")

    if args.dry_run:
        n = (len(slugs) + args.batch_size - 1) // args.batch_size
        print(f"\n  [DRY RUN] Would create ~{n} packages")
        return

    os.makedirs(output_dir, exist_ok=True)

    # ---- Phase 1: measure each slug's UTF-16 footprint (single-slug bundle), cached ----
    cache_path = os.path.join(output_dir, ".size-cache.json")
    single = {}
    if os.path.isfile(cache_path):
        with open(cache_path, encoding="utf-8") as f:
            single = json.load(f)
    to_measure = [s for s in slugs if not single.get(s)]
    print(f"  Measuring {len(to_measure)} slugs (cached: {len(slugs) - len(to_measure)})...")
    for s in to_measure:
        try:
            single[s] = utf16_len(optimise(fetch_bundle([s], "measure"), publisher))
        except Exception as e:
            print(f"    measure {s}: FAILED {e} (skipping)")
            # Do NOT persist None — leave s absent so it is re-measured next run.
        time.sleep(args.delay)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in single.items() if v}, f, indent=2)
    live = {s: single[s] for s in slugs if single.get(s)}
    missing = [s for s in slugs if not single.get(s)]
    if missing:
        print(f"  WARNING: {len(missing)} slug(s) excluded from packing (measurement failed): {missing}")

    # ---- Phase 2: FFD assign on RAW single-slug sizes (the true per-slug cost when composed) ----
    # Empirically (measured on the real build), a composed package is ~= the sum of its slugs'
    # single-slug sizes minus only ~1KB/slug of shared scaffolding. Marginal-based packing
    # (single - wrapper) UNDER-counts and over-fills bins -> server 422 -> split -> too many pkgs.
    # So we pack on raw single sizes against a budget set ABOVE the hard cap by the composition
    # shrink (~16%): real_composed ~= 0.835 * sum(singles_in_bin). A 165KB singles-budget lands
    # real packages near ~138KB UTF-16, safely under the 150KB hard cap, in <=9 bins with 0 dropped.
    # Phase 3 still verifies the REAL size and splits any bin that overshoots, as a backstop.
    SINGLES_PACK_BUDGET = 165 * 1024
    bins, dropped = ffd_assign(live, wrapper=0, budget=SINGLES_PACK_BUDGET, max_packages=MAX_PACKAGES)
    if dropped:
        print(f"  WARNING: {len(dropped)} slug(s) dropped (no headroom in {MAX_PACKAGES} packages): {dropped}")

    # ---- Phase 3: fetch each bin, verify UTF-16 <= hard cap, write UTF-8 ----
    results = []
    work = [(b, f"{prefix}-{args.tier}-{i+1:02d}") for i, b in enumerate(bins)]
    while work:
        batch_slugs, pkg_name = work.pop(0)
        print(f"  {pkg_name} ({len(batch_slugs)} slugs)...", end=" ", flush=True)
        try:
            xml_text = optimise(fetch_bundle(batch_slugs, pkg_name), publisher)
            size16 = utf16_len(xml_text)
            if size16 > MAX_PACKAGE_UTF16 and len(batch_slugs) > 1:
                half = len(batch_slugs) // 2
                print(f"OVERSIZED ({size16 // 1024}KB UTF-16), splitting...")
                work.append((batch_slugs[:half], f"{pkg_name}a")); work.append((batch_slugs[half:], f"{pkg_name}b"))
                time.sleep(args.delay); continue
            elif size16 > MAX_PACKAGE_UTF16:
                print(f"OVERSIZED (single slug '{batch_slugs[0]}', {size16 // 1024}KB UTF-16) — exceeds 150KB, cannot deploy as-is")
                time.sleep(args.delay); continue
            entities = count_entities(xml_text)
            with open(os.path.join(output_dir, f"{pkg_name}.xml"), "w", encoding="utf-8") as f:
                f.write(xml_text)
            print(f"OK ({entities} entities, {size16 // 1024}KB UTF-16)")
            results.append({"name": pkg_name, "entities": entities, "size": size16})
        except urllib.error.HTTPError as e:
            if e.code == 422 and len(batch_slugs) > 1:
                half = len(batch_slugs) // 2
                print("OVERSIZED (server 422), splitting...")
                work.append((batch_slugs[:half], f"{pkg_name}a")); work.append((batch_slugs[half:], f"{pkg_name}b"))
            elif e.code == 422:
                print(f"OVERSIZED (server 422, single slug '{batch_slugs[0]}') — exceeds 150KB, cannot deploy as-is")
            else:
                print(f"FAILED: {e}")
        except Exception as e:
            print(f"FAILED: {e}")
        time.sleep(args.delay)

    # Write registry
    reg_path = os.path.join(output_dir, "deploy-registry.json")
    with open(reg_path, "w", encoding="utf-8") as f:
        json.dump({
            "tier": args.tier,
            "packages": [{"key": r["name"], "entities": r["entities"], "sizeKB": round(r["size"] / 1024, 1)} for r in results],
        }, f, indent=2)

    total_ents = sum(r["entities"] for r in results)
    print(f"\n  Done: {total_ents} entities across {len(results)} packages")
    if len(results) > MAX_PACKAGES:
        print(f"  WARNING: {len(results)} exceeds {MAX_PACKAGES} package limit!")
    print(f"  Written to {output_dir}")


if __name__ == "__main__":
    main()
