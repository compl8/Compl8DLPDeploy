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
from pathlib import Path

MAX_PACKAGE_SIZE = 148 * 1024  # 148KB, margin under 150KB
MAX_PACKAGES = 9
TESTPATTERN_API = "https://testpattern.dev/api/export/purview-bundle"
TIER_COLS = {"small": 9, "medium": 10, "large": 11}


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
        return resp.read().decode("utf-8")


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

    if args.dry_run:
        n = (len(slugs) + args.batch_size - 1) // args.batch_size
        print(f"\n  [DRY RUN] Would create ~{n} packages")
        return

    os.makedirs(output_dir, exist_ok=True)

    # Build work queue
    pkg_num = 0
    work = []
    for i in range(0, len(slugs), args.batch_size):
        pkg_num += 1
        work.append((slugs[i:i + args.batch_size], f"{prefix}-{args.tier}-{pkg_num:02d}"))

    results = []
    retry_queue = []

    while work or retry_queue:
        if not work:
            work = retry_queue
            retry_queue = []

        batch_slugs, pkg_name = work.pop(0)
        print(f"  {pkg_name} ({len(batch_slugs)} slugs)...", end=" ", flush=True)

        try:
            raw_xml = fetch_bundle(batch_slugs, pkg_name)
            xml_text = optimise(raw_xml, publisher)
            size = len(xml_text.encode("utf-8"))
            entities = count_entities(xml_text)

            if size > MAX_PACKAGE_SIZE:
                if len(batch_slugs) <= 5:
                    print(f"OVERSIZED ({size // 1024}KB, {len(batch_slugs)} slugs) - cannot split further")
                    continue
                half = len(batch_slugs) // 2
                print(f"OVERSIZED ({size // 1024}KB), splitting...")
                retry_queue.append((batch_slugs[:half], f"{pkg_name}a"))
                retry_queue.append((batch_slugs[half:], f"{pkg_name}b"))
                continue

            out_path = os.path.join(output_dir, f"{pkg_name}.xml")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(xml_text)

            print(f"OK ({entities} entities, {size // 1024}KB)")
            results.append({"name": pkg_name, "entities": entities, "size": size})

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
