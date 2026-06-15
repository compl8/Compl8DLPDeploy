#!/usr/bin/env python3
"""Record content-parity fixtures from testpattern.dev (curation-side; run once).

Fetches each slug as a single-slug purview-bundle (fragment source) plus the full
batch bundle (golden), pipes both through the SAME optimise() as
build-deploy-packages.py, and writes:

  tests/fixtures/content/parity/inputs.json          slug order, package name, RulePack id
  tests/fixtures/content/parity/fragments/<slug>.json  compl8.fragment/v1 sections
  tests/fixtures/content/parity/golden/<package>.xml   pipeline output (UTF-8 no BOM, CRLF)

The recombination assumption (single-slug fragments compose to the batch bundle) is
asserted HERE, at record time: if the id sets differ, recording fails loudly.

Usage:
  python scripts/record-content-fixtures.py                       # defaults to QGISCF-medium-08
  python scripts/record-content-fixtures.py --package QGISCF-medium-08
  python scripts/record-content-fixtures.py --slugs a,b,c --package X-test-01
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

TESTPATTERN_API = "https://testpattern.dev/api/export/purview-bundle"


def load_settings(project_root):
    path = os.path.join(str(project_root), "config", "settings.json")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("namingPrefix", "DLP"), data.get("publisher", "")
    return "DLP", ""


def fetch_bundle(slugs, name):
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
    """IDENTICAL to build-deploy-packages.py optimise() — the parity contract depends on it."""
    xml_text = re.sub(r"<!--.*?-->", "", xml_text, flags=re.DOTALL)
    xml_text = re.sub(r">\s+<", ">\n<", xml_text)
    if publisher:
        xml_text = re.sub(
            r"<PublisherName>[^<]*</PublisherName>",
            f"<PublisherName>{publisher}</PublisherName>",
            xml_text,
        )
    return xml_text


def extract_slug_order(xml_text):
    """Entity order from a deployed package: each Entity's first idRef trailing-slug token."""
    slugs = []
    for entity in re.findall(r"<Entity .*?</Entity>", xml_text, re.DOTALL):
        m = re.search(r'idRef="[A-Za-z]+_[^"]*_([a-z0-9][a-z0-9-]*)"', entity)
        if not m:
            raise SystemExit(f"ERROR: cannot derive slug from entity: {entity[:120]}")
        if m.group(1) not in slugs:
            slugs.append(m.group(1))
    return slugs


def extract_sections(optimised_text):
    rules = optimised_text.split("<Rules>", 1)[1].rsplit("</Rules>", 1)[0]
    loc = re.search(r"<LocalizedStrings>(.*?)</LocalizedStrings>", rules, re.DOTALL)
    resources = (
        re.findall(r'<Resource idRef="[^"]+">.*?</Resource>', loc.group(1), re.DOTALL)
        if loc
        else []
    )
    body = re.sub(r"<LocalizedStrings>.*?</LocalizedStrings>", "", rules, flags=re.DOTALL)
    entities = re.findall(r"<Entity .*?</Entity>", body, re.DOTALL)
    if len(entities) != 1:
        raise SystemExit(f"ERROR: expected 1 entity in single-slug bundle, found {len(entities)}")
    return {
        "entity": entities[0],
        "regexes": re.findall(r'<Regex id="[^"]+">.*?</Regex>', body, re.DOTALL),
        "keywords": re.findall(r'<Keyword id="[^"]+">.*?</Keyword>', body, re.DOTALL),
        "filters": re.findall(r"<Filter\b[^>]*>.*?</Filter>", body, re.DOTALL),
        "validators": re.findall(r"<Validator\b[^>]*>.*?</Validator>", body, re.DOTALL),
        "resources": resources,
    }


def rules_ids(optimised_text):
    rules = optimised_text.split("<Rules>", 1)[1].rsplit("</Rules>", 1)[0]
    return set(re.findall(r'\bid="([^"]+)"', rules))


def main():
    parser = argparse.ArgumentParser(description="Record content-parity fixtures")
    parser.add_argument("--package", default="QGISCF-medium-08")
    parser.add_argument("--from-xml", default=None, help="Deployed XML to derive slug order from")
    parser.add_argument("--slugs", default=None, help="Explicit comma-separated slug order")
    parser.add_argument("--out", default="tests/fixtures/content/parity")
    parser.add_argument("--delay", type=float, default=1.0)
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    out_dir = (project_root / args.out).resolve()
    _, publisher = load_settings(project_root)

    if args.slugs:
        slugs = [s.strip() for s in args.slugs.split(",") if s.strip()]
    else:
        xml_path = Path(args.from_xml) if args.from_xml else project_root / "xml" / "deploy" / f"{args.package}.xml"
        if not xml_path.is_file():
            raise SystemExit(f"ERROR: {xml_path} not found; pass --slugs or --from-xml")
        slugs = extract_slug_order(xml_path.read_text(encoding="utf-8"))
    print(f"  Package: {args.package}")
    print(f"  Publisher: {publisher}")
    print(f"  Slugs ({len(slugs)}): {', '.join(slugs)}")

    print(f"  Fetching batch bundle...", flush=True)
    golden = optimise(fetch_bundle(slugs, args.package), publisher)
    m = re.search(r'<RulePack id="([^"]+)">', golden)
    if not m:
        raise SystemExit("ERROR: batch bundle has no RulePack id")
    rule_pack_id = m.group(1)
    batch_entities = len(re.findall(r"<Entity ", golden))
    if batch_entities != len(slugs):
        raise SystemExit(
            f"ERROR: requested {len(slugs)} slugs but the batch bundle has {batch_entities} "
            "entities — the API silently dropped unknown slug(s). Fix the slug list "
            "(--slugs) before recording."
        )
    golden_ids = rules_ids(golden)
    time.sleep(args.delay)

    (out_dir / "fragments").mkdir(parents=True, exist_ok=True)
    (out_dir / "golden").mkdir(parents=True, exist_ok=True)

    fragment_ids = set()
    for slug in slugs:
        print(f"  Fetching fragment {slug}...", flush=True)
        try:
            single = optimise(fetch_bundle([slug], slug), publisher)
        except urllib.error.HTTPError as e:
            raise SystemExit(
                f"ERROR: slug '{slug}' fetch failed ({e.code}) — it may have been renamed or "
                "removed upstream; fix the slug list before recording."
            )
        sections = extract_sections(single)
        entity_id = re.search(r'<Entity id="([^"]+)"', sections["entity"]).group(1)
        fragment_ids |= rules_ids(single)
        fragment = {
            "schemaVersion": "compl8.fragment/v1",
            "slug": slug,
            "entityId": entity_id,
            "sections": sections,
        }
        with open(out_dir / "fragments" / f"{slug}.json", "w", encoding="utf-8", newline="\n") as f:
            json.dump(fragment, f, indent=2)
        time.sleep(args.delay)

    # The fragment-compose assumption, checked at record time: recombined ids must equal
    # the batch bundle's ids exactly (catches per-bundle id namespacing differences).
    if fragment_ids != golden_ids:
        only_frag = sorted(fragment_ids - golden_ids)
        only_gold = sorted(golden_ids - fragment_ids)
        print("ERROR: fragment/batch id sets differ — fragment composition is NOT valid here.", file=sys.stderr)
        if only_frag:
            print(f"  only in fragments: {only_frag}", file=sys.stderr)
        if only_gold:
            print(f"  only in batch:     {only_gold}", file=sys.stderr)
        sys.exit(1)

    # Golden bytes: UTF-8 no BOM, CRLF — written binary so recording is OS-independent.
    golden_bytes = golden.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")
    with open(out_dir / "golden" / f"{args.package}.xml", "wb") as f:
        f.write(golden_bytes)

    inputs = {
        "package": args.package,
        "slugs": slugs,
        "rulePackId": rule_pack_id,
        "publisher": publisher,
        "entities": len(slugs),
        "recordedUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with open(out_dir / "inputs.json", "w", encoding="utf-8", newline="\n") as f:
        json.dump(inputs, f, indent=2)

    print(f"  Done: {len(slugs)} fragments + golden ({len(golden_bytes)} bytes) -> {out_dir}")


if __name__ == "__main__":
    main()
