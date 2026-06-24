"""
_bfx_analysis.py -- GUID resolution, assembly, validation and reporting for Build-FromXLS.py.

Handles: GUID resolution from multiple sources, tier filtering, classifiers.json
assembly, label validation, and gap-report printing. No I/O or network calls.
"""

import re
from collections import defaultdict

GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)


def _norm_name(n):
    return "".join(c for c in str(n or "").lower() if c.isalnum())


def resolve_guid(entry, xml_lookup, classifier_lookup, builtin_map=None):
    """Resolve GUID. Priority: verified Microsoft built-in (tenant) -> spreadsheet UUID -> XML -> existing -> unresolved."""
    # 0. Verified Microsoft built-in (authoritative; independent of packing).
    if builtin_map and _norm_name(entry["name"]) in builtin_map:
        return builtin_map[_norm_name(entry["name"])], "builtin"
    # 1. Spreadsheet GUID column (actual UUID format)
    if GUID_RE.match(entry["guid_slug"]):
        return entry["guid_slug"], "spreadsheet"

    # 2. XML package entity lookup (exact name match, including prefix-stripped)
    name_lower = entry["name"].lower()
    if name_lower in xml_lookup:
        return xml_lookup[name_lower]["guid"], "xml"

    # 3. Current classifiers.json fallback
    if name_lower in classifier_lookup:
        existing = classifier_lookup[name_lower]
        if existing["id"]:
            return existing["id"], "existing"

    return entry["guid_slug"], "unresolved"


def filter_by_tier(entries, tier):
    """Filter entries by deployment tier (small/medium/large)."""
    if tier == "large":
        return [e for e in entries if e["large"]]
    elif tier == "medium":
        return [e for e in entries if e["medium"]]
    elif tier == "small":
        return [e for e in entries if e["small"]]
    else:
        raise ValueError(f"Unknown tier: {tier}")


def build_classifier_entry(entry, guid, classifier_type):
    """Build a classifiers.json entry for the given classifier."""
    if classifier_type == "MLModel":
        return {
            "name": entry["name"],
            "id": guid,
            "classifierType": "MLModel",
        }
    else:
        # SIT, Regex, Keyword List all become SIT entries in DLP rules
        result = {
            "name": entry["name"],
            "id": guid,
        }
        # Add minCount/maxCount/confidenceLevel overrides if specified
        # (defaults are applied by Resolve-ClassifierConfig in the module)
        if entry.get("minCount"):
            result["minCount"] = entry["minCount"]
        if entry.get("maxCount"):
            result["maxCount"] = entry["maxCount"]
        if entry.get("confidenceLevel"):
            result["confidenceLevel"] = entry["confidenceLevel"]
        return result


def build_classifiers_json(entries, xml_lookup, classifier_lookup, builtin_map=None):
    """Build the full classifiers.json structure from spreadsheet entries.

    Returns (classifiers_dict, stats_dict).
    """
    classifiers = defaultdict(list)
    stats = {
        "resolved": {"builtin": 0, "spreadsheet": 0, "xml": 0, "existing": 0},
        "unresolved": [],
        "by_label": defaultdict(int),
        "by_type": defaultdict(int),
        "by_source": defaultdict(int),
    }

    # Deduplicate by (label_code, name)
    seen = set()

    for entry in entries:
        label_code = entry["label_code"]
        if not label_code:
            continue

        key = (label_code, entry["name"])
        if key in seen:
            continue
        seen.add(key)

        guid, source = resolve_guid(entry, xml_lookup, classifier_lookup, builtin_map)

        # Map classifier type from spreadsheet to classifiers.json type
        ct = entry["classifier_type"]
        if ct == "MLModel":
            cfg_type = "MLModel"
        else:
            cfg_type = "SIT"  # SIT, Regex, Keyword List all become SIT entries

        entry_obj = build_classifier_entry(entry, guid, cfg_type)
        classifiers[label_code].append(entry_obj)

        stats["by_label"][label_code] += 1
        stats["by_type"][ct] += 1
        stats["by_source"][entry["source"]] += 1

        if source == "unresolved":
            stats["unresolved"].append({
                "name": entry["name"],
                "label_code": label_code,
                "type": ct,
                "source": entry["source"],
                "slug": entry["guid_slug"],
            })
        else:
            stats["resolved"][source] += 1

    # Sort entries within each label code by name
    for label_code in classifiers:
        classifiers[label_code] = sorted(
            classifiers[label_code], key=lambda x: x["name"]
        )

    # Sort label codes alphabetically
    ordered = {}
    for k in sorted(classifiers.keys()):
        ordered[k] = classifiers[k]

    return ordered, stats


def validate_labels(labels_json, label_sheet_data, sheet_name="QGISCFDLM"):
    """Compare labels.json against label sheet for discrepancies."""
    issues = []

    # Build lookup from labels.json
    json_labels = {}
    for lbl in labels_json:
        display = lbl.get("displayName", "")
        if display:
            json_labels[display] = lbl

    # Check each label sheet entry
    for xl in label_sheet_data:
        name = xl["name"]
        if name not in json_labels:
            issues.append(f"{sheet_name} label '{name}' not found in labels.json")
            continue

        jl = json_labels[name]

        # Check tooltip text matches
        xl_tip = xl["tooltip"].replace(" -- ", " — ") if xl["tooltip"] else ""
        jl_tip = jl.get("tooltip", "")
        if xl_tip and jl_tip and not jl_tip.startswith(xl_tip[:50]):
            issues.append(f"Tooltip mismatch for '{name}': XLS starts '{xl_tip[:60]}...', JSON starts '{jl_tip[:60]}...'")

        # Check visual marking
        if xl["marking"] and jl.get("headerText"):
            if xl["marking"] != jl["headerText"]:
                issues.append(f"Header marking mismatch for '{name}': XLS='{xl['marking']}', JSON='{jl['headerText']}'")

    # Check for labels.json entries not in label sheet
    xl_names = {lbl["name"] for lbl in label_sheet_data}
    for jl in labels_json:
        dn = jl.get("displayName", "")
        if dn and not jl.get("isGroup") and dn not in xl_names:
            if jl.get("code") and "IT" in jl.get("code", ""):
                issues.append(f"labels.json has '{dn}' (code: {jl['code']}) but {sheet_name} sheet does not -- consider adding InfoTech labels to spreadsheet")
            else:
                issues.append(f"labels.json has '{dn}' but not in {sheet_name} sheet")

    return issues


def print_report(stats, label_issues, total_entries, tier):
    """Print the gap analysis report."""
    print(f"\n{'='*70}")
    print(f"  DLP Build Report -- Tier: {tier}")
    print(f"{'='*70}")

    resolved_total = sum(stats["resolved"].values())
    unresolved_total = len(stats["unresolved"])
    print(f"\n  Entries processed: {total_entries}")
    print(f"  GUIDs resolved:   {resolved_total}")
    print(f"    From builtin: {stats['resolved']['builtin']}")
    print(f"    From spreadsheet: {stats['resolved']['spreadsheet']}")
    print(f"    From XML packages: {stats['resolved']['xml']}")
    print(f"    From existing config: {stats['resolved']['existing']}")
    print(f"  Unresolved (need XML): {unresolved_total}")

    print(f"\n  By label code:")
    for lc in sorted(stats["by_label"]):
        print(f"    {lc:12s}: {stats['by_label'][lc]:4d}")

    print(f"\n  By classifier type:")
    for ct in sorted(stats["by_type"]):
        print(f"    {ct:15s}: {stats['by_type'][ct]:4d}")

    print(f"\n  By source:")
    for src in sorted(stats["by_source"]):
        print(f"    {src:20s}: {stats['by_source'][src]:4d}")

    if stats["unresolved"]:
        print(f"\n  --- Unresolved Entries ({unresolved_total}) ---")
        print(f"  These classifiers need XML SIT packages before DLP deployment:")
        by_lc = defaultdict(list)
        for u in stats["unresolved"]:
            by_lc[u["label_code"]].append(u)
        for lc in sorted(by_lc):
            items = by_lc[lc]
            print(f"\n    [{lc}] ({len(items)} entries)")
            for item in sorted(items, key=lambda x: x["name"])[:10]:
                print(f"      {item['name']} ({item['type']}, {item['source']})")
            if len(items) > 10:
                print(f"      ... and {len(items) - 10} more")

    if label_issues:
        print(f"\n  --- Label Validation Issues ({len(label_issues)}) ---")
        for issue in label_issues:
            print(f"    - {issue}")

    print(f"\n{'='*70}")
