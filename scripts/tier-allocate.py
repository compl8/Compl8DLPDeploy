#!/usr/bin/env python3
"""Generate tier assignments for custom SITs from the SIT-Risk-Analysis spreadsheet.

Outputs config/tier-assignments.json with Small/Medium/Large name lists.
"""

import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

def main():
    try:
        import openpyxl
    except ImportError:
        print("ERROR: openpyxl required", file=sys.stderr)
        sys.exit(1)

    project_root = Path(__file__).resolve().parent.parent
    candidates = sorted(project_root.glob("SIT-Risk-Analysis-v*.xlsx"), reverse=True)
    if not candidates:
        print("ERROR: No SIT-Risk-Analysis-v*.xlsx found in project root.", file=sys.stderr)
        sys.exit(1)
    xls_path = candidates[0]

    wb = openpyxl.load_workbook(str(xls_path), read_only=True, data_only=True)
    ws = wb["SIT Risk Analysis"]

    entries = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not row[0]:
            continue
        entries.append({
            "name": str(row[0]).strip(),
            "risk": row[4] if row[4] else 0,
            "label_code": str(row[12] or "").strip(),
            "type": str(row[13] or "").strip(),
            "source": str(row[14] or "").strip(),
            "category": str(row[2] or "").strip(),
            "jurisdictions": str(row[15] or "").strip(),
            "large": str(row[11] or "").strip().upper() == "Y",
        })
    wb.close()

    # Dedup the large pool
    large = [e for e in entries if e["large"]]
    seen = set()
    deduped = []
    for e in large:
        key = (e["label_code"], e["name"])
        if key not in seen:
            seen.add(key)
            deduped.append(e)

    # Cut non-AU jurisdictions
    pool = [e for e in deduped if e["jurisdictions"] in ("au", "global", "")]
    custom = [e for e in pool if e["source"] != "Microsoft Built-in"]
    builtin = [e for e in pool if e["source"] == "Microsoft Built-in"]

    print(f"Pool: {len(pool)} ({len(builtin)} built-in + {len(custom)} custom)")

    # Score custom SITs
    def priority_score(e):
        score = 0
        score += e["risk"] * 3
        if "qld" in e["name"].lower():
            score += 15
        elif e["jurisdictions"] == "au" or "australia" in e["name"].lower():
            score += 10
        elif e["jurisdictions"] == "global":
            score += 5
        t = e["type"]
        if t == "SIT":
            score += 4
        elif t == "MLModel":
            score += 3
        elif t == "Keyword List":
            score += 2
        elif t == "Regex":
            score += 1
        cat = e["category"].lower()
        if "credential" in cat or "secret" in cat:
            score += 3
        elif "health" in cat or "medical" in cat:
            score += 3
        elif "government" in cat or "public sector" in cat:
            score += 2
        elif "financial" in cat:
            score += 2
        elif "personal identity" in cat:
            score += 2
        return score

    for e in custom:
        e["score"] = priority_score(e)

    label_codes = sorted(set(e["label_code"] for e in custom))
    by_label = {
        lc: sorted([e for e in custom if e["label_code"] == lc], key=lambda x: -x["score"])
        for lc in label_codes
    }

    # Proportional allocation with PROT suppression
    def allocate_tier(pool_by_label, target, prot_weight=1.0, min_per_label=1):
        total_pool = sum(len(v) for v in pool_by_label.values())
        allocations = {}
        for lc, items in pool_by_label.items():
            proportion = len(items) / total_pool
            weight = prot_weight if lc.startswith("PROT") else 1.0
            raw = proportion * target * weight
            allocations[lc] = max(min_per_label, min(round(raw), len(items)))

        current = sum(allocations.values())
        for _ in range(200):
            if current == target:
                break
            if current < target:
                added = False
                for lc in sorted(allocations, key=lambda x: len(pool_by_label[x]), reverse=True):
                    if current >= target:
                        break
                    if allocations[lc] < len(pool_by_label[lc]):
                        allocations[lc] += 1
                        current += 1
                        added = True
                if not added:
                    break
            elif current > target:
                removed = False
                for lc in sorted(
                    allocations,
                    key=lambda x: (0 if x.startswith("PROT") else 1, len(pool_by_label[x])),
                ):
                    if current <= target:
                        break
                    if allocations[lc] > min_per_label:
                        allocations[lc] -= 1
                        current -= 1
                        removed = True
                if not removed:
                    break

        selected = []
        for lc, count in allocations.items():
            selected.extend(pool_by_label[lc][:count])
        return selected, allocations

    # Base Large allocation
    lg_base, _ = allocate_tier(by_label, 375, prot_weight=0.8)
    lg_base_names = set(e["name"] for e in lg_base)

    # OT/SCADA swap: find cut OT items
    ot_categories = ["Critical Infrastructure"]
    ot_keywords = [
        "PLC", "SCADA", "substation", "pipeline", "water treatment",
        "electric grid", "plant shutdown", "refinery", "rail signal",
        "air traffic", "port facility", "telecom core", "distributed control",
        "CCTV", "hazardous material", "OT cyber", "emergency restoration",
        "critical spare", "data protection impact",
    ]

    def is_ot(e):
        if e["category"] in ot_categories:
            return True
        name_lower = e["name"].lower()
        return any(kw.lower() in name_lower for kw in ot_keywords)

    ot_all_names = set(e["name"] for e in custom if is_ot(e))
    ot_cut = [e for e in custom if e["name"] not in lg_base_names and is_ot(e)]

    # Drop lowest-scored non-OT items to make room
    non_ot_in_large = sorted(
        [e for e in lg_base if e["name"] not in ot_all_names], key=lambda x: x["score"]
    )
    to_drop = non_ot_in_large[: len(ot_cut)]
    drop_names = set(e["name"] for e in to_drop)

    # Final Large = base - drops + OT swaps
    final_large = [e for e in lg_base if e["name"] not in drop_names] + ot_cut
    final_large_names = set(e["name"] for e in final_large)

    # Small and Medium
    sm_custom, _ = allocate_tier(by_label, 90, prot_weight=0.3)
    md_custom, _ = allocate_tier(by_label, 250, prot_weight=0.5)

    # Ensure subset property: fix Medium items not in Large
    md_not_in_lg = [e for e in md_custom if e["name"] not in final_large_names]
    if md_not_in_lg:
        # Replace with highest-scored Large items not already in Medium
        md_names = set(e["name"] for e in md_custom)
        replacements = sorted(
            [e for e in final_large if e["name"] not in md_names],
            key=lambda x: -x["score"],
        )
        md_custom = [e for e in md_custom if e["name"] in final_large_names]
        md_custom.extend(replacements[: len(md_not_in_lg)])

    # Fix Small items not in Medium
    md_names = set(e["name"] for e in md_custom)
    sm_not_in_md = [e for e in sm_custom if e["name"] not in md_names]
    if sm_not_in_md:
        sm_custom_names = set(e["name"] for e in sm_custom)
        replacements = sorted(
            [e for e in md_custom if e["name"] not in sm_custom_names],
            key=lambda x: -x["score"],
        )
        sm_custom = [e for e in sm_custom if e["name"] in md_names]
        sm_custom.extend(replacements[: len(sm_not_in_md)])

    # Build name sets (custom only - built-in always included)
    tiers = {
        "small": sorted(set(e["name"] for e in sm_custom)),
        "medium": sorted(set(e["name"] for e in md_custom)),
        "large": sorted(set(e["name"] for e in final_large)),
    }

    builtin_names = sorted(set(e["name"] for e in builtin))

    # Verify subset property
    sm_set = set(tiers["small"])
    md_set = set(tiers["medium"])
    lg_set = set(tiers["large"])
    assert sm_set <= md_set, f"Small not subset of Medium: {sm_set - md_set}"
    assert md_set <= lg_set, f"Medium not subset of Large: {md_set - lg_set}"

    # Write tier assignments
    output = {
        "_comment": "Custom SIT tier assignments. Built-in SITs are always included at all tiers.",
        "builtin_count": len(builtin_names),
        "small_custom": tiers["small"],
        "medium_custom": tiers["medium"],
        "large_custom": tiers["large"],
    }
    out_path = project_root / "config" / "tier-assignments.json"
    with open(str(out_path), "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # Print summary
    builtin_by_label = Counter(e["label_code"] for e in builtin)

    print()
    for tier_name, tier_list in [("SMALL", sm_custom), ("MEDIUM", md_custom), ("LARGE", final_large)]:
        by_lc = Counter(e["label_code"] for e in tier_list)
        by_type = Counter(e["type"] for e in tier_list)
        pkg = (len(tier_list) + 49) // 50
        total = len(tier_list) + len(builtin)
        print(f"=== {tier_name}: {len(tier_list)} custom + {len(builtin)} built-in = {total} total ({pkg} pkg) ===")
        all_labels = sorted(set(list(by_lc.keys()) + list(builtin_by_label.keys())))
        for lc in all_labels:
            c = by_lc.get(lc, 0)
            bi = builtin_by_label.get(lc, 0)
            print(f"  {lc:12s}: {c:3d} custom + {bi:3d} built-in = {c + bi:3d}")
        print(f"  Types: {dict(sorted(by_type.items()))}")
        print()

    print(f"Dropped for OT/SCADA swap ({len(to_drop)}):")
    for e in sorted(to_drop, key=lambda x: x["score"]):
        print(f"  score={e['score']:2d}  {e['label_code']:12s}  {e['name']}")
    print()
    print(f"OT/SCADA swapped in ({len(ot_cut)}):")
    for e in sorted(ot_cut, key=lambda x: x["name"]):
        print(f"  score={e['score']:2d}  {e['label_code']:12s}  {e['name']}")

    print(f"\nWritten: {out_path}")
    print(f"  Small:  {len(tiers['small'])} custom")
    print(f"  Medium: {len(tiers['medium'])} custom")
    print(f"  Large:  {len(tiers['large'])} custom")
    print(f"  Built-in (all tiers): {len(builtin_names)}")

    # Verify counts
    sm_total = len(set(tiers["small"] + builtin_names))
    md_total = len(set(tiers["medium"] + builtin_names))
    lg_total = len(set(tiers["large"] + builtin_names))
    print(f"\n  Totals: S={sm_total} M={md_total} L={lg_total}")


if __name__ == "__main__":
    main()
