# SIT Catalog Rollout Runbook

**Purpose.** A repeatable process for rolling out **new and updated** SIT (classifier) items from the testpattern.dev catalog into the tiered, region-aware deployment sets — so each refresh is the same procedure, not a one-off.

**Status legend:** ✅ built · 📝 spec'd (design approved, not built) · 🔭 designed (in this runbook, spec pending).

---

## 1. The model (what we're maintaining)

```
testpattern.dev /patterns.json   ──refresh──▶  SIT Risk Analysis spreadsheet
        (1569 patterns, the catalog)                (curated selection + risk + tier layer)
                                                            │
                                              panel-score (risk/quality/coverage/usefulness)
                                                            │
                                                     re-tier + region packs
                                                            │
                                   small ~75   medium ~225   large ~450   (per-tenant, ≤500 ceiling)
                                   = core(tier) + region pack(tier)
                                                            │
                                          build-deploy-packages.py  ──▶  XML packages
                                                            │
                                                  deploy to tenant (Deploy-Classifiers)
```

**Capacity (per tenant):** 50 SITs/package · 10 packages · **500 custom SITs** — the binding ceiling. Tiers leave the customer headroom.

**Region model — core + packs.** `jurisdiction=global` patterns form the **core pool**; each jurisdiction (au, eu, us, …) is a **region pack**. A tenant build = `core(tier) + chosen region pack(s)(tier)`. Example splits: small 50c+25p · medium 150c+75p · large 300c+150p.

**Cross-repo map:**
- `Compl8DLPDeploy` (this repo) — spreadsheet, build, deploy, refresh + scoring tooling.
- `testpattern.dev` (`C:\claudecode\testpattern`) — the catalog/API; per-package size guardrail (now 770KB).
- `patterns` (`C:\claudecode\patterns`) — pattern YAML source (where new patterns, incl. snaffler, are authored).
- `C8GroundTruth` (`C:\dev\C8GroundTruth`) — judge wiring reused for scoring (xAI-OAuth Grok, codex/claude CLIs).

---

## 2. The rollout loop

Run this whenever the catalog changes (new patterns published, existing ones tuned) or before a deploy cycle.

### Stage 1 — Refresh 📝 (`scripts/sync-spreadsheet.py`, spec: `docs/superpowers/specs/2026-06-27-catalog-refresh-design.md`)
Pull `/patterns.json`, reconcile by slug, add new rows (enriched from catalog metadata), sync freshness provenance, report changes.
```
python scripts/sync-spreadsheet.py                      # report only (added / removed / drift / tuned)
python scripts/sync-spreadsheet.py --update --out SIT-Risk-Analysis-v<N>.xlsx
```
- **New items** → appended with catalog columns populated; tier/classification blank (filled by Stages 2–3).
- **Updated items** → a `version` increase is reported as **"tuned/updated"** (cols 24–26 Created/Updated/Version always synced). This is the trigger to re-score.
- Excludes `source=microsoft` replicas (built-ins are GUID-referenced). Never deletes; never overwrites curated values.

### Stage 2 — Panel-score 🔭 (spec pending)
Each candidate is scored by a **3-judge panel** — Claude + Codex + Grok — on four dimensions (1–5):
| Dimension | What it measures |
|---|---|
| **Risk** | severity if the data leaks (seeded from catalog `risk_rating`, judge-confirmed) |
| **SIT quality** | regex robustness, Boost-safety, test cases, false-positive handling, confidence |
| **Coverage** | unique data-category / jurisdiction / regulation coverage vs. redundancy |
| **Usefulness** | real-world prevalence / practical value for the tenant |

Scores aggregate (mean); wide disagreement is flagged for human review. Connection methods only (no framework): Grok via xAI-OAuth (`C8GroundTruth` TokenStore → `https://api.x.ai/v1/responses`, model `grok-4.3`), Codex via `codex exec`, Claude in-session. Batch ~20 patterns/call.

**Tuned-ness weighting (the maintenance signal).** Apply a weighting modifier from `version`/`updated`:
- `version ≥ 1.1.0` / `2.x` (bumped) or recently `updated` → **boost** — the item has been *tuned*, so it's more proven/useful.
- `version = 1.0.0`, never moved, old → **neutral-to-slight-discount** — may be untested or stale; scrutinize usefulness.
- `version = 0.1.0` (draft) → **discount** — not yet stable; generally exclude from small/medium.

Rationale: tuning is evidence of real use. `version` is the sharp proxy (catalog: 982 never-bumped vs ~573 tuned); `updated != created` alone is 84% of the catalog, too broad to discriminate.

### Stage 3 — Re-tier + region packs 🔭 (spec pending)
From aggregate scores (× tuned-ness weighting), assign **core + region-pack** tier membership to hit the targets, validate ≤500/tenant, write tier flags (cols 9–11) + an override column. Human overrides borderline picks.

### Stage 4 — Build + deploy ✅
```
python scripts/build-deploy-packages.py --tier <small|medium|large> --xls SIT-Risk-Analysis-v<N>.xlsx --output-dir xml/deploy[-test]
```
Packs to dense ≤50-SIT / ≤770KB packages (50-SIT limit binds). Then `Deploy-Classifiers.ps1` to a tenant (separate, gated).

---

## 3. Tier targets

| Tier | Total | Core (global) | Region pack | Notes |
|---|---|---|---|---|
| Small | ~70–80 | ~50 | ~25 | highest score × tuned, broad coverage |
| Medium | ~200–250 | ~150 | ~75 | the workhorse set |
| Large | ~450 | ~300 | ~150 | maximal, leaves customer headroom under 500 |

Tiers are nested (small ⊂ medium ⊂ large) within both core and each pack.

---

## 4. Handling new vs updated items (summary)

- **New pattern published** → Stage 1 adds it (blank tier) → Stage 2 scores it → Stage 3 places it if it earns a slot. Snaffler patterns arrive here automatically once authored in the `patterns` repo.
- **Existing pattern tuned (version bump)** → Stage 1 flags "tuned/updated" → re-score with the tuned-ness **boost** → Stage 3 may promote it. Tuning increases standing.
- **Pattern never moves (stale 1.0.0)** → carries no boost; over successive rounds it can be displaced from a tier by tuned, higher-scoring items — the discount expresses "untouched ≠ proven."
- **Pattern removed from catalog** → Stage 1 reports it; a human decides (could be a rename). Never auto-deleted.

---

## 5. References
- Stage 1 spec: `docs/superpowers/specs/2026-06-27-catalog-refresh-design.md`
- Build: `scripts/build-deploy-packages.py` · Deploy: `scripts/Deploy-Classifiers.ps1`
- Limits: `modules/Compl8.Model/Public/Get-DeploymentLimits.ps1` (770KB / 50-SIT)
- Judge wiring: `C:\dev\C8GroundTruth` (referrer backends, xAI OAuth)
