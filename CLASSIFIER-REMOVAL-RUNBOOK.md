# Classifier Removal Runbook (Production)

**Audience:** operators deleting SIT classifier packages from a live Purview tenant.
**Companion:** `CLASSIFIER-REFIT-POLICY.md` (the *why*; this is the *how*).

> **Deletion is a last resort.** If you are *changing* classifier content, refit in place
> (`ApplyRefitPlan` → `Set-DlpSensitiveInformationTypeRulePackage`) — it keeps the existing
> SIT **entity IDs**, so DLP rules that reference them keep working and nothing below applies.
> Only follow this runbook for packages that are genuinely being **retired**.

All commands assume a single connected session. Concrete example tenant in this runbook:
`compl8.dev` (its fingerprint = the `nonprod` profile, `block`-pinned). Substitute
`<TENANT>`, `<ENV>`, `<PREFIX>`, `<PKG>` for your case.

> **Runnable from the TUI.** This whole gated sequence is available via `Start-DLPDeploy.ps1`
> option **`[10]` Remove SIT Packages** (guided), and within the **rollout wizard (`R`)**
> cleanup phase ("Surgical gated removal"). The CLI commands below are what those flows run.

---

## Why you can't just delete a referenced classifier

DLP rules reference SIT **entity GUIDs**. Delete a package whose entities a rule still
references and that rule silently under-matches. The tool refuses to let that happen: the
`Remove` path runs two hard gates plus the fingerprint gate before it will delete anything.

### What `Deploy-Classifiers.ps1 -Action Remove` enforces (in order)

1. **`Invoke-TenantFingerprintGate`** — connected tenant must match the `-TargetEnvironment`
   fingerprint. With `nonprod` in `block` mode, a wrong-tenant connection aborts here.
2. **`Assert-CurrentRefitPlanForPackageRemoval`** (deletion gate):
   - requires `-RefitPlanPath <refit-plan.json>` **and** `-ApproveRefitPlan`;
   - the plan must be **≤ 24 hours old** (regenerate if older);
   - **every** package you are removing must be classified in that plan as
     `RetireCandidate`, `ReusableEmptySlot`, or `ReusableUnreferencedSlot`. Anything else
     (e.g. `ProtectedCustomerPackage`) → the run throws and nothing is deleted.
3. **`Test-DlpRulePackageRemovalReferenceGuard`** (reference guard):
   - extracts the target packages' entity GUIDs, builds the dict→SIT→rule→policy→label
     graph, and scans **every live DLP rule** for those GUIDs;
   - if any rule references them → throws *"removal blocked by DLP rule reference guard"*
     **unless** `-AllowBreakingClassifierReferences` is supplied (dangerous — see below).
4. **Pre-flight impact check** (unless `-SkipPreFlight`) — if rule dependencies are found,
   an interactive `[R]emove / [A]bort` prompt.
5. **Embedded plan + final `[Y/N]` confirmation** before the actual
   `Remove-DlpSensitiveInformationTypeRulePackage`.

So to delete an actively-referenced classifier you must, in order: **(a)** have a current
approved plan that classifies it as retire/reusable, and **(b)** clear the DLP rule
references first. The steps below do exactly that.

---

## The process

### Step 0 — Confirm the tenant and what's deployed (read-only)

```
pwsh -File scripts/Deploy-Classifiers.ps1 -Action List   -Connect -Tenant <TENANT> -TargetEnvironment <ENV> -Prefix <PREFIX>
pwsh -File scripts/Deploy-Classifiers.ps1 -Action Impact -Connect -Tenant <TENANT> -TargetEnvironment <ENV> -Prefix <PREFIX>
```

`List` shows each deployed package (Identity, RulePackId, entity count). `Impact` shows the
dependency picture. Both run the fingerprint gate first — confirm it reports a **match** for
`<ENV>` before continuing. Note the **registry key(s)** of the package(s) you intend to delete
(e.g. `QGISCF-medium-08`) — you target removal by key.

### Step 0.5 — Capture the "old config" snapshot (MANDATORY before any delete)

The `Remove` path does **not** back up package XML before deleting, and there is no reverse
export of DLP rules into config — so capture a rebuild-grade snapshot first. This is
read-only and never touches the tenant:

```
pwsh -File scripts/Export-TenantSnapshot.ps1 -Connect -Tenant <TENANT> -TargetEnvironment <ENV>
```

It writes `backups/tenant-snapshots/<ENV>-<timestamp>/` containing:
- `classifiers/*.xml` — every deployed SIT rule-package's full XML (rebuild source),
- `live/*.json` — DLP policies+rules, **labels + label policies (incl. IRM/encryption
  settings)**, auto-labeling policies+rules, keyword dictionaries, and the SIT inventory,
- `config/*` + `xml-deploy/*` — the redeployable deploy config and source classifier XML,
- `snapshot-manifest.json` — tenant identity, counts, and file index.

Verify `snapshot-manifest.json` shows the expected package/rule/label/dictionary counts, then
keep the bundle (and commit the `config/` copy if you want it version-controlled). To recreate
DLP rules later you redeploy from the captured config; to rebuild classifiers you reuse the
captured package XML + keyword dictionaries.

### Step 1 — Generate the retire plan

```
pwsh -File scripts/Deploy-Classifiers.ps1 -Action RefitPlan -Connect -Tenant <TENANT> -TargetEnvironment <ENV> -Prefix <PREFIX>
```

This writes `reports/refit-plans/<run>/refit-plan.json`, `refit-summary.md`, and
`refit-plan.sha256`. **Open `refit-summary.md` and confirm:**
- each package you want gone is classified `RetireCandidate` (or `ReusableEmptySlot` /
  `ReusableUnreferencedSlot`). If it shows `ProtectedCustomerPackage` or lists referencing
  rules, it is **not** safe to delete yet — that's the plan telling you to do Step 2 first;
- note the listed **DLP rules that reference** the target entity IDs — those are what you
  must clear next.

Keep this plan path; you pass it in Step 4. **The plan expires in 24h** — do Steps 2–4 within
that window or regenerate it.

### Step 2 — Clear the DLP rule references (only if Step 1 listed any)

The reference guard (gate 3) will block while any rule references the target entities. Clear
them by one of:
- **Repoint/trim the rules:** remove the retiring SIT from `config/classifiers.json` (the
  SIT→label mapping), then redeploy rules — `Set-DlpComplianceRule` rewrites the rule
  conditions without that entity:
  ```
  pwsh -File scripts/Deploy-DLPRules.ps1 -Connect -Tenant <TENANT> -TargetEnvironment <ENV> -Prefix <PREFIX> -WhatIf   # preview
  pwsh -File scripts/Deploy-DLPRules.ps1 -Connect -Tenant <TENANT> -TargetEnvironment <ENV> -Prefix <PREFIX>           # apply
  ```
- **Or retire the rules** if they exist only to serve the retiring classifier:
  `Remove-OrphanedPolicies.ps1 -GhostDlpRules -DlpPolicy "<policy>" -Connect`, or a full rule
  teardown via `Deploy-DLPRules.ps1 -Connect -Cleanup`.

Re-run `-Action Impact` and confirm **zero** referencing rules for the target entity IDs
before proceeding.

### Step 3 — Dry-run the removal

```
pwsh -File scripts/Deploy-Classifiers.ps1 -Action Remove -PackageNames <PKG>,<PKG2> -WhatIf -Connect -Tenant <TENANT> -TargetEnvironment <ENV> -Prefix <PREFIX>
```

`-WhatIf` lists exactly which packages would be removed and stops — no gates, no changes.
**Always pass explicit `-PackageNames`**: it defaults to `All`, which would target every
registry package.

### Step 4 — Execute the gated removal

```
pwsh -File scripts/Deploy-Classifiers.ps1 -Action Remove -PackageNames <PKG>,<PKG2> `
     -RefitPlanPath "reports/refit-plans/<run>/refit-plan.json" -ApproveRefitPlan `
     -Connect -Tenant <TENANT> -TargetEnvironment <ENV> -Prefix <PREFIX>
```

At runtime this walks the gate sequence above: fingerprint match → current-plan gate
(≤24h + classified retire/reusable) → reference guard (must be zero references now) →
impact pre-flight (`R/A` if anything is still flagged) → final `Y/N`. Only then does it call
`Remove-DlpSensitiveInformationTypeRulePackage`.

### Step 5 — Verify

```
pwsh -File scripts/Deploy-Classifiers.ps1 -Action List -Connect -Tenant <TENANT> -TargetEnvironment <ENV> -Prefix <PREFIX>
```

Confirm the package(s) are gone and the remaining rules still resolve their classifiers.

---

## The dangerous override

`-AllowBreakingClassifierReferences` bypasses **only** the reference guard (gate 3). It still
requires the approved current plan (gate 2). Using it deletes a package that DLP rules still
reference, leaving those rules pointing at a non-existent SIT (silent under-match). Use it
only when those rules are being intentionally retired in the same change and you have explicit
sign-off. The tool prints a red warning and records the override in the flight-recorder
manifest. Prefer Step 2 (clear references first) in every normal case.

## Quick reference

| You want to… | Do this | Deletes anything? |
|---|---|---|
| Change a classifier's content | `RefitPlan` → `ApplyRefitPlan` (keeps entity IDs) | No |
| Free an empty/unreferenced slot | `RefitPlan` → `-Action Prune` (same gates) | Yes, gated |
| Retire a specific package | This runbook (`-Action Remove -PackageNames …`) | Yes, gated |
| Force-delete a referenced package | add `-AllowBreakingClassifierReferences` | Yes — breaks refs |

## Pre-flight checklist

- [ ] **`Export-TenantSnapshot.ps1` run and the snapshot bundle verified** (classifier XML, labels, dictionaries, DLP rules, and config all captured) — Step 0.5.
- [ ] Connected to the **right** tenant — fingerprint gate reported a `<ENV>` match.
- [ ] Current (≤24h) `refit-plan.json` exists, reviewed, with `refit-plan.sha256` beside it.
- [ ] Every target package is `RetireCandidate` / `ReusableEmptySlot` / `ReusableUnreferencedSlot` in that plan.
- [ ] DLP rule references to the target entity IDs are cleared (`-Action Impact` shows zero).
- [ ] `-WhatIf` removal preview lists exactly the intended `-PackageNames` and nothing else.
- [ ] You are **not** using `-AllowBreakingClassifierReferences` unless the referencing rules are intentionally retired with sign-off.
