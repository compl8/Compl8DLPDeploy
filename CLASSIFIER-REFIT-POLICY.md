# Classifier Package Refit Policy

**Date:** 2026-05-20
**Status:** Required design guardrail, implementation hardening in place; tenant validation gates remain

## Purpose

Classifier package changes must preserve customer-owned sensitive information types and downstream DLP rule references wherever possible. The deployment workflow must prefer updating and refitting existing rule packages over deleting and recreating packages.

This matters because DLP rules reference sensitive information type entity IDs. If a package is deleted and classifiers are recreated with different entity IDs, downstream DLP rules, labels, auto-labeling policies, reports, or other tenant workflows can lose the classifier references they were built against. Even when entity IDs can theoretically be recreated, delete/recreate introduces propagation and identity risk that is avoidable when an in-place package update is possible.

## Operating Rules

- Use `Set-DlpSensitiveInformationTypeRulePackage` to update existing packages wherever possible.
- Do not remove a package just to make room for a regenerated package if the existing package can be refitted.
- Preserve existing customer classifier entities unless the customer explicitly approves removal.
- Preserve every entity ID currently referenced by DLP rules unless the referenced rules are also intentionally retired in the same approved plan.
- Treat package deletion as a last resort, not a normal deployment step.
- Plans must be framework-agnostic. QGISCF is only one input set; the same logic must work for any deployment prefix, package registry, and tenant state.
- Plans must be iterative. Do not assume the customer has exactly one package or that the remaining package slots are always free.

## Expected Tenant Shape

Most customers are expected to have one tenant-owned custom rule package containing their existing custom sensitive information types. In that common case:

- The customer package should normally be classified as protected and left alone.
- The deployment can consume the remaining available package slots with Compl8-generated packages.
- If the generated package set needs more slots than are available, the workflow must refit into existing package structures rather than deleting customer content.

The workflow must still handle non-typical tenants:

- No existing customer package.
- Multiple customer packages.
- Existing packages from prior Compl8 deployments.
- Packages with no entities.
- Packages with DLP references.
- Packages with no DLP references but unknown business ownership.
- Tenants where generated packages no longer fit within current package/entity/size limits.

## Package Classification

The planner should classify every non-Microsoft package into one of these states:

| State | Meaning | Default action |
|-------|---------|----------------|
| `ProtectedCustomerPackage` | Contains referenced entities or unknown/customer-owned content | Preserve as-is unless merge is explicitly planned |
| `ReusableCompl8Package` | Existing package already owned by this deployment and safe to update | Rebase/update in place |
| `ReusableEmptySlot` | Existing custom package has no entities and no references | Candidate for reuse after plan approval |
| `ReusableUnreferencedSlot` | Has entities, no detected references, and ownership is known or approved | Candidate for refit after review |
| `MergeRequired` | Customer/protected content and deployment content must share a package to fit capacity | Preserve existing entities and add/refit deployment entities |
| `DropRequired` | Required classifiers cannot fit safely under limits | Defer/drop selected classifiers and report exact reasons |
| `RetireCandidate` | Package appears unused and is not needed for refit | Removable only after explicit approval and a final reference scan |

## Refit Algorithm

The refit planner should run as a plan-first workflow:

1. Connect once and inventory all custom rule packages, sensitive information type entity IDs, DLP rules, and package XML.
2. Build a reference index of every DLP rule condition that mentions candidate entity IDs.
3. Classify all existing packages using ownership, publisher/name, rule pack ID, entity overlap, DLP references, and package content.
4. Resolve local deployment packages from `xml/deploy/deploy-registry.json` or an explicit package selection.
5. Try the lowest-risk fit first:
   - update existing Compl8-owned packages in place;
   - create packages only in genuinely free slots;
   - leave protected customer packages untouched.
6. If package slots are exhausted, try refitting into reusable or merge-required packages:
   - preserve the target RulePack ID;
   - preserve referenced entity IDs and their dependent XML resources;
   - add or replace deployment entities only where the plan says it is safe.
7. If the result exceeds entity, file size, or package count limits, iteratively drop the lowest-priority deployment classifiers until the plan fits.
8. Emit a plan JSON and Markdown summary that shows every preserved, updated, added, dropped, and retired entity/package.
9. Require explicit approval before applying the plan.
10. Apply approved changes with package updates first, using `Set-DlpSensitiveInformationTypeRulePackage`; use `New-DlpSensitiveInformationTypeRulePackage` only for new free slots; use `Remove-DlpSensitiveInformationTypeRulePackage` only for approved, unreferenced retire candidates.

## Implemented Hardening

The current implementation adds a shared dependency graph for keyword dictionary -> sensitive information type -> DLP rule -> DLP policy -> label relationships. Destructive package paths use this graph and a final tenant re-scan to block deletion when DLP rules still reference targeted classifier IDs.

Purview objects created by the toolkit can now carry a `Compl8DLPDeploy` provenance stamp with prefix, component, deployment ID, and target environment. Cleanup scope prefers matching provenance and treats prefix-only or broad heuristic matches as higher-risk evidence.

`RefitPlan` writes a reviewed plan bundle: `refit-plan.json`, `refit-summary.md`, draft XML, and a `refit-plan.sha256` sidecar. `ApplyRefitPlan` refuses to run when the sidecar is missing, malformed, or does not match the plan file hash.

Package deletion is gated by a current approved plan. `Remove` and `Prune` paths require `-RefitPlanPath` and `-ApproveRefitPlan`, verify that the plan is still current, require the target package to be classified as `RetireCandidate`, `ReusableEmptySlot`, or `ReusableUnreferencedSlot`, and re-check live references immediately before deletion.

Refit evidence now separates customer-preserved content from Compl8-applied content. The JSON and Markdown summaries list protected customer packages, preserved entity IDs, ready Compl8 assignments, deferred classifiers, and DLP rules that reference preserved or at-risk classifier IDs.

The refit planner has an entity-level split fallback. When package-level fit is insufficient, it can preserve referenced tenant entities and dependency resources, place Compl8 entities into existing package drafts where limits allow, and emit `DropRequired`/deferred classifier evidence for anything that cannot fit safely.

Dictionary sync records per-dictionary decision logs when a report directory is supplied. `dictionary-decisions.json` records create, reuse, merge, over-budget keep, opaque keep, and approved replace decisions so dictionary provenance and tenant preservation choices are reviewable.

## Enforcement Plan

### 1. Promote adoption/refit planning

Current baseline: `Deploy-Classifiers.ps1 -Action RefitPlan` emits a refit-first plan JSON and Markdown summary with package classifications, customer-preserved evidence, Compl8-applied evidence, DLP rule references, iterative fit results, entity-level split assignments, and drop-required entries. `Deploy-Classifiers.ps1 -Action ApplyRefitPlan` consumes a saved `refit-plan.json`, verifies its SHA-256 sidecar, updates existing package slots, and can create explicitly plan-approved new packages only when current free slots allow it.

Remaining hardening:

- Keep customer-package preservation decisions in `packager-input.json` aligned with the refit plan schema.

### 2. Gate destructive package paths

Current baseline: package-removal paths now require a current approved refit plan and run a reference guard before deletion. The shared guard parses targeted package XML, extracts entity IDs, scans DLP rules for references, and blocks removal if references remain or package XML cannot be parsed. `Reset-DeploymentScope.ps1` separately scans for external classifier references and blocks reset execution unless `-AllowBreakingExternalClassifierReferences` is explicitly supplied.

Remaining hardening:

- Keep package removal opt-in with explicit dangerous override names.

### 3. Make upload consume approved plans

Current baseline: `ApplyRefitPlan` applies saved ready refit assignments with `Set-DlpSensitiveInformationTypeRulePackage`, supports explicit `CreateInFreeSlot`/approved-new-slot assignments with `New-DlpSensitiveInformationTypeRulePackage` after checking current slot availability, and keeps deletion out of apply. Direct `Upload` in a tenant that already has custom non-Microsoft packages is blocked unless an approved `-RefitPlanPath` is supplied, `-Greenfield` is supplied, or the explicit `-AllowDirectUploadWithoutRefitPlan` override is used.

Remaining hardening:

- Never regenerate entity IDs for preserved tenant entities.

### 4. Reporting Baseline

Current baseline:

- Summary includes package slot usage, entity counts, file sizes, protected/reusable package classifications, dropped classifiers, entity-level split counts, and package/classifier transition counts.
- Reports separate "customer content preserved" from "Compl8 content applied".
- Reports show DLP rules that reference preserved, referenced, deferred, or at-risk entity IDs.
- Flight recorder manifests include the refit plan path and plan SHA-256 used for approved-plan deletion and apply operations.

### 5. Remaining Tenant Validation Gates

Before treating the hardening as production-validated for a customer tenant, run these live gates:

- Tenant fingerprint match for the intended `-TargetEnvironment`.
- Package/XML validation and dictionary placeholder resolution before upload or apply.
- Dictionary decision review, especially any merge, over-budget keep, opaque keep, or approved replace decision.
- Refit plan review with `refit-plan.sha256` retained beside the approved `refit-plan.json`.
- Current-plan deletion gate, including final tenant re-scan, for any `Remove` or `Prune` operation.
- Post-apply SIT visibility verification with tenant propagation time allowed before DLP rule deployment.
- DLP rule deployment dry run after classifier propagation to confirm referenced classifier IDs are visible.

### 6. Add Tests

Add tests or fixtures for:

- Tenant with one protected customer package and enough free slots.
- Tenant with one protected customer package and no free slots.
- Tenant with multiple customer packages.
- Tenant with external DLP rule references to targeted classifier IDs.
- Tenant with empty/unreferenced packages.
- Oversized refit draft requiring iterative classifier drops.
- Delete path refusing to run without an approved current plan.

## Non-Goals

- Automatically delete customer classifier content.
- Automatically rewrite customer DLP rules to new entity IDs.
- Assume QGISCF naming or package count.
- Assume one customer package is always present.
- Assume package deletion is safe because no toolkit-managed DLP rules reference it.

## Acceptance Criteria

- A deployment can update existing deployment-owned packages without deleting them.
- A customer package with referenced entities is preserved by default.
- If capacity is insufficient, the plan reports `MergeRequired` or `DropRequired` instead of deleting packages.
- Any remove/reset/prune path blocks when non-scoped DLP rules reference targeted classifier IDs.
- Every destructive operation has a current evidence export and a plan explaining why the operation is safe.
