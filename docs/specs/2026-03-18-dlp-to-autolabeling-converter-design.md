# DLP-to-Auto-Labeling Converter

**Date:** 2026-03-18
**Status:** Approved design, pending implementation

## Purpose

Walk into any Microsoft Purview tenant, scan its DLP compliance rules, and convert selected rules into auto-labeling policies. Produces an auditable plan file that records what was scanned, what was approved, and what was executed.

This enables organisations to predict labelling impact from proven DLP rules with low false positive rates, without manually rebuilding each rule in the auto-labeling UI.

## Design Principles

- **Framework-agnostic** — no QGISCF or other framework knowledge baked in. All context comes from tenant state, optional mapping JSON, and optional settings.json for naming. When settings.json is absent, naming falls back to tenant-derived defaults.
- **Plan-as-audit-trail** — the plan JSON is the single source of truth across scan, approval, and execution. Every decision is recorded.
- **User makes the call** — the tool doesn't score or filter rules by false positive risk. The user selects which DLP rules to convert and assigns labels.
- **Partial conversion is transparent** — when a DLP rule has conditions that auto-labeling can't replicate, the plan documents exactly what would be dropped and why.

## Two-Phase Flow

### Phase 1: Scan & Plan (`-Scan`)

```
Connect to tenant
  Read all DLP compliance rules (optionally filtered by -DlpPolicyFilter)
  Read existing auto-labeling policies (for scaling check)
  Read existing sensitivity labels (for interactive label assignment)

  For each DLP rule:
    Skip disabled rules by default (include with -IncludeDisabled)
    Extract: SIT conditions, scope conditions, unsupported conditions
    Classify: fully convertible / partial / unconvertible
    For partial: document each dropped condition (what + why)
    Resolve label assignment:
      1. Toolkit naming convention match -> auto-assign from config
      2. Mapping JSON match (supports wildcards) -> auto-assign
      3. Unknown -> prompt user to select from tenant labels
    Record assignment method (naming-convention / mapping-json / interactive)

  Scaling check:
    Count: existing auto-label policies + planned new policies
    Warn at configurable threshold (default 80)
    Hard block at tenant limit (default 100)
    Advisory note: 100K files/day limit, 4M simulation cap

  Write plan JSON to plans/ directory (auto-created, filename includes tenant+timestamp)
  Print formatted terminal summary (grouped by label)
  Interactive approval per label:
    "SENSITIVE-Financial: 3 DLP rules, 30 SITs, all convertible. Convert? [Y/n]"
    Option to drill into detail per rule
  Write approval decisions back to plan JSON
```

### Phase 2: Execute (`-Execute`)

```
Read approved plan JSON
  For each label group where approved = true:
    Create/update auto-labeling policy (ApplySensitivityLabel = label name)
    Create rules per workload with converted conditions
    Apply AccessScope and other scope params from source DLP rules
    Record source DLP rule name in Comment field for traceability
    All API calls use Invoke-WithRetry (throttle-safe)
  Stamp plan JSON with execution results (status, created rule names, timestamps)
  Print execution summary
```

## Label Assignment: Three Input Paths

### 1. Auto-detect (toolkit rules)

DLP rules matching our naming convention (`P{nn}-R{nn}-{WorkloadCode}-{LabelCode}-{Suffix}`) are parsed to extract the label code. The label code is resolved against the tenant's sensitivity labels.

When multiple label codes resolve to the same label name (e.g. `SENS_Pvca` and `SENS_Pvcb` both resolve to `SENSITIVE-Personal-Privacyv2`), they are grouped under the same label entry in the plan. The `labelCodes` field (array) tracks all contributing codes.

### 2. Pre-prepared mapping JSON

User provides a mapping file before running the scan. Format:

```json
{
  "mappings": [
    { "dlpRule": "Custom-PII-Rule-*", "label": "SENSITIVE-Personal-Privacy" },
    { "dlpRule": "Finance-*", "label": "SENSITIVE-Financial" },
    { "dlpRule": "P01-R04-ECH-SENS_Fin-EXT-ADT", "label": "SENSITIVE-Financialv2" }
  ]
}
```

- `dlpRule` supports exact names and wildcard patterns (`*`)
- `label` must match a sensitivity label name in the tenant
- First match wins (order matters for overlapping wildcards)

### 3. Interactive assignment

For DLP rules not matched by convention or mapping JSON, the user is prompted:

```
DLP Rule: Custom-Rule-SSN-Detection (Exchange, 5 SITs)
  No label mapping found. Select a label:
    1. OFFICIALv2
    2. SENSITIVE-Personal-Privacyv2
    3. SENSITIVE-Financialv2
    ...
    0. Skip (do not convert)
  >
```

### `-AutoApprove` behaviour

When `-AutoApprove` is set, all rules must be resolvable via naming convention or mapping JSON. If any DLP rule has no mapping match, the scan fails with an error listing the unmapped rules. The user must either add mappings or run without `-AutoApprove`.

## SIT Condition Extraction

DLP rules store conditions in two formats. The scanner handles both:

### Simple format

`ContentContainsSensitiveInformation` is a deserialized PSObject with `groups`, `operator`, and `sensitivetypes` properties. The scanner converts this to a normalised hashtable, preserving:
- Group structure (operator, name)
- Per-SIT fields: `name`, `id`, `mincount`, `maxcount`, `confidencelevel`

### AdvancedRule format

The entire condition is a JSON string in the rule's `AdvancedRule` property. `ContentContainsSensitiveInformation` may be null. The scanner:
1. Parses the JSON string
2. Extracts the `ContentContainsSensitiveInformation` subcondition
3. Extracts any scope conditions (`AccessScope`) embedded in the JSON
4. Checks for trainable classifiers (`classifiertype: "MLModel"`)

**Trainable classifiers**: DLP rules containing trainable classifiers in AdvancedRule JSON are classified as **unconvertible**. The auto-labeling `-AdvancedRule` parameter exists but is undocumented by Microsoft — until it is tested and confirmed working, these rules should not be converted. The plan records the reason: "Rule contains trainable classifiers (MLModel) in AdvancedRule format. Auto-labeling AdvancedRule support is undocumented."

### ExceptIf conditions

`ExceptIfContentContainsSensitiveInformation` and `ExceptIfAccessScope` are extracted and stored separately in the plan under `conditions.converted.exceptIf`:

```json
{
  "converted": {
    "ContentContainsSensitiveInformation": { "..." },
    "AccessScope": "NotInOrganization",
    "exceptIf": {
      "ExceptIfContentContainsSensitiveInformation": { "..." },
      "ExceptIfAccessScope": "InOrganization"
    }
  }
}
```

## SIT Condition Merging

When multiple DLP rules map to the same label and workload, their SIT conditions are merged into a single auto-labeling rule. Merge rules:

1. **SIT union (OR)**: All SITs from all source rules are combined into a single `groups` array with `operator: "Or"`. The original group structures are flattened — each source rule's SITs become one group in the merged condition.

2. **Duplicate SIT resolution**: If the same SIT ID appears in multiple source rules with different thresholds, use the **most permissive** values (lowest `minCount`, lowest confidence level). This matches the broadest source rule's behaviour. The plan logs the conflict and which values were chosen.

3. **Scope intersection**: If source rules have different `AccessScope` values (e.g. one is `NotInOrganization`, another has no scope), the merged rule uses the **most restrictive** scope. If scopes conflict irreconcilably, the merge is flagged as needing manual review.

4. **ExceptIf merging**: Exception conditions are intersected (AND) — the merged rule only excludes content that ALL source rules would have excluded.

5. **Format mismatch**: If one source rule uses Simple format and another uses AdvancedRule (non-TC), both are normalised to Simple format before merging. AdvancedRule conditions are parsed and their SIT subconditions extracted.

The plan records all merge decisions under a `mergeNotes` field on the label entry.

## Convertibility Classification

Each DLP rule is classified into one of three states:

### Fully convertible

All conditions have auto-labeling equivalents:
- `ContentContainsSensitiveInformation` (groups/operators/sensitivetypes) — Simple format only
- `ExceptIfContentContainsSensitiveInformation`
- `AccessScope` / `ExceptIfAccessScope`
- `ContentExtensionMatchesWords` / `ExceptIfContentExtensionMatchesWords`
- `ContentPropertyContainsWords`
- `DocumentIsPasswordProtected` / `DocumentIsUnsupported`
- `DocumentCreatedBy` / `DocumentNameMatchesWords`
- `DocumentSizeOver` (Exchange only)
- `SubjectMatchesPatterns` / `HeaderMatchesPatterns` (Exchange only)
- `SenderDomainIs` / `RecipientDomainIs` / `SentTo` / `SentToMemberOf`
- `AnyOfRecipientAddressContainsWords` / `AnyOfRecipientAddressMatchesPatterns`
- `FromAddressContainsWords` / `FromAddressMatchesPatterns`
- `SenderIPRanges`
- `ProcessingLimitExceeded`

### Partially convertible

Has convertible conditions (at minimum `ContentContainsSensitiveInformation`) plus one or more unsupported conditions. The plan documents each dropped condition:

```json
{
  "dropped": [
    {
      "condition": "SubjectContainsWords",
      "value": ["CONFIDENTIAL", "RESTRICTED"],
      "what": "Word matching on email subjects will be dropped",
      "why": "Auto-labeling rules only support regex patterns (SubjectMatchesPatterns), not word lists. The auto-labeling rule will match more broadly than the DLP rule."
    }
  ]
}
```

### Unconvertible

- Rules with no `ContentContainsSensitiveInformation` or `AdvancedRule` condition
- Rules containing trainable classifiers (`ClassifierType=MLModel`) in AdvancedRule format (auto-labeling AdvancedRule is undocumented)

## DLP-Only Conditions Reference

Conditions that exist on DLP rules but NOT on auto-labeling rules:

| Condition | Why it can't convert |
|-----------|---------------------|
| `FromScope` | No sender location filtering in auto-labeling. Partial workaround: `SenderDomainIs` or `SenderIPRanges`. |
| `From` / `FromMemberOf` | Reserved for internal Microsoft use on auto-labeling cmdlets. |
| `SenderADAttributeContainsWords` / `MatchesPatterns` | No AD attribute conditions in auto-labeling. |
| `RecipientADAttributeContainsWords` / `MatchesPatterns` | No AD attribute conditions in auto-labeling. |
| `MessageTypeMatches` | No message type filtering (AutoForward, Encrypted, etc.). |
| `SubjectContainsWords` | Only regex patterns available (`SubjectMatchesPatterns`). |
| `SubjectOrBodyContainsWords` / `MatchesPatterns` | No body content matching in auto-labeling. |
| `DocumentContainsWords` / `MatchesPatterns` | No document body word/pattern search. |
| `DocumentNameMatchesPatterns` | Only word matching available (`DocumentNameMatchesWords`). |
| `HeaderContainsWords` | Only regex patterns available (`HeaderMatchesPatterns`). |
| `ContentIsNotLabeled` / `AttachmentIsNotLabeled` / `MessageIsNotLabeled` | Cannot condition on existing label state. |
| `ContentIsShared` | Not available. |
| `HasSenderOverride` | Not available. |
| `MessageSizeOver` | Not available (auto-labeling has `DocumentSizeOver` for Exchange, not message size). |
| `WithImportance` | Not available. |
| `StopPolicyProcessing` | Not available — highest priority label wins. |
| `EvaluateRulePerComponent` | Not available. |
| `SharedByIRMUserRisk` | Not available. |

### Limits that differ

| Limit | DLP | Auto-labeling |
|-------|-----|---------------|
| `AnyOfRecipientAddressMatchesPatterns` | 300 regex | 10 regex |
| Policies per tenant | 10,000 | 100 |
| `-AdvancedRule` (trainable classifiers) | Documented JSON format | Parameter exists but undocumented |

## Scaling Guardrails

Thresholds are configurable via settings.json (`autoLabelWarnThreshold`, `autoLabelMaxPolicies`), defaulting to:

| Check | Threshold | Behaviour |
|-------|-----------|-----------|
| Total auto-labeling policies (existing + planned) | >= 80 | Warning printed |
| Total auto-labeling policies (existing + planned) | > 100 | Hard block, refuse to generate plan |
| Daily auto-label file limit | 100,000 | Advisory note in plan output |
| Simulation match cap | 4,000,000 files | Advisory note in plan output |

## Auto-Labeling Policy Structure

One policy per label, rules per workload (mirroring Deploy-AutoLabeling.ps1):

- Policy: `AL{nn}-{LabelCode}-{Prefix}-{Suffix}`
  - `Prefix` and `Suffix` come from `config/settings.json` when available
  - When settings.json is absent, `Prefix` defaults to `"ALC"` (Auto-Label Convert) and `Suffix` defaults to `"SIM"` (simulation)
- Rules: `AL{nn}-R{nn}-{WorkloadCode}-{LabelCode}-{Suffix}`
- Comment field records source DLP rule name(s) for traceability
- Mode: `TestWithoutNotifications` (simulation) by default

When multiple DLP rules map to the same label and workload, their SIT conditions are merged (see SIT Condition Merging section).

## Plan JSON Schema

```json
{
  "version": "1",
  "scanDate": "2026-03-18T18:00:00Z",
  "tenant": "testp4ttern.dev",
  "scannedBy": "natadmin@testp4ttern.dev",
  "existingAutoLabelPolicies": 12,
  "scalingStatus": "ok",
  "labels": {
    "SENSITIVE-Financialv2": {
      "labelCodes": ["SENS_Fin"],
      "approved": true,
      "approvedAt": "2026-03-18T18:05:00Z",
      "mergeNotes": [],
      "sourceRules": [
        {
          "dlpRuleName": "P01-R04-ECH-SENS_Fin-EXT-ADT",
          "dlpPolicyName": "P01-ECH-QGISCF-EXT-ADT",
          "workload": "Exchange",
          "disabled": false,
          "convertible": "full",
          "assignedBy": "naming-convention",
          "sitCount": 30,
          "conditions": {
            "converted": {
              "ContentContainsSensitiveInformation": { "operator": "And", "groups": ["..."] },
              "AccessScope": "NotInOrganization"
            },
            "exceptIf": {},
            "dropped": []
          },
          "executed": null
        },
        {
          "dlpRuleName": "P02-R04-ODB-SENS_Fin-EXT-ADT",
          "dlpPolicyName": "P02-ODB-QGISCF-EXT-ADT",
          "workload": "OneDriveForBusiness",
          "disabled": false,
          "convertible": "full",
          "assignedBy": "naming-convention",
          "sitCount": 30,
          "conditions": {
            "converted": {
              "ContentContainsSensitiveInformation": "...",
              "AccessScope": "NotInOrganization"
            },
            "exceptIf": {},
            "dropped": []
          },
          "executed": null
        }
      ]
    },
    "SENSITIVE-Legal": {
      "labelCodes": [],
      "approved": false,
      "approvedAt": null,
      "mergeNotes": [],
      "sourceRules": [
        {
          "dlpRuleName": "Custom-Legal-Hold-Rule",
          "dlpPolicyName": "Legal-DLP-Policy",
          "workload": "SharePoint",
          "disabled": false,
          "convertible": "partial",
          "assignedBy": "interactive",
          "sitCount": 9,
          "conditions": {
            "converted": {
              "ContentContainsSensitiveInformation": "..."
            },
            "exceptIf": {},
            "dropped": [
              {
                "condition": "SubjectOrBodyContainsWords",
                "value": ["LEGAL HOLD", "LITIGATION"],
                "what": "Body/subject word matching will be dropped",
                "why": "Auto-labeling has no equivalent to SubjectOrBodyContainsWords. The auto-labeling rule will trigger on SIT matches alone, without the additional keyword filter. This broadens the rule's scope."
              }
            ]
          },
          "executed": null
        }
      ]
    }
  },
  "unconvertible": [
    {
      "dlpRuleName": "Header-Only-Rule",
      "dlpPolicyName": "Custom-Policy",
      "reason": "Rule has no ContentContainsSensitiveInformation or AdvancedRule condition. Auto-labeling requires SIT-based conditions."
    },
    {
      "dlpRuleName": "TC-Detection-Rule",
      "dlpPolicyName": "ML-Policy",
      "reason": "Rule contains trainable classifiers (MLModel) in AdvancedRule format. Auto-labeling AdvancedRule support is undocumented."
    }
  ],
  "execution": {
    "executedAt": null,
    "policiesCreated": 0,
    "rulesCreated": 0,
    "failures": []
  }
}
```

## Execution Stamping

After execution, each source rule's `executed` field is updated:

```json
{
  "executed": {
    "status": "success",
    "autoLabelPolicyName": "AL04-SENS_Fin-ALC-SIM",
    "autoLabelRuleName": "AL04-R01-ECH-SENS_Fin-SIM",
    "timestamp": "2026-03-18T18:10:00Z"
  }
}
```

Failed conversions record the error:

```json
{
  "executed": {
    "status": "failed",
    "error": "Protection label not found: 'SENSITIVE-Financialv2'",
    "timestamp": "2026-03-18T18:10:05Z"
  }
}
```

## Cleanup

The `-Cleanup` phase reads the plan JSON and removes only resources that were successfully created during execution:

- Iterates `executed` stamps in the plan — only targets policies/rules with `status: "success"`
- Verifies each resource still exists before attempting removal
- Does not use pattern matching — exclusively uses plan-recorded identities
- Updates the plan JSON to reflect cleanup (clears `executed` stamps)

## Script Interface

```powershell
# Scan tenant, build plan, prompt for approval
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Scan

# Scan with pre-prepared mapping (skip interactive assignment for matched rules)
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Scan -MappingFile .\config\dlp-label-mapping.json

# Scan with auto-approve (no interactive prompts — requires mapping for all rules)
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Scan -MappingFile .\config\dlp-label-mapping.json -AutoApprove

# Scan only specific DLP policies
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Scan -DlpPolicyFilter "P0*-QGISCF*"

# Include disabled DLP rules in scan
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Scan -IncludeDisabled

# Execute an approved plan
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Execute -PlanFile .\plans\conversion-plan-2026-03-18.json

# Dry run execution
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Execute -PlanFile .\plans\conversion-plan-2026-03-18.json -WhatIf

# Cleanup auto-labeling policies created from a plan
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Cleanup -PlanFile .\plans\conversion-plan-2026-03-18.json
```

## Logging

Uses `Start-DeploymentLog` from the shared module (same pattern as Deploy-DLPRules.ps1 and Deploy-AutoLabeling.ps1). Transcript captures all scan output, approval decisions, and execution results.

## Dependencies

- `modules/DLP-Deploy.psm1` — connection management, retry logic (`Invoke-WithRetry`), SIT condition building
- `config/settings.json` — naming prefix/suffix (optional — falls back to `ALC`/`SIM` defaults)
- PowerShell 7+ with ExchangeOnlineManagement module

## Future Extension Points

- Plan JSON format is versioned (`"version": "1"`) for forward compatibility
- The scan/plan/execute pattern can be reused for other Purview object conversions (noted: potential for DLP element replication via text-based plans)
- Mapping JSON wildcards allow bulk assignment without per-rule entries
