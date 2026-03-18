# DLP-to-Auto-Labeling Converter

**Date:** 2026-03-18
**Status:** Approved design, pending implementation

## Purpose

Walk into any Microsoft Purview tenant, scan its DLP compliance rules, and convert selected rules into auto-labeling policies. Produces an auditable plan file that records what was scanned, what was approved, and what was executed.

This enables organisations to predict labelling impact from proven DLP rules with low false positive rates, without manually rebuilding each rule in the auto-labeling UI.

## Design Principles

- **Framework-agnostic** — no QGISCF or other framework knowledge baked in. All context comes from tenant state and optional mapping JSON.
- **Plan-as-audit-trail** — the plan JSON is the single source of truth across scan, approval, and execution. Every decision is recorded.
- **User makes the call** — the tool doesn't score or filter rules by false positive risk. The user selects which DLP rules to convert and assigns labels.
- **Partial conversion is transparent** — when a DLP rule has conditions that auto-labeling can't replicate, the plan documents exactly what would be dropped and why.

## Two-Phase Flow

### Phase 1: Scan & Plan (`-Scan`)

```
Connect to tenant
  Read all DLP compliance rules (all policies)
  Read existing auto-labeling policies (for scaling check)
  Read existing sensitivity labels (for interactive label assignment)

  For each DLP rule:
    Extract: SIT conditions, scope conditions, unsupported conditions
    Classify: fully convertible / partial / unconvertible
    For partial: document each dropped condition (what + why)
    Resolve label assignment:
      1. Toolkit naming convention match -> auto-assign from config
      2. Mapping JSON match (supports wildcards) -> auto-assign
      3. Unknown -> prompt user to select from tenant labels

  Scaling check:
    Count: existing auto-label policies + planned new policies
    Warn at 80 total policies
    Hard block at 100 (tenant limit)
    Advisory note: 100K files/day limit, 4M simulation cap

  Write plan JSON
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
  Stamp plan JSON with execution results (status, created rule names, timestamps)
  Print execution summary
```

## Label Assignment: Three Input Paths

### 1. Auto-detect (toolkit rules)

DLP rules matching our naming convention (`P{nn}-R{nn}-{WorkloadCode}-{LabelCode}-{Suffix}`) are parsed to extract the label code. The label code is resolved against the tenant's sensitivity labels.

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

## Convertibility Classification

Each DLP rule is classified into one of three states:

### Fully convertible

All conditions have auto-labeling equivalents:
- `ContentContainsSensitiveInformation` (groups/operators/sensitivetypes)
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

Rules that have no `ContentContainsSensitiveInformation` or `AdvancedRule` condition at all. Auto-labeling requires SIT-based conditions — rules based purely on sender/recipient, message type, or other non-SIT conditions cannot be converted.

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

| Check | Threshold | Behaviour |
|-------|-----------|-----------|
| Total auto-labeling policies (existing + planned) | >= 80 | Warning printed |
| Total auto-labeling policies (existing + planned) | > 100 | Hard block, refuse to generate plan |
| Daily auto-label file limit | 100,000 | Advisory note in plan output |
| Simulation match cap | 4,000,000 files | Advisory note in plan output |

## Auto-Labeling Policy Structure

One policy per label, rules per workload (mirroring Deploy-AutoLabeling.ps1):

- Policy: `AL{nn}-{LabelCode}-{Prefix}-{Suffix}`
- Rules: `AL{nn}-R{nn}-{WorkloadCode}-{LabelCode}-{Suffix}`
- Comment field records source DLP rule name(s) for traceability
- Mode: `TestWithoutNotifications` (simulation) by default

When multiple DLP rules map to the same label and workload, their SIT conditions are merged into a single auto-labeling rule.

## Plan JSON Schema

```json
{
  "version": 1,
  "scanDate": "2026-03-18T18:00:00Z",
  "tenant": "testp4ttern.dev",
  "scannedBy": "natadmin@testp4ttern.dev",
  "existingAutoLabelPolicies": 12,
  "scalingStatus": "ok",
  "mappingSource": "naming-convention+mapping-json",
  "labels": {
    "SENSITIVE-Financialv2": {
      "labelCode": "SENS_Fin",
      "approved": true,
      "approvedAt": "2026-03-18T18:05:00Z",
      "sourceRules": [
        {
          "dlpRuleName": "P01-R04-ECH-SENS_Fin-EXT-ADT",
          "dlpPolicyName": "P01-ECH-QGISCF-EXT-ADT",
          "workload": "Exchange",
          "convertible": "full",
          "sitCount": 30,
          "conditions": {
            "converted": {
              "ContentContainsSensitiveInformation": { "operator": "And", "groups": ["..."] },
              "AccessScope": "NotInOrganization"
            },
            "dropped": []
          },
          "executed": null
        },
        {
          "dlpRuleName": "P02-R04-ODB-SENS_Fin-EXT-ADT",
          "dlpPolicyName": "P02-ODB-QGISCF-EXT-ADT",
          "workload": "OneDriveForBusiness",
          "convertible": "full",
          "sitCount": 30,
          "conditions": {
            "converted": { "ContentContainsSensitiveInformation": "...", "AccessScope": "NotInOrganization" },
            "dropped": []
          },
          "executed": null
        }
      ]
    },
    "SENSITIVE-Legal": {
      "labelCode": null,
      "approved": false,
      "approvedAt": null,
      "sourceRules": [
        {
          "dlpRuleName": "Custom-Legal-Hold-Rule",
          "dlpPolicyName": "Legal-DLP-Policy",
          "workload": "SharePoint",
          "convertible": "partial",
          "sitCount": 9,
          "conditions": {
            "converted": {
              "ContentContainsSensitiveInformation": "..."
            },
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
    "autoLabelPolicyName": "AL04-SENS_Fin-QGISCF-EXT-ADT",
    "autoLabelRuleName": "AL04-R01-ECH-SENS_Fin-EXT-ADT",
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

## Script Interface

```powershell
# Scan tenant, build plan, prompt for approval
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Scan

# Scan with pre-prepared mapping (skip interactive assignment for matched rules)
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Scan -MappingFile .\config\dlp-label-mapping.json

# Scan with auto-approve (no interactive prompts — requires mapping for all rules)
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Scan -MappingFile .\config\dlp-label-mapping.json -AutoApprove

# Execute an approved plan
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Execute -PlanFile .\plans\conversion-plan-2026-03-18.json

# Dry run execution
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Execute -PlanFile .\plans\conversion-plan-2026-03-18.json -WhatIf

# Cleanup auto-labeling policies created from a plan
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Cleanup -PlanFile .\plans\conversion-plan-2026-03-18.json
```

## Dependencies

- `modules/DLP-Deploy.psm1` — connection management, retry logic, SIT condition building
- `config/settings.json` — naming prefix/suffix (for generated policy/rule names)
- PowerShell 7+ with ExchangeOnlineManagement module

## Future Extension Points

- Plan JSON format is versioned (`"version": 1`) for forward compatibility
- The scan/plan/execute pattern can be reused for other Purview object conversions
- Mapping JSON wildcards allow bulk assignment without per-rule entries
