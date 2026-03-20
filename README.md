# Compl8 DLP Deployment Toolkit

Config-driven Data Loss Prevention (DLP) deployment engine for Microsoft Purview. Deploys sensitivity labels, keyword dictionaries, custom Sensitive Information Type (SIT) rule packages, and DLP policies/rules — all from JSON configuration files.

Framework-agnostic: works with PSPF (Australia), NZISM (New Zealand), UK GSC, or any custom classification framework. Ships with a Queensland Government (QGISCF) reference configuration.

Two data pipeline options: generate classifier config from a **spreadsheet** (with optional [testpattern.dev](https://testpattern.dev) integration), or **import directly from an existing tenant**.

## Prerequisites

- PowerShell 7+ (or 5.1 with limitations)
- [ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement) module
- Microsoft Purview Compliance admin permissions (Compliance Administrator or equivalent)
- Python 3.x with `openpyxl` (for spreadsheet pipeline scripts only)

## Architecture

The toolkit has two layers: a **data pipeline** that decides *what* to deploy, and a **deployment engine** that deploys it.

### Data Pipeline Options

There are two ways to generate the `config/classifiers.json` that drives deployment:

**Option A: Spreadsheet Pipeline** — for users with a SIT risk analysis workbook and/or testpattern.dev integration:

```
Input Spreadsheet (SIT-Inputs-Example.xlsx)
         │
         ▼
  Build-FromXLS.py ──► config/classifiers.json
    Reads spreadsheet, resolves SIT GUIDs,
    outputs classifier-to-label mapping
         │
         ▼
  build-deploy-packages.py ──► xml/deploy/*.xml
    Fetches SIT patterns from testpattern.dev,
    bin-packs into right-sized packages
```

**Option B: Tenant Import** — for users importing SITs from an existing tenant (no spreadsheet or testpattern.dev needed):

```
Source Tenant (any M365 tenant)
         │
         ▼
  Export-TenantSITs.ps1 ──► config/tenant-sits.json
    Exports all SIT names, GUIDs, and publishers
         │
         ▼
  Build-ClassifierSchema.py --init ──► config/classifier-mapping.csv
    Generates editable CSV template
         │  (user fills in LabelCode column)
         ▼
  Build-ClassifierSchema.py --apply ──► config/classifiers.json
    Reads mapping, generates config
```

Both options produce the same `classifiers.json` format consumed by the deployment engine.

### Deployment Engine

```
  config/classifiers.json + config/labels.json + config/policies.json
         │
         ▼
  greenfield-deploy.ps1  (or full-deploy.ps1)
    Creates keyword dictionaries, deploys          ──► Purview tenant
    labels, uploads packages, creates
    DLP policies and rules
```

## Quick Start

### Option A: From Spreadsheet

```powershell
# 1. Set your spreadsheet name in config/settings.json (inputSpreadsheet field)
#    or place your .xlsx in the project root

# 2. Generate classifiers.json from the spreadsheet
python scripts/Build-FromXLS.py --tier medium

# 3. Build SIT packages from testpattern.dev (if using TestPattern SITs)
python scripts/build-deploy-packages.py --tier medium --max-terms 5

# 4. Deploy everything (PublishTo is mandatory — specify a named group or user)
pwsh -File scripts/greenfield-deploy.ps1 -UPN admin@yourtenant.onmicrosoft.com -PublishTo "DL-InfoSec@agency.gov"
```

### Option B: From Existing Tenant

```powershell
# 1. Export SITs from your source tenant
pwsh -File scripts/Export-TenantSITs.ps1 -Connect -UPN admin@source-tenant.com

# 2. Generate a mapping CSV template
python scripts/Build-ClassifierSchema.py --init

# 3. Open config/classifier-mapping.csv in Excel or a text editor
#    Fill in the LabelCode column for each SIT you want to include
#    (or use --auto to pre-fill with keyword-based rules)
python scripts/Build-ClassifierSchema.py --auto

# 4. Review the CSV, then generate classifiers.json
python scripts/Build-ClassifierSchema.py --apply

# 5. Deploy (PublishTo is mandatory — specify a named group or user)
pwsh -File scripts/greenfield-deploy.ps1 -UPN admin@target-tenant.onmicrosoft.com -PublishTo "DL-InfoSec@agency.gov"
```

### Phased Deployment

For more control, deploy in phases:

```powershell
# Phase 1: Labels only (PublishTo is mandatory)
pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Labels -PublishTo "DL-InfoSec@agency.gov"

# Phase 1.5: Keyword dictionaries
pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Dictionaries -PublishTo "DL-InfoSec@agency.gov"

# Phase 2: SIT classifier packages
pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Classifiers -PublishTo "DL-InfoSec@agency.gov"

# Phase 3: DLP rules (wait 1-24h after Phase 2 for SIT propagation)
pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase DLPRules -PublishTo "DL-InfoSec@agency.gov"

# Cleanup everything
pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Cleanup -PublishTo "DL-InfoSec@agency.gov"

# Dry run
pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -WhatIf -PublishTo "DL-InfoSec@agency.gov"
```

## The Input Spreadsheet

The included `SIT-Inputs-Example.xlsx` is an example spreadsheet for the QGISCF framework. To create your own, use a workbook with a sheet named **"SIT Risk Analysis"** containing these columns (0-indexed):

| Col | Header | Description | Example |
|-----|--------|-------------|---------|
| 0 | SIT Name | Human-readable name | `Australia Tax File Number` |
| 1 | GUID/Slug | Microsoft GUID or testpattern.dev slug | `e29d56f5-...` or `au-tfn` |
| 2 | Category | Classification category | `Financial`, `Privacy`, `Government` |
| 3 | Risk Description | What this SIT detects | `Australian tax file numbers` |
| 4 | Risk Rating | Severity 1-10 (used for tier scoring) | `8` |
| 5 | Reference URL | Documentation link | `https://learn.microsoft.com/...` |
| 6 | Classification | Security classification level | `SENSITIVE` |
| 7 | Framework | Framework code | `QGISCF` |
| 8 | Framework DLM | Dissemination Limiting Marker | `Financial` |
| 9 | Small | Include in Small tier? | `Y` or blank |
| 10 | Medium | Include in Medium tier? | `Y` or blank |
| 11 | Large | Include in Large tier? | `Y` or blank |
| 12 | Label Code | Target label code for DLP rules | `SENS_Fin` |
| 13 | Classifier Type | `SIT`, `Regex`, `Keyword List`, or `MLModel` | `SIT` |
| 14 | Source | `TestPattern` or `Microsoft Built-in` | `Microsoft Built-in` |

The spreadsheet filename is configurable via `inputSpreadsheet` in `config/settings.json`, or pass `--xls <path>` to any pipeline script. If neither is set, the scripts will use the first `.xlsx` found in the project root.

Optionally add a label definition sheet (default name: `QGISCFDLM`) for cross-validation against `labels.json`.

## Scripts

### Deployment

| Script | Purpose |
|--------|---------|
| `greenfield-deploy.ps1` | Single-command deployment: dictionaries, labels, packages, rules |
| `full-deploy.ps1` | Phased deployment with propagation checks and dictionary support |
| `Deploy-Labels.ps1` | Deploy sensitivity labels and label policy (requires named `-PublishTo` target; `-ApproveOpenPublish` needed for `"All"`) |
| `Deploy-DLPRules.ps1` | Deploy DLP policies and rules across workloads (auto-splits >125 SITs) |
| `Deploy-Classifiers.ps1` | Upload, validate, list, or remove custom SIT packages |

### Data Pipeline — Spreadsheet

| Script | Purpose |
|--------|---------|
| `Build-FromXLS.py` | Generate `classifiers.json` from the input spreadsheet |
| `build-deploy-packages.py` | Fetch SITs from testpattern.dev, bin-pack into deployment packages |
| `tier-allocate.py` | Generate tier assignments using priority scoring model |
| `sync-spreadsheet.py` | Sync spreadsheet with current testpattern.dev catalogue |

### Data Pipeline — Tenant Import

| Script | Purpose |
|--------|---------|
| `Export-TenantSITs.ps1` | Export SIT list from a tenant to `config/tenant-sits.json` |
| `Build-ClassifierSchema.py` | Build classifier mapping: `--init` (CSV template), `--auto` (keyword rules), `--apply` (generate config) |

### Utilities

| Script | Purpose |
|--------|---------|
| `Test-Classifiers.ps1` | Validate config SITs exist in the tenant |
| `Invoke-ChangePack.ps1` | Apply a CSV of targeted DLP rule changes |
| `Generate-ChangePack.ps1` | Generate a change pack CSV from config vs tenant diff |
| `Test-MinimalKeywords.ps1` | Test keyword dictionary upload and DLP rule integration |

> **Note:** To use trainable classifiers (MLModel type) in DLP rules, retrieve their GUIDs from your tenant using `Get-DlpSensitiveInformationType` and add them to `classifiers.json` with `"classifierType": "MLModel"`.

## Naming Convention

All tenant resources are named using a consistent convention driven by `namingPrefix` and `namingSuffix` in `config/settings.json`. **You must change these before deploying to a customer environment** — the scripts will prompt if they detect default values.

### Key Settings

| Setting | Default | Purpose | Example |
|---------|---------|---------|---------|
| `namingPrefix` | `DLP` | Identifies your deployment across all resource types | `QGISCF`, `NZISM`, `ACME` |
| `namingSuffix` | `EXT-ADT` | Encodes deployment mode | `EXT-ADT`, `INT-BLK` |
| `publisher` | (empty) | Publisher name on SIT rule packages | `Queensland Government CSU` |
| `labelPolicyName` | `DLP-Label-Policy` | Name of the sensitivity label publishing policy | `QGISCF-Label-Policy` |

The suffix encodes two things: **scoping** (`EXT` = external/outbound, `INT` = internal) and **enforcement mode** (`ADT` = audit, `NFY` = notify, `BLK` = block).

### Resource Naming Patterns

Given `namingPrefix = QGISCF` and `namingSuffix = EXT-ADT`:

**DLP Policies** — `P{NN}-{WorkloadCode}-{Prefix}-{Suffix}`
```
P01-ECH-QGISCF-EXT-ADT
│   │     │      │
│   │     │      └── Suffix: external scoping, audit mode
│   │     └── Prefix: deployment/framework identifier
│   └── Workload code from policies.json (ECH, ODB, SPO, END, TMS)
└── Policy number from policies.json (01-05)
```

**DLP Rules** — `P{NN}-R{RR}-{WorkloadCode}-{LabelCode}-{Suffix}`
```
P01-R03-ECH-SENS_Fin-EXT-ADT       (single chunk)
P01-R01a-ECH-SENS_Pvca-EXT-ADT     (chunk "a" when >125 SITs split)
│    │  │  │     │        │
│    │  │  │     │        └── Suffix
│    │  │  │     └── Target label code from labels.json
│    │  │  └── Workload code
│    │  └── Chunk letter (a, b, c...) — only when a label has >125 SITs
│    └── Rule number within the policy
└── Policy number
```

**Auto-Labeling Policies** — `AL{NN}-{LabelCode}-{Prefix}-{Suffix}`
```
AL01-OFFI-QGISCF-EXT-ADT
│     │      │       │
│     │      │       └── Suffix
│     │      └── Prefix
│     └── Target label code
└── Sequential policy number
```

**Auto-Labeling Rules** — `AL{NN}-R{RR}-{WorkloadCode}-{LabelCode}-{Suffix}`
```
AL01-R01-ECH-OFFI-EXT-ADT
```

**SIT Rule Packages** — `{Prefix}-{Tier}-{NN}`
```
QGISCF-medium-01        QGISCF-medium-07a
│        │     │         │        │     │└── Split suffix (a/b when oversized)
│        │     │         │        │     └── Package number
│        │     └── Package number
│        └── Deployment tier (narrow, medium, full)
└── Prefix from settings.json
```

**Label Publishing Policy** — configured directly via `labelPolicyName`
```
QGISCF-Label-Policy
```

**Keyword Dictionaries** — named by the testpattern.dev export API, prefixed with `namingPrefix` for cleanup identification.

## Configuration

All deployment behaviour is driven by JSON config files:

| File | Description |
|------|-------------|
| `config/settings.json` | Naming prefix, publisher, deployment mode, input spreadsheet path |
| `config/labels.json` | Sensitivity label hierarchy (any framework — PSPF, NZISM, GSC, custom) |
| `config/policies.json` | DLP policy definitions per workload (Exchange, SPO, ODB, Teams, Endpoint) |
| `config/classifiers.json` | SIT-to-label mapping — which classifiers protect which labels |
| `config/rule-overrides.json` | Per-label/per-policy DLP rule parameter overrides |
| `config/tier-assignments.json` | Small/Medium/Large tier SIT name lists |
| `config/tenant-sits.json` | Exported SIT list from a tenant (for tenant import pipeline) |
| `config/classifier-mapping.csv` | Editable SIT-to-label mapping template (for tenant import pipeline) |

## Shared Module

`modules/DLP-Deploy.psm1` provides shared functions: connection management, config loading, naming conventions, SIT condition building (Simple and AdvancedRule formats), auto-splitting rules >125 classifiers, keyword dictionary sync, retry logic with throttle detection, logging, and XML validation.

## Keyword Dictionaries

The toolkit integrates with [testpattern.dev's keyword dictionary system](https://testpattern.dev). Shared keyword lists (noise exclusion, domain context, classification markers, name lists) are created as Purview keyword dictionaries — these don't consume SIT package slots and are referenced by SIT entities via GUID placeholders.

Both `greenfield-deploy.ps1` and `full-deploy.ps1` automatically:
1. Fetch the dictionary manifest from testpattern.dev
2. Create or update keyword dictionaries in the tenant (idempotent)
3. Patch `{{DICT_*}}` placeholders in SIT packages with tenant-specific GUIDs

## Deployment Tiers

SITs are assigned to deployment tiers based on a priority scoring model that weighs risk rating, jurisdiction relevance, classifier type, and category:

| Tier | Custom SITs | Purpose |
|------|-------------|---------|
| Small | ~90 | Core essentials — key PII, credentials, critical AU identifiers |
| Medium | ~250 | Comprehensive — adds financial, legal, health, government docs |
| Large | ~375 | Full coverage — broad international PII, all document classifiers |

Microsoft Built-in SITs (254) are included free at all tiers — they don't consume custom SIT quota or package slots. The tier targets refer to custom SITs only.

## Using a Different Framework

To deploy for a different classification framework:

**With a spreadsheet:**

1. Create your input spreadsheet (use `SIT-Inputs-Example.xlsx` as a template)
2. Edit `config/labels.json` with your label hierarchy
3. Edit `config/settings.json` with your naming prefix, publisher, and spreadsheet filename
4. Edit `config/policies.json` with your workload and policy settings
5. Run `python scripts/Build-FromXLS.py` to generate `classifiers.json`
6. Run `python scripts/build-deploy-packages.py` to build packages (if using testpattern.dev)
7. Deploy with `greenfield-deploy.ps1 -PublishTo "group@domain"` or `full-deploy.ps1 -PublishTo "group@domain"`

**Without a spreadsheet (tenant import):**

1. Export SITs from any tenant: `Export-TenantSITs.ps1 -Connect -UPN admin@source.com`
2. Edit `config/labels.json` with your label hierarchy
3. Edit `config/settings.json` with your naming prefix and publisher
4. Edit `config/policies.json` with your workload and policy settings
5. Generate mapping: `python scripts/Build-ClassifierSchema.py --auto`
6. Review/edit `config/classifier-mapping.csv`, then: `python scripts/Build-ClassifierSchema.py --apply`
7. Deploy with `greenfield-deploy.ps1 -PublishTo "group@domain"` or `full-deploy.ps1 -PublishTo "group@domain"`

The deployment scripts read everything from config — no code changes needed.

## Reference Implementation

The included config files implement the **Queensland Government Information Security Classification Framework (QGISCF)** with:
- 17 sensitivity labels (OFFICIAL, SENSITIVE with 7 DLMs, PROTECTED with 7 DLMs)
- 5 DLP policies (Exchange, OneDrive, SharePoint, Endpoint, Teams)
- 250+ custom SITs across 12 label codes (medium tier)
- Audit mode with external-scoping rules

## Purview Constraints

| Limit | Value | Notes |
|-------|-------|-------|
| Custom SITs per tenant | 500 | Microsoft Built-in don't count |
| Rule packages per tenant | 10 | 1 is Microsoft's built-in = 9 usable |
| Package file size | 150KB | UTF-8 accepted, dictionaries reduce inline size |
| SITs per DLP rule | 125 | Auto-split into multiple rules when exceeded |
| Keyword dictionaries | 50 dictionary-based SITs, 1MB combined | Separate from package limits |
