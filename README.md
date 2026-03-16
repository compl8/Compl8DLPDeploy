# Compl8 DLP Deployment Toolkit

Config-driven Data Loss Prevention (DLP) deployment engine for Microsoft Purview. Deploys sensitivity labels, keyword dictionaries, custom Sensitive Information Type (SIT) rule packages, and DLP policies/rules — all from JSON configuration files and the [testpattern.dev](https://testpattern.dev) pattern API.

Framework-agnostic: works with PSPF (Australia), NZISM (New Zealand), UK GSC, or any custom classification framework. Ships with a Queensland Government (QGISCF) reference configuration.

## Prerequisites

- PowerShell 7+ (or 5.1 with limitations)
- [ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement) module
- Microsoft Purview Compliance admin permissions (Compliance Administrator or equivalent)
- Python 3.x with `openpyxl` (for data pipeline scripts)

## Architecture

The toolkit has two layers: a **data pipeline** that decides *what* to deploy, and a **deployment engine** that deploys it.

### Data Pipeline

The SIT Risk Analysis spreadsheet is the master document. It maps every Sensitive Information Type to a classification label and deployment tier. The pipeline works like this:

```
SIT Risk Analysis Spreadsheet (v12.xlsx)
  ├── Which SITs exist and what they detect
  ├── Which label each SIT maps to (OFFI, SENS_Pvc, PROT_IT, etc.)
  ├── Which deployment tier includes each SIT (Small / Medium / Large)
  └── Risk rating, jurisdiction, classifier type, source
         │
         ▼
  Build-FromXLS.py ──► config/classifiers.json
    Reads spreadsheet, resolves SIT GUIDs from          (SIT-to-label mapping
    testpattern.dev XML packages, outputs the             with resolved GUIDs)
    classifier-to-label mapping
         │
         ▼
  build-deploy-packages.py ──► xml/deploy/*.xml
    Fetches SIT patterns from testpattern.dev             (UTF-8 XML packages
    API, prunes keywords, bin-packs into                   ready to upload)
    right-sized packages under 150KB
         │
         ▼
  greenfield-deploy.ps1 ──► Purview tenant
    Creates keyword dictionaries, deploys                 (Labels, dictionaries,
    labels, uploads packages, creates                      packages, DLP rules)
    DLP policies and rules
```

### The Spreadsheet

The SIT Risk Analysis spreadsheet (`SIT-Risk-Analysis-v12.xlsx`) is the single source of truth for classification decisions. Each row is a Sensitive Information Type with:

- **SIT Name** and **GUID/Slug** — what pattern to use (testpattern.dev slug or Microsoft Built-in GUID)
- **Label Code** — which sensitivity label this SIT maps to (e.g. `SENS_Pvc`, `PROT_IT`)
- **Small / Medium / Large** — which deployment tiers include this SIT
- **Risk Rating** (1-10) — used by the tier allocation scoring model
- **Source** — `TestPattern` (from testpattern.dev) or `Microsoft Built-in`
- **Classifier Type** — SIT, Regex, Keyword List, or MLModel

To update what gets deployed, edit the spreadsheet, then re-run the pipeline:

```powershell
# 1. Regenerate classifiers.json from the spreadsheet
python scripts/Build-FromXLS.py --tier medium

# 2. Rebuild deployment packages from testpattern.dev
python scripts/build-deploy-packages.py --tier medium --max-terms 5

# 3. Deploy
.\scripts\greenfield-deploy.ps1 -UPN admin@yourtenant.onmicrosoft.com
```

### Syncing with TestPattern

To update the spreadsheet with the latest patterns from testpattern.dev:

```powershell
# Sync spreadsheet SITs against current testpattern.dev catalogue
python scripts/sync-spreadsheet.py
```

This checks for new patterns added to testpattern.dev that aren't in the spreadsheet, patterns that have been removed, and slug/GUID changes. It produces a report and optionally updates the spreadsheet.

## Quick Start

### Greenfield Deployment (new tenant)

```powershell
# 1. Build SIT packages from testpattern.dev
python scripts/build-deploy-packages.py --tier medium --max-terms 5

# 2. Deploy everything in one command
.\scripts\greenfield-deploy.ps1 -UPN admin@yourtenant.onmicrosoft.com
```

This will: create keyword dictionaries, deploy labels, upload SIT packages, and deploy DLP rules — all in a single session.

### Phased Deployment

For more control, deploy in phases:

```powershell
# Phase 1: Labels only
.\scripts\full-deploy.ps1 -UPN admin@tenant.com -Phase Labels

# Phase 2: SIT classifier packages
.\scripts\full-deploy.ps1 -UPN admin@tenant.com -Phase Classifiers

# Phase 3: DLP rules
.\scripts\full-deploy.ps1 -UPN admin@tenant.com -Phase DLPRules

# Cleanup everything
.\scripts\full-deploy.ps1 -UPN admin@tenant.com -Phase Cleanup

# Dry run
.\scripts\full-deploy.ps1 -UPN admin@tenant.com -WhatIf
```

## Scripts

### Deployment

| Script | Purpose |
|--------|---------|
| `greenfield-deploy.ps1` | Single-command deployment: dictionaries, labels, packages, rules |
| `full-deploy.ps1` | Phased deployment with propagation checks |
| `Deploy-Labels.ps1` | Deploy sensitivity labels and label policy |
| `Deploy-DLPRules.ps1` | Deploy DLP policies and rules across workloads |
| `Deploy-Classifiers.ps1` | Upload, validate, list, or remove custom SIT packages |

### Data Pipeline

| Script | Purpose |
|--------|---------|
| `Build-FromXLS.py` | Generate `classifiers.json` from the SIT Risk Analysis spreadsheet |
| `build-deploy-packages.py` | Fetch SITs from testpattern.dev, bin-pack into deployment packages |
| `tier-allocate.py` | Generate tier assignments using priority scoring model |
| `sync-spreadsheet.py` | Sync spreadsheet with current testpattern.dev catalogue |

### Utilities

| Script | Purpose |
|--------|---------|
| `Test-Classifiers.ps1` | Validate config SITs exist in the tenant |
| `Invoke-ChangePack.ps1` | Apply a CSV of targeted DLP rule changes |
| `Generate-ChangePack.ps1` | Generate a change pack CSV from config vs tenant diff |

> **Note:** To use trainable classifiers (MLModel type) in DLP rules, you'll need to retrieve their GUIDs from your tenant using `Get-DlpSensitiveInformationType` and add them to `classifiers.json` with `"classifierType": "MLModel"`.
| `Test-MinimalKeywords.ps1` | Test keyword dictionary upload and DLP rule integration |

## Configuration

All deployment behaviour is driven by JSON config files:

| File | Description |
|------|-------------|
| `config/settings.json` | Naming prefix, publisher, deployment mode, notification settings |
| `config/labels.json` | Sensitivity label hierarchy (any framework — PSPF, NZISM, GSC, custom) |
| `config/policies.json` | DLP policy definitions per workload (Exchange, SPO, ODB, Teams, Endpoint) |
| `config/classifiers.json` | SIT-to-label mapping — which classifiers protect which labels |
| `config/rule-overrides.json` | Per-label/per-policy DLP rule parameter overrides |
| `config/tier-assignments.json` | Small/Medium/Large tier SIT name lists |

## Shared Module

`modules/DLP-Deploy.psm1` provides shared functions: connection management, config loading, naming conventions, SIT condition building (Simple and AdvancedRule formats), retry logic with throttle detection, logging, and XML validation.

## Keyword Dictionaries

The toolkit integrates with [testpattern.dev's keyword dictionary system](https://testpattern.dev). Shared keyword lists (noise exclusion, domain context, classification markers, name lists) are created as Purview keyword dictionaries — these don't consume SIT package slots and are referenced by SIT entities via GUID placeholders.

The greenfield deploy script automatically:
1. Fetches the dictionary manifest from testpattern.dev
2. Creates or updates keyword dictionaries in the tenant
3. Patches `{{DICT_*}}` placeholders in SIT packages with tenant-specific GUIDs

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

1. Create your SIT Risk Analysis spreadsheet (use the included v12 as a template)
2. Edit `config/labels.json` with your label hierarchy
3. Edit `config/settings.json` with your naming prefix and publisher
4. Edit `config/policies.json` with your workload and policy settings
5. Run `python scripts/Build-FromXLS.py` to generate `classifiers.json`
6. Run `python scripts/build-deploy-packages.py` to build packages
7. Deploy with `greenfield-deploy.ps1`

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
| Keyword dictionaries | 50 dictionary-based SITs, 1MB combined | Separate from package limits |
