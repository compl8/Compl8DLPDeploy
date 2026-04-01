# QGISCF DLP Deployment Package

Pre-configured deployment package for the Queensland Government Information Security Classification Framework (QGISCF). All configuration, SIT classifier packages, and keyword dictionaries are ready to deploy.

## Prerequisites

- PowerShell 7+ (`pwsh`)
- ExchangeOnlineManagement module:
  ```powershell
  Install-Module ExchangeOnlineManagement -Scope CurrentUser
  ```
- Admin UPN with Security & Compliance Center permissions on the target tenant

## Directory Structure

```
config/          Deployment configuration (settings, labels, policies, classifiers)
modules/         PowerShell modules (DLP-Deploy.psm1)
scripts/         Deployment scripts
xml/deploy/      9 SIT classifier XML packages (253 custom SITs)
```

## Deployment

Run all commands from the root directory (where this file is).

### 1. Deploy keyword dictionaries

Creates 10 keyword dictionaries on the tenant, including Australian Forenames (10,961 terms) and Australian Surnames (23,065 terms).

```powershell
pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Dictionaries
```

### 2. Deploy SIT classifier packages

Uploads all 9 XML packages. If packages already exist on the tenant, they are updated in-place (requires a version bump in the XML).

```powershell
pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Classifiers
```

### 3. Wait for propagation

Custom SITs take **4-24 hours** to propagate in Purview's DLP engine. Do not proceed to DLP rules until SITs appear in Content Explorer.

### 4. Deploy DLP rules

```powershell
pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase DLPRules
```

### 5. Deploy labels (if needed)

Only required if sensitivity labels haven't been deployed yet. `-PublishTo` specifies who receives the label policy.

```powershell
pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Labels -PublishTo "DL-InfoSec@agency.gov.au"
```

### All-in-one

Deploys everything in sequence (labels + dictionaries + classifiers + rules). Requires `-PublishTo`.

```powershell
pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -PublishTo "DL-InfoSec@agency.gov.au"
```

### Dry run

Append `-WhatIf` to any command to preview changes without modifying the tenant.

```powershell
pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Dictionaries -WhatIf
```

## Cleanup

Remove the deployment from the tenant:

```powershell
pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Cleanup              # everything
pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Cleanup -SkipLabels   # keep labels
```

## What's Deployed

### Sensitivity Labels

17 labels: UNOFFICIAL, OFFICIAL, SENSITIVE (7 DLMs), PROTECTED (7 DLMs).

### SIT Classifier Packages

| Package | SITs | Description |
|---|---|---|
| QGISCF-medium-01 | 35 | AU identifiers, financial, healthcare |
| QGISCF-medium-02 | 35 | Immigration, residential, social services |
| QGISCF-medium-03 | 35 | Payroll, pension, tax |
| QGISCF-medium-04 | 35 | Corporate governance, audit, IP |
| QGISCF-medium-05 | 35 | Cybersecurity, vulnerability, threat intel |
| QGISCF-medium-06 | 35 | Welfare, child protection, civil registry |
| QGISCF-medium-07a | 17 | Cabinet, coronial, native title, government legal |
| QGISCF-medium-07b | 18 | Law enforcement, investigation, controlled operations |
| QGISCF-medium-08 | 6 | Justice (bail, DVO, corrections, QPS) + Legal Full Name |

### Keyword Dictionaries

| Dictionary | Terms | Purpose |
|---|---|---|
| Noise Exclusion | 13 | False positive suppression |
| EN Government Exclusion | 65 | Government/enterprise noise |
| Domain Context | 29 | Structural data-handling terms |
| Data Labels | 12 | Generic data identifiers |
| EN Government Classification | 29 | Security classification markers |
| AU Forenames (Male, Very Common) | 200 | Top male forenames |
| AU Forenames (Female, Very Common) | 200 | Top female forenames |
| AU Family Names (Top Tier) | 1,286 | Common surnames |
| **Australian Forenames** | **10,961** | Consolidated forenames (BDM + QLD Unclaimed Money) |
| **Australian Surnames** | **23,065** | Consolidated surnames (immigration + unclaimed money) |

### DLP Policies

5 policies across workloads: Exchange, OneDrive, SharePoint, Endpoint, Teams. Deployed in **audit mode** by default.

## Configuration

Settings are in `config/settings.json`:

| Setting | Value | Purpose |
|---|---|---|
| `namingPrefix` | `QGISCF` | Prefix on all tenant resources |
| `namingSuffix` | `EXT-ADT` | External scoping, audit mode |
| `publisher` | `Queensland Government CSU` | Publisher on SIT packages |
| `sitPrefix` | `QGISCF` | SIT entity name prefix (replaces `TestPattern -`) |
| `auditMode` | `true` | Rules audit only, no blocking |

To switch from audit to enforcement, change `auditMode` to `false` and update `namingSuffix` (e.g. `EXT-BLK`).
