#==============================================================================
# greenfield-deploy.ps1
# Clean greenfield deployment: dictionaries, labels, SIT packages, DLP rules.
# Single session, single command. Wipes existing config first.
#
# Usage:
#   pwsh -File scripts/greenfield-deploy.ps1 -Tenant tenant.onmicrosoft.com -TargetEnvironment tenant-profile
#   pwsh -File scripts/greenfield-deploy.ps1 -UPN admin@yourtenant.onmicrosoft.com
#   pwsh -File scripts/greenfield-deploy.ps1 -UPN admin@agency.gov.au -Tier small
#   pwsh -File scripts/greenfield-deploy.ps1 -UPN admin@agency.gov.au -SkipCleanup
#==============================================================================

param(
    [string]$UPN,
    [ValidateSet("narrow", "wide", "full", "small", "medium", "large")]
    [string]$Tier = "medium",
    [string]$Scope = "universal,en-government,au",
    [Parameter(Mandatory)][string]$PublishTo,
    [string]$Tenant,
    [string]$TargetEnvironment,
    [string]$Prefix,
    [switch]$Delegated,
    [switch]$SkipCleanup,
    [switch]$AllowBreakingClassifierReferences,
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath = Join-Path $ProjectRoot "config"
$DeployDir = Join-Path $ProjectRoot "xml" "deploy"

Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

$Defaults = Get-ModuleDefaults
$settingsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
$Config = Merge-GlobalConfig -Defaults $Defaults -GlobalJson $settingsJson
$Config = Set-DeploymentConfigPrefix -Config $Config -Prefix $Prefix
if (-not (Assert-ConfigCustomised -Config $Config)) { return }
$prefix = $Config.namingPrefix

if (-not $UPN -and -not $Tenant) {
    Write-Error "Specify -Tenant, -UPN, or both so the SCC connection target is explicit."
    return
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  Greenfield DLP Deployment" -ForegroundColor Cyan
Write-Host "  Tenant: $(if ($Tenant) { $Tenant } else { $UPN })" -ForegroundColor Cyan
if ($TargetEnvironment) { Write-Host "  Tenant profile: $TargetEnvironment" -ForegroundColor Cyan }
Write-Host "  Tier: $Tier | Prefix: $prefix" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

# ── Connect ──────────────────────────────────────────────────────────────────
Write-Host "=== Connecting ===" -ForegroundColor Cyan
$connectArgs = @{}
if ($UPN) { $connectArgs["UPN"] = $UPN }
if ($Tenant) { $connectArgs["Tenant"] = $Tenant }
if ($Delegated) { $connectArgs["Delegated"] = $true }
$connected = Connect-DLPSession @connectArgs
if (-not $connected) { Write-Error "Connection failed."; return }
Write-Host "  Connected.`n" -ForegroundColor Green

$connectTarget = if ($Tenant) { $Tenant } else { $UPN }

# ── Tenant fingerprint guard ───────────────────────────────────────────────────
# Refuse to operate against a tenant that does not match the pinned fingerprint.
$fingerprint = Test-DeploymentTenantFingerprint -ProjectRoot $ProjectRoot -TargetEnvironment $TargetEnvironment
Write-Host "=== Tenant Fingerprint ===" -ForegroundColor Cyan
foreach ($m in @($fingerprint.messages)) {
    Write-Host "  $m" -ForegroundColor $(if ($fingerprint.passed) { "Green" } else { "Red" })
}
foreach ($mm in @($fingerprint.mismatches)) {
    Write-Host "  MISMATCH $($mm.field): expected '$($mm.expected)', actual '$($mm.actual)'" -ForegroundColor Red
}
if (-not $fingerprint.passed) { throw "Tenant fingerprint check failed. Aborting." }
Write-Host ""

# ── Phase 0: Cleanup ────────────────────────────────────────────────────────
# Resolve exactly which live tenant objects each pattern matches, present the full
# list, then (after typed confirmation) delete ONLY those previewed objects.
if (-not $SkipCleanup) {
    Write-Host "=== Phase 0: Cleanup ===" -ForegroundColor Cyan

    $objects = @{
        AutoLabelPolicy   = @(Get-AutoSensitivityLabelPolicy -ErrorAction SilentlyContinue)
        DlpPolicy         = @(Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)
        SitPackage        = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction SilentlyContinue)
        KeywordDictionary = @(Get-DlpKeywordDictionary -ErrorAction SilentlyContinue)
        LabelPolicy       = @(Get-LabelPolicy -ErrorAction SilentlyContinue)
        Label             = @(Get-Label -ErrorAction SilentlyContinue)
    }

    $targets = @(Resolve-CleanupTargets -Config $Config -Objects $objects -IncludeLabels)
    $null = Show-CleanupPlan -Targets $targets -Tenant $connectTarget

    if ($targets.Count -eq 0) {
        Write-Host "`n  Clean — nothing to remove.`n" -ForegroundColor Green
    } elseif ($WhatIf) {
        Write-Host "`n  WhatIf: previewed $($targets.Count) object(s). No deletions performed.`n" -ForegroundColor Yellow
    } else {
        $phrase = Get-CleanupConfirmationPhrase -Prefix $Config.namingPrefix -Tenant $connectTarget
        $answer = Read-Host "Type '$phrase' to delete the $($targets.Count) object(s) listed above"
        if ($answer -ne $phrase) {
            Write-Host "  Cleanup aborted. Nothing was deleted." -ForegroundColor Yellow
            return
        }
        $removal = Invoke-CleanupPlan -Targets $targets -AllowBreakingClassifierReferences:$AllowBreakingClassifierReferences
        Write-Host "`n  Removal results:" -ForegroundColor Green
        foreach ($k in $removal.Keys) { Write-Host "    ${k}: $($removal[$k]) deleted" -ForegroundColor Gray }
        Write-Host "  Waiting 2 minutes for Purview cleanup propagation..." -ForegroundColor Gray
        Write-Host "  Note: Labels may take hours/days to fully purge. SIT packages and rules take minutes." -ForegroundColor Gray
        Start-Sleep 120
        Write-Host "  Clean.`n" -ForegroundColor Green
    }
} else {
    Write-Host "=== Skipping cleanup ===`n" -ForegroundColor Yellow
}

# ── Phase 1: Keyword Dictionaries ───────────────────────────────────────────
Write-Host "=== Phase 1: Keyword Dictionaries ===" -ForegroundColor Cyan

$manifestUrl = "https://testpattern.dev/api/export/dictionary-manifest?scope=$Scope"
if ($WhatIf) {
    $guidMap = Sync-DlpKeywordDictionaries -ManifestUrl $manifestUrl -WhatIf
} else {
    $guidMap = Sync-DlpKeywordDictionaries -ManifestUrl $manifestUrl
}
Write-Host ""

# ── Phase 2: Labels ─────────────────────────────────────────────────────────
Write-Host "=== Phase 2: Labels ===" -ForegroundColor Cyan
$labelArgs = @{ PublishTo = $PublishTo }
if ($Prefix) { $labelArgs["Prefix"] = $Prefix }
if ($WhatIf) { $labelArgs["WhatIf"] = $true }
& (Join-Path $PSScriptRoot "Deploy-Labels.ps1") @labelArgs
Write-Host ""

# ── Phase 3: SIT Packages ───────────────────────────────────────────────────
Write-Host "=== Phase 3: SIT Classifier Package Manager ===" -ForegroundColor Cyan

$xmlFiles = Get-ChildItem -Path $DeployDir -Filter "*.xml" -ErrorAction SilentlyContinue | Sort-Object Name
if (-not $xmlFiles -or $xmlFiles.Count -eq 0) {
    Write-Warning "  No packages in $DeployDir -- run build-deploy-packages.py first"
} else {
    Write-Host "  $($xmlFiles.Count) package(s). Delegating to Deploy-Classifiers safety workflow." -ForegroundColor Gray
    $classifierArgs = @{
        Action = "Upload"
        Scope = $Scope
        Greenfield = $true
    }
    if ($WhatIf) { $classifierArgs["WhatIf"] = $true }
    if ($Tenant) { $classifierArgs["Tenant"] = $Tenant }
    if ($TargetEnvironment) { $classifierArgs["TargetEnvironment"] = $TargetEnvironment }
    if ($Prefix) { $classifierArgs["Prefix"] = $Prefix }
    if ($Delegated) { $classifierArgs["Delegated"] = $true }
    & (Join-Path $PSScriptRoot "Deploy-Classifiers.ps1") @classifierArgs

    if (-not $WhatIf) {
        @{ timestamp = (Get-Date).ToUniversalTime().ToString("o"); packages = $xmlFiles.Count } | ConvertTo-Json | Out-File (Join-Path $ConfigPath "last-classifier-upload.json") -Encoding utf8
    }
}
Write-Host ""

# ── Phase 4: DLP Rules ──────────────────────────────────────────────────────
Write-Host "=== Phase 4: DLP Rules ===" -ForegroundColor Cyan
Write-Host "  Waiting 15s for SIT indexing..." -ForegroundColor Gray
if (-not $WhatIf) { Start-Sleep 15 }

$ruleArgs = @{ SkipValidation = $true }
if ($WhatIf) { $ruleArgs["WhatIf"] = $true }
if ($Tenant) { $ruleArgs["Tenant"] = $Tenant }
if ($TargetEnvironment) { $ruleArgs["TargetEnvironment"] = $TargetEnvironment }
if ($Prefix) { $ruleArgs["Prefix"] = $Prefix }
if ($Delegated) { $ruleArgs["Delegated"] = $true }
& (Join-Path $PSScriptRoot "Deploy-DLPRules.ps1") @ruleArgs

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "  Greenfield Deployment Complete" -ForegroundColor Green
Write-Host "  Dictionaries: $($guidMap.Count) resolved" -ForegroundColor Green
Write-Host "  Labels: deployed + published" -ForegroundColor Green
if ($xmlFiles) { Write-Host "  SIT Packages: $($xmlFiles.Count)" -ForegroundColor Green }
Write-Host "  DLP Rules: deployed" -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Green
