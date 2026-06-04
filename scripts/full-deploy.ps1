#==============================================================================
# full-deploy.ps1
# Orchestrates DLP deployment in phases:
#   Phase 1:   Labels (immediate)
#   Phase 1.5: Keyword dictionaries (create-or-update, returns GUID map)
#   Phase 2:   SIT classifier packages (patches dictionary placeholders, uploads)
#   Phase 3:   DLP rules (requires SITs to be indexed — up to 24h after upload)
#
# Phases can be run independently or together. When run together, Phase 3
# checks whether custom SITs have propagated and warns if too recent.
#
# Usage:
#   pwsh -File scripts/full-deploy.ps1 -Tenant tenant.onmicrosoft.com -TargetEnvironment tenant-profile
#   pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Labels        # Labels only
#   pwsh -File scripts/full-deploy.ps1 -Tenant tenant.onmicrosoft.com -Phase Dictionaries
#   pwsh -File scripts/full-deploy.ps1 -Tenant tenant.onmicrosoft.com -Phase Classifiers -TargetEnvironment tenant-profile
#   pwsh -File scripts/full-deploy.ps1 -Tenant tenant.onmicrosoft.com -Phase DLPRules -TargetEnvironment tenant-profile
#   pwsh -File scripts/full-deploy.ps1 -Tenant tenant.onmicrosoft.com -Phase Cleanup -TargetEnvironment tenant-profile
#   pwsh -File scripts/full-deploy.ps1 -Tenant tenant.onmicrosoft.com -Phase Cleanup -SkipLabels  # Teardown, keep labels
#   pwsh -File scripts/full-deploy.ps1 -Tenant tenant.onmicrosoft.com -SkipLabels  # Nuke & redeploy, keep labels
#==============================================================================

param(
    [string]$UPN,
    [ValidateSet("All", "Labels", "Dictionaries", "Classifiers", "DLPRules", "Cleanup")]
    [string]$Phase = "All",
    [string]$PublishTo,
    [string]$Tenant,
    [string]$TargetEnvironment,
    [string]$Prefix,
    [switch]$Delegated,
    [string]$Scope = "universal,en-government,au",
    [string]$DeployDir = "xml/deploy",
    [switch]$SkipLabels,
    [switch]$Force,
    [switch]$AllowBreakingClassifierReferences,
    [switch]$Greenfield,
    [switch]$WhatIf,
    [switch]$RegisterFingerprint
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent

Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

# ── Load Config ───────────────────────────────────────────────────────────────
$ConfigPath  = Join-Path $ProjectRoot "config"
$Defaults    = Get-ModuleDefaults
$settingsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
$Config      = Merge-GlobalConfig -Defaults $Defaults -GlobalJson $settingsJson
$Config      = Set-DeploymentConfigPrefix -Config $Config -Prefix $Prefix
if (-not (Assert-ConfigCustomised -Config $Config)) { return }

# PublishTo is required for Labels and All phases
if (($Phase -eq "All" -or $Phase -eq "Labels") -and -not $PublishTo) {
    Write-Error "-PublishTo is required for Labels and All phases (e.g. -PublishTo 'user@domain.com')"
    return
}
$cleanupPrefix = $Config.namingPrefix

# ── Connect ──────────────────────────────────────────────────────────────────
if (-not $UPN -and -not $Tenant) {
    Write-Error "Specify -Tenant, -UPN, or both so the SCC connection target is explicit."
    return
}

$connectTarget = if ($Tenant) { $Tenant } else { $UPN }
Write-Host "`n=== Connecting to $connectTarget ===" -ForegroundColor Cyan
$connectArgs = @{}
if ($UPN) { $connectArgs["UPN"] = $UPN }
if ($Tenant) { $connectArgs["Tenant"] = $Tenant }
if ($Delegated) { $connectArgs["Delegated"] = $true }
$connected = Connect-DLPSession @connectArgs
if (-not $connected) {
    Write-Error "Connection failed. Aborting."
    return
}
Write-Host "  Connected.`n" -ForegroundColor Green

# ── Tenant fingerprint guard ───────────────────────────────────────────────────
# Refuse to operate against a tenant that does not match the pinned fingerprint.
$fingerprint = Test-DeploymentTenantFingerprint -ProjectRoot $ProjectRoot -TargetEnvironment $TargetEnvironment -RegisterIfMissing:$RegisterFingerprint
Write-Host "=== Tenant Fingerprint ===" -ForegroundColor Cyan
foreach ($m in @($fingerprint.messages)) {
    Write-Host "  $m" -ForegroundColor $(if ($fingerprint.passed) { "Green" } else { "Red" })
}
foreach ($mm in @($fingerprint.mismatches)) {
    Write-Host "  MISMATCH $($mm.field): expected '$($mm.expected)', actual '$($mm.actual)'" -ForegroundColor Red
}
if (-not $fingerprint.passed) { throw "Tenant fingerprint check failed. Aborting." }
Write-Host ""

# ── Cleanup ──────────────────────────────────────────────────────────────────
# Resolve exactly which live tenant objects each pattern matches, present the full
# list, then (after typed confirmation) delete ONLY those previewed objects.
if ($Phase -eq "All" -or $Phase -eq "Cleanup") {
    Write-Host "=== Cleanup: planning removal ===" -ForegroundColor Cyan
    if ($SkipLabels) { Write-Host "  (Labels and label policy will be preserved)" -ForegroundColor Gray }

    $objects = @{
        AutoLabelPolicy   = @(Get-AutoSensitivityLabelPolicy -ErrorAction SilentlyContinue)
        DlpPolicy         = @(Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)
        SitPackage        = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction SilentlyContinue)
        KeywordDictionary = @(Get-DlpKeywordDictionary -ErrorAction SilentlyContinue)
    }
    if (-not $SkipLabels) {
        $objects.LabelPolicy = @(Get-LabelPolicy -ErrorAction SilentlyContinue)
        $objects.Label       = @(Get-Label -ErrorAction SilentlyContinue)
    }

    $targets     = @(Resolve-CleanupTargets -Config $Config -Objects $objects -IncludeLabels:(-not $SkipLabels))
    $planSummary = Show-CleanupPlan -Targets $targets -Tenant $connectTarget

    if ($targets.Count -eq 0) {
        Write-Host "`n  Nothing to clean up." -ForegroundColor Green
    } elseif ($WhatIf) {
        Write-Host "`n  WhatIf: previewed $($targets.Count) object(s). No deletions performed." -ForegroundColor Yellow
    } else {
        $phrase = Get-CleanupConfirmationPhrase -Prefix $Config.namingPrefix -Tenant $connectTarget
        if ($Force) {
            Write-Host "`n  -Force supplied: skipping typed confirmation." -ForegroundColor Yellow
        } else {
            Write-Host ""
            $answer = Read-Host "Type '$phrase' to delete the $($targets.Count) object(s) listed above"
            if ($answer -ne $phrase) {
                Write-Host "  Cleanup aborted. Nothing was deleted." -ForegroundColor Yellow
                return
            }
        }
        $removal = Invoke-CleanupPlan -Targets $targets -AllowBreakingClassifierReferences:$AllowBreakingClassifierReferences
        Write-Host "`n  Removal results:" -ForegroundColor Green
        foreach ($k in $removal.Keys) { Write-Host "    ${k}: $($removal[$k]) deleted" -ForegroundColor Gray }
        Write-Host "  Waiting 2 minutes for Purview cleanup propagation..." -ForegroundColor Gray
        Write-Host "  Note: Labels may take hours/days to fully purge. SIT packages and rules take minutes." -ForegroundColor Gray
        Start-Sleep 120
    }
    Write-Host ""

    if ($Phase -eq "Cleanup") {
        Write-Host "=== Cleanup Complete ===" -ForegroundColor Green
        return
    }
}

# ── Phase 1: Labels ──────────────────────────────────────────────────────────
if (($Phase -eq "All" -or $Phase -eq "Labels") -and -not $SkipLabels) {
    Write-Host "=== Phase 1: Deploying Labels ===" -ForegroundColor Cyan
    $labelArgs = @{ PublishTo = $PublishTo }
    if ($Prefix) { $labelArgs["Prefix"] = $Prefix }
    if ($WhatIf) { $labelArgs["WhatIf"] = $true }
    if ($TargetEnvironment) { $labelArgs["TargetEnvironment"] = $TargetEnvironment }
    & (Join-Path $PSScriptRoot "Deploy-Labels.ps1") @labelArgs
    Write-Host ""
}

# ── Phase 1.5: Keyword Dictionaries ──────────────────────────────────────────
if ($Phase -eq "All" -or $Phase -eq "Dictionaries" -or $Phase -eq "Classifiers") {
    Write-Host "=== Phase 1.5: Keyword Dictionaries ===" -ForegroundColor Cyan

    $manifestUrl = "$($Config.dictionaryManifestUrl)?scope=$Scope"
    if ($WhatIf) {
        $guidMap = Sync-DlpKeywordDictionaries -ManifestUrl $manifestUrl -NamePrefix $Config.namingPrefix -WhatIf
    } else {
        $guidMap = Sync-DlpKeywordDictionaries -ManifestUrl $manifestUrl -NamePrefix $Config.namingPrefix
    }
    Write-Host ""

    if ($Phase -eq "Dictionaries") { return }
}

# ── Phase 2: SIT Classifier Packages ─────────────────────────────────────────
if ($Phase -eq "All" -or $Phase -eq "Classifiers") {
    Write-Host "=== Phase 2: SIT Classifier Package Manager ===" -ForegroundColor Cyan

    $deployPath = Join-Path $ProjectRoot $DeployDir
    $xmlFiles = Get-ChildItem -Path $deployPath -Filter "*.xml" | Sort-Object Name

    if ($xmlFiles.Count -eq 0) {
        Write-Warning "No XML files found in $deployPath"
    } else {
        Write-Host "  Found $($xmlFiles.Count) package(s). Delegating to Deploy-Classifiers safety workflow." -ForegroundColor Gray
        $classifierArgs = @{
            Action = "Upload"
            Scope  = $Scope
        }
        if ($WhatIf) { $classifierArgs["WhatIf"] = $true }
        if ($Tenant) { $classifierArgs["Tenant"] = $Tenant }
        if ($TargetEnvironment) { $classifierArgs["TargetEnvironment"] = $TargetEnvironment }
        if ($Prefix) { $classifierArgs["Prefix"] = $Prefix }
        if ($Delegated) { $classifierArgs["Delegated"] = $true }
        if ($Greenfield) { $classifierArgs["Greenfield"] = $true }
        & (Join-Path $PSScriptRoot "Deploy-Classifiers.ps1") @classifierArgs

        if ($Phase -eq "Classifiers" -or $Phase -eq "All") {
            Write-Host ""
            Write-Host "  NOTE: Custom SITs take 4-24 hours to propagate in Purview's DLP engine." -ForegroundColor Yellow
            Write-Host "  DLP rules referencing these SITs will fail until propagation completes." -ForegroundColor Yellow
            Write-Host "  Run Phase 3 (DLPRules) separately after propagation:" -ForegroundColor Yellow
            $ruleCommandTarget = if ($Tenant) { "-Tenant $Tenant" } else { "-UPN $UPN" }
            $ruleCommandProfile = if ($TargetEnvironment) { " -TargetEnvironment $TargetEnvironment" } else { "" }
            Write-Host "    .\scripts\full-deploy.ps1 $ruleCommandTarget -Phase DLPRules$ruleCommandProfile" -ForegroundColor Gray
            Write-Host ""

            # Record upload timestamp for propagation check
            $timestampFile = Join-Path $ProjectRoot "config" "last-classifier-upload.json"
            if (-not $WhatIf) {
                @{ timestamp = (Get-Date).ToUniversalTime().ToString("o"); packages = $xmlFiles.Count } | ConvertTo-Json | Out-File $timestampFile -Encoding utf8
            }
        }
    }

    if ($Phase -eq "Classifiers") { return }
}

# ── Phase 3: DLP Rules ──────────────────────────────────────────────────────
if ($Phase -eq "All" -or $Phase -eq "DLPRules") {
    Write-Host "=== Phase 3: Deploying DLP Rules ===" -ForegroundColor Cyan

    # Propagation check: warn if classifiers were uploaded recently
    $timestampFile = Join-Path $ProjectRoot "config" "last-classifier-upload.json"
    if (Test-Path $timestampFile) {
        $uploadInfo = Get-Content $timestampFile -Raw | ConvertFrom-Json
        # ConvertFrom-Json may auto-convert ISO timestamps to DateTime objects,
        # which lose timezone info and get culture-formatted on ToString().
        # Handle both string and DateTime inputs.
        $ts = $uploadInfo.timestamp
        if ($ts -is [datetime]) {
            $uploadTime = [DateTimeOffset]::new($ts, [TimeSpan]::Zero)
        } else {
            $uploadTime = [DateTimeOffset]::Parse($ts, [System.Globalization.CultureInfo]::InvariantCulture)
        }
        $hoursAgo = [math]::Round(((Get-Date).ToUniversalTime() - $uploadTime.UtcDateTime).TotalHours, 1)

        if ($hoursAgo -lt 1) {
            Write-Host ""
            Write-Host "  WARNING: Classifier packages were uploaded $hoursAgo hours ago." -ForegroundColor Red
            Write-Host "  Microsoft states custom SITs take 'up to one hour' to propagate," -ForegroundColor Red
            Write-Host "  but real-world experience shows 1-24+ hours depending on workload." -ForegroundColor Red
            Write-Host "  DLP rules referencing custom SITs will almost certainly fail." -ForegroundColor Red
            Write-Host "  Ref: https://learn.microsoft.com/en-us/purview/sit-create-a-custom-sensitive-information-type-in-scc-powershell" -ForegroundColor Gray
            Write-Host ""

            if (-not $Force) {
                $choice = Read-Host "  Continue anyway? (Y/N)"
                if (-not $choice) { $choice = "N" }  # Default to No in non-interactive
                if ($choice -ne "Y") {
                    Write-Host "  Skipping DLP rules. Re-run with -Phase DLPRules after propagation." -ForegroundColor Yellow
                    return
                }
            }
        } elseif ($hoursAgo -lt 4) {
            Write-Host "  Classifier packages uploaded $hoursAgo hours ago." -ForegroundColor Yellow
            Write-Host "  MS official SLA is 1 hour, but propagation may still be in progress." -ForegroundColor Yellow
            Write-Host "  Proceeding - some SITs may not have propagated yet." -ForegroundColor Yellow
        } else {
            Write-Host "  Classifier packages uploaded $hoursAgo hours ago - propagation likely complete." -ForegroundColor Green
        }
    }

    $ruleArgs = @{ SkipValidation = $true }
    if ($WhatIf) { $ruleArgs["WhatIf"] = $true }
    if ($Tenant) { $ruleArgs["Tenant"] = $Tenant }
    if ($TargetEnvironment) { $ruleArgs["TargetEnvironment"] = $TargetEnvironment }
    if ($Prefix) { $ruleArgs["Prefix"] = $Prefix }
    if ($Delegated) { $ruleArgs["Delegated"] = $true }
    & (Join-Path $PSScriptRoot "Deploy-DLPRules.ps1") @ruleArgs
}

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host "`n=== Deployment Complete ===" -ForegroundColor Green
Write-Host "  Session left open (run Disconnect-ExchangeOnline to close).`n"
