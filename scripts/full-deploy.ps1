#==============================================================================
# full-deploy.ps1
# Orchestrates DLP deployment in three phases:
#   Phase 1: Labels (immediate)
#   Phase 2: SIT classifier packages (immediate, but SITs take 4-24h to index)
#   Phase 3: DLP rules (requires SITs to be indexed first)
#
# Phases can be run independently or together. When run together, Phase 3
# checks whether custom SITs have propagated and warns if too recent.
#
# Usage:
#   pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com                  # All phases
#   pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Labels     # Labels only
#   pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Classifiers # Packages only
#   pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase DLPRules   # Rules only
#   pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Cleanup    # Teardown only
#==============================================================================

param(
    [Parameter(Mandatory)][string]$UPN,
    [ValidateSet("All", "Labels", "Classifiers", "DLPRules", "Cleanup")]
    [string]$Phase = "All",
    [string]$PublishTo = "All",
    [string]$DeployDir = "xml/deploy",
    [switch]$Force,
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent

Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

# ── Load Config ───────────────────────────────────────────────────────────────
$ConfigPath  = Join-Path $ProjectRoot "config"
$Defaults    = Get-ModuleDefaults
$settingsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
$Config      = Merge-GlobalConfig -Defaults $Defaults -GlobalJson $settingsJson
$cleanupPrefix = $Config.namingPrefix

# ── Connect ──────────────────────────────────────────────────────────────────
Write-Host "`n=== Connecting to $UPN ===" -ForegroundColor Cyan
$connected = Connect-DLPSession -UPN $UPN
if (-not $connected) {
    Write-Error "Connection failed. Aborting."
    return
}
Write-Host "  Connected.`n" -ForegroundColor Green

# ── Cleanup ──────────────────────────────────────────────────────────────────
if ($Phase -eq "All" -or $Phase -eq "Cleanup") {
    Write-Host "=== Cleanup: Removing existing deployment ===" -ForegroundColor Cyan

    # Rules first (they block policy deletion)
    Write-Host "  Removing DLP rules..." -ForegroundColor Yellow
    try {
        $rules = Get-DlpComplianceRule -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$($cleanupPrefix)*" -or $_.Name -like "P0*-R0*" }
        foreach ($rule in $rules) {
            Write-Host "    $($rule.Name)" -ForegroundColor Yellow
            if (-not $WhatIf) { Remove-DlpComplianceRule -Identity $rule.Name -Confirm:$false -ErrorAction SilentlyContinue; Start-Sleep 2 }
        }
        if ($rules) { Write-Host "    Removed $($rules.Count) rule(s)" -ForegroundColor Green }
    } catch { Write-Warning "Rules: $_" }

    # Policies
    Write-Host "  Removing DLP policies..." -ForegroundColor Yellow
    try {
        $policies = Get-DlpCompliancePolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$($cleanupPrefix)*" -or $_.Name -like "P0*-*" }
        foreach ($pol in $policies) {
            Write-Host "    $($pol.Name)" -ForegroundColor Yellow
            if (-not $WhatIf) { Remove-DlpCompliancePolicy -Identity $pol.Name -Confirm:$false -ErrorAction SilentlyContinue; Start-Sleep 3 }
        }
        if ($policies) { Write-Host "    Removed $($policies.Count) policy(ies)" -ForegroundColor Green }
    } catch { Write-Warning "Policies: $_" }

    # SIT packages
    Write-Host "  Removing SIT packages..." -ForegroundColor Yellow
    try {
        $existing = Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop
        $removed = 0
        foreach ($pkg in $existing) {
            $identity = $pkg.Identity
            if (-not $identity) { continue }
            try {
                $bytes = $pkg.SerializedClassificationRuleCollection
                if ($bytes) {
                    $xml = [System.Text.Encoding]::Unicode.GetString($bytes)
                    if ($xml -match "Microsoft Corporation") { continue }
                }
            } catch { }
            Write-Host "    $identity" -ForegroundColor Yellow
            if (-not $WhatIf) { Remove-DlpSensitiveInformationTypeRulePackage -Identity $identity -Confirm:$false -ErrorAction Stop; $removed++; Start-Sleep 5 }
        }
        if ($removed -gt 0) { Write-Host "    Removed $removed package(s)" -ForegroundColor Green }
    } catch { Write-Warning "Packages: $_" }

    Write-Host "  Waiting 60s for propagation..." -ForegroundColor Gray
    if (-not $WhatIf) { Start-Sleep 60 }
    Write-Host ""

    if ($Phase -eq "Cleanup") {
        Write-Host "=== Cleanup Complete ===" -ForegroundColor Green
        return
    }
}

# ── Phase 1: Labels ──────────────────────────────────────────────────────────
if ($Phase -eq "All" -or $Phase -eq "Labels") {
    Write-Host "=== Phase 1: Deploying Labels ===" -ForegroundColor Cyan
    if ($WhatIf) {
        & (Join-Path $PSScriptRoot "Deploy-Labels.ps1") -PublishTo $PublishTo -WhatIf
    } else {
        & (Join-Path $PSScriptRoot "Deploy-Labels.ps1") -PublishTo $PublishTo
    }
    Write-Host ""
}

# ── Phase 2: SIT Classifier Packages ─────────────────────────────────────────
if ($Phase -eq "All" -or $Phase -eq "Classifiers") {
    Write-Host "=== Phase 2: Uploading SIT Packages ===" -ForegroundColor Cyan

    $deployPath = Join-Path $ProjectRoot $DeployDir
    $xmlFiles = Get-ChildItem -Path $deployPath -Filter "*.xml" | Sort-Object Name

    if ($xmlFiles.Count -eq 0) {
        Write-Warning "No XML files found in $deployPath"
    } else {
        Write-Host "  Found $($xmlFiles.Count) package(s)"
        $uploadSuccess = 0
        $uploadFailed = 0

        foreach ($xmlFile in $xmlFiles) {
            $sizeKB = [math]::Round($xmlFile.Length / 1024, 1)
            Write-Host "  $($xmlFile.BaseName) (${sizeKB}KB)..." -NoNewline
            if ($WhatIf) { Write-Host " [WHATIF]" -ForegroundColor Yellow; $uploadSuccess++; continue }
            try {
                $fileData = [System.IO.File]::ReadAllBytes($xmlFile.FullName)
                New-DlpSensitiveInformationTypeRulePackage -FileData $fileData -Confirm:$false -ErrorAction Stop | Out-Null
                Write-Host " OK" -ForegroundColor Green
                $uploadSuccess++
            } catch {
                Write-Host " FAILED" -ForegroundColor Red
                Write-Host "    $($_.Exception.Message)" -ForegroundColor Red
                $uploadFailed++
            }
            Start-Sleep 10
        }
        Write-Host "`n  Upload: $uploadSuccess succeeded, $uploadFailed failed"

        if ($Phase -eq "Classifiers" -or $Phase -eq "All") {
            Write-Host ""
            Write-Host "  NOTE: Custom SITs take 4-24 hours to propagate in Purview's DLP engine." -ForegroundColor Yellow
            Write-Host "  DLP rules referencing these SITs will fail until propagation completes." -ForegroundColor Yellow
            Write-Host "  Run Phase 3 (DLPRules) separately after propagation:" -ForegroundColor Yellow
            Write-Host "    .\scripts\full-deploy.ps1 -UPN $UPN -Phase DLPRules" -ForegroundColor Gray
            Write-Host ""

            # Record upload timestamp for propagation check
            $timestampFile = Join-Path $ProjectRoot "config" "last-classifier-upload.json"
            @{ timestamp = (Get-Date).ToUniversalTime().ToString("o"); packages = $uploadSuccess } | ConvertTo-Json | Out-File $timestampFile -Encoding utf8
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
        $uploadTime = [DateTimeOffset]::Parse($uploadInfo.timestamp)
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

    if ($WhatIf) {
        & (Join-Path $PSScriptRoot "Deploy-DLPRules.ps1") -SkipValidation -WhatIf
    } else {
        & (Join-Path $PSScriptRoot "Deploy-DLPRules.ps1") -SkipValidation
    }
}

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host "`n=== Deployment Complete ===" -ForegroundColor Green
Write-Host "  Session left open (run Disconnect-ExchangeOnline to close).`n"
