#==============================================================================
# greenfield-deploy.ps1
# Clean greenfield deployment: dictionaries, labels, SIT packages, DLP rules.
# Single session, single command. Wipes existing config first.
#
# Usage:
#   pwsh -File scripts/greenfield-deploy.ps1 -UPN admin@yourtenant.onmicrosoft.com
#   pwsh -File scripts/greenfield-deploy.ps1 -UPN admin@agency.gov.au -Tier small
#   pwsh -File scripts/greenfield-deploy.ps1 -UPN admin@agency.gov.au -SkipCleanup
#==============================================================================

param(
    [Parameter(Mandatory)][string]$UPN,
    [string]$Tier = "medium",
    [string]$Scope = "universal,en-government,au",
    [Parameter(Mandatory)][string]$PublishTo,
    [switch]$SkipCleanup,
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
$prefix = $Config.namingPrefix

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  Greenfield DLP Deployment" -ForegroundColor Cyan
Write-Host "  Tenant: $UPN" -ForegroundColor Cyan
Write-Host "  Tier: $Tier | Prefix: $prefix" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

# ── Connect ──────────────────────────────────────────────────────────────────
Write-Host "=== Connecting ===" -ForegroundColor Cyan
$connected = Connect-DLPSession -UPN $UPN
if (-not $connected) { Write-Error "Connection failed."; return }
Write-Host "  Connected.`n" -ForegroundColor Green

# ── Phase 0: Cleanup ────────────────────────────────────────────────────────
if (-not $SkipCleanup) {
    Write-Host "=== Phase 0: Cleanup ===" -ForegroundColor Cyan
    $cleanupNeeded = $false

    # DLP rules first
    $rules = Get-DlpComplianceRule -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$prefix*" -or $_.Name -like "P0*-R0*" }
    if ($rules) {
        $cleanupNeeded = $true
        Write-Host "  Removing $($rules.Count) DLP rules..."
        foreach ($r in $rules) {
            if (-not $WhatIf) {
                try {
                    Invoke-WithRetry -OperationName "Remove-Rule $($r.Name)" -ScriptBlock {
                        Remove-DlpComplianceRule -Identity $r.Name -Confirm:$false -ErrorAction Stop
                    } -MaxRetries 2 -BaseDelaySec 30
                } catch { Write-Warning "  Could not remove rule $($r.Name): $($_.Exception.Message)" }
                Start-Sleep 1
            }
        }
    }

    # DLP policies
    $policies = Get-DlpCompliancePolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$prefix*" -or $_.Name -like "P0*-*" }
    if ($policies) {
        $cleanupNeeded = $true
        Write-Host "  Removing $($policies.Count) DLP policies..."
        foreach ($p in $policies) {
            if (-not $WhatIf) {
                try {
                    Invoke-WithRetry -OperationName "Remove-Policy $($p.Name)" -ScriptBlock {
                        Remove-DlpCompliancePolicy -Identity $p.Name -Confirm:$false -ErrorAction Stop
                    } -MaxRetries 2 -BaseDelaySec 30
                } catch { Write-Warning "  Could not remove policy $($p.Name): $($_.Exception.Message)" }
                Start-Sleep 2
            }
        }
    }

    # SIT packages
    $pkgs = Get-DlpSensitiveInformationTypeRulePackage -ErrorAction SilentlyContinue
    $customPkgCount = 0
    foreach ($pkg in $pkgs) {
        if (-not $pkg.Identity) { continue }
        try {
            $bytes = $pkg.SerializedClassificationRuleCollection
            if ($bytes) {
                $xml = [System.Text.Encoding]::Unicode.GetString($bytes)
                if ($xml -match "Microsoft Corporation") { continue }
            }
        } catch { }
        $cleanupNeeded = $true
        $customPkgCount++
        Write-Host "  Removing SIT package $customPkgCount..."
        if (-not $WhatIf) {
            try {
                Invoke-WithRetry -OperationName "Remove-SITPackage $customPkgCount" -ScriptBlock {
                    Remove-DlpSensitiveInformationTypeRulePackage -Identity $pkg.Identity -Confirm:$false -ErrorAction Stop
                } -MaxRetries 2 -BaseDelaySec 30
            } catch { Write-Warning "  Could not remove SIT package $($pkg.Identity): $($_.Exception.Message)" }
            Start-Sleep 3
        }
    }

    # Label policy
    $labelPolicy = Get-LabelPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$prefix*" -or $_.Name -eq $Config.labelPolicyName }
    if ($labelPolicy) {
        $cleanupNeeded = $true
        Write-Host "  Removing label policy..."
        foreach ($lp in $labelPolicy) {
            if (-not $WhatIf) {
                try {
                    Invoke-WithRetry -OperationName "Remove-LabelPolicy $($lp.Name)" -ScriptBlock {
                        Remove-LabelPolicy -Identity $lp.Name -Confirm:$false -ErrorAction Stop
                    } -MaxRetries 2 -BaseDelaySec 30
                } catch { Write-Warning "  Could not remove label policy $($lp.Name): $($_.Exception.Message)" }
                Start-Sleep 3
            }
        }
    }

    # Labels — sublabels first (highest priority = deepest nesting), then groups, then top-level
    $labels = Get-Label -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$prefix*" -or $_.Name -match "^(OFFICIAL|SENSITIVE|PROTECTED)" }
    if ($labels) {
        $cleanupNeeded = $true
        # Sort: sublabels (have ParentId) first, then groups/top-level
        $sublabels = $labels | Where-Object { $_.ParentId } | Sort-Object { $_.Priority } -Descending
        $topLabels = $labels | Where-Object { -not $_.ParentId } | Sort-Object { $_.Priority } -Descending

        if ($sublabels) {
            Write-Host "  Removing $($sublabels.Count) sublabels..."
            foreach ($l in $sublabels) {
                if (-not $WhatIf) {
                    try {
                        Invoke-WithRetry -OperationName "Remove-Label $($l.Name)" -ScriptBlock {
                            Remove-Label -Identity $l.Name -Confirm:$false -ErrorAction Stop
                        } -MaxRetries 2 -BaseDelaySec 30
                    } catch { Write-Warning "  Could not remove sublabel $($l.Name): $($_.Exception.Message)" }
                    Start-Sleep 2
                }
            }
        }
        # Wait for sublabel deletion to propagate before removing parents
        if ($sublabels -and -not $WhatIf) {
            Write-Host "  Waiting 30s for sublabel deletion..." -ForegroundColor Gray
            Start-Sleep 30
        }
        if ($topLabels) {
            Write-Host "  Removing $($topLabels.Count) top-level labels/groups..."
            foreach ($l in $topLabels) {
                if (-not $WhatIf) {
                    try {
                        Invoke-WithRetry -OperationName "Remove-Label $($l.Name)" -ScriptBlock {
                            Remove-Label -Identity $l.Name -Confirm:$false -ErrorAction Stop
                        } -MaxRetries 2 -BaseDelaySec 30
                    } catch { Write-Warning "  Could not remove label $($l.Name): $($_.Exception.Message)" }
                    Start-Sleep 2
                }
            }
        }
    }

    if ($cleanupNeeded) {
        Write-Host "  Waiting 2 minutes for Purview cleanup propagation..." -ForegroundColor Gray
        Write-Host "  Note: Labels may take hours/days to fully purge. SIT packages and rules take minutes." -ForegroundColor Gray
        if (-not $WhatIf) { Start-Sleep 120 }
    }
    Write-Host "  Clean.`n" -ForegroundColor Green
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
if ($WhatIf) {
    & (Join-Path $PSScriptRoot "Deploy-Labels.ps1") -PublishTo $PublishTo -WhatIf
} else {
    & (Join-Path $PSScriptRoot "Deploy-Labels.ps1") -PublishTo $PublishTo
}
Write-Host ""

# ── Phase 3: SIT Packages ───────────────────────────────────────────────────
Write-Host "=== Phase 3: SIT Packages ===" -ForegroundColor Cyan

$uploadSuccess = 0
$uploadFailed = 0
$xmlFiles = Get-ChildItem -Path $DeployDir -Filter "*.xml" -ErrorAction SilentlyContinue | Sort-Object Name
if (-not $xmlFiles -or $xmlFiles.Count -eq 0) {
    Write-Warning "  No packages in $DeployDir -- run build-deploy-packages.py first"
} else {
    Write-Host "  $($xmlFiles.Count) package(s)"

    foreach ($xmlFile in $xmlFiles) {
        $content = [System.IO.File]::ReadAllText($xmlFile.FullName, [System.Text.Encoding]::UTF8)

        # Patch dictionary placeholders
        foreach ($kv in $guidMap.GetEnumerator()) {
            $content = $content -replace [regex]::Escape($kv.Key), $kv.Value
        }

        # Patch publisher
        if ($Config.publisher) {
            $content = $content -replace '<PublisherName>[^<]+</PublisherName>', "<PublisherName>$($Config.publisher)</PublisherName>"
        }

        if ($content -match '\{\{DICT_') {
            Write-Warning "  $($xmlFile.BaseName): unpatched placeholders, skipping"
            $uploadFailed++
            continue
        }

        $fileBytes = [System.Text.Encoding]::UTF8.GetBytes($content)
        $sizeKB = [math]::Round($fileBytes.Length / 1KB, 1)
        Write-Host "  $($xmlFile.BaseName) (${sizeKB}KB)..." -NoNewline

        if ($WhatIf) { Write-Host " [WHATIF]" -ForegroundColor Yellow; $uploadSuccess++; continue }

        try {
            New-DlpSensitiveInformationTypeRulePackage -FileData $fileBytes -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Host " OK" -ForegroundColor Green
            $uploadSuccess++
        } catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Host "    $($_.Exception.Message)" -ForegroundColor Red
            $uploadFailed++
        }
        Start-Sleep 10
    }

    Write-Host "`n  Packages: $uploadSuccess OK, $uploadFailed failed"
    @{ timestamp = (Get-Date).ToUniversalTime().ToString("o"); packages = $uploadSuccess } | ConvertTo-Json | Out-File (Join-Path $ConfigPath "last-classifier-upload.json") -Encoding utf8
}
Write-Host ""

# ── Phase 4: DLP Rules ──────────────────────────────────────────────────────
Write-Host "=== Phase 4: DLP Rules ===" -ForegroundColor Cyan
Write-Host "  Waiting 15s for SIT indexing..." -ForegroundColor Gray
if (-not $WhatIf) { Start-Sleep 15 }

if ($WhatIf) {
    & (Join-Path $PSScriptRoot "Deploy-DLPRules.ps1") -SkipValidation -WhatIf
} else {
    & (Join-Path $PSScriptRoot "Deploy-DLPRules.ps1") -SkipValidation
}

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "  Greenfield Deployment Complete" -ForegroundColor Green
Write-Host "  Dictionaries: $($guidMap.Count) resolved" -ForegroundColor Green
Write-Host "  Labels: deployed + published" -ForegroundColor Green
if ($uploadSuccess) { Write-Host "  SIT Packages: $uploadSuccess" -ForegroundColor Green }
Write-Host "  DLP Rules: deployed" -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Green
