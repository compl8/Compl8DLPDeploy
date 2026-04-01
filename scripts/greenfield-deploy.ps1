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
    [string]$Tenant,
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
if (-not (Assert-ConfigCustomised -Config $Config)) { return }
$prefix = $Config.namingPrefix

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  Greenfield DLP Deployment" -ForegroundColor Cyan
Write-Host "  Tenant: $UPN" -ForegroundColor Cyan
Write-Host "  Tier: $Tier | Prefix: $prefix" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

# ── Connect ──────────────────────────────────────────────────────────────────
Write-Host "=== Connecting ===" -ForegroundColor Cyan
$connectArgs = @{ UPN = $UPN }
if ($Tenant) { $connectArgs["Tenant"] = $Tenant }
$connected = Connect-DLPSession @connectArgs
if (-not $connected) { Write-Error "Connection failed."; return }
Write-Host "  Connected.`n" -ForegroundColor Green

# ── Phase 0: Cleanup ────────────────────────────────────────────────────────
if (-not $SkipCleanup) {
    Write-Host "=== Phase 0: Cleanup ===" -ForegroundColor Cyan
    $cleanupNeeded = $false

    # DLP policies (cascade-deletes their rules)
    $policies = Get-DlpCompliancePolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$prefix*" -or $_.Name -like "P0*-*" }
    if ($policies) {
        $cleanupNeeded = $true
        Write-Host "  Removing $($policies.Count) DLP policies (rules cascade-deleted)..."
        foreach ($p in $policies) {
            Remove-PurviewObject -Identity $p.Name -InputObject $p `
                -RemoveCommand "Remove-DlpCompliancePolicy" `
                -OperationName "DLP policy" `
                -MaxRetries 2 -BaseDelaySec 30 -WhatIf:$WhatIf
            if (-not $WhatIf) { Start-Sleep 2 }
        }
    }

    # SIT packages — only remove packages matching our publisher
    $pkgs = Get-DlpSensitiveInformationTypeRulePackage -ErrorAction SilentlyContinue
    $ours = @()
    $others = @()
    foreach ($pkg in $pkgs) {
        if (-not $pkg.Identity) { continue }
        if ($pkg.Publisher -eq "Microsoft Corporation" -or $pkg.Publisher -eq "Microsoft") { continue }
        if ($Config.publisher -and $pkg.Publisher -eq $Config.publisher) {
            $ours += $pkg
        } else {
            $others += $pkg
        }
    }
    if ($others.Count -gt 0) {
        Write-Host "  Skipping $($others.Count) package(s) from other publishers:" -ForegroundColor DarkGray
        foreach ($o in $others) { Write-Host "    $($o.Publisher): $($o.Identity)" -ForegroundColor DarkGray }
    }
    if ($ours.Count -gt 0) {
        $cleanupNeeded = $true
        Write-Host "  Removing $($ours.Count) package(s) from '$($Config.publisher)':" -ForegroundColor Yellow
        foreach ($pkg in $ours) { Write-Host "    $($pkg.Identity)" -ForegroundColor Yellow }
        if (-not $WhatIf) {
            $confirm = Read-Host "  Proceed with package removal? (yes/no)"
            if ($confirm -ne "yes") {
                Write-Host "  Package removal skipped." -ForegroundColor Yellow
            } else {
                $pkgDeleted = 0
                foreach ($pkg in $ours) {
                    $status = Remove-PurviewObject -Identity $pkg.Identity `
                        -GetCommand "Get-DlpSensitiveInformationTypeRulePackage" `
                        -RemoveCommand "Remove-DlpSensitiveInformationTypeRulePackage" `
                        -OperationName "SIT package" -MaxRetries 2 -BaseDelaySec 30
                    if ($status -eq "deleted") { $pkgDeleted++ }
                    Start-Sleep 3
                }
                Write-Host "  Removed $pkgDeleted package(s)" -ForegroundColor Green
            }
        }
    }

    # Label policy
    $labelPolicy = Get-LabelPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$prefix*" -or $_.Name -eq $Config.labelPolicyName }
    if ($labelPolicy) {
        $cleanupNeeded = $true
        Write-Host "  Removing label policy..."
        foreach ($lp in $labelPolicy) {
            Remove-PurviewObject -Identity $lp.Name `
                -GetCommand "Get-LabelPolicy" `
                -RemoveCommand "Remove-LabelPolicy" `
                -OperationName "label policy" `
                -MaxRetries 2 -BaseDelaySec 30 -WhatIf:$WhatIf
            if (-not $WhatIf) { Start-Sleep 3 }
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
                Remove-PurviewObject -Identity $l.Name `
                    -GetCommand "Get-Label" `
                    -RemoveCommand "Remove-Label" `
                    -OperationName "sublabel" `
                    -MaxRetries 2 -BaseDelaySec 30 -WhatIf:$WhatIf
                if (-not $WhatIf) { Start-Sleep 2 }
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
                Remove-PurviewObject -Identity $l.Name `
                    -GetCommand "Get-Label" `
                    -RemoveCommand "Remove-Label" `
                    -OperationName "label" `
                    -MaxRetries 2 -BaseDelaySec 30 -WhatIf:$WhatIf
                if (-not $WhatIf) { Start-Sleep 2 }
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

        # Patch SIT entity name prefix (replace "TestPattern - " with configured prefix)
        if ($Config.sitPrefix) {
            $content = $content -replace 'TestPattern - ', "$($Config.sitPrefix) - "
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
            Write-Host " OK (created)" -ForegroundColor Green
            $uploadSuccess++
        } catch {
            # Package already exists — try update instead
            try {
                Set-DlpSensitiveInformationTypeRulePackage -FileData $fileBytes -Confirm:$false -ErrorAction Stop | Out-Null
                Write-Host " OK (updated)" -ForegroundColor Green
                $uploadSuccess++
            } catch {
                Write-Host " FAILED" -ForegroundColor Red
                Write-Host "    $($_.Exception.Message)" -ForegroundColor Red
                $uploadFailed++
            }
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
