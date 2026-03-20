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
#   pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com                     # All phases
#   pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Labels        # Labels only
#   pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Dictionaries  # Dictionaries only
#   pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Classifiers   # Packages only
#   pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase DLPRules      # Rules only
#   pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Cleanup       # Teardown only
#   pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -Phase Cleanup -SkipLabels  # Teardown, keep labels
#   pwsh -File scripts/full-deploy.ps1 -UPN admin@tenant.com -SkipLabels         # Nuke & redeploy, keep labels
#==============================================================================

param(
    [Parameter(Mandatory)][string]$UPN,
    [ValidateSet("All", "Labels", "Dictionaries", "Classifiers", "DLPRules", "Cleanup")]
    [string]$Phase = "All",
    [Parameter(Mandatory)][string]$PublishTo,
    [string]$Scope = "universal,en-government,au",
    [string]$DeployDir = "xml/deploy",
    [switch]$SkipLabels,
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
if (-not (Assert-ConfigCustomised -Config $Config)) { return }
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
    if ($SkipLabels) { Write-Host "  (Labels and label policy will be preserved)" -ForegroundColor Gray }

    # Auto-labeling rules and policies
    Write-Host "  Removing auto-labeling policies..." -ForegroundColor Yellow
    try {
        $alPolicies = @(Get-AutoSensitivityLabelPolicy -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "AL*-$($cleanupPrefix)-$($Config.namingSuffix)" })
        $alDeleted = 0
        foreach ($alp in $alPolicies) {
            $alRules = @()
            try { $alRules = @(Get-AutoSensitivityLabelRule -Policy $alp.Name -ErrorAction SilentlyContinue) } catch { }
            foreach ($alr in $alRules) {
                $status = Remove-PurviewObject -Identity $alr.Name `
                    -GetCommand "Get-AutoSensitivityLabelRule" -RemoveCommand "Remove-AutoSensitivityLabelRule" `
                    -OperationName "AL rule" -MaxRetries 2 -BaseDelaySec 30 -WhatIf:$WhatIf
                if (-not $WhatIf -and $status -eq "deleted") { Start-Sleep 2 }
            }
            if ($alRules.Count -gt 0 -and -not $WhatIf) { Start-Sleep -Seconds $Config.interCallDelaySec }
            $status = Remove-PurviewObject -Identity $alp.Name `
                -GetCommand "Get-AutoSensitivityLabelPolicy" -RemoveCommand "Remove-AutoSensitivityLabelPolicy" `
                -OperationName "AL policy" -MaxRetries 2 -BaseDelaySec 30 -WhatIf:$WhatIf
            if ($status -eq "deleted") { $alDeleted++ }
            if (-not $WhatIf) { Start-Sleep 3 }
        }
        if ($alPolicies.Count -gt 0) { Write-Host "    Processed $($alPolicies.Count) auto-labeling policy(ies) ($alDeleted deleted)" -ForegroundColor Green }
        else { Write-Host "    No matching auto-labeling policies found." -ForegroundColor Gray }
    } catch { Write-Warning "Auto-labeling: $_" }

    # DLP rules first (they block policy deletion)
    Write-Host "  Removing DLP rules..." -ForegroundColor Yellow
    try {
        $rules = Get-DlpComplianceRule -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$($cleanupPrefix)*" -or $_.Name -like "P0*-R0*" }
        $ruleDeleted = 0
        foreach ($rule in $rules) {
            $status = Remove-PurviewObject -Identity $rule.Name `
                -GetCommand "Get-DlpComplianceRule" -RemoveCommand "Remove-DlpComplianceRule" `
                -OperationName "DLP rule" -MaxRetries 2 -BaseDelaySec 30 -WhatIf:$WhatIf
            if ($status -eq "deleted") { $ruleDeleted++ }
            if (-not $WhatIf) { Start-Sleep 2 }
        }
        if ($rules) { Write-Host "    Processed $($rules.Count) rule(s) ($ruleDeleted deleted)" -ForegroundColor Green }
    } catch { Write-Warning "Rules: $_" }

    # Policies
    Write-Host "  Removing DLP policies..." -ForegroundColor Yellow
    try {
        $policies = Get-DlpCompliancePolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$($cleanupPrefix)*" -or $_.Name -like "P0*-*" }
        $polDeleted = 0
        foreach ($pol in $policies) {
            $status = Remove-PurviewObject -Identity $pol.Name `
                -GetCommand "Get-DlpCompliancePolicy" -RemoveCommand "Remove-DlpCompliancePolicy" `
                -OperationName "DLP policy" -MaxRetries 2 -BaseDelaySec 30 -WhatIf:$WhatIf
            if ($status -eq "deleted") { $polDeleted++ }
            if (-not $WhatIf) { Start-Sleep 3 }
        }
        if ($policies) { Write-Host "    Processed $($policies.Count) policy(ies) ($polDeleted deleted)" -ForegroundColor Green }
    } catch { Write-Warning "Policies: $_" }

    # SIT packages — only remove packages matching our publisher
    Write-Host "  Removing SIT packages..." -ForegroundColor Yellow
    try {
        $existing = Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop
        $ours = @()
        $others = @()
        foreach ($pkg in $existing) {
            if (-not $pkg.Identity) { continue }
            if ($pkg.Publisher -eq "Microsoft Corporation" -or $pkg.Publisher -eq "Microsoft") { continue }
            if ($Config.publisher -and $pkg.Publisher -eq $Config.publisher) {
                $ours += $pkg
            } else {
                $others += $pkg
            }
        }

        if ($others.Count -gt 0) {
            Write-Host "    Skipping $($others.Count) package(s) from other publishers:" -ForegroundColor DarkGray
            foreach ($o in $others) {
                Write-Host "      $($o.Publisher): $($o.Identity)" -ForegroundColor DarkGray
            }
        }

        if ($ours.Count -eq 0) {
            Write-Host "    No packages matching publisher '$($Config.publisher)' found." -ForegroundColor Gray
        } else {
            Write-Host "    Removing $($ours.Count) package(s) from '$($Config.publisher)':" -ForegroundColor Yellow
            foreach ($pkg in $ours) {
                Write-Host "      $($pkg.Identity)" -ForegroundColor Yellow
            }

            if (-not $WhatIf) {
                $confirm = Read-Host "    Proceed with removal? (yes/no)"
                if ($confirm -ne "yes") {
                    Write-Host "    Package removal skipped." -ForegroundColor Yellow
                } else {
                    $removed = 0
                    foreach ($pkg in $ours) {
                        $status = Remove-PurviewObject -Identity $pkg.Identity `
                            -GetCommand "Get-DlpSensitiveInformationTypeRulePackage" `
                            -RemoveCommand "Remove-DlpSensitiveInformationTypeRulePackage" `
                            -OperationName "SIT package" -MaxRetries 2 -BaseDelaySec 30
                        if ($status -eq "deleted") { $removed++ }
                        Start-Sleep 5
                    }
                    Write-Host "    Removed $removed package(s)" -ForegroundColor Green
                }
            }
        }
    } catch { Write-Warning "Packages: $_" }

    # Keyword dictionaries
    Write-Host "  Removing keyword dictionaries..." -ForegroundColor Yellow
    try {
        $dicts = Get-DlpKeywordDictionary -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$($Config.namingPrefix)*" }
        $dictDeleted = 0
        foreach ($d in $dicts) {
            $status = Remove-PurviewObject -Identity $d.Identity `
                -GetCommand "Get-DlpKeywordDictionary" -RemoveCommand "Remove-DlpKeywordDictionary" `
                -OperationName "dictionary" -MaxRetries 2 -BaseDelaySec 30 -WhatIf:$WhatIf
            if ($status -eq "deleted") { $dictDeleted++ }
            if (-not $WhatIf) { Start-Sleep 2 }
        }
        if ($dicts) { Write-Host "    Processed $($dicts.Count) dictionary(ies) ($dictDeleted deleted)" -ForegroundColor Green }
    } catch { Write-Warning "Dictionaries: $_" }

    if (-not $SkipLabels) {
        # Label policy
        Write-Host "  Removing label policy..." -ForegroundColor Yellow
        try {
            $labelPolicies = Get-LabelPolicy -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$($cleanupPrefix)*" -or $_.Name -eq $Config.labelPolicyName }
            foreach ($lp in $labelPolicies) {
                $status = Remove-PurviewObject -Identity $lp.Name `
                    -GetCommand "Get-LabelPolicy" -RemoveCommand "Remove-LabelPolicy" `
                    -OperationName "label policy" -MaxRetries 2 -BaseDelaySec 30 -WhatIf:$WhatIf
                if (-not $WhatIf) { Start-Sleep 3 }
            }
        } catch { Write-Warning "Label policy: $_" }

        # Labels (sublabels first, then parents)
        Write-Host "  Removing labels..." -ForegroundColor Yellow
        try {
            $labels = Get-Label -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -like "*$($cleanupPrefix)*" -or $_.Name -match "^(OFFICIAL|SENSITIVE|PROTECTED)"
            }
            if ($labels) {
                $sublabels = $labels | Where-Object { $_.ParentId } | Sort-Object { $_.Priority } -Descending
                $topLabels = $labels | Where-Object { -not $_.ParentId } | Sort-Object { $_.Priority } -Descending
                foreach ($l in @($sublabels) + @($topLabels)) {
                    $status = Remove-PurviewObject -Identity $l.Name `
                        -GetCommand "Get-Label" -RemoveCommand "Remove-Label" `
                        -OperationName "label" -MaxRetries 2 -BaseDelaySec 30 -WhatIf:$WhatIf
                    if (-not $WhatIf) { Start-Sleep 2 }
                }
            }
        } catch { Write-Warning "Labels: $_" }
    } else {
        Write-Host "  Skipping label and label policy removal (-SkipLabels)" -ForegroundColor DarkGray
    }

    Write-Host "  Waiting 2 minutes for Purview cleanup propagation..." -ForegroundColor Gray
    Write-Host "  Note: Labels may take hours/days to fully purge. SIT packages and rules take minutes." -ForegroundColor Gray
    if (-not $WhatIf) { Start-Sleep 120 }
    Write-Host ""

    if ($Phase -eq "Cleanup") {
        Write-Host "=== Cleanup Complete ===" -ForegroundColor Green
        return
    }
}

# ── Phase 1: Labels ──────────────────────────────────────────────────────────
if (($Phase -eq "All" -or $Phase -eq "Labels") -and -not $SkipLabels) {
    Write-Host "=== Phase 1: Deploying Labels ===" -ForegroundColor Cyan
    if ($WhatIf) {
        & (Join-Path $PSScriptRoot "Deploy-Labels.ps1") -PublishTo $PublishTo -WhatIf
    } else {
        & (Join-Path $PSScriptRoot "Deploy-Labels.ps1") -PublishTo $PublishTo
    }
    Write-Host ""
}

# ── Phase 1.5: Keyword Dictionaries ──────────────────────────────────────────
if ($Phase -eq "All" -or $Phase -eq "Dictionaries" -or $Phase -eq "Classifiers") {
    Write-Host "=== Phase 1.5: Keyword Dictionaries ===" -ForegroundColor Cyan

    $manifestUrl = "https://testpattern.dev/api/export/dictionary-manifest?scope=$Scope"
    if ($WhatIf) {
        $guidMap = Sync-DlpKeywordDictionaries -ManifestUrl $manifestUrl -WhatIf
    } else {
        $guidMap = Sync-DlpKeywordDictionaries -ManifestUrl $manifestUrl
    }
    Write-Host ""

    if ($Phase -eq "Dictionaries") { return }
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
            $content = [System.IO.File]::ReadAllText($xmlFile.FullName, [System.Text.Encoding]::UTF8)

            # Patch dictionary placeholders if we have a GUID map
            if ($guidMap) {
                foreach ($kv in $guidMap.GetEnumerator()) {
                    $content = $content -replace [regex]::Escape($kv.Key), $kv.Value
                }
            }

            # Patch publisher
            if ($Config.publisher) {
                $content = $content -replace '<PublisherName>[^<]+</PublisherName>', "<PublisherName>$($Config.publisher)</PublisherName>"
            }

            # Check for unpatched placeholders
            if ($content -match '\{\{DICT_') {
                Write-Warning "  $($xmlFile.BaseName): unpatched dictionary placeholders, skipping"
                $uploadFailed++
                continue
            }

            $fileData = [System.Text.Encoding]::UTF8.GetBytes($content)
            $sizeKB = [math]::Round($fileData.Length / 1KB, 1)
            Write-Host "  $($xmlFile.BaseName) (${sizeKB}KB)..." -NoNewline
            if ($WhatIf) { Write-Host " [WHATIF]" -ForegroundColor Yellow; $uploadSuccess++; continue }
            try {
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
