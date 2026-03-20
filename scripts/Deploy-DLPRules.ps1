#==============================================================================
# Deploy-DLPRules.ps1
# Deploys DLP policies and rules to Microsoft Purview.
# Slimmed-down version — all shared functions come from DLP-Deploy module.
#
# Usage:
#   .\scripts\Deploy-DLPRules.ps1 -Connect                  # Deploy
#   .\scripts\Deploy-DLPRules.ps1 -Connect -WhatIf          # Dry run
#   .\scripts\Deploy-DLPRules.ps1 -Connect -Cleanup         # Remove policies/rules
#   .\scripts\Deploy-DLPRules.ps1 -Connect -SkipValidation  # Skip SIT check
#   .\scripts\Deploy-DLPRules.ps1 -Connect -SkipVerification
#==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$SkipValidation,
    [switch]$SkipVerification,
    [switch]$Cleanup,
    [switch]$Connect,
    [string]$UPN
)

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "config"

# Import shared module
Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

$ErrorActionPreference = "Stop"

#region Config Loading & Validation
Write-Host "=== Loading Configuration ===" -ForegroundColor Cyan

$Defaults        = Get-ModuleDefaults
$globalJson      = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json")     -Description "deployment settings"
$labelsJson      = Import-JsonConfig -FilePath (Join-Path $ConfigPath "labels.json")        -Description "label definitions"
$policiesJson    = Import-JsonConfig -FilePath (Join-Path $ConfigPath "policies.json")      -Description "policy definitions"
$classifiersJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "classifiers.json")   -Description "classifier definitions"
$overridesJson   = Import-JsonConfig -FilePath (Join-Path $ConfigPath "rule-overrides.json") -Description "rule overrides"

if (-not $labelsJson -or -not $policiesJson -or -not $classifiersJson) {
    Write-Error "Required config files missing or invalid. Aborting."
    return
}

$Config      = Merge-GlobalConfig -Defaults $Defaults -GlobalJson $globalJson
$Labels      = Resolve-LabelConfig -LabelsJson $labelsJson
$Policies    = Resolve-PolicyConfig -PoliciesJson $policiesJson
$Classifiers = Resolve-ClassifierConfig -ClassifiersJson $classifiersJson -Defaults $Defaults
$Overrides   = Resolve-RuleOverrides -OverridesJson $overridesJson
$PolicyMode  = Resolve-PolicyMode -AuditMode $Config.auditMode -NotifyUser $Config.notifyUser

Write-Host "  Policy Mode: $PolicyMode" -ForegroundColor Gray

# Cross-validation
$validationErrors = @()
$validationWarnings = @()
foreach ($label in $Labels) {
    if (-not $Classifiers.ContainsKey($label.code)) {
        $validationWarnings += "Label '$($label.code)' ($($label.fullName)) has no classifiers -- DLP rules will be skipped for this label"
    }
}
$labelCodes = $Labels | ForEach-Object { $_.code }
foreach ($key in $Classifiers.Keys) {
    if ($key -notin $labelCodes) {
        $validationErrors += "Classifier key '$key' does not match any label code"
    }
}
foreach ($key in $Classifiers.Keys) {
    if ($Classifiers[$key].Count -eq 0) {
        $validationErrors += "Classifier list for '$key' is empty"
    }
}

if ($validationWarnings.Count -gt 0) {
    Write-Host "`n  Config warnings:" -ForegroundColor Yellow
    foreach ($warn in $validationWarnings) {
        Write-Host "    - $warn" -ForegroundColor Yellow
    }
}

if ($validationErrors.Count -gt 0) {
    Write-Host "`n  Config validation errors:" -ForegroundColor Red
    foreach ($err in $validationErrors) {
        Write-Host "    - $err" -ForegroundColor Red
    }
    Write-Error "Fix config errors before deploying. Aborting."
    return
}

# Filter to only labels that have classifiers
$Labels = $Labels | Where-Object { $Classifiers.ContainsKey($_.code) }

$totalRules = 0
foreach ($p in ($Policies | Where-Object { $_.Enabled })) {
    foreach ($l in $Labels) {
        $totalRules += @(Split-ClassifierChunks -ClassifierList $Classifiers[$l.code] -MaxPerRule 125).Count
    }
}
$totalClassifiers = ($Classifiers.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
$totalTCs = ($Classifiers.Values | ForEach-Object { ($_ | Where-Object { $_.ClassifierType -eq "MLModel" }).Count } | Measure-Object -Sum).Sum
$totalSITs = $totalClassifiers - $totalTCs
Write-Host "  Labels: $($Labels.Count), Policies: $($Policies.Count), Rules: $totalRules, Classifiers: $totalClassifiers ($totalSITs SITs, $totalTCs TCs)" -ForegroundColor Gray
#endregion

#region Connection & Session
if ($Connect) {
    $connected = Connect-DLPSession -UPN $UPN
    if (-not $connected) { return }
}

if (-not (Assert-DLPSession)) { return }
#endregion

#region Logging
$null = Start-DeploymentLog -ScriptName "Deploy-DLPRules"
#endregion

#region Cleanup
if ($Cleanup) {
    Write-Host "`n=== Cleanup Mode ===" -ForegroundColor Yellow

    $policyNames = foreach ($policy in $Policies) {
        Get-PolicyName -PolicyNumber $policy.Number -PolicyCode $policy.Code -Prefix $Config.namingPrefix -Suffix $Config.namingSuffix
    }

    foreach ($policyName in $policyNames) {
        Write-Host "`n  Policy: $policyName" -ForegroundColor Cyan

        # Remove rules first
        $rules = @()
        try { $rules = Get-DlpComplianceRule -Policy $policyName -ErrorAction Stop } catch {
            $msg = $_.Exception.Message
            if ($msg -notmatch "couldn't be found|not found|does not exist") {
                Write-Warning "  Error listing rules for ${policyName}: $msg"
            }
        }
        $ruleIndex = 0
        foreach ($rule in $rules) {
            if ($ruleIndex -gt 0 -and -not $WhatIfPreference) { Start-Sleep -Seconds $Config.interCallDelaySec }
            $null = Remove-PurviewObject -Identity $rule.Name `
                -GetCommand "Get-DlpComplianceRule" `
                -RemoveCommand "Remove-DlpComplianceRule" `
                -OperationName "DLP rule" `
                -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec `
                -WhatIf:$WhatIfPreference
            $ruleIndex++
        }

        # Remove policy
        if ($rules.Count -gt 0 -and -not $WhatIfPreference) { Start-Sleep -Seconds $Config.interCallDelaySec }
        $null = Remove-PurviewObject -Identity $policyName `
            -GetCommand "Get-DlpCompliancePolicy" `
            -RemoveCommand "Remove-DlpCompliancePolicy" `
            -OperationName "DLP policy" `
            -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec `
            -WhatIf:$WhatIfPreference
    }

    Write-Host "`nCleanup complete." -ForegroundColor Green
    try { Stop-Transcript } catch { }
    return
}
#endregion

#region SIT Validation
if (-not $Config.skipSitValidation -and -not $SkipValidation) {
    Write-Host "`n=== Validating Sensitive Information Types ===" -ForegroundColor Cyan

    $tenantSITs = $null
    try {
        $tenantSITs = Get-DlpSensitiveInformationType -ErrorAction Stop
        Write-Host "  Retrieved $($tenantSITs.Count) SITs from tenant." -ForegroundColor Gray
    } catch {
        Write-Warning "Could not retrieve SIT list from tenant. Skipping validation."
    }

    if ($tenantSITs) {
        $tenantSITLookup = @{}
        foreach ($t in $tenantSITs) {
            $tenantSITLookup[$t.Id.ToString().ToLower()] = $t.Name
        }

        $missingSITs = @()
        $mismatchedNames = @()
        $tcCount = 0
        foreach ($labelCode in $Classifiers.Keys) {
            foreach ($entry in $Classifiers[$labelCode]) {
                # Skip trainable classifiers — they aren't in the SIT list
                if ($entry.ClassifierType -eq "MLModel") { $tcCount++; continue }
                $lookupId = $entry.Id.ToLower()
                if (-not $tenantSITLookup.ContainsKey($lookupId)) {
                    $missingSITs += "  [$labelCode] $($entry.Name) ($($entry.Id))"
                } elseif ($tenantSITLookup[$lookupId] -ne $entry.Name) {
                    $mismatchedNames += "  [$labelCode] Config: '$($entry.Name)' -> Tenant: '$($tenantSITLookup[$lookupId])' ($($entry.Id))"
                }
            }
        }
        if ($tcCount -gt 0) {
            Write-Host "  Skipped $tcCount trainable classifier(s) (not validated against SIT list)" -ForegroundColor Gray
        }

        if ($mismatchedNames.Count -gt 0) {
            Write-Host "`n  $($mismatchedNames.Count) SIT name mismatch(es) (GUIDs match, names differ):" -ForegroundColor Yellow
            $mismatchedNames | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
        }

        if ($missingSITs.Count -gt 0) {
            Write-Host "`n  $($missingSITs.Count) SIT(s) not found in tenant:" -ForegroundColor Red
            $missingSITs | ForEach-Object { Write-Host $_ -ForegroundColor Red }
            Write-Warning "Rules referencing missing SITs will fail to create. Consider running with -SkipValidation to proceed."
            try { Stop-Transcript } catch { }
            return
        } else {
            Write-Host "  All SITs found in tenant." -ForegroundColor Green
        }
    }
} else {
    Write-Host "`n=== SIT Validation Skipped ===" -ForegroundColor Yellow
}
#endregion

#region Deployment Loop
Write-Host "`n=== DLP Rules Deployment ===" -ForegroundColor Cyan
Write-Host "Starting deployment at $(Get-Date)" -ForegroundColor Cyan

$successPolicies = 0
$failPolicies    = 0
$skippedPolicies = 0
$successRules    = 0
$failRules       = 0

foreach ($policy in $Policies) {
    if (-not $policy.Enabled) {
        Write-Host "`n--- Policy $($policy.Code) skipped (disabled in config) ---" -ForegroundColor Gray
        $skippedPolicies++
        continue
    }

    $policyName = Get-PolicyName -PolicyNumber $policy.Number -PolicyCode $policy.Code -Prefix $Config.namingPrefix -Suffix $Config.namingSuffix
    $policyNum  = $policy.Number

    Write-Host "`n--- Policy: $policyName ---" -ForegroundColor Green

    $newPolicyParams = @{
        Name    = $policyName
        Comment = $policy.Comment
        Mode    = $PolicyMode
    }
    foreach ($loc in $policy.Location.GetEnumerator()) {
        $newPolicyParams[$loc.Key] = $loc.Value
    }

    $existingPolicy = $null
    try { $existingPolicy = Get-DlpCompliancePolicy -Identity $policyName -ErrorAction Stop } catch { }

    try {
        if ($existingPolicy) {
            Write-Host "  Policy exists. Updating..." -ForegroundColor Yellow
            $updatePolicyParams = @{
                Identity = $policyName
                Comment  = $policy.Comment
                Mode     = $PolicyMode
            }
            if ($PSCmdlet.ShouldProcess($policyName, "Set-DlpCompliancePolicy")) {
                Invoke-WithRetry -OperationName "Set-Policy $policyName" -ScriptBlock {
                    Set-DlpCompliancePolicy @updatePolicyParams -Confirm:$false -ErrorAction Stop
                } -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec
            }
        } else {
            Write-Host "  Creating new policy..." -ForegroundColor Green
            if ($PSCmdlet.ShouldProcess($policyName, "New-DlpCompliancePolicy")) {
                Invoke-WithRetry -OperationName "New-Policy $policyName" -ScriptBlock {
                    New-DlpCompliancePolicy @newPolicyParams -ErrorAction Stop
                } -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec
            }
        }
        $successPolicies++
    } catch {
        $errMsg = $_.Exception.Message
        if ($policy.Optional -and ($errMsg -match "EndpointDlpLocation|TeamsLocation|parameter")) {
            Write-Warning "  Optional policy skipped — feature not available in this tenant: $errMsg"
            $skippedPolicies++
            continue
        }
        Write-Error "  Failed to create/update policy ${policyName}: $errMsg"
        $failPolicies++
        Write-Warning "  Skipping rules for this policy."
        continue
    }

    # Create rules per label — auto-split if >125 classifiers
    $ruleNum = 0
    foreach ($label in $Labels) {
        $ruleNum++
        $labelCode      = $label.code
        $classifierList = $Classifiers[$labelCode]
        $chunks = @(Split-ClassifierChunks -ClassifierList $classifierList -MaxPerRule 125)

        $chunkIndex = 0
        foreach ($chunk in $chunks) {
            $chunkIndex++
            if (($ruleNum -gt 1 -or $chunkIndex -gt 1) -and -not $WhatIfPreference) { Start-Sleep -Seconds $Config.interCallDelaySec }

            # Build rule name: append chunk letter to R-number only when split
            if ($chunks.Count -gt 1) {
                $chunkLetter = [char]([int][char]'a' + $chunkIndex - 1)
                $ruleName = "P{0:D2}-R{1:D2}{2}-{3}-{4}-{5}" -f $policyNum, $ruleNum, $chunkLetter, $policy.Code, $labelCode, $Config.namingSuffix
            } else {
                $ruleName = Get-RuleName -PolicyNumber $policyNum -RuleNumber $ruleNum -PolicyCode $policy.Code -LabelCode $labelCode -Suffix $Config.namingSuffix
            }

            $condition = New-DLPSITCondition -ClassifierList $chunk -ScopeParam $policy.ScopeParam -ScopeValue $policy.ScopeValue

            $chunkNote = if ($chunks.Count -gt 1) { " [chunk $chunkIndex/$($chunks.Count)]" } else { "" }
            Write-Host "  Creating Rule: $ruleName ($($label.fullName)$chunkNote, $($chunk.Count) classifiers, $($condition.Format))" -ForegroundColor Cyan

            $baseRuleParams = @{
                Name                = $ruleName
                Policy              = $policyName
                Comment             = "$($label.fullName)$chunkNote ($($chunk.Count) classifiers)"
                ReportSeverityLevel = $(if ($Config.generateIncidentReport) { $Config.incidentReportSeverity } else { "Low" })
                Disabled            = $false
            }

            if ($condition.Format -eq "AdvancedRule") {
                $baseRuleParams["AdvancedRule"] = $condition.Value
            } else {
                $baseRuleParams["ContentContainsSensitiveInformation"] = $condition.Value
                if ($policy.ScopeParam) {
                    $baseRuleParams[$policy.ScopeParam] = $policy.ScopeValue
                }
            }

            if ($Config.generateIncidentReport) {
                $baseRuleParams["GenerateIncidentReport"] = $Config.incidentReportRecipient
                $baseRuleParams["IncidentReportContent"]  = "All"
            }
            if ($Config.notifyUser) {
                $baseRuleParams["NotifyUser"] = "SiteAdmin,LastModifier,Owner"
            }

            $finalRuleParams = Get-MergedRuleParams -BaseParams $baseRuleParams -Overrides $Overrides -LabelCode $labelCode -PolicyCode $policy.Code -RuleName $ruleName

            $existingRule = $null
            try { $existingRule = Get-DlpComplianceRule -Identity $ruleName -ErrorAction Stop } catch { }

            try {
                if ($existingRule) {
                    Write-Host "    Rule exists. Updating..." -ForegroundColor Yellow
                    $updateRuleParams = @{ Identity = $ruleName }
                    foreach ($key in $finalRuleParams.Keys) {
                        if ($key -notin @("Name", "Policy")) {
                            $updateRuleParams[$key] = $finalRuleParams[$key]
                        }
                    }
                    if ($PSCmdlet.ShouldProcess($ruleName, "Set-DlpComplianceRule")) {
                        Invoke-WithRetry -OperationName "Set-Rule $ruleName" -ScriptBlock {
                            Set-DlpComplianceRule @updateRuleParams -Confirm:$false -ErrorAction Stop
                        } -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec
                    }
                } else {
                    if ($PSCmdlet.ShouldProcess($ruleName, "New-DlpComplianceRule")) {
                        Invoke-WithRetry -OperationName "New-Rule $ruleName" -ScriptBlock {
                            if ($Config.suppressRuleOutput) {
                                $null = New-DlpComplianceRule @finalRuleParams -ErrorAction Stop
                            } else {
                                New-DlpComplianceRule @finalRuleParams -ErrorAction Stop
                            }
                        } -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec
                    }
                }
                $successRules++
            } catch {
                Write-Warning "    Failed to create/update rule ${ruleName}: $($_.Exception.Message)"
                $failRules++
            }
        }
    }
}
#endregion

#region Verification
if (-not $SkipVerification) {
    Write-Host "`n=== Deployment Verification ===" -ForegroundColor Cyan

    $policyPattern = "P0[1-5]-*-$($Config.namingPrefix)-$($Config.namingSuffix)"
    $rulePattern   = "P0[1-5]-R*-*-*-$($Config.namingSuffix)"

    $deployedPolicies = Get-DlpCompliancePolicy -ErrorAction Stop | Where-Object { $_.Name -like $policyPattern }
    $deployedRules = Get-DlpComplianceRule -ErrorAction Stop | Where-Object { $_.Name -like $rulePattern } | Sort-Object Policy, Priority

    $expectedPolicies = ($Policies | Where-Object { $_.Enabled }).Count
    $expectedRules = 0
    foreach ($l in $Labels) {
        $expectedRules += @(Split-ClassifierChunks -ClassifierList $Classifiers[$l.code] -MaxPerRule 125).Count
    }
    $expectedRules *= $expectedPolicies

    Write-Host "`nPolicies deployed: $($deployedPolicies.Count) (expected $expectedPolicies)" -ForegroundColor $(if ($deployedPolicies.Count -ge $expectedPolicies) { "Green" } else { "Yellow" })
    $deployedPolicies | Format-Table Name, Mode -AutoSize

    Write-Host "Rules deployed: $($deployedRules.Count) (expected $expectedRules)" -ForegroundColor $(if ($deployedRules.Count -ge $expectedRules) { "Green" } else { "Yellow" })
    $deployedRules | Format-Table Name, Policy, Priority -AutoSize
} else {
    Write-Host "`n=== Verification Skipped ===" -ForegroundColor Yellow
}
#endregion

#region Summary
Write-Host "`n=== Deployment Summary ===" -ForegroundColor Cyan
Write-Host "  Policies: $successPolicies succeeded, $failPolicies failed, $skippedPolicies skipped" -ForegroundColor $(if ($failPolicies -eq 0) { "Green" } else { "Red" })
Write-Host "  Rules:    $successRules succeeded, $failRules failed" -ForegroundColor $(if ($failRules -eq 0) { "Green" } else { "Red" })
Write-Host "`nDeployment complete at $(Get-Date)" -ForegroundColor Green

try { Stop-Transcript } catch { }
#endregion
