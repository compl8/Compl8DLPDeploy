#==============================================================================
# Deploy-DLPRules.ps1
# Deploys DLP policies and rules to Microsoft Purview.
# Slimmed-down version — all shared functions come from DLP-Deploy module.
#
# Usage:
#   .\scripts\Deploy-DLPRules.ps1 -Connect                  # Deploy
#   .\scripts\Deploy-DLPRules.ps1 -Connect -Tenant compl8.dev -TargetEnvironment nonprod
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
    [string]$UPN,
    [string]$Tenant,
    [switch]$Delegated,
    [string]$TargetEnvironment,
    [string]$Prefix,
    [switch]$RegisterFingerprint,
    [string]$FingerprintMode = 'warn',
    [string]$ExpectedTenantId,
    [string]$DeploymentSessionPath,
    [switch]$AllowDirectRun
)

$ProjectRoot = Split-Path $PSScriptRoot -Parent

# Import shared modules
Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force
Assert-OrchestrationGate -ScriptName 'Deploy-DLPRules.ps1' -AllowDirectRun:$AllowDirectRun -SessionPath $DeploymentSessionPath

$script:DeploymentSession = $null
if ($DeploymentSessionPath) {
    if (-not (Test-Path -LiteralPath $DeploymentSessionPath)) { throw "DeploymentSessionPath not found: $DeploymentSessionPath" }
    Import-Module (Join-Path $ProjectRoot "modules" "DeploymentPackage.psm1") -Force
    $script:DeploymentSession = Read-DeploymentPackageManifest -SessionPath $DeploymentSessionPath
}

$ConfigPath = if ($script:DeploymentSession) { Join-Path $script:DeploymentSession.SessionPath 'working/config' } else { Get-EffectiveConfigDir -ProjectRoot $ProjectRoot -Environment $TargetEnvironment }
$script:DRStartedAt = (Get-Date).ToString('o')

$ErrorActionPreference = "Stop"

function Invoke-TenantFingerprintGate {
    $fingerprint = Test-DeploymentTenantFingerprint -ProjectRoot $ProjectRoot -TargetEnvironment $TargetEnvironment -RegisterIfMissing:$RegisterFingerprint -RegisterMode $FingerprintMode -ExpectedTenantId $ExpectedTenantId

    Write-Host "`n=== Tenant Fingerprint ===" -ForegroundColor Cyan
    Write-Host "  Environment: $($fingerprint.environment)" -ForegroundColor Gray
    Write-Host "  Mode:        $($fingerprint.mode)" -ForegroundColor Gray
    if ($fingerprint.actual.name) {
        Write-Host "  Tenant:      $($fingerprint.actual.name)" -ForegroundColor Gray
    }
    if ($fingerprint.actual.guid) {
        Write-Host "  Tenant GUID: $($fingerprint.actual.guid)" -ForegroundColor Gray
    }

    foreach ($message in @($fingerprint.messages)) {
        $color = if (-not $fingerprint.passed) { "Red" } elseif ($fingerprint.configured -and $fingerprint.matched) { "Green" } else { "Yellow" }
        Write-Host "  $message" -ForegroundColor $color
    }

    foreach ($mismatch in @($fingerprint.mismatches)) {
        Write-Host "  MISMATCH $($mismatch.field): expected '$($mismatch.expected)', actual '$($mismatch.actual)'" -ForegroundColor Red
    }

    if (-not $fingerprint.passed) {
        Write-Error "Tenant fingerprint check failed. Aborting before DLP rule changes."
        return $false
    }

    return $true
}

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
$Config      = Set-DeploymentConfigPrefix -Config $Config -Prefix $Prefix
$Labels      = Resolve-LabelConfig -LabelsJson $labelsJson
$Policies    = Resolve-PolicyConfig -PoliciesJson $policiesJson
$Classifiers = Resolve-ClassifierConfig -ClassifiersJson $classifiersJson -Defaults $Defaults
$Overrides   = Resolve-RuleOverrides -OverridesJson $overridesJson
$PolicyMode  = Resolve-PolicyMode -AuditMode $Config.auditMode -NotifyUser $Config.notifyUser
$DeploymentId = if ($env:COMPL8_DEPLOYMENT_ID) { $env:COMPL8_DEPLOYMENT_ID } else { Get-Date -Format "yyyyMMdd" }

Write-Host "  Policy Mode: $PolicyMode" -ForegroundColor Gray

function Resolve-DeploymentPolicyName {
    param([Parameter(Mandatory)][hashtable]$Policy)
    return Get-PolicyName -PolicyNumber $Policy.Number -PolicyCode $Policy.Code -Config $Config
}

function Resolve-DeploymentRuleName {
    param(
        [Parameter(Mandatory)][hashtable]$Policy,
        [Parameter(Mandatory)][int]$RuleNumber,
        [Parameter(Mandatory)][string]$LabelCode,
        [string]$ChunkLetter = ""
    )
    return Get-RuleName -PolicyNumber $Policy.Number -RuleNumber $RuleNumber -PolicyCode $Policy.Code -LabelCode $LabelCode -ChunkLetter $ChunkLetter -Config $Config
}

function Get-ExpectedClassifierNames {
    param([Parameter(Mandatory)][string]$Name)
    $names = @($Name)
    if ($Config.sitPrefix) {
        $sitPrefixed = $Name -replace '^TestPattern\s*-\s*', "$($Config.sitPrefix) - "
        if ($sitPrefixed -and $names -notcontains $sitPrefixed) { $names += $sitPrefixed }
    }
    $templateName = Get-DeploymentObjectName -Config $Config -ObjectType "classifierEntity" -Name $Name
    if ($templateName -and $names -notcontains $templateName) { $names += $templateName }
    return $names
}

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

if (-not $Cleanup) {
    $plannedPolicyNames = @()
    $plannedRuleNames = @()
    foreach ($policy in ($Policies | Where-Object { $_.Enabled })) {
        $plannedPolicyNames += Resolve-DeploymentPolicyName -Policy $policy
        $ruleNum = 0
        foreach ($label in $Labels) {
            $ruleNum++
            $chunks = @(Split-ClassifierChunks -ClassifierList $Classifiers[$label.code] -MaxPerRule 125)
            $chunkIndex = 0
            foreach ($chunk in $chunks) {
                $chunkIndex++
                if ($chunks.Count -gt 1) {
                    $chunkLetter = Get-ChunkLetter -ChunkIndex $chunkIndex
                    $plannedRuleNames += Resolve-DeploymentRuleName -Policy $policy -RuleNumber $ruleNum -LabelCode $label.code -ChunkLetter $chunkLetter
                } else {
                    $plannedRuleNames += Resolve-DeploymentRuleName -Policy $policy -RuleNumber $ruleNum -LabelCode $label.code
                }
            }
        }
    }

    try {
        $null = Assert-PurviewObjectNameSafety -Names $plannedPolicyNames -ObjectType "DLP policy"
        $null = Assert-PurviewObjectNameSafety -Names $plannedRuleNames -ObjectType "DLP rule"
        Write-Host "  Name safety: generated DLP policy/rule names are ASCII deployment-safe." -ForegroundColor Green
    } catch {
        Write-Error $_.Exception.Message
        return
    }
}
#endregion

#region Connection & Session
if ($Connect) {
    $previousWhatIf = $WhatIfPreference
    try {
        $WhatIfPreference = $false
        $connected = Connect-DLPSession -UPN $UPN -Tenant $Tenant -Delegated:$Delegated
    } finally {
        $WhatIfPreference = $previousWhatIf
    }
    if (-not $connected) { return }
}

if (-not (Assert-DLPSession)) { return }
if (-not (Invoke-TenantFingerprintGate)) { return }
#endregion

#region Logging
$null = Start-DeploymentLog -ScriptName "Deploy-DLPRules"
#endregion

#region Cleanup
if ($Cleanup) {
    Write-Host "`n=== Cleanup Mode ===" -ForegroundColor Yellow

    $policyNames = foreach ($policy in $Policies) {
        Resolve-DeploymentPolicyName -Policy $policy
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
                } elseif ((Get-ExpectedClassifierNames -Name $entry.Name) -notcontains $tenantSITLookup[$lookupId]) {
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

#region Pre-flight: check for name conflicts across all policies
Write-Host "`n=== Pre-flight: Checking for name conflicts ===" -ForegroundColor Cyan
$allPlannedPolicyNames = @()
$allPlannedNames = @()
foreach ($policy in $Policies) {
    if (-not $policy.Enabled) { continue }
    $policyNum = $policy.Number
    $policyName = Resolve-DeploymentPolicyName -Policy $policy
    $allPlannedPolicyNames += $policyName
    $ruleNum = 0
    foreach ($label in $Labels) {
        $ruleNum++
        $labelCode = $label.code
        $chunks = @(Split-ClassifierChunks -ClassifierList $Classifiers[$labelCode] -MaxPerRule 125)
        $chunkIndex = 0
        foreach ($chunk in $chunks) {
            $chunkIndex++
            if ($chunks.Count -gt 1) {
                $chunkLetter = Get-ChunkLetter -ChunkIndex $chunkIndex
                $name = Resolve-DeploymentRuleName -Policy $policy -RuleNumber $ruleNum -LabelCode $labelCode -ChunkLetter $chunkLetter
            } else {
                $name = Resolve-DeploymentRuleName -Policy $policy -RuleNumber $ruleNum -LabelCode $labelCode
            }
            $allPlannedNames += $name
        }
    }
}

try {
    $null = Assert-PurviewObjectNameSafety -Names $allPlannedPolicyNames -ObjectType "DLP policy"
    $null = Assert-PurviewObjectNameSafety -Names $allPlannedNames -ObjectType "DLP rule"
    Write-Host "  Name safety: generated policy/rule names are ASCII deployment-safe." -ForegroundColor Green
} catch {
    Write-Error $_.Exception.Message
    return
}

# Query all existing rules across target policies
$allExistingRules = @()
foreach ($policy in $Policies) {
    if (-not $policy.Enabled) { continue }
    $policyName = Resolve-DeploymentPolicyName -Policy $policy
    try { $allExistingRules += @(Get-DlpComplianceRule -Policy $policyName -ErrorAction SilentlyContinue) } catch { }
}

Write-Host "  Planned rules: $($allPlannedNames.Count), Existing rules on tenant: $($allExistingRules.Count)" -ForegroundColor Gray
$safe = Test-PurviewNameConflicts -PlannedNames $allPlannedNames -ExistingObjects $allExistingRules -ObjectType "DLP rule"
if (-not $safe) { return }
#endregion

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

    $policyName = Resolve-DeploymentPolicyName -Policy $policy
    $policyNum  = $policy.Number

    Write-Host "`n--- Policy: $policyName ---" -ForegroundColor Green
    $policyComment = Add-DeploymentProvenanceStamp `
        -Text $policy.Comment `
        -Prefix $Config.namingPrefix `
        -Component "DlpPolicy" `
        -DeploymentId $DeploymentId `
        -TargetEnvironment $TargetEnvironment `
        -Metadata @{ PolicyCode = $policy.Code }

    $newPolicyParams = @{
        Name    = $policyName
        Comment = $policyComment
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
                Comment  = $policyComment
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
                $chunkLetter = Get-ChunkLetter -ChunkIndex $chunkIndex
                $ruleName = Resolve-DeploymentRuleName -Policy $policy -RuleNumber $ruleNum -LabelCode $labelCode -ChunkLetter $chunkLetter
            } else {
                $ruleName = Resolve-DeploymentRuleName -Policy $policy -RuleNumber $ruleNum -LabelCode $labelCode
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
            $finalRuleParams["Comment"] = Add-DeploymentProvenanceStamp `
                -Text $finalRuleParams["Comment"] `
                -Prefix $Config.namingPrefix `
                -Component "DlpRule" `
                -DeploymentId $DeploymentId `
                -TargetEnvironment $TargetEnvironment `
                -Metadata @{ LabelCode = $labelCode; PolicyCode = $policy.Code; Chunk = $chunkIndex }

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

    $expectedPolicies = ($Policies | Where-Object { $_.Enabled }).Count
    $expectedRules = 0
    $expectedPolicyNames = @()
    $expectedRuleNames = @()
    foreach ($policy in @($Policies | Where-Object { $_.Enabled })) {
        $expectedPolicyNames += Resolve-DeploymentPolicyName -Policy $policy
        $ruleNum = 0
        foreach ($label in $Labels) {
            $ruleNum++
            $chunks = @(Split-ClassifierChunks -ClassifierList $Classifiers[$label.code] -MaxPerRule 125)
            $expectedRules += $chunks.Count
            $chunkIndex = 0
            foreach ($chunk in $chunks) {
                $chunkIndex++
                $chunkLetter = if ($chunks.Count -gt 1) { Get-ChunkLetter -ChunkIndex $chunkIndex } else { "" }
                $expectedRuleNames += Resolve-DeploymentRuleName -Policy $policy -RuleNumber $ruleNum -LabelCode $label.code -ChunkLetter $chunkLetter
            }
        }
    }

    $deployedPolicies = Get-DlpCompliancePolicy -ErrorAction Stop | Where-Object { $expectedPolicyNames -contains $_.Name }
    $deployedRules = Get-DlpComplianceRule -ErrorAction Stop | Where-Object { $expectedRuleNames -contains $_.Name } | Sort-Object Policy, Priority

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

if ($script:DeploymentSession) {
    $phaseStatus = if (($failPolicies + $failRules) -eq 0) { 'success' } elseif ($successPolicies -gt 0 -or $successRules -gt 0) { 'partial' } else { 'failed' }
    try {
        Add-DeploymentPhaseResult -SessionPath $script:DeploymentSession.SessionPath `
            -Phase 'dlprules' -Action 'Deploy' -Status $phaseStatus `
            -StartedAt $script:DRStartedAt -CompletedAt (Get-Date).ToString('o') `
            -Artifacts @() -Errors @()
    } catch {
        Write-Warning "Failed to emit dlprules phase-result: $($_.Exception.Message)"
    }
}

try { Stop-Transcript } catch { }
#endregion
