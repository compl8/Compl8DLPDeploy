#==============================================================================
# Deploy-AutoLabeling.ps1
# Deploys auto-labeling policies and rules to Microsoft Purview.
# Creates one policy per label, with one rule per workload per label.
# Uses the same classifier-to-label mapping as Deploy-DLPRules.ps1.
#
# Usage:
#   .\scripts\Deploy-AutoLabeling.ps1 -Connect                  # Deploy (simulation mode)
#   .\scripts\Deploy-AutoLabeling.ps1 -Connect -Tenant customer.gov.au -TargetEnvironment customer-profile
#   .\scripts\Deploy-AutoLabeling.ps1 -Connect -WhatIf          # Dry run
#   .\scripts\Deploy-AutoLabeling.ps1 -Connect -Cleanup         # Remove policies/rules
#   .\scripts\Deploy-AutoLabeling.ps1 -Connect -SkipValidation  # Skip SIT check
#   .\scripts\Deploy-AutoLabeling.ps1 -Connect -SkipVerification
#   .\scripts\Deploy-AutoLabeling.ps1 -Connect -StartSimulation  # Restart simulation on all policies
#==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$SkipValidation,
    [switch]$SkipVerification,
    [switch]$Cleanup,
    [switch]$StartSimulation,
    [switch]$Connect,
    [string]$UPN,
    [string]$Tenant,
    [switch]$Delegated,
    [string]$TargetEnvironment,
    [string]$Prefix
)

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "config"

# Import shared module
Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

$ErrorActionPreference = "Stop"

function Invoke-TenantFingerprintGate {
    $fingerprint = Test-DeploymentTenantFingerprint -ProjectRoot $ProjectRoot -TargetEnvironment $TargetEnvironment

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
        Write-Error "Tenant fingerprint check failed. Aborting before auto-labeling changes."
        return $false
    }

    return $true
}

# Auto-labeling workloads (only Exchange, SharePoint, OneDrive are supported)
# Auto-labeling supported workloads — mapped from policies.json codes
# ScopeParam/ScopeValue are read from policies.json at runtime
$AutoLabelWorkloadMap = @{
    "ECH" = @{ Workload = "Exchange";            LocationKey = "ExchangeLocation" }
    "SPO" = @{ Workload = "SharePoint";          LocationKey = "SharePointLocation" }
    "ODB" = @{ Workload = "OneDriveForBusiness"; LocationKey = "OneDriveLocation" }
}

#region Config Loading & Validation
Write-Host "=== Loading Configuration ===" -ForegroundColor Cyan

$Defaults        = Get-ModuleDefaults
$globalJson      = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json")     -Description "deployment settings"
$labelsJson      = Import-JsonConfig -FilePath (Join-Path $ConfigPath "labels.json")        -Description "label definitions"
$policiesJson    = Import-JsonConfig -FilePath (Join-Path $ConfigPath "policies.json")      -Description "policy definitions"
$classifiersJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "classifiers.json")   -Description "classifier definitions"

if (-not $labelsJson -or -not $policiesJson -or -not $classifiersJson) {
    Write-Error "Required config files missing or invalid. Aborting."
    return
}

$Config      = Merge-GlobalConfig -Defaults $Defaults -GlobalJson $globalJson
$Config      = Set-DeploymentConfigPrefix -Config $Config -Prefix $Prefix
$Labels      = Resolve-LabelConfig -LabelsJson $labelsJson
$Policies    = Resolve-PolicyConfig -PoliciesJson $policiesJson
$Classifiers = Resolve-ClassifierConfig -ClassifiersJson $classifiersJson -Defaults $Defaults
$DeploymentId = if ($env:COMPL8_DEPLOYMENT_ID) { $env:COMPL8_DEPLOYMENT_ID } else { Get-Date -Format "yyyyMMdd" }

# Build auto-labeling workloads from policies.json, filtering to supported workloads
$AutoLabelWorkloads = @()
foreach ($policy in ($Policies | Where-Object { $_.Enabled })) {
    $wlDef = $AutoLabelWorkloadMap[$policy.Code]
    if (-not $wlDef) { continue }  # Skip unsupported workloads (Endpoint, Teams)
    $AutoLabelWorkloads += @{
        Code       = $policy.Code
        Workload   = $wlDef.Workload
        Location   = @{ $wlDef.LocationKey = "All" }
        ScopeParam = $policy.ScopeParam
        ScopeValue = $policy.ScopeValue
    }
}
if ($AutoLabelWorkloads.Count -eq 0) {
    Write-Error "No supported auto-labeling workloads found in policies.json. Need ECH, SPO, or ODB."
    return
}
Write-Host "  Auto-labeling workloads: $($AutoLabelWorkloads.Code -join ', ') (from policies.json)" -ForegroundColor Gray

# Cross-validation
$validationErrors = @()
$validationWarnings = @()
foreach ($label in $Labels) {
    if ($label.code -and -not $Classifiers.ContainsKey($label.code)) {
        $validationWarnings += "Label '$($label.code)' ($($label.fullName)) has no classifiers -- auto-labeling policy will be skipped"
    }
}
foreach ($key in $Classifiers.Keys) {
    $labelCodes = $Labels | ForEach-Object { $_.code }
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

# Filter to non-group labels that have classifiers
$Labels = $Labels | Where-Object { $_.code -and $Classifiers.ContainsKey($_.code) }

# Build label name lookup (code -> Purview label name for ApplySensitivityLabel)
# Must read from raw labelsJson — Resolve-LabelConfig strips the name property
$LabelNameLookup = @{}
foreach ($l in $labelsJson) {
    if ($l.code) {
        $LabelNameLookup[$l.code] = Get-DeploymentObjectName -Config $Config -ObjectType "label" -Name $l.name -Tokens @{
            labelCode   = $l.code
            displayName = $l.displayName
        }
    }
}

function Get-AutoLabelPolicyName {
    param(
        [Parameter(Mandatory)][int]$PolicyNumber,
        [Parameter(Mandatory)][string]$LabelCode
    )

    return Get-DeploymentObjectName -Config $Config -ObjectType "autoLabelPolicy" -Tokens @{
        policyNumber = ("{0:D2}" -f $PolicyNumber)
        labelCode    = $LabelCode
    }
}

function Get-AutoLabelRuleName {
    param(
        [Parameter(Mandatory)][int]$PolicyNumber,
        [Parameter(Mandatory)][int]$RuleNumber,
        [Parameter(Mandatory)][string]$WorkloadCode,
        [Parameter(Mandatory)][string]$LabelCode,
        [string]$ChunkLetter = ""
    )

    return Get-DeploymentObjectName -Config $Config -ObjectType "autoLabelRule" -Tokens @{
        policyNumber = ("{0:D2}" -f $PolicyNumber)
        ruleNumber   = ("{0:D2}" -f $RuleNumber)
        chunkLetter  = $ChunkLetter
        workloadCode = $WorkloadCode
        labelCode    = $LabelCode
    }
}

$totalPolicies = $Labels.Count
$totalRules = 0
foreach ($l in $Labels) {
    $chunksPerLabel = @(Split-ClassifierChunks -ClassifierList $Classifiers[$l.code] -MaxPerRule 125).Count
    $totalRules += $chunksPerLabel * $AutoLabelWorkloads.Count
}
$totalClassifiers = ($Classifiers.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
Write-Host "  Labels: $($Labels.Count), Policies: $totalPolicies, Rules: $totalRules (across $($AutoLabelWorkloads.Count) workloads), Classifiers: $totalClassifiers" -ForegroundColor Gray

if (-not $Cleanup -and -not $StartSimulation) {
    $plannedPolicyNames = @()
    $plannedRuleNames = @()
    $policyNum = 0
    foreach ($label in $Labels) {
        $policyNum++
        $plannedPolicyNames += Get-AutoLabelPolicyName -PolicyNumber $policyNum -LabelCode $label.code
        $chunks = @(Split-ClassifierChunks -ClassifierList $Classifiers[$label.code] -MaxPerRule 125)
        $ruleNum = 0
        foreach ($wl in $AutoLabelWorkloads) {
            $ruleNum++
            $chunkIndex = 0
            foreach ($chunk in $chunks) {
                $chunkIndex++
                if ($chunks.Count -gt 1) {
                    $chunkLetter = Get-ChunkLetter -ChunkIndex $chunkIndex
                    $plannedRuleNames += Get-AutoLabelRuleName -PolicyNumber $policyNum -RuleNumber $ruleNum -WorkloadCode $wl.Code -LabelCode $label.code -ChunkLetter $chunkLetter
                } else {
                    $plannedRuleNames += Get-AutoLabelRuleName -PolicyNumber $policyNum -RuleNumber $ruleNum -WorkloadCode $wl.Code -LabelCode $label.code
                }
            }
        }
    }

    try {
        $null = Assert-PurviewObjectNameSafety -Names $plannedPolicyNames -ObjectType "auto-labeling policy"
        $null = Assert-PurviewObjectNameSafety -Names $plannedRuleNames -ObjectType "auto-labeling rule"
        Write-Host "  Name safety: generated auto-labeling policy/rule names are ASCII deployment-safe." -ForegroundColor Green
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
        $connectArgs = @{}
        if ($UPN) { $connectArgs["UPN"] = $UPN }
        if ($Tenant) { $connectArgs["Tenant"] = $Tenant }
        if ($Delegated) { $connectArgs["Delegated"] = $true }
        $connected = Connect-DLPSession @connectArgs
    } finally {
        $WhatIfPreference = $previousWhatIf
    }
    if (-not $connected) { return }
}

if (-not (Assert-DLPSession)) { return }
if (-not (Invoke-TenantFingerprintGate)) { return }
#endregion

#region Logging
$null = Start-DeploymentLog -ScriptName "Deploy-AutoLabeling"
#endregion

#region Start Simulation
if ($StartSimulation) {
    Write-Host "`n=== Start Simulation ===" -ForegroundColor Cyan
    Write-Host "  Querying auto-labeling policies matching $($Config.namingPrefix)..." -ForegroundColor Gray

    $expectedPolicyNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $policyNum = 0
    foreach ($label in $Labels) {
        $policyNum++
        [void]$expectedPolicyNames.Add((Get-AutoLabelPolicyName -PolicyNumber $policyNum -LabelCode $label.code))
    }
    $alPolicies = @(Get-AutoSensitivityLabelPolicy -ErrorAction Stop |
        Where-Object { $expectedPolicyNames.Contains($_.Name) })

    if ($alPolicies.Count -eq 0) {
        Write-Host "  No matching policies found." -ForegroundColor Yellow
        try { Stop-Transcript } catch { }
        return
    }

    Write-Host "  Found $($alPolicies.Count) policy(ies)" -ForegroundColor Gray
    $started = 0
    foreach ($pol in ($alPolicies | Sort-Object Name)) {
        Write-Host "    $($pol.Name)" -ForegroundColor Yellow -NoNewline
        if ($PSCmdlet.ShouldProcess($pol.Name, "Start simulation")) {
            try {
                Set-AutoSensitivityLabelPolicy -Identity $pol.Name -StartSimulation $true -ErrorAction Stop
                Write-Host " -> simulation started" -ForegroundColor Green
                $started++
            } catch {
                Write-Host " -> FAILED: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    Write-Host "`n  Simulation started on $started of $($alPolicies.Count) policies." -ForegroundColor Cyan
    try { Stop-Transcript } catch { }
    return
}
#endregion

#region Cleanup
if ($Cleanup) {
    Write-Host "`n=== Cleanup Mode ===" -ForegroundColor Yellow

    $policyNum = 0
    foreach ($label in $Labels) {
        $policyNum++
        $policyName = Get-AutoLabelPolicyName -PolicyNumber $policyNum -LabelCode $label.code

        $existingPolicy = $null
        try { $existingPolicy = Get-AutoSensitivityLabelPolicy -Identity $policyName -ErrorAction Stop } catch { }

        if (-not $existingPolicy) {
            Write-Host "  Policy not found (skipping): $policyName" -ForegroundColor Gray
            continue
        }

        # Remove rules first
        $rules = @()
        try { $rules = @(Get-AutoSensitivityLabelRule -Policy $policyName -ErrorAction Stop) } catch {
            Write-Warning "  Error listing rules for ${policyName}: $($_.Exception.Message)"
        }
        $ruleIndex = 0
        foreach ($rule in $rules) {
            if ($ruleIndex -gt 0 -and -not $WhatIfPreference) { Start-Sleep -Seconds $Config.interCallDelaySec }
            $result = Remove-PurviewObject -Identity $rule.Name `
                -GetCommand "Get-AutoSensitivityLabelRule" `
                -RemoveCommand "Remove-AutoSensitivityLabelRule" `
                -OperationName "AL rule" `
                -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec `
                -WhatIf:$WhatIfPreference
            if ($result -eq "failed") {
                Write-Warning "  Failed to remove rule $($rule.Name)"
            }
            $ruleIndex++
        }

        # Remove policy
        if ($rules.Count -gt 0 -and -not $WhatIfPreference) { Start-Sleep -Seconds $Config.interCallDelaySec }
        $result = Remove-PurviewObject -Identity $policyName `
            -GetCommand "Get-AutoSensitivityLabelPolicy" `
            -RemoveCommand "Remove-AutoSensitivityLabelPolicy" `
            -OperationName "AL policy" `
            -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec `
            -WhatIf:$WhatIfPreference
        if ($result -eq "failed") {
            Write-Warning "  Error removing policy $policyName"
        }
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

#region Pre-flight: check for name conflicts
Write-Host "`n=== Pre-flight: Checking for name conflicts ===" -ForegroundColor Cyan
$allPlannedPolicyNames = @()
$allPlannedRuleNames = @()
$pn = 0
foreach ($l in $Labels) {
    $pn++
    $allPlannedPolicyNames += Get-AutoLabelPolicyName -PolicyNumber $pn -LabelCode $l.code
    $classifierList = $Classifiers[$l.code]
    $chunks = @(Split-ClassifierChunks -ClassifierList $classifierList -MaxPerRule 125)
    $rn = 0
    foreach ($wl in $AutoLabelWorkloads) {
        $rn++
        $ci = 0
        foreach ($chunk in $chunks) {
            $ci++
            if ($chunks.Count -gt 1) {
                $cl = Get-ChunkLetter -ChunkIndex $ci
                $allPlannedRuleNames += Get-AutoLabelRuleName -PolicyNumber $pn -RuleNumber $rn -WorkloadCode $wl.Code -LabelCode $l.code -ChunkLetter $cl
            } else {
                $allPlannedRuleNames += Get-AutoLabelRuleName -PolicyNumber $pn -RuleNumber $rn -WorkloadCode $wl.Code -LabelCode $l.code
            }
        }
    }
}

$allExistingALRules = @()
foreach ($polName in $allPlannedPolicyNames) {
    try { $allExistingALRules += @(Get-AutoSensitivityLabelRule -Policy $polName -ErrorAction SilentlyContinue) } catch { }
}
$allExistingALPolicies = @()
foreach ($polName in $allPlannedPolicyNames) {
    try {
        $p = Get-AutoSensitivityLabelPolicy -Identity $polName -ErrorAction SilentlyContinue
        if ($p) { $allExistingALPolicies += $p }
    } catch { }
}

Write-Host "  Planned: $($allPlannedPolicyNames.Count) policies, $($allPlannedRuleNames.Count) rules" -ForegroundColor Gray
Write-Host "  Existing: $($allExistingALPolicies.Count) policies, $($allExistingALRules.Count) rules" -ForegroundColor Gray

try {
    $null = Assert-PurviewObjectNameSafety -Names $allPlannedPolicyNames -ObjectType "auto-labeling policy"
    $null = Assert-PurviewObjectNameSafety -Names $allPlannedRuleNames -ObjectType "auto-labeling rule"
    Write-Host "  Name safety: generated auto-labeling policy/rule names are ASCII deployment-safe." -ForegroundColor Green
} catch {
    Write-Error $_.Exception.Message
    try { Stop-Transcript } catch { }
    return
}

$safe = Test-PurviewNameConflicts -PlannedNames $allPlannedRuleNames -ExistingObjects $allExistingALRules -ObjectType "AL rule"
if (-not $safe) { try { Stop-Transcript } catch { }; return }
#endregion

#region Deployment Loop
Write-Host "`n=== Auto-Labeling Deployment ===" -ForegroundColor Cyan
Write-Host "Starting deployment at $(Get-Date)" -ForegroundColor Cyan

$successPolicies = 0
$failPolicies    = 0
$successRules    = 0
$failRules       = 0

$policyNum = 0
foreach ($label in $Labels) {
    $policyNum++
    $labelCode  = $label.code
    $labelName  = $LabelNameLookup[$labelCode]
    $policyName = Get-AutoLabelPolicyName -PolicyNumber $policyNum -LabelCode $labelCode

    Write-Host "`n--- Policy: $policyName (label: $labelName) ---" -ForegroundColor Green

    # Build location params — all supported workloads
    $locationParams = @{}
    foreach ($wl in $AutoLabelWorkloads) {
        foreach ($loc in $wl.Location.GetEnumerator()) {
            $locationParams[$loc.Key] = $loc.Value
        }
    }

    $existingPolicy = $null
    try { $existingPolicy = Get-AutoSensitivityLabelPolicy -Identity $policyName -ErrorAction Stop } catch { }
    $policyComment = Add-DeploymentProvenanceStamp `
        -Text "Auto-label $($label.fullName) ($labelCode)" `
        -Prefix $Config.namingPrefix `
        -Component "AutoLabelPolicy" `
        -DeploymentId $DeploymentId `
        -TargetEnvironment $TargetEnvironment `
        -Metadata @{ LabelCode = $labelCode }

    try {
        if ($existingPolicy) {
            Write-Host "  Policy exists. Updating..." -ForegroundColor Yellow
            if ($PSCmdlet.ShouldProcess($policyName, "Set-AutoSensitivityLabelPolicy")) {
                $setPolicyParams = @{
                    Identity              = $policyName
                    ApplySensitivityLabel = $labelName
                    Comment              = $policyComment
                    Mode                 = "TestWithoutNotifications"
                    Confirm              = $false
                    ErrorAction          = "Stop"
                }
                if ($Config.overwriteLabel) { $setPolicyParams['OverwriteLabel'] = $true }
                Invoke-WithRetry -OperationName "Set-ALPolicy $policyName" -ScriptBlock {
                    Set-AutoSensitivityLabelPolicy @setPolicyParams
                } -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec
            }
        } else {
            Write-Host "  Creating new policy..." -ForegroundColor Green
            $newPolicyParams = @{
                Name                    = $policyName
                ApplySensitivityLabel   = $labelName
                Comment                 = $policyComment
                Mode                    = "TestWithoutNotifications"
            }
            if ($Config.overwriteLabel) { $newPolicyParams['OverwriteLabel'] = $true }
            $newPolicyParams += $locationParams

            if ($PSCmdlet.ShouldProcess($policyName, "New-AutoSensitivityLabelPolicy")) {
                Invoke-WithRetry -OperationName "New-ALPolicy $policyName" -ScriptBlock {
                    New-AutoSensitivityLabelPolicy @newPolicyParams -ErrorAction Stop
                } -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec
            }
        }
        $successPolicies++
    } catch {
        Write-Error "  Failed to create/update policy ${policyName}: $($_.Exception.Message)"
        $failPolicies++
        Write-Warning "  Skipping rules for this policy."
        continue
    }

    # Create rules per workload — auto-split if >125 classifiers
    $classifierList = $Classifiers[$labelCode]
    $chunks = @(Split-ClassifierChunks -ClassifierList $classifierList -MaxPerRule 125)

    $ruleNum = 0
    foreach ($wl in $AutoLabelWorkloads) {
        $ruleNum++

        $chunkIndex = 0
        foreach ($chunk in $chunks) {
            $chunkIndex++
            if (($ruleNum -gt 1 -or $chunkIndex -gt 1) -and -not $WhatIfPreference) { Start-Sleep -Seconds $Config.interCallDelaySec }

            # Build rule name: AL{policy}-R{rule}{chunk}-{workload}-{label}-{suffix}
            if ($chunks.Count -gt 1) {
                $chunkLetter = Get-ChunkLetter -ChunkIndex $chunkIndex
                $ruleName = Get-AutoLabelRuleName -PolicyNumber $policyNum -RuleNumber $ruleNum -WorkloadCode $wl.Code -LabelCode $labelCode -ChunkLetter $chunkLetter
            } else {
                $ruleName = Get-AutoLabelRuleName -PolicyNumber $policyNum -RuleNumber $ruleNum -WorkloadCode $wl.Code -LabelCode $labelCode
            }

            # Build SIT condition (reuse existing helper — same hashtable format)
            # Pass scope params so AdvancedRule JSON embeds them if needed
            $condition = New-DLPSITCondition -ClassifierList $chunk -ScopeParam $wl.ScopeParam -ScopeValue $wl.ScopeValue

            $scopeNote = if ($wl.ScopeParam) { ", $($wl.ScopeParam)=$($wl.ScopeValue)" } else { "" }
            $chunkNote = if ($chunks.Count -gt 1) { " [chunk $chunkIndex/$($chunks.Count)]" } else { "" }
            Write-Host "  Creating Rule: $ruleName ($($wl.Workload)$chunkNote, $($chunk.Count) classifiers$scopeNote)" -ForegroundColor Cyan
            $ruleComment = Add-DeploymentProvenanceStamp `
                -Text "$($label.fullName) - $($wl.Workload)$chunkNote ($($chunk.Count) classifiers)" `
                -Prefix $Config.namingPrefix `
                -Component "AutoLabelRule" `
                -DeploymentId $DeploymentId `
                -TargetEnvironment $TargetEnvironment `
                -Metadata @{ LabelCode = $labelCode; Workload = $wl.Code; Chunk = $chunkIndex }

            $ruleParams = @{
                Name                = $ruleName
                Policy              = $policyName
                Workload            = $wl.Workload
                Comment             = $ruleComment
                ReportSeverityLevel = "Low"
                Disabled            = $false
            }

            if ($condition.Format -eq "AdvancedRule") {
                $ruleParams["AdvancedRule"] = $condition.Value
            } else {
                $ruleParams["ContentContainsSensitiveInformation"] = $condition.Value
                # Apply scope from policies.json (e.g. AccessScope = NotInOrganization)
                if ($wl.ScopeParam) {
                    $ruleParams[$wl.ScopeParam] = $wl.ScopeValue
                }
            }

            $existingRule = $null
            try { $existingRule = Get-AutoSensitivityLabelRule -Identity $ruleName -ErrorAction Stop } catch { }

            try {
                if ($existingRule) {
                    Write-Host "    Rule exists. Updating..." -ForegroundColor Yellow
                    $updateRuleParams = @{ Identity = $ruleName }
                    foreach ($key in $ruleParams.Keys) {
                        if ($key -notin @("Name", "Policy")) {
                            $updateRuleParams[$key] = $ruleParams[$key]
                        }
                    }
                    if ($PSCmdlet.ShouldProcess($ruleName, "Set-AutoSensitivityLabelRule")) {
                        Invoke-WithRetry -OperationName "Set-ALRule $ruleName" -ScriptBlock {
                            Set-AutoSensitivityLabelRule @updateRuleParams -Confirm:$false -ErrorAction Stop
                        } -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec
                    }
                } else {
                    if ($PSCmdlet.ShouldProcess($ruleName, "New-AutoSensitivityLabelRule")) {
                        Invoke-WithRetry -OperationName "New-ALRule $ruleName" -ScriptBlock {
                            $null = New-AutoSensitivityLabelRule @ruleParams -ErrorAction Stop
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

    $deployedPolicies = @(Get-AutoSensitivityLabelPolicy -ErrorAction Stop | Where-Object { $_.Name -like "AL*-$($Config.namingPrefix)-$($Config.namingSuffix)" })
    $deployedRules = @(Get-AutoSensitivityLabelRule -ErrorAction Stop | Where-Object { $_.Name -like "AL*-$($Config.namingSuffix)" })

    Write-Host "`nPolicies deployed: $($deployedPolicies.Count) (expected $totalPolicies)" -ForegroundColor $(if ($deployedPolicies.Count -ge $totalPolicies) { "Green" } else { "Yellow" })
    $deployedPolicies | Format-Table Name, Mode -AutoSize

    Write-Host "Rules deployed: $($deployedRules.Count) (expected $totalRules)" -ForegroundColor $(if ($deployedRules.Count -ge $totalRules) { "Green" } else { "Yellow" })
    $deployedRules | Format-Table Name, Workload, Policy -AutoSize
} else {
    Write-Host "`n=== Verification Skipped ===" -ForegroundColor Yellow
}
#endregion

#region Start Simulation (post-deploy)
if ($successPolicies -gt 0 -and -not $WhatIfPreference) {
    Write-Host "`n=== Starting Simulation ===" -ForegroundColor Cyan
    $simPolicies = @(Get-AutoSensitivityLabelPolicy -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "AL*-$($Config.namingPrefix)-$($Config.namingSuffix)" })
    $simStarted = 0
    foreach ($pol in ($simPolicies | Sort-Object Name)) {
        Write-Host "    $($pol.Name)" -ForegroundColor Yellow -NoNewline
        try {
            Set-AutoSensitivityLabelPolicy -Identity $pol.Name -StartSimulation $true -ErrorAction Stop
            Write-Host " -> simulation started" -ForegroundColor Green
            $simStarted++
        } catch {
            Write-Host " -> $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host "  Simulation started on $simStarted policy(ies)" -ForegroundColor Cyan
}
#endregion

#region Summary
Write-Host "`n=== Deployment Summary ===" -ForegroundColor Cyan
Write-Host "  Policies: $successPolicies succeeded, $failPolicies failed" -ForegroundColor $(if ($failPolicies -eq 0) { "Green" } else { "Red" })
Write-Host "  Rules:    $successRules succeeded, $failRules failed" -ForegroundColor $(if ($failRules -eq 0) { "Green" } else { "Red" })
Write-Host "  Mode:     TestWithoutNotifications (simulation)" -ForegroundColor Gray
Write-Host "`nDeployment complete at $(Get-Date)" -ForegroundColor Green

try { Stop-Transcript } catch { }
#endregion
