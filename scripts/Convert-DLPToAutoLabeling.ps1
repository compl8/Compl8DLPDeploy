#==============================================================================
# Convert-DLPToAutoLabeling.ps1
# Converts existing DLP compliance policies/rules into auto-labeling policies.
# Three phases: Scan (analyse & plan), Execute (create policies), Cleanup (remove).
#
# Usage:
#   .\scripts\Convert-DLPToAutoLabeling.ps1 -Scan -Connect
#   .\scripts\Convert-DLPToAutoLabeling.ps1 -Scan -Connect -DlpPolicyFilter "QGISCF*"
#   .\scripts\Convert-DLPToAutoLabeling.ps1 -Execute -PlanFile plans/conversion-plan-*.json -Connect
#   .\scripts\Convert-DLPToAutoLabeling.ps1 -Cleanup -PlanFile plans/conversion-plan-*.json -Connect
#==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Scan,
    [switch]$Execute,
    [switch]$Cleanup,
    [string]$MappingFile,
    [string]$PlanFile,
    [string]$DlpPolicyFilter,
    [switch]$IncludeDisabled,
    [switch]$AutoApprove,
    [switch]$Connect,
    [string]$UPN
)

$ErrorActionPreference = "Stop"

#region Validation — exactly one phase
$phaseCount = @($Scan, $Execute, $Cleanup) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
if ($phaseCount -ne 1) {
    Write-Error "Specify exactly one of -Scan, -Execute, or -Cleanup."
    return
}

if ($Execute -and -not $PlanFile) {
    Write-Error "-Execute requires -PlanFile parameter."
    return
}
if ($Cleanup -and -not $PlanFile) {
    Write-Error "-Cleanup requires -PlanFile parameter."
    return
}
#endregion

#region Module & Config Loading
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "config"

Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force
Import-Module (Join-Path $ProjectRoot "modules" "AutoLabel-Converter.psm1") -Force

# Load optional settings.json for naming prefix/suffix
$namingPrefix = "ALC"
$namingSuffix = "SIM"
$interCallDelaySec = 10
$maxRetries = 3
$baseDelaySec = 300
$overwriteLabel = $false

try {
    $globalJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
} catch {
    $globalJson = $null
}
if ($globalJson) {
    $defaults = Get-ModuleDefaults
    $mergedConfig = Merge-GlobalConfig -Defaults $defaults -GlobalJson $globalJson
    if ($mergedConfig.namingPrefix) { $namingPrefix = $mergedConfig.namingPrefix }
    if ($mergedConfig.namingSuffix) { $namingSuffix = $mergedConfig.namingSuffix }
    if ($mergedConfig.interCallDelaySec) { $interCallDelaySec = $mergedConfig.interCallDelaySec }
    if ($mergedConfig.maxRetries) { $maxRetries = $mergedConfig.maxRetries }
    if ($mergedConfig.baseDelaySec) { $baseDelaySec = $mergedConfig.baseDelaySec }
    if ($mergedConfig.overwriteLabel) { $overwriteLabel = $mergedConfig.overwriteLabel }
}

# Load optional labels.json
$labelsJson = $null
try {
    $labelsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "labels.json") -Description "label definitions"
} catch {
    $labelsJson = $null
}

# Workload code mapping
$WorkloadCodeMap = @{
    'Exchange'            = 'ECH'
    'SharePoint'          = 'SPO'
    'OneDriveForBusiness' = 'ODB'
}

$SupportedWorkloads = @('Exchange', 'SharePoint', 'OneDriveForBusiness')
#endregion

#region Helper: Count SITs from CCSI structure
function Get-SITCountFromCCSI {
    param([object]$CCSI)
    if (-not $CCSI) { return 0 }

    # Flat array of SIT hashtables (from Purview API / plan JSON)
    if ($CCSI -is [System.Collections.IList] -and $CCSI.Count -gt 0) {
        $first = $CCSI[0]
        if ($first -is [System.Collections.IDictionary] -or ($first -is [PSCustomObject] -and $first.PSObject.Properties['id'])) {
            return $CCSI.Count
        }
    }

    # Nested groups/sensitivetypes structure
    $groups = $null
    if ($CCSI -is [hashtable] -or $CCSI -is [System.Collections.Specialized.OrderedDictionary]) {
        $groups = if ($CCSI.Contains('groups')) { $CCSI['groups'] } elseif ($CCSI.Contains('Groups')) { $CCSI['Groups'] } else { $null }
    } elseif ($CCSI -is [PSCustomObject]) {
        $groups = $CCSI.groups
        if (-not $groups) { $groups = $CCSI.Groups }
    }
    if (-not $groups) { return 0 }
    $count = 0
    foreach ($group in $groups) {
        $sits = $null
        if ($group -is [hashtable] -or $group -is [System.Collections.Specialized.OrderedDictionary]) {
            $sits = if ($group.Contains('sensitivetypes')) { $group['sensitivetypes'] } elseif ($group.Contains('Sensitivetypes')) { $group['Sensitivetypes'] } else { $null }
        } elseif ($group -is [PSCustomObject]) {
            $sits = $group.sensitivetypes
            if (-not $sits) { $sits = $group.Sensitivetypes }
        }
        if ($sits) { $count += @($sits).Count }
    }
    return $count
}
#endregion

###############################################################################
#                              PHASE 1: SCAN                                  #
###############################################################################
if ($Scan) {
    Write-Host "`n=== DLP-to-Auto-Labeling Conversion Scan ===" -ForegroundColor Cyan

    # Load optional mapping file
    $mappings = $null
    if ($MappingFile) {
        $mappingPath = if ([System.IO.Path]::IsPathRooted($MappingFile)) { $MappingFile } else { Join-Path $ProjectRoot $MappingFile }
        try {
            $mappings = Import-JsonConfig -FilePath $mappingPath -Description "rule-to-label mappings"
        } catch {
            Write-Warning "Could not load mapping file: $MappingFile"
        }
    }

    #region Connection
    if ($Connect) {
        $connected = Connect-DLPSession -UPN $UPN
        if (-not $connected) { return }
    }
    if (-not (Assert-DLPSession)) { return }
    #endregion

    $null = Start-DeploymentLog -ScriptName "Convert-DLPToAutoLabeling-Scan"

    #region Read DLP policies and rules
    Write-Host "`nReading DLP policies..." -ForegroundColor Cyan
    $dlpPolicies = @(Get-DlpCompliancePolicy -ErrorAction Stop)
    if ($DlpPolicyFilter) {
        $dlpPolicies = @($dlpPolicies | Where-Object { $_.Name -like $DlpPolicyFilter })
        Write-Host "  Filtered to $($dlpPolicies.Count) policies matching '$DlpPolicyFilter'" -ForegroundColor Gray
    } else {
        Write-Host "  Found $($dlpPolicies.Count) DLP policies" -ForegroundColor Gray
    }

    if ($dlpPolicies.Count -eq 0) {
        Write-Warning "No DLP policies found. Nothing to scan."
        try { Stop-Transcript } catch { }
        return
    }

    # Read all rules for matched policies
    $allDlpRules = @()
    foreach ($policy in $dlpPolicies) {
        $rules = @(Get-DlpComplianceRule -Policy $policy.Name -ErrorAction SilentlyContinue)
        Write-Host "  Scanning policy: $($policy.Name) ($($rules.Count) rules)..." -ForegroundColor Gray
        foreach ($rule in $rules) {
            # Skip disabled unless -IncludeDisabled
            if (-not $IncludeDisabled -and $rule.Disabled) {
                Write-Host "    Skipping disabled rule: $($rule.Name)" -ForegroundColor DarkGray
                continue
            }
            $allDlpRules += [PSCustomObject]@{
                Rule   = $rule
                Policy = $policy
            }
        }
    }

    Write-Host "  Total rules to analyse: $($allDlpRules.Count)" -ForegroundColor Gray
    if ($allDlpRules.Count -eq 0) {
        Write-Warning "No active DLP rules found. Nothing to convert."
        try { Stop-Transcript } catch { }
        return
    }
    #endregion

    #region Read existing auto-labeling policies and tenant labels
    Write-Host "`nReading existing auto-labeling policies..." -ForegroundColor Cyan
    $existingALPolicies = @(Get-AutoSensitivityLabelPolicy -ErrorAction SilentlyContinue)
    Write-Host "  Existing auto-labeling policies: $($existingALPolicies.Count)" -ForegroundColor Gray

    Write-Host "Reading tenant sensitivity labels..." -ForegroundColor Cyan
    $tenantLabels = @(Get-Label -ErrorAction Stop)
    Write-Host "  Tenant labels: $($tenantLabels.Count)" -ForegroundColor Gray
    #endregion

    #region Analyse each DLP rule
    Write-Host "`nAnalysing DLP rules..." -ForegroundColor Cyan

    # Structure: analysed rule entries
    $analysedRules = @()
    $unconvertibleRules = @()

    foreach ($item in $allDlpRules) {
        $rule = $item.Rule
        $policy = $item.Policy

        # Detect workload
        $workload = Get-WorkloadFromPolicy -Policy $policy

        # Skip unsupported workloads
        if ($workload -notin $SupportedWorkloads) {
            Write-Host "    N/A: $($rule.Name) — auto-labeling does not support $workload" -ForegroundColor DarkGray
            $unconvertibleRules += @{
                RuleName = $rule.Name
                PolicyName = $policy.Name
                Reason = "Not applicable: auto-labeling does not support $workload workload"
            }
            continue
        }

        # Extract conditions
        $conditions = ConvertFrom-DlpRuleConditions -DlpRule $rule

        # Classify
        $classification = Get-DlpRuleClassification -ExtractedConditions $conditions

        if ($classification -eq 'unconvertible') {
            $reason = if (-not $conditions.HasSIT) { "No SIT conditions" }
                      elseif ($conditions.HasTrainableClassifier) { "Contains trainable classifiers" }
                      else { "Unconvertible conditions" }
            $unconvertibleRules += @{
                RuleName = $rule.Name
                PolicyName = $policy.Name
                Reason = $reason
            }
            Write-Host "    Unconvertible: $($rule.Name) — $reason" -ForegroundColor DarkGray
            continue
        }

        # Resolve label
        $labelResult = Resolve-LabelAssignment -RuleName $rule.Name -Mappings $mappings -TenantLabels $tenantLabels -LabelsJson $labelsJson

        # Count SITs
        $ccsi = $conditions.Converted['ContentContainsSensitiveInformation']
        $sitCount = Get-SITCountFromCCSI -CCSI $ccsi

        $analysedRules += @{
            RuleName       = $rule.Name
            PolicyName     = $policy.Name
            Workload       = $workload
            Classification = $classification
            Conditions     = $conditions
            LabelResult    = $labelResult
            SITCount       = $sitCount
            Dropped        = $conditions.Dropped
        }
    }
    #endregion

    #region Handle unresolved labels
    $unresolvedRules = @($analysedRules | Where-Object { $_.LabelResult.AssignedBy -eq 'unresolved' })

    if ($unresolvedRules.Count -gt 0) {
        if ($AutoApprove) {
            $unresolvedNames = ($unresolvedRules | ForEach-Object { $_.RuleName }) -join ", "
            Write-Error "Cannot auto-approve: $($unresolvedRules.Count) rules have unresolved labels: $unresolvedNames"
            try { Stop-Transcript } catch { }
            return
        }

        Write-Host "`n=== Unresolved Label Assignments ===" -ForegroundColor Yellow
        Write-Host "The following rules could not be automatically mapped to a label." -ForegroundColor Yellow
        Write-Host "Select a tenant label for each, or enter 0 to skip." -ForegroundColor Yellow

        # Build numbered label list
        $labelChoices = @()
        $idx = 0
        foreach ($tl in $tenantLabels) {
            $idx++
            $labelChoices += @{ Index = $idx; Label = $tl }
        }

        foreach ($ur in $unresolvedRules) {
            Write-Host "`n  Rule: $($ur.RuleName) (Policy: $($ur.PolicyName), Workload: $($ur.Workload))" -ForegroundColor Yellow
            Write-Host "  Available labels:" -ForegroundColor Gray
            foreach ($lc in $labelChoices) {
                $parentInfo = if ($lc.Label.ParentLabelName) { " (under $($lc.Label.ParentLabelName))" } else { "" }
                Write-Host "    $($lc.Index). $($lc.Label.DisplayName)$parentInfo" -ForegroundColor Gray
            }
            Write-Host "    0. Skip this rule" -ForegroundColor DarkGray

            $selection = Read-Host "  Select label number [0]"
            if (-not $selection -or $selection -eq '0') {
                # Move to unconvertible
                $unconvertibleRules += @{
                    RuleName = $ur.RuleName
                    PolicyName = $ur.PolicyName
                    Reason = "Skipped during interactive label assignment"
                }
                # Remove from analysed
                $analysedRules = @($analysedRules | Where-Object { $_.RuleName -ne $ur.RuleName })
            } else {
                $selIdx = [int]$selection
                if ($selIdx -ge 1 -and $selIdx -le $labelChoices.Count) {
                    $chosen = $labelChoices[$selIdx - 1].Label
                    $ur.LabelResult = @{
                        Label      = $chosen.DisplayName
                        LabelCode  = $null
                        AssignedBy = 'interactive'
                    }
                    # Try to find matching label code from labels.json
                    if ($labelsJson) {
                        $matchedLJ = $labelsJson | Where-Object {
                            ($_.displayName -eq $chosen.DisplayName -or $_.name -eq $chosen.Name) -and -not $_.isGroup
                        } | Select-Object -First 1
                        if ($matchedLJ -and $matchedLJ.code) {
                            $ur.LabelResult.LabelCode = $matchedLJ.code
                        }
                    }
                } else {
                    Write-Warning "Invalid selection. Skipping rule: $($ur.RuleName)"
                    $unconvertibleRules += @{
                        RuleName = $ur.RuleName
                        PolicyName = $ur.PolicyName
                        Reason = "Invalid selection during interactive label assignment"
                    }
                    $analysedRules = @($analysedRules | Where-Object { $_.RuleName -ne $ur.RuleName })
                }
            }
        }
    }
    #endregion

    #region Group by label and build plan entries
    # Group source rules by label name
    $labelGroups = [ordered]@{}
    foreach ($ar in $analysedRules) {
        $labelName = $ar.LabelResult.Label
        if (-not $labelName) { continue }

        if (-not $labelGroups.Contains($labelName)) {
            $labelGroups[$labelName] = @{
                LabelName   = $labelName
                LabelCodes  = [System.Collections.Generic.List[string]]::new()
                SourceRules = [System.Collections.Generic.List[object]]::new()
                Workloads   = [System.Collections.Generic.HashSet[string]]::new()
                SITCount    = 0
                Classification = 'full'
                AllDropped  = @()
            }
        }
        $group = $labelGroups[$labelName]

        # Collect label codes (deduplicated)
        if ($ar.LabelResult.LabelCode -and $ar.LabelResult.LabelCode -notin $group.LabelCodes) {
            $group.LabelCodes.Add($ar.LabelResult.LabelCode)
        }

        $group.SourceRules.Add($ar)
        [void]$group.Workloads.Add($ar.Workload)
        $group.SITCount += $ar.SITCount

        # Downgrade classification if any rule is partial
        if ($ar.Classification -eq 'partial') {
            $group.Classification = 'partial'
        }

        if ($ar.Dropped -and $ar.Dropped.Count -gt 0) {
            $group.AllDropped += $ar.Dropped
        }
    }
    #endregion

    #region Build conversion plan
    # Determine tenant name for plan filename
    $tenantName = "unknown"
    try {
        # Get-ConnectionInformation is available after Connect-IPPSSession
        $connInfo = Get-ConnectionInformation -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($connInfo -and $connInfo.Organization) {
            $tenantName = $connInfo.Organization -replace '\.onmicrosoft\.com$', ''
        }
    } catch { }
    if ($tenantName -eq "unknown") {
        try {
            $orgConfig = Get-OrganizationConfig -ErrorAction SilentlyContinue
            if ($orgConfig -and $orgConfig.Name) {
                $tenantName = $orgConfig.Name
            }
        } catch { }
    }
    $tenantSanitised = $tenantName -replace '[.\s]', '-'

    $plannedPolicyCount = $labelGroups.Count
    $scalingStatus = Test-ScalingLimits -ExistingPolicies $existingALPolicies.Count -PlannedPolicies $plannedPolicyCount

    $plan = New-ConversionPlan -Tenant $tenantName -ScannedBy ($env:USERNAME ?? "unknown") -ExistingPolicies $existingALPolicies.Count -ScalingStatus $scalingStatus

    # Add label entries
    foreach ($labelName in $labelGroups.Keys) {
        $group = $labelGroups[$labelName]

        $sourceRuleEntries = @()
        foreach ($sr in $group.SourceRules) {
            $sourceRuleEntries += [ordered]@{
                ruleName       = $sr.RuleName
                policyName     = $sr.PolicyName
                workload       = $sr.Workload
                classification = $sr.Classification
                sitCount       = $sr.SITCount
                conditions     = [ordered]@{
                    converted = $sr.Conditions.Converted
                    exceptIf  = $sr.Conditions.ExceptIf
                    dropped   = $sr.Conditions.Dropped
                }
                executed       = $null
            }
        }

        $droppedSummary = @()
        foreach ($d in $group.AllDropped) {
            $droppedSummary += [ordered]@{
                condition = $d.Condition
                what      = $d.What
                why       = $d.Why
            }
        }

        $entry = [ordered]@{
            labelName      = $group.LabelName
            labelCodes     = @($group.LabelCodes)
            workloads      = @($group.Workloads)
            sourceRules    = $sourceRuleEntries
            totalSITs      = $group.SITCount
            classification = $group.Classification
            dropped        = $droppedSummary
            approved       = $false
        }
        $plan.Entries.Add($entry)
    }

    # Add unconvertible section
    $plan['Unconvertible'] = @()
    foreach ($uc in $unconvertibleRules) {
        $plan['Unconvertible'] += [ordered]@{
            ruleName   = $uc.RuleName
            policyName = $uc.PolicyName
            reason     = $uc.Reason
        }
    }

    # Add execution summary placeholder
    $plan['ExecutionSummary'] = [ordered]@{
        executedAt      = $null
        policiesCreated = 0
        rulesCreated    = 0
        failures        = 0
    }
    #endregion

    #region Scaling check
    Write-Host ""
    if ($scalingStatus.Status -eq 'blocked') {
        Write-Host "SCALING BLOCKED: $($scalingStatus.Message)" -ForegroundColor Red
        Write-Error "Cannot proceed — would exceed auto-labeling policy limit."
        try { Stop-Transcript } catch { }
        return
    } elseif ($scalingStatus.Status -eq 'warning') {
        Write-Warning "SCALING WARNING: $($scalingStatus.Message)"
    }
    #endregion

    #region Print summary
    Write-Host "`n=== Conversion Plan Summary ===" -ForegroundColor Cyan

    foreach ($entry in $plan.Entries) {
        Write-Host ""
        Write-Host "Label: $($entry.labelName)" -ForegroundColor Green
        $workloadList = ($entry.workloads -join ', ')
        Write-Host "  Source rules: $($entry.sourceRules.Count) ($workloadList)" -ForegroundColor Gray
        Write-Host "  SITs: $($entry.totalSITs) | Convertible: $($entry.classification)" -ForegroundColor Gray
        if ($entry.dropped -and $entry.dropped.Count -gt 0) {
            foreach ($d in $entry.dropped) {
                Write-Host "  Dropped: $($d.condition) -- $($d.why)" -ForegroundColor Yellow
            }
        }
    }

    if ($plan.Unconvertible -and $plan.Unconvertible.Count -gt 0) {
        $naRules = @($plan.Unconvertible | Where-Object { $_.reason -like 'Not applicable:*' })
        $ucRules = @($plan.Unconvertible | Where-Object { $_.reason -notlike 'Not applicable:*' })
        if ($naRules.Count -gt 0) {
            $naWorkloads = ($naRules | ForEach-Object { if ($_.reason -match 'support (\S+) workload') { $Matches[1] } }) | Sort-Object -Unique
            Write-Host ("`nNot applicable: $($naRules.Count) rules (" + ($naWorkloads -join ', ') + " workload - no auto-labeling support)") -ForegroundColor DarkGray
        }
        if ($ucRules.Count -gt 0) {
            $ucReasons = ($ucRules | Group-Object reason | ForEach-Object { "$($_.Count) $($_.Name)" }) -join '; '
            Write-Host "Unconvertible: $($ucRules.Count) rules ($ucReasons)" -ForegroundColor DarkGray
        }
    }

    Write-Host "`nScaling: $($scalingStatus.Total) of 100 policies ($($scalingStatus.Status))" -ForegroundColor $(
        if ($scalingStatus.Status -eq 'ok') { 'Green' } elseif ($scalingStatus.Status -eq 'warning') { 'Yellow' } else { 'Red' }
    )
    #endregion

    #region Interactive approval per label
    if (-not $AutoApprove) {
        Write-Host ""
        foreach ($entry in $plan.Entries) {
            $prompt = "Approve $($entry.labelName)? ($($entry.sourceRules.Count) rules, $($entry.totalSITs) SITs, $($entry.classification)) [Y/n]"
            $response = Read-Host $prompt
            if (-not $response -or $response -match '^[Yy]') {
                $entry.approved = $true
                Write-Host "  Approved." -ForegroundColor Green
            } else {
                $entry.approved = $false
                Write-Host "  Skipped." -ForegroundColor Yellow
            }
        }
    } else {
        # Auto-approve all
        foreach ($entry in $plan.Entries) {
            $entry.approved = $true
        }
        Write-Host "`nAuto-approved all $($plan.Entries.Count) labels." -ForegroundColor Green
    }
    #endregion

    #region Save plan
    $plansDir = Join-Path $ProjectRoot "plans"
    if (-not (Test-Path $plansDir)) {
        New-Item -ItemType Directory -Path $plansDir -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $planFileName = "conversion-plan-${tenantSanitised}-${timestamp}.json"
    $planPath = Join-Path $plansDir $planFileName

    Export-ConversionPlan -Plan $plan -Path $planPath
    Write-Host "`nPlan saved: $planPath" -ForegroundColor Green
    #endregion

    $approvedCount = @($plan.Entries | Where-Object { $_.approved }) | Measure-Object | Select-Object -ExpandProperty Count
    Write-Host "`nScan complete. $approvedCount of $($plan.Entries.Count) labels approved." -ForegroundColor Cyan
    Write-Host "To execute: .\scripts\Convert-DLPToAutoLabeling.ps1 -Execute -PlanFile `"$planPath`" -Connect" -ForegroundColor Gray

    try { Stop-Transcript } catch { }
    return
}

###############################################################################
#                             PHASE 2: EXECUTE                                #
###############################################################################
if ($Execute) {
    Write-Host "`n=== DLP-to-Auto-Labeling Conversion Execute ===" -ForegroundColor Cyan

    #region Connection
    if ($Connect) {
        $connected = Connect-DLPSession -UPN $UPN
        if (-not $connected) { return }
    }
    if (-not (Assert-DLPSession)) { return }
    #endregion

    $null = Start-DeploymentLog -ScriptName "Convert-DLPToAutoLabeling-Execute"

    #region Load and validate plan
    $planPath = if ([System.IO.Path]::IsPathRooted($PlanFile)) { $PlanFile } else { Join-Path $ProjectRoot $PlanFile }
    $plan = Import-ConversionPlan -Path $planPath
    if (-not $plan) {
        Write-Error "Failed to load conversion plan from: $planPath"
        try { Stop-Transcript } catch { }
        return
    }

    # Validate version
    if ($plan.Version -ne '1') {
        Write-Error "Unsupported plan version: $($plan.Version). Expected '1'."
        try { Stop-Transcript } catch { }
        return
    }

    # Check for approved labels
    $approvedEntries = @($plan.Entries | Where-Object { $_.approved -eq $true })
    if ($approvedEntries.Count -eq 0) {
        Write-Warning "No approved labels in plan. Nothing to execute."
        try { Stop-Transcript } catch { }
        return
    }
    Write-Host "  Plan loaded: $($approvedEntries.Count) approved labels" -ForegroundColor Gray

    # Build display-name -> internal-name lookup from labels.json
    # ApplySensitivityLabel requires the internal label Name, not DisplayName
    $labelDisplayToName = @{}
    if ($labelsJson) {
        foreach ($lj in $labelsJson) {
            if ($lj.displayName -and $lj.name -and -not $lj.isGroup) {
                $labelDisplayToName[$lj.displayName] = $lj.name
            }
        }
        Write-Host "  Label name lookup: $($labelDisplayToName.Count) entries from labels.json" -ForegroundColor Gray
    }
    # Also check tenant labels as fallback
    $tenantLabels = @(Get-Label -ErrorAction SilentlyContinue)
    $labelDisplayToTenantName = @{}
    foreach ($tl in $tenantLabels) {
        if ($tl.DisplayName -and $tl.Name) {
            # For child labels, use the full Name (which is the internal name)
            $labelDisplayToTenantName[$tl.DisplayName] = $tl.Name
        }
    }
    Write-Host "  Tenant label lookup: $($labelDisplayToTenantName.Count) entries" -ForegroundColor Gray
    #endregion

    #region Execute per approved label
    $successPolicies = 0
    $failPolicies    = 0
    $successRules    = 0
    $failRules       = 0
    $policyNum       = 0

    foreach ($entry in $approvedEntries) {
        $policyNum++
        $labelDisplayName = $entry.labelName

        # Resolve display name to internal label name for ApplySensitivityLabel
        $labelName = $null
        if ($labelDisplayToName.ContainsKey($labelDisplayName)) {
            $labelName = $labelDisplayToName[$labelDisplayName]
        } elseif ($labelDisplayToTenantName.ContainsKey($labelDisplayName)) {
            $labelName = $labelDisplayToTenantName[$labelDisplayName]
        } else {
            # Fallback: use display name as-is (may work if tenant uses display names as internal names)
            $labelName = $labelDisplayName
            Write-Warning "  Could not resolve internal name for label '$labelDisplayName' — using as-is"
        }

        # Determine label code for naming
        $labelCode = $null
        if ($entry.labelCodes -and @($entry.labelCodes).Count -gt 0) {
            $labelCode = @($entry.labelCodes)[0]
        }
        if (-not $labelCode) {
            # Derive from display name: strip spaces and special chars
            $labelCode = ($labelDisplayName -replace '[^A-Za-z0-9-]', '') -replace '--+', '-'
        }

        $policyName = "AL{0:D2}-{1}-{2}-{3}" -f $policyNum, $labelCode, $namingPrefix, $namingSuffix

        Write-Host "`n--- Creating policy: $policyName (label: $labelDisplayName -> $labelName) ---" -ForegroundColor Green

        # Build comment from source rule names
        $sourceNames = ($entry.sourceRules | ForEach-Object { $_.ruleName }) -join ', '
        $policyComment = "Converted from DLP: $sourceNames"
        # Truncate comment if too long (Purview limit ~1024 chars)
        if ($policyComment.Length -gt 1000) {
            $policyComment = $policyComment.Substring(0, 997) + "..."
        }

        # Check if policy already exists
        $existingPolicy = $null
        try {
            $existingPolicy = Get-AutoSensitivityLabelPolicy -Identity $policyName -ErrorAction SilentlyContinue
        } catch { }

        # Create or reuse policy
        try {
            if ($existingPolicy) {
                Write-Host "  Policy already exists: $policyName (reusing)" -ForegroundColor Yellow
            } elseif ($PSCmdlet.ShouldProcess($policyName, "New-AutoSensitivityLabelPolicy")) {
                $newPolicyParams = @{
                    Name                    = $policyName
                    ApplySensitivityLabel   = $labelName
                    ExchangeLocation        = "All"
                    SharePointLocation      = "All"
                    OneDriveLocation        = "All"
                    Mode                    = "TestWithoutNotifications"
                    Comment                 = $policyComment
                    ErrorAction             = "Stop"
                }
                if ($overwriteLabel) { $newPolicyParams['OverwriteLabel'] = $true }
                Invoke-WithRetry -OperationName "New-ALPolicy $policyName" -ScriptBlock {
                    New-AutoSensitivityLabelPolicy @newPolicyParams
                } -MaxRetries $maxRetries -BaseDelaySec $baseDelaySec
                Write-Host "  Policy created: $policyName" -ForegroundColor Green
            }
            $successPolicies++
        } catch {
            Write-Warning "  Failed to create policy ${policyName}: $($_.Exception.Message)"
            $failPolicies++
            # Stamp all source rules as failed
            foreach ($sr in $entry.sourceRules) {
                $sr.executed = [ordered]@{
                    status    = "failed"
                    error     = $_.Exception.Message
                    timestamp = (Get-Date -Format 'o')
                }
            }
            continue
        }

        if (-not $WhatIfPreference) { Start-Sleep -Seconds $interCallDelaySec }

        # Group source rules by workload
        $workloadGroups = @{}
        foreach ($sr in $entry.sourceRules) {
            $wl = $sr.workload
            if (-not $workloadGroups.ContainsKey($wl)) {
                $workloadGroups[$wl] = @()
            }
            $workloadGroups[$wl] += $sr
        }

        # For each workload group, merge SIT conditions and create rule
        $ruleNum = 0
        foreach ($wl in $workloadGroups.Keys) {
            $ruleNum++
            $wlRules = $workloadGroups[$wl]
            $wlCode = $WorkloadCodeMap[$wl]
            if (-not $wlCode) { $wlCode = $wl.Substring(0, 3).ToUpper() }

            # Collect CCSI sources for merging
            $ccsiSources = @()
            $allExceptIf = [ordered]@{}
            $accessScope = $null
            $sourceRuleNames = @()

            foreach ($sr in $wlRules) {
                $sourceRuleNames += $sr.ruleName

                # Extract CCSI from conditions
                $converted = $null
                if ($sr.conditions -is [PSCustomObject]) {
                    $converted = $sr.conditions.converted
                } elseif ($sr.conditions -is [hashtable] -or $sr.conditions -is [System.Collections.Specialized.OrderedDictionary]) {
                    $converted = $sr.conditions['converted']
                }

                if ($converted) {
                    $ccsi = $null
                    if ($converted -is [PSCustomObject]) {
                        $ccsi = $converted.ContentContainsSensitiveInformation
                        if (-not $ccsi) { $ccsi = $converted.'ContentContainsSensitiveInformation' }
                        # Check for AccessScope
                        if ($converted.AccessScope) { $accessScope = $converted.AccessScope }
                    } elseif ($converted -is [hashtable] -or $converted -is [System.Collections.Specialized.OrderedDictionary]) {
                        $ccsi = if ($converted.Contains('ContentContainsSensitiveInformation')) { $converted['ContentContainsSensitiveInformation'] } else { $null }
                        if ($converted.Contains('AccessScope')) { $accessScope = $converted['AccessScope'] }
                    }
                    if ($ccsi) {
                        # Convert PSCustomObject to hashtable if needed
                        if ($ccsi -is [PSCustomObject]) {
                            $ccsi = Convert-PSOToHashtable -InputObject $ccsi
                        }
                        # Use comma operator to prevent PowerShell array flattening
                        # Each CCSI (flat SIT array or groups structure) must stay as one element
                        $ccsiSources += ,$ccsi
                    }
                }

                # Collect ExceptIf conditions
                $exceptIf = $null
                if ($sr.conditions -is [PSCustomObject]) {
                    $exceptIf = $sr.conditions.exceptIf
                } elseif ($sr.conditions -is [hashtable] -or $sr.conditions -is [System.Collections.Specialized.OrderedDictionary]) {
                    $exceptIf = $sr.conditions['exceptIf']
                }
                if ($exceptIf) {
                    if ($exceptIf -is [PSCustomObject]) {
                        foreach ($prop in $exceptIf.PSObject.Properties) {
                            $allExceptIf[$prop.Name] = $prop.Value
                        }
                    } elseif ($exceptIf -is [hashtable] -or $exceptIf -is [System.Collections.Specialized.OrderedDictionary]) {
                        foreach ($key in $exceptIf.Keys) {
                            $allExceptIf[$key] = $exceptIf[$key]
                        }
                    }
                }
            }

            # Normalise flat arrays to groups structure before merging
            $normalisedSources = @()
            foreach ($src in $ccsiSources) {
                if ($src -is [System.Collections.IList] -and $src.Count -gt 0 -and -not ($src -is [string])) {
                    # Flat array of SIT hashtables — wrap into groups structure
                    $normalisedSources += @{
                        operator = "And"
                        groups = @(@{
                            operator       = "Or"
                            name           = "Default"
                            sensitivetypes = @($src)
                        })
                    }
                } else {
                    $normalisedSources += $src
                }
            }

            # Merge SIT conditions
            $mergeResult = Merge-SITConditions -Sources $normalisedSources
            if (-not $mergeResult.Merged) {
                Write-Warning "    No SIT conditions to merge for $wl workload. Skipping rule."
                foreach ($sr in $wlRules) {
                    $sr.executed = [ordered]@{
                        status    = "skipped"
                        reason    = "No SIT conditions after merge"
                        timestamp = (Get-Date -Format 'o')
                    }
                }
                continue
            }

            foreach ($note in $mergeResult.Notes) {
                Write-Host "    Merge note: $note" -ForegroundColor DarkGray
            }

            $sourceComment = "Source: $($sourceRuleNames -join ', ')"
            if ($sourceComment.Length -gt 1000) {
                $sourceComment = $sourceComment.Substring(0, 997) + "..."
            }

            # Split SITs into chunks of 125 (Purview per-rule limit)
            $mergedSITs = $mergeResult.Merged['groups'][0]['sensitivetypes']
            $sitChunks = @(Split-ClassifierChunks -ClassifierList $mergedSITs -MaxPerRule 125)
            if ($sitChunks.Count -gt 1) {
                Write-Host "    Splitting $($mergedSITs.Count) SITs into $($sitChunks.Count) chunks" -ForegroundColor Yellow
            }

            $chunkIdx = 0
            $allChunksOk = $true
            $createdRuleNames = @()
            foreach ($chunk in $sitChunks) {
                $chunkIdx++
                # Append chunk letter suffix for multi-chunk rules (a, b, c...)
                $chunkSuffix = if ($sitChunks.Count -gt 1) { [char](96 + $chunkIdx) } else { '' }
                $ruleName = "AL{0:D2}-R{1:D2}{5}-{2}-{3}-{4}" -f $policyNum, $ruleNum, $wlCode, $labelCode, $namingSuffix, $chunkSuffix

                $chunkCCSI = [ordered]@{
                    operator = 'And'
                    groups   = @([ordered]@{
                        operator       = 'Or'
                        name           = 'Default'
                        sensitivetypes = @($chunk)
                    })
                }

                Write-Host "  Creating rule: $ruleName ($wl, $(@($chunk).Count) SITs)" -ForegroundColor Cyan

                $ruleParams = @{
                    Name                                  = $ruleName
                    Policy                                = $policyName
                    Workload                              = $wl
                    ContentContainsSensitiveInformation    = $chunkCCSI
                    Comment                               = $sourceComment
                }

                if ($accessScope) {
                    $ruleParams['AccessScope'] = $accessScope
                }
                foreach ($eiKey in $allExceptIf.Keys) {
                    $ruleParams[$eiKey] = $allExceptIf[$eiKey]
                }

                try {
                    if ($PSCmdlet.ShouldProcess($ruleName, "New-AutoSensitivityLabelRule")) {
                        Invoke-WithRetry -OperationName "New-ALRule $ruleName" -ScriptBlock {
                            $null = New-AutoSensitivityLabelRule @ruleParams -ErrorAction Stop
                        } -MaxRetries $maxRetries -BaseDelaySec $baseDelaySec
                        Write-Host "    Rule created: $ruleName" -ForegroundColor Green
                    }
                    $successRules++
                    $createdRuleNames += $ruleName
                } catch {
                    Write-Warning "    Failed to create rule ${ruleName}: $($_.Exception.Message)"
                    $failRules++
                    $allChunksOk = $false
                }

                if (-not $WhatIfPreference) { Start-Sleep -Seconds $interCallDelaySec }
            }

            # Stamp source rules
            foreach ($sr in $wlRules) {
                if ($allChunksOk) {
                    $sr.executed = [ordered]@{
                        status     = "success"
                        policyName = $policyName
                        ruleName   = ($createdRuleNames -join ', ')
                        timestamp  = (Get-Date -Format 'o')
                    }
                } else {
                    $sr.executed = [ordered]@{
                        status    = "partial"
                        policyName = $policyName
                        ruleName  = ($createdRuleNames -join ', ')
                        error     = "Some rule chunks failed"
                        timestamp = (Get-Date -Format 'o')
                    }
                }
            }
        }
    }
    #endregion

    #region Update plan with execution summary
    if ($plan.ExecutionSummary -is [PSCustomObject]) {
        $plan.ExecutionSummary.executedAt = (Get-Date -Format 'o')
        $plan.ExecutionSummary.policiesCreated = $successPolicies
        $plan.ExecutionSummary.rulesCreated = $successRules
        $plan.ExecutionSummary.failures = $failPolicies + $failRules
    } else {
        $plan.ExecutionSummary = [ordered]@{
            executedAt      = (Get-Date -Format 'o')
            policiesCreated = $successPolicies
            rulesCreated    = $successRules
            failures        = $failPolicies + $failRules
        }
    }

    # Save updated plan
    Export-ConversionPlan -Plan $plan -Path $planPath
    Write-Host "`nUpdated plan saved: $planPath" -ForegroundColor Gray
    #endregion

    #region Summary
    Write-Host "`n=== Execution Summary ===" -ForegroundColor Cyan
    Write-Host "  Policies: $successPolicies created, $failPolicies failed" -ForegroundColor $(if ($failPolicies -eq 0) { "Green" } else { "Red" })
    Write-Host "  Rules:    $successRules created, $failRules failed" -ForegroundColor $(if ($failRules -eq 0) { "Green" } else { "Red" })
    Write-Host "  Mode:     TestWithoutNotifications (simulation)" -ForegroundColor Gray
    Write-Host "`nExecution complete at $(Get-Date)" -ForegroundColor Green
    #endregion

    try { Stop-Transcript } catch { }
    return
}

###############################################################################
#                             PHASE 3: CLEANUP                                #
###############################################################################
if ($Cleanup) {
    Write-Host "`n=== DLP-to-Auto-Labeling Conversion Cleanup ===" -ForegroundColor Yellow

    #region Connection
    if ($Connect) {
        $connected = Connect-DLPSession -UPN $UPN
        if (-not $connected) { return }
    }
    if (-not (Assert-DLPSession)) { return }
    #endregion

    $null = Start-DeploymentLog -ScriptName "Convert-DLPToAutoLabeling-Cleanup"

    #region Load plan
    $planPath = if ([System.IO.Path]::IsPathRooted($PlanFile)) { $PlanFile } else { Join-Path $ProjectRoot $PlanFile }
    $plan = Import-ConversionPlan -Path $planPath
    if (-not $plan) {
        Write-Error "Failed to load conversion plan from: $planPath"
        try { Stop-Transcript } catch { }
        return
    }
    #endregion

    #region Collect deployed policy names from executed stamps
    $policyNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $plan.Entries) {
        foreach ($sr in $entry.sourceRules) {
            $exec = $sr.executed
            if (-not $exec) { continue }
            $status = $null
            $polName = $null
            if ($exec -is [PSCustomObject]) {
                $status = $exec.status
                $polName = $exec.policyName
            } elseif ($exec -is [hashtable] -or $exec -is [System.Collections.Specialized.OrderedDictionary]) {
                $status = $exec['status']
                $polName = $exec['policyName']
            }
            if ($status -eq 'success' -and $polName) {
                [void]$policyNames.Add($polName)
            }
        }
    }

    if ($policyNames.Count -eq 0) {
        Write-Warning "No successfully executed policies found in plan. Nothing to clean up."
        try { Stop-Transcript } catch { }
        return
    }

    Write-Host "  Found $($policyNames.Count) policies to remove." -ForegroundColor Gray
    #endregion

    #region Remove policies and rules
    $removedPolicies = 0
    $removedRules    = 0
    $failedRemovals  = 0

    foreach ($polName in $policyNames) {
        Write-Host "`n  Cleaning up policy: $polName" -ForegroundColor Yellow

        # Get rules for this policy
        $rules = @()
        try {
            $rules = @(Get-AutoSensitivityLabelRule -Policy $polName -ErrorAction Stop)
        } catch {
            Write-Warning "    Could not list rules for ${polName}: $($_.Exception.Message)"
        }

        # Remove each rule
        $ruleIdx = 0
        foreach ($rule in $rules) {
            if ($ruleIdx -gt 0 -and -not $WhatIfPreference) { Start-Sleep -Seconds $interCallDelaySec }
            if ($PSCmdlet.ShouldProcess($rule.Name, "Remove-AutoSensitivityLabelRule")) {
                try {
                    Invoke-WithRetry -OperationName "Remove-ALRule $($rule.Name)" -ScriptBlock {
                        Remove-AutoSensitivityLabelRule -Identity $rule.Name -Confirm:$false -ErrorAction Stop
                    } -MaxRetries $maxRetries -BaseDelaySec $baseDelaySec
                    Write-Host "    Removed rule: $($rule.Name)" -ForegroundColor Yellow
                    $removedRules++
                } catch {
                    Write-Warning "    Failed to remove rule $($rule.Name): $($_.Exception.Message)"
                    $failedRemovals++
                }
                $ruleIdx++
            }
        }

        # Remove policy
        if ($rules.Count -gt 0 -and -not $WhatIfPreference) { Start-Sleep -Seconds $interCallDelaySec }
        if ($PSCmdlet.ShouldProcess($polName, "Remove-AutoSensitivityLabelPolicy")) {
            try {
                Invoke-WithRetry -OperationName "Remove-ALPolicy $polName" -ScriptBlock {
                    Remove-AutoSensitivityLabelPolicy -Identity $polName -Confirm:$false -ErrorAction Stop
                } -MaxRetries $maxRetries -BaseDelaySec $baseDelaySec
                Write-Host "    Removed policy: $polName" -ForegroundColor Yellow
                $removedPolicies++
            } catch {
                Write-Warning "    Failed to remove policy ${polName}: $($_.Exception.Message)"
                $failedRemovals++
            }
        }
    }
    #endregion

    #region Clear executed stamps and reset summary in plan
    foreach ($entry in $plan.Entries) {
        foreach ($sr in $entry.sourceRules) {
            $sr.executed = $null
            # For PSCustomObject, need to set the property
            if ($sr -is [PSCustomObject] -and $sr.PSObject.Properties['executed']) {
                $sr.executed = $null
            }
        }
    }

    if ($plan.ExecutionSummary -is [PSCustomObject]) {
        $plan.ExecutionSummary.executedAt = $null
        $plan.ExecutionSummary.policiesCreated = 0
        $plan.ExecutionSummary.rulesCreated = 0
        $plan.ExecutionSummary.failures = 0
    } else {
        $plan.ExecutionSummary = [ordered]@{
            executedAt      = $null
            policiesCreated = 0
            rulesCreated    = 0
            failures        = 0
        }
    }

    Export-ConversionPlan -Plan $plan -Path $planPath
    Write-Host "`nUpdated plan saved: $planPath" -ForegroundColor Gray
    #endregion

    #region Summary
    Write-Host "`n=== Cleanup Summary ===" -ForegroundColor Cyan
    Write-Host "  Policies removed: $removedPolicies" -ForegroundColor $(if ($removedPolicies -gt 0) { "Yellow" } else { "Gray" })
    Write-Host "  Rules removed:    $removedRules" -ForegroundColor $(if ($removedRules -gt 0) { "Yellow" } else { "Gray" })
    if ($failedRemovals -gt 0) {
        Write-Host "  Failures:         $failedRemovals" -ForegroundColor Red
    }
    Write-Host "`nCleanup complete at $(Get-Date)" -ForegroundColor Green
    #endregion

    try { Stop-Transcript } catch { }
    return
}
