#==============================================================================
# Invoke-ChangePack.ps1
# Applies a CSV of targeted changes (add/update/delete/disable/enable).
#
# Supports two CSV formats:
#   Legacy:  Action,RuleName,Policy,LabelCode           (DLP rules only)
#   New:     Component,Action,Identity,Policy,LabelCode,Detail  (multi-component)
#
# Components (new format): Label, SITPackage, DLPPolicy, DLPRule
# Processing order: Labels -> SIT Packages -> DLP Policies -> DLP Rules
#
# Usage:
#   .\scripts\Invoke-ChangePack.ps1 -CsvPath .\changepacks\remove-stale-rules.csv -Connect
#   .\scripts\Invoke-ChangePack.ps1 -CsvPath .\changepacks\changepack-20260313.csv -WhatIf
#==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$CsvPath,
    [switch]$Connect,
    [switch]$Force,
    [string]$UPN,
    [int]$DelaySec = 10,
    [int]$MaxRetries = 3,
    [int]$BaseDelaySec = 300
)

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "config"
$XmlDir      = Join-Path $ProjectRoot "xml"

# Import shared module
Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

$ErrorActionPreference = "Stop"

#region Connection
if ($Connect) {
    $connected = Connect-DLPSession -UPN $UPN
    if (-not $connected) { return }
}

if (-not (Assert-DLPSession)) { return }
#endregion

#region Logging
$null = Start-DeploymentLog -ScriptName "Invoke-ChangePack"
#endregion

#region Load CSV
Write-Host "`n=== Loading Change Pack ===" -ForegroundColor Cyan

if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV not found: $CsvPath"
    return
}

$changes = Import-Csv -Path $CsvPath -ErrorAction Stop
if ($changes.Count -eq 0) {
    Write-Host "  CSV is empty. Nothing to do." -ForegroundColor Yellow
    return
}

if ($changes.Count -gt 500 -and -not $Force) {
    Write-Warning "CSV contains $($changes.Count) rows (>500). Use -Force to proceed with large change packs."
    return
}

# Detect mode: legacy (no Component column) vs new (Component column present)
$csvCols = $changes[0].PSObject.Properties.Name
$hasComponent = $csvCols -contains "Component"
#endregion

$results = @{ success = 0; failed = 0; skipped = 0 }

if (-not $hasComponent) {
    #==========================================================================
    # LEGACY MODE — DLP Rules only (original format: Action,RuleName,Policy,LabelCode)
    #==========================================================================
    $ValidActions = @("delete", "add", "update", "disable", "enable")

    #region Legacy Validation
    $requiredCols = @("Action", "RuleName", "Policy")
    foreach ($col in $requiredCols) {
        if ($col -notin $csvCols) {
            Write-Error "CSV missing required column: $col. Found: $($csvCols -join ', ')"
            return
        }
    }

    $errors = @()
    $rowNum = 1
    foreach ($row in $changes) {
        $rowNum++
        $action = $row.Action.Trim().ToLower()
        if ($action -notin $ValidActions) {
            $errors += "Row ${rowNum}: Invalid action '$($row.Action)'. Valid: $($ValidActions -join ', ')"
        }
        if (-not $row.RuleName.Trim()) {
            $errors += "Row ${rowNum}: RuleName is blank"
        }
        if ($action -eq "add" -and (-not $row.Policy.Trim() -or -not $row.LabelCode.Trim())) {
            $errors += "Row ${rowNum}: 'add' requires Policy and LabelCode"
        }
        if ($action -eq "update" -and -not $row.LabelCode.Trim()) {
            $errors += "Row ${rowNum}: 'update' requires LabelCode"
        }
    }
    if ($errors.Count -gt 0) {
        Write-Error "CSV validation failed:`n  $($errors -join "`n  ")"
        return
    }
    #endregion

    $actionCounts = $changes | Group-Object { $_.Action.Trim().ToLower() }
    Write-Host "  Loaded $($changes.Count) change(s) from $(Split-Path $CsvPath -Leaf) [legacy format]:" -ForegroundColor Gray
    foreach ($grp in $actionCounts) {
        Write-Host "    $($grp.Name): $($grp.Count)" -ForegroundColor Gray
    }

    #region Legacy Config
    $needsConfig = $changes | Where-Object { $_.Action.Trim().ToLower() -in @("add", "update") }

    $Classifiers  = $null
    $Config       = $null
    $Policies     = $null
    $Overrides    = $null

    if ($needsConfig.Count -gt 0) {
        Write-Host "`n=== Loading Config (for add/update) ===" -ForegroundColor Cyan

        $Defaults = Get-ModuleDefaults
        $settingsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
        $Config = Merge-GlobalConfig -Defaults $Defaults -GlobalJson $settingsJson

        $classifiersJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "classifiers.json") -Description "classifier definitions"
        if (-not $classifiersJson) {
            Write-Error "classifiers.json required for add/update but not found."
            return
        }
        $Classifiers = Resolve-ClassifierConfig -ClassifiersJson $classifiersJson -Defaults $Defaults
        Write-Host "  Loaded $($Classifiers.Count) label classifiers" -ForegroundColor Gray

        $policiesJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "policies.json") -Description "policy definitions"
        if ($policiesJson) {
            $Policies = Resolve-PolicyConfig -PoliciesJson $policiesJson
            Write-Host "  Loaded $($Policies.Count) policy definitions" -ForegroundColor Gray
        }

        $overridesJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "rule-overrides.json") -Description "rule overrides"
        $Overrides = Resolve-RuleOverrides -OverridesJson $overridesJson

        $labelCodes = @($needsConfig | ForEach-Object { $_.LabelCode.Trim() } | Sort-Object -Unique)
        foreach ($lc in $labelCodes) {
            if (-not $Classifiers.ContainsKey($lc)) {
                Write-Error "LabelCode '$lc' not found in classifiers.json. Available: $($Classifiers.Keys -join ', ')"
                return
            }
        }
    }
    #endregion

    #region Legacy Processing
    Write-Host "`n=== Processing Changes ===" -ForegroundColor Cyan
    $index = 0

    foreach ($row in $changes) {
        $action    = $row.Action.Trim().ToLower()
        $ruleName  = $row.RuleName.Trim()
        $policy    = if ($row.PSObject.Properties.Name -contains "Policy") { $row.Policy.Trim() } else { "" }
        $labelCode = if ($row.PSObject.Properties.Name -contains "LabelCode") { $row.LabelCode.Trim() } else { "" }

        if ($index -gt 0 -and -not $WhatIfPreference) { Start-Sleep -Seconds $DelaySec }
        $index++

        $tag = "[$index/$($changes.Count)]"

        switch ($action) {

            "delete" {
                if ($PSCmdlet.ShouldProcess($ruleName, "Remove-DlpComplianceRule")) {
                    try {
                        Invoke-WithRetry -OperationName "Delete $ruleName" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                            Remove-DlpComplianceRule -Identity $ruleName -Confirm:$false -ErrorAction Stop
                        }
                        Write-Host "  $tag DELETE  $ruleName" -ForegroundColor Green
                        $results.success++
                    } catch {
                        Write-Warning "  $tag FAILED  $ruleName -- $($_.Exception.Message)"
                        $results.failed++
                    }
                } else {
                    $results.skipped++
                }
            }

            "add" {
                $classifierList = $Classifiers[$labelCode]
                # Handle chunk-suffixed rules (e.g., R02a) — use only the relevant chunk
                if ($ruleName -match '-R\d{2}([a-z])-') {
                    $chunkLetter = $Matches[1]
                    $chunkIndex = [int][char]$chunkLetter - [int][char]'a'
                    $chunks = Split-ClassifierChunks -ClassifierList $classifierList -MaxPerRule 125
                    if ($chunkIndex -lt $chunks.Count) {
                        $classifierList = $chunks[$chunkIndex]
                    } else {
                        Write-Warning "  Chunk '$chunkLetter' out of range for $labelCode ($($chunks.Count) chunks). Using full list."
                    }
                }

                $scopeParam = $null
                $scopeValue = $null
                $policyCode = ""
                if ($Policies) {
                    foreach ($p in $Policies) {
                        $expectedName = Get-PolicyName -PolicyNumber $p.Number -PolicyCode $p.Code -Prefix $Config.namingPrefix -Suffix $Config.namingSuffix
                        if ($expectedName -eq $policy) {
                            $scopeParam = $p.ScopeParam
                            $scopeValue = $p.ScopeValue
                            $policyCode = $p.Code
                            break
                        }
                    }
                }

                $condition = New-DLPSITCondition -ClassifierList $classifierList -ScopeParam $scopeParam -ScopeValue $scopeValue

                $ruleParams = @{
                    Name                = $ruleName
                    Policy              = $policy
                    Comment             = "$labelCode ($($classifierList.Count) classifiers)"
                    ReportSeverityLevel = "Low"
                    Disabled            = $false
                }

                if ($condition.Format -eq "AdvancedRule") {
                    $ruleParams["AdvancedRule"] = $condition.Value
                } else {
                    $ruleParams["ContentContainsSensitiveInformation"] = $condition.Value
                    if ($scopeParam) {
                        $ruleParams[$scopeParam] = $scopeValue
                    }
                }

                if ($Overrides) {
                    $ruleParams = Get-MergedRuleParams -BaseParams $ruleParams -Overrides $Overrides -LabelCode $labelCode -PolicyCode $policyCode -RuleName $ruleName
                }

                if ($PSCmdlet.ShouldProcess($ruleName, "New-DlpComplianceRule")) {
                    try {
                        Invoke-WithRetry -OperationName "Add $ruleName" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                            $null = New-DlpComplianceRule @ruleParams -ErrorAction Stop
                        }
                        Write-Host "  $tag ADD     $ruleName ($labelCode, $($classifierList.Count) classifiers)" -ForegroundColor Green
                        $results.success++
                    } catch {
                        Write-Warning "  $tag FAILED  $ruleName -- $($_.Exception.Message)"
                        $results.failed++
                    }
                } else {
                    $results.skipped++
                }
            }

            "update" {
                $classifierList = $Classifiers[$labelCode]
                # Handle chunk-suffixed rules (e.g., R02a) — use only the relevant chunk
                if ($ruleName -match '-R\d{2}([a-z])-') {
                    $chunkLetter = $Matches[1]
                    $chunkIndex = [int][char]$chunkLetter - [int][char]'a'
                    $chunks = Split-ClassifierChunks -ClassifierList $classifierList -MaxPerRule 125
                    if ($chunkIndex -lt $chunks.Count) {
                        $classifierList = $chunks[$chunkIndex]
                    } else {
                        Write-Warning "  Chunk '$chunkLetter' out of range for $labelCode ($($chunks.Count) chunks). Using full list."
                    }
                }

                $scopeParam = $null
                $scopeValue = $null
                if ($Policies) {
                    foreach ($p in $Policies) {
                        $expectedName = Get-PolicyName -PolicyNumber $p.Number -PolicyCode $p.Code -Prefix $Config.namingPrefix -Suffix $Config.namingSuffix
                        if ($expectedName -eq $policy) {
                            $scopeParam = $p.ScopeParam
                            $scopeValue = $p.ScopeValue
                            break
                        }
                    }
                }

                $condition = New-DLPSITCondition -ClassifierList $classifierList -ScopeParam $scopeParam -ScopeValue $scopeValue

                $updateParams = @{
                    Identity = $ruleName
                    Comment  = "$labelCode ($($classifierList.Count) classifiers)"
                }

                if ($condition.Format -eq "AdvancedRule") {
                    $updateParams["AdvancedRule"] = $condition.Value
                    if (-not $scopeParam -and $policy) {
                        Write-Warning "  $tag AdvancedRule used but could not resolve scope from Policy '$policy'. AccessScope may be missing from rule JSON."
                    }
                } else {
                    $updateParams["ContentContainsSensitiveInformation"] = $condition.Value
                }

                if ($PSCmdlet.ShouldProcess($ruleName, "Set-DlpComplianceRule (update classifiers)")) {
                    try {
                        Invoke-WithRetry -OperationName "Update $ruleName" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                            Set-DlpComplianceRule @updateParams -Confirm:$false -ErrorAction Stop
                        }
                        Write-Host "  $tag UPDATE  $ruleName ($labelCode, $($classifierList.Count) classifiers)" -ForegroundColor Green
                        $results.success++
                    } catch {
                        Write-Warning "  $tag FAILED  $ruleName -- $($_.Exception.Message)"
                        $results.failed++
                    }
                } else {
                    $results.skipped++
                }
            }

            "disable" {
                if ($PSCmdlet.ShouldProcess($ruleName, "Set-DlpComplianceRule -Disabled `$true")) {
                    try {
                        Invoke-WithRetry -OperationName "Disable $ruleName" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                            Set-DlpComplianceRule -Identity $ruleName -Disabled $true -Confirm:$false -ErrorAction Stop
                        }
                        Write-Host "  $tag DISABLE $ruleName" -ForegroundColor Green
                        $results.success++
                    } catch {
                        Write-Warning "  $tag FAILED  $ruleName -- $($_.Exception.Message)"
                        $results.failed++
                    }
                } else {
                    $results.skipped++
                }
            }

            "enable" {
                if ($PSCmdlet.ShouldProcess($ruleName, "Set-DlpComplianceRule -Disabled `$false")) {
                    try {
                        Invoke-WithRetry -OperationName "Enable $ruleName" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                            Set-DlpComplianceRule -Identity $ruleName -Disabled $false -Confirm:$false -ErrorAction Stop
                        }
                        Write-Host "  $tag ENABLE  $ruleName" -ForegroundColor Green
                        $results.success++
                    } catch {
                        Write-Warning "  $tag FAILED  $ruleName -- $($_.Exception.Message)"
                        $results.failed++
                    }
                } else {
                    $results.skipped++
                }
            }
        }
    }
    #endregion

} else {
    #==========================================================================
    # NEW MODE — Multi-component (Component,Action,Identity,Policy,LabelCode,Detail)
    #==========================================================================

    $ValidComponents = @("Label", "SITPackage", "DLPPolicy", "DLPRule")
    $ValidActions    = @("add", "update", "delete", "disable", "enable", "skip")

    #region New Mode Validation
    $requiredCols = @("Component", "Action", "Identity")
    foreach ($col in $requiredCols) {
        if ($col -notin $csvCols) {
            Write-Error "CSV missing required column: $col. Found: $($csvCols -join ', ')"
            return
        }
    }

    $errors = @()
    $rowNum = 1
    foreach ($row in $changes) {
        $rowNum++
        $comp   = $row.Component.Trim()
        $action = $row.Action.Trim().ToLower()

        if ($comp -notin $ValidComponents) {
            $errors += "Row ${rowNum}: Invalid Component '$comp'. Valid: $($ValidComponents -join ', ')"
        }
        if ($action -notin $ValidActions) {
            $errors += "Row ${rowNum}: Invalid Action '$($row.Action)'. Valid: $($ValidActions -join ', ')"
        }
        if (-not $row.Identity.Trim()) {
            $errors += "Row ${rowNum}: Identity is blank"
        }
        # DLPRule add requires Policy and LabelCode
        if ($comp -eq "DLPRule" -and $action -eq "add" -and (-not $row.Policy.Trim() -or -not $row.LabelCode.Trim())) {
            $errors += "Row ${rowNum}: DLPRule 'add' requires Policy and LabelCode"
        }
        if ($comp -eq "DLPRule" -and $action -eq "update" -and -not $row.LabelCode.Trim()) {
            $errors += "Row ${rowNum}: DLPRule 'update' requires LabelCode"
        }
    }
    if ($errors.Count -gt 0) {
        Write-Error "CSV validation failed:`n  $($errors -join "`n  ")"
        return
    }
    #endregion

    # Filter out skip rows
    $actionableChanges = @($changes | Where-Object { $_.Action.Trim().ToLower() -ne "skip" })
    $skipCount = $changes.Count - $actionableChanges.Count

    $actionCounts = $actionableChanges | Group-Object { $_.Action.Trim().ToLower() }
    Write-Host "  Loaded $($changes.Count) row(s) from $(Split-Path $CsvPath -Leaf) [multi-component]:" -ForegroundColor Gray
    foreach ($grp in $actionCounts) {
        Write-Host "    $($grp.Name): $($grp.Count)" -ForegroundColor Gray
    }
    if ($skipCount -gt 0) {
        Write-Host "    skip: $skipCount (ignored)" -ForegroundColor DarkGray
    }

    if ($actionableChanges.Count -eq 0) {
        Write-Host "  No actionable changes. Nothing to do." -ForegroundColor Yellow
        try { Stop-Transcript } catch { }
        return
    }

    #region New Mode Config Loading
    $needsConfig = $actionableChanges | Where-Object { $_.Action.Trim().ToLower() -in @("add", "update") }

    $Config       = $null
    $Defaults     = $null
    $LabelsJson   = $null
    $LabelMap     = $null
    $RegistryJson = $null
    $RegistryMap  = $null
    $PoliciesJson = $null
    $Policies     = $null
    $Classifiers  = $null
    $Overrides    = $null

    if ($needsConfig.Count -gt 0) {
        Write-Host "`n=== Loading Config (for add/update) ===" -ForegroundColor Cyan

        $Defaults = Get-ModuleDefaults
        $settingsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
        $Config = Merge-GlobalConfig -Defaults $Defaults -GlobalJson $settingsJson

        # Labels config (for Label add/update)
        $hasLabelAddUpdate = $needsConfig | Where-Object { $_.Component.Trim() -eq "Label" }
        if ($hasLabelAddUpdate) {
            $LabelsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "labels.json") -Description "label definitions"
            if ($LabelsJson) {
                $LabelMap = @{}
                foreach ($l in $LabelsJson) { $LabelMap[$l.name] = $l }
                Write-Host "  Loaded $($LabelsJson.Count) label definitions" -ForegroundColor Gray
            }
        }

        # SIT Package registry (for SITPackage add/update)
        $hasPkgAddUpdate = $needsConfig | Where-Object { $_.Component.Trim() -eq "SITPackage" }
        if ($hasPkgAddUpdate) {
            $RegistryJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "classifiers-registry.json") -Description "classifier registry"
            if ($RegistryJson) {
                $RegistryMap = @{}
                foreach ($pkg in $RegistryJson.packages) {
                    if ($pkg.enabled) { $RegistryMap[$pkg.key] = $pkg }
                }
                Write-Host "  Loaded $($RegistryMap.Count) package definitions" -ForegroundColor Gray
            }
        }

        # Policy config (for DLPPolicy add)
        $hasPolicyAdd = $needsConfig | Where-Object { $_.Component.Trim() -eq "DLPPolicy" }
        if ($hasPolicyAdd) {
            $PoliciesJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "policies.json") -Description "policy definitions"
            if ($PoliciesJson) {
                $Policies = Resolve-PolicyConfig -PoliciesJson $PoliciesJson
                Write-Host "  Loaded $($Policies.Count) policy definitions" -ForegroundColor Gray
            }
        }

        # DLP Rule config (for DLPRule add/update)
        $hasRuleAddUpdate = $needsConfig | Where-Object { $_.Component.Trim() -eq "DLPRule" }
        if ($hasRuleAddUpdate) {
            $classifiersJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "classifiers.json") -Description "classifier definitions"
            if ($classifiersJson) {
                $Classifiers = Resolve-ClassifierConfig -ClassifiersJson $classifiersJson -Defaults $Defaults
                Write-Host "  Loaded $($Classifiers.Count) label classifiers" -ForegroundColor Gray
            }
            if (-not $Policies) {
                $PoliciesJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "policies.json") -Description "policy definitions"
                if ($PoliciesJson) { $Policies = Resolve-PolicyConfig -PoliciesJson $PoliciesJson }
            }
            $overridesJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "rule-overrides.json") -Description "rule overrides"
            $Overrides = Resolve-RuleOverrides -OverridesJson $overridesJson
        }
    }
    #endregion

    #region New Mode Processing
    Write-Host "`n=== Processing Changes ===" -ForegroundColor Cyan

    # Sort by component processing order: Labels -> SITPackages -> DLPPolicies -> DLPRules
    $componentOrder = @{ "Label" = 1; "SITPackage" = 2; "DLPPolicy" = 3; "DLPRule" = 4 }
    $sortedChanges = $actionableChanges | Sort-Object { $componentOrder[$_.Component.Trim()] }

    $index    = 0
    $total    = $sortedChanges.Count
    $parentGuids = @{}  # Track label parent GUIDs for sublabel creation

    foreach ($row in $sortedChanges) {
        $comp      = $row.Component.Trim()
        $action    = $row.Action.Trim().ToLower()
        $identity  = $row.Identity.Trim()
        $policy    = if ($row.PSObject.Properties.Name -contains "Policy") { $row.Policy.Trim() } else { "" }
        $labelCode = if ($row.PSObject.Properties.Name -contains "LabelCode") { $row.LabelCode.Trim() } else { "" }

        if ($index -gt 0 -and -not $WhatIfPreference) { Start-Sleep -Seconds $DelaySec }
        $index++
        $tag = "[$index/$total]"

        switch ($comp) {

            "Label" {
                switch ($action) {
                    "add" {
                        $labelDef = if ($LabelMap) { $LabelMap[$identity] } else { $null }
                        if (-not $labelDef) {
                            Write-Warning "  $tag SKIP    Label '$identity' - not found in labels.json"
                            $results.skipped++
                            continue
                        }

                        # Build label params (mirrors Deploy-Labels.ps1)
                        $labelParams = @{
                            DisplayName = $labelDef.displayName
                            Tooltip     = $labelDef.tooltip
                            Comment     = "$($Config.namingPrefix) label deployed $(Get-Date -Format 'yyyy-MM-dd'). Priority: $($labelDef.priority)."
                        }
                        if ($labelDef.isGroup) {
                            $labelParams["IsLabelGroup"] = $true
                        } else {
                            $labelParams["ContentType"] = "File, Email"
                        }
                        if ($labelDef.parentGroup) {
                            if ($parentGuids.ContainsKey($labelDef.parentGroup)) {
                                $labelParams["ParentId"] = $parentGuids[$labelDef.parentGroup]
                            } else {
                                try {
                                    $parentLabel = Get-Label -Identity $labelDef.parentGroup -ErrorAction Stop
                                    $labelParams["ParentId"] = $parentLabel.Guid.ToString()
                                    $parentGuids[$labelDef.parentGroup] = $parentLabel.Guid.ToString()
                                } catch {
                                    Write-Warning "  $tag FAILED  Label '$identity' - parent '$($labelDef.parentGroup)' not found"
                                    $results.failed++
                                    continue
                                }
                            }
                        }
                        $advancedSettings = @{}
                        if ($labelDef.colour) { $advancedSettings["color"] = $labelDef.colour }
                        if ($labelDef.headerText) {
                            $labelParams["ApplyContentMarkingHeaderEnabled"]   = $true
                            $labelParams["ApplyContentMarkingHeaderText"]      = $labelDef.headerText
                            $labelParams["ApplyContentMarkingHeaderFontSize"]  = 10
                            $labelParams["ApplyContentMarkingHeaderAlignment"] = "Center"
                            if ($labelDef.colour) { $labelParams["ApplyContentMarkingHeaderFontColor"] = $labelDef.colour }
                        }
                        if ($labelDef.footerText) {
                            $labelParams["ApplyContentMarkingFooterEnabled"]   = $true
                            $labelParams["ApplyContentMarkingFooterText"]      = $labelDef.footerText
                            $labelParams["ApplyContentMarkingFooterFontSize"]  = 8
                            $labelParams["ApplyContentMarkingFooterAlignment"] = "Center"
                            if ($labelDef.colour) { $labelParams["ApplyContentMarkingFooterFontColor"] = $labelDef.colour }
                        }

                        $createParams = @{ Name = $identity }
                        foreach ($key in $labelParams.Keys) { $createParams[$key] = $labelParams[$key] }
                        if ($advancedSettings.Count -gt 0) { $createParams["AdvancedSettings"] = $advancedSettings }

                        if ($PSCmdlet.ShouldProcess($identity, "New-Label")) {
                            try {
                                Invoke-WithRetry -OperationName "Add Label $identity" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                                    $newLabel = New-Label @createParams -ErrorAction Stop
                                    $script:parentGuids[$identity] = $newLabel.Guid.ToString()
                                }
                                Write-Host "  $tag ADD     Label: $identity" -ForegroundColor Green
                                $results.success++
                            } catch {
                                Write-Warning "  $tag FAILED  Label: $identity -- $($_.Exception.Message)"
                                $results.failed++
                            }
                        } else { $results.skipped++ }
                    }

                    "update" {
                        $labelDef = if ($LabelMap) { $LabelMap[$identity] } else { $null }
                        if (-not $labelDef) {
                            Write-Warning "  $tag SKIP    Label '$identity' - not found in labels.json"
                            $results.skipped++
                            continue
                        }

                        $updateParams = @{
                            Identity    = $identity
                            DisplayName = $labelDef.displayName
                            Tooltip     = $labelDef.tooltip
                            Comment     = "$($Config.namingPrefix) label deployed $(Get-Date -Format 'yyyy-MM-dd'). Priority: $($labelDef.priority)."
                        }
                        if ($labelDef.headerText) {
                            $updateParams["ApplyContentMarkingHeaderEnabled"]   = $true
                            $updateParams["ApplyContentMarkingHeaderText"]      = $labelDef.headerText
                            $updateParams["ApplyContentMarkingHeaderFontSize"]  = 10
                            $updateParams["ApplyContentMarkingHeaderAlignment"] = "Center"
                            if ($labelDef.colour) { $updateParams["ApplyContentMarkingHeaderFontColor"] = $labelDef.colour }
                        }
                        if ($labelDef.footerText) {
                            $updateParams["ApplyContentMarkingFooterEnabled"]   = $true
                            $updateParams["ApplyContentMarkingFooterText"]      = $labelDef.footerText
                            $updateParams["ApplyContentMarkingFooterFontSize"]  = 8
                            $updateParams["ApplyContentMarkingFooterAlignment"] = "Center"
                            if ($labelDef.colour) { $updateParams["ApplyContentMarkingFooterFontColor"] = $labelDef.colour }
                        }
                        $advancedSettings = @{}
                        if ($labelDef.colour) { $advancedSettings["color"] = $labelDef.colour }
                        if ($advancedSettings.Count -gt 0) { $updateParams["AdvancedSettings"] = $advancedSettings }

                        if ($PSCmdlet.ShouldProcess($identity, "Set-Label")) {
                            try {
                                Invoke-WithRetry -OperationName "Update Label $identity" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                                    Set-Label @updateParams -ErrorAction Stop
                                }
                                Write-Host "  $tag UPDATE  Label: $identity" -ForegroundColor Green
                                $results.success++
                            } catch {
                                Write-Warning "  $tag FAILED  Label: $identity -- $($_.Exception.Message)"
                                $results.failed++
                            }
                        } else { $results.skipped++ }
                    }

                    "delete" {
                        if ($PSCmdlet.ShouldProcess($identity, "Remove-Label")) {
                            try {
                                Invoke-WithRetry -OperationName "Delete Label $identity" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                                    Remove-Label -Identity $identity -Confirm:$false -ErrorAction Stop
                                }
                                Write-Host "  $tag DELETE  Label: $identity" -ForegroundColor Green
                                $results.success++
                            } catch {
                                Write-Warning "  $tag FAILED  Label: $identity -- $($_.Exception.Message)"
                                $results.failed++
                            }
                        } else { $results.skipped++ }
                    }
                }
            }

            "SITPackage" {
                switch ($action) {
                    "add" {
                        $pkgDef = if ($RegistryMap) { $RegistryMap[$identity] } else { $null }
                        if (-not $pkgDef) {
                            Write-Warning "  $tag SKIP    SITPackage '$identity' - not found in registry"
                            $results.skipped++
                            continue
                        }

                        # Resolve XML file path
                        $tier = $Config.deploymentTier
                        $variants = @{}
                        foreach ($prop in $pkgDef.variants.PSObject.Properties) { $variants[$prop.Name] = $prop.Value }
                        $xmlFile = $null
                        if ($variants.ContainsKey($tier))  { $xmlFile = Join-Path $XmlDir $variants[$tier] }
                        elseif ($variants.ContainsKey("full")) { $xmlFile = Join-Path $XmlDir $variants["full"] }
                        else { $firstKey = $variants.Keys | Select-Object -First 1; if ($firstKey) { $xmlFile = Join-Path $XmlDir $variants[$firstKey] } }

                        if (-not $xmlFile -or -not (Test-Path $xmlFile)) {
                            Write-Warning "  $tag FAILED  SITPackage '$identity' - XML file not found: $xmlFile"
                            $results.failed++
                            continue
                        }

                        if ($PSCmdlet.ShouldProcess($identity, "New-DlpSensitiveInformationTypeRulePackage")) {
                            try {
                                $fileData = [System.IO.File]::ReadAllBytes($xmlFile)
                                Invoke-WithRetry -OperationName "Add SITPackage $identity" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                                    New-DlpSensitiveInformationTypeRulePackage -FileData $fileData -ErrorAction Stop
                                }
                                Write-Host "  $tag ADD     SITPackage: $identity" -ForegroundColor Green
                                $results.success++
                            } catch {
                                Write-Warning "  $tag FAILED  SITPackage: $identity -- $($_.Exception.Message)"
                                $results.failed++
                            }
                        } else { $results.skipped++ }
                    }

                    "update" {
                        $pkgDef = if ($RegistryMap) { $RegistryMap[$identity] } else { $null }
                        if (-not $pkgDef) {
                            Write-Warning "  $tag SKIP    SITPackage '$identity' - not found in registry"
                            $results.skipped++
                            continue
                        }

                        $tier = $Config.deploymentTier
                        $variants = @{}
                        foreach ($prop in $pkgDef.variants.PSObject.Properties) { $variants[$prop.Name] = $prop.Value }
                        $xmlFile = $null
                        if ($variants.ContainsKey($tier))  { $xmlFile = Join-Path $XmlDir $variants[$tier] }
                        elseif ($variants.ContainsKey("full")) { $xmlFile = Join-Path $XmlDir $variants["full"] }
                        else { $firstKey = $variants.Keys | Select-Object -First 1; if ($firstKey) { $xmlFile = Join-Path $XmlDir $variants[$firstKey] } }

                        if (-not $xmlFile -or -not (Test-Path $xmlFile)) {
                            Write-Warning "  $tag FAILED  SITPackage '$identity' - XML file not found: $xmlFile"
                            $results.failed++
                            continue
                        }

                        # Resolve identity for Set cmdlet — use rulePackId from registry
                        $pkgIdentity = $pkgDef.rulePackId
                        if (-not $pkgIdentity) {
                            # Fallback: query deployed packages to find by displayName
                            try {
                                $deployed = Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop | Where-Object { $_.Name -eq $pkgDef.displayName }
                                if ($deployed) { $pkgIdentity = $deployed.Identity }
                            } catch {}
                        }
                        if (-not $pkgIdentity) {
                            Write-Warning "  $tag FAILED  SITPackage '$identity' - cannot resolve deployed identity"
                            $results.failed++
                            continue
                        }

                        if ($PSCmdlet.ShouldProcess($identity, "Set-DlpSensitiveInformationTypeRulePackage")) {
                            try {
                                $fileData = [System.IO.File]::ReadAllBytes($xmlFile)
                                Invoke-WithRetry -OperationName "Update SITPackage $identity" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                                    Set-DlpSensitiveInformationTypeRulePackage -Identity $pkgIdentity -FileData $fileData -ErrorAction Stop
                                }
                                Write-Host "  $tag UPDATE  SITPackage: $identity" -ForegroundColor Green
                                $results.success++
                            } catch {
                                Write-Warning "  $tag FAILED  SITPackage: $identity -- $($_.Exception.Message)"
                                $results.failed++
                            }
                        } else { $results.skipped++ }
                    }

                    "delete" {
                        # Identity may be the rulePackId or the package key
                        $deleteIdentity = $identity
                        if ($RegistryMap -and $RegistryMap.ContainsKey($identity) -and $RegistryMap[$identity].rulePackId) {
                            $deleteIdentity = $RegistryMap[$identity].rulePackId
                        }

                        if ($PSCmdlet.ShouldProcess($identity, "Remove-DlpSensitiveInformationTypeRulePackage")) {
                            try {
                                Invoke-WithRetry -OperationName "Delete SITPackage $identity" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                                    Remove-DlpSensitiveInformationTypeRulePackage -Identity $deleteIdentity -Confirm:$false -ErrorAction Stop
                                }
                                Write-Host "  $tag DELETE  SITPackage: $identity" -ForegroundColor Green
                                $results.success++
                            } catch {
                                Write-Warning "  $tag FAILED  SITPackage: $identity -- $($_.Exception.Message)"
                                $results.failed++
                            }
                        } else { $results.skipped++ }
                    }
                }
            }

            "DLPPolicy" {
                switch ($action) {
                    "add" {
                        # Find matching policy definition by generated name
                        $policyDef = $null
                        if ($Policies -and $Config) {
                            foreach ($p in $Policies) {
                                $expectedName = Get-PolicyName -PolicyNumber $p.Number -PolicyCode $p.Code -Prefix $Config.namingPrefix -Suffix $Config.namingSuffix
                                if ($expectedName -eq $identity) {
                                    $policyDef = $p
                                    break
                                }
                            }
                        }
                        if (-not $policyDef) {
                            Write-Warning "  $tag SKIP    DLPPolicy '$identity' - no matching policy in config"
                            $results.skipped++
                            continue
                        }

                        $policyMode = Resolve-PolicyMode -AuditMode $Config.auditMode -NotifyUser $Config.notifyUser
                        $policyParams = @{
                            Name    = $identity
                            Comment = $policyDef.Comment
                            Mode    = $policyMode
                        }
                        foreach ($locKey in $policyDef.Location.Keys) {
                            $policyParams[$locKey] = $policyDef.Location[$locKey]
                        }

                        if ($PSCmdlet.ShouldProcess($identity, "New-DlpCompliancePolicy")) {
                            try {
                                Invoke-WithRetry -OperationName "Add Policy $identity" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                                    $null = New-DlpCompliancePolicy @policyParams -ErrorAction Stop
                                }
                                Write-Host "  $tag ADD     Policy: $identity" -ForegroundColor Green
                                $results.success++
                            } catch {
                                Write-Warning "  $tag FAILED  Policy: $identity -- $($_.Exception.Message)"
                                $results.failed++
                            }
                        } else { $results.skipped++ }
                    }

                    "delete" {
                        if ($PSCmdlet.ShouldProcess($identity, "Remove-DlpCompliancePolicy")) {
                            try {
                                Invoke-WithRetry -OperationName "Delete Policy $identity" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                                    Remove-DlpCompliancePolicy -Identity $identity -Confirm:$false -ErrorAction Stop
                                }
                                Write-Host "  $tag DELETE  Policy: $identity" -ForegroundColor Green
                                $results.success++
                            } catch {
                                Write-Warning "  $tag FAILED  Policy: $identity -- $($_.Exception.Message)"
                                $results.failed++
                            }
                        } else { $results.skipped++ }
                    }
                }
            }

            "DLPRule" {
                switch ($action) {

                    "delete" {
                        if ($PSCmdlet.ShouldProcess($identity, "Remove-DlpComplianceRule")) {
                            try {
                                Invoke-WithRetry -OperationName "Delete $identity" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                                    Remove-DlpComplianceRule -Identity $identity -Confirm:$false -ErrorAction Stop
                                }
                                Write-Host "  $tag DELETE  Rule: $identity" -ForegroundColor Green
                                $results.success++
                            } catch {
                                Write-Warning "  $tag FAILED  Rule: $identity -- $($_.Exception.Message)"
                                $results.failed++
                            }
                        } else { $results.skipped++ }
                    }

                    "add" {
                        if (-not $Classifiers -or -not $Classifiers.ContainsKey($labelCode)) {
                            Write-Warning "  $tag SKIP    Rule '$identity' - LabelCode '$labelCode' not in classifiers"
                            $results.skipped++
                            continue
                        }

                        $classifierList = $Classifiers[$labelCode]
                        # Handle chunk-suffixed rules (e.g., R02a) — use only the relevant chunk
                        if ($identity -match '-R\d{2}([a-z])-') {
                            $chunkLetter = $Matches[1]
                            $chunkIndex = [int][char]$chunkLetter - [int][char]'a'
                            $chunks = Split-ClassifierChunks -ClassifierList $classifierList -MaxPerRule 125
                            if ($chunkIndex -lt $chunks.Count) {
                                $classifierList = $chunks[$chunkIndex]
                            } else {
                                Write-Warning "  Chunk '$chunkLetter' out of range for $labelCode ($($chunks.Count) chunks). Using full list."
                            }
                        }
                        $scopeParam = $null
                        $scopeValue = $null
                        $policyCode = ""
                        if ($Policies -and $Config) {
                            foreach ($p in $Policies) {
                                $expectedName = Get-PolicyName -PolicyNumber $p.Number -PolicyCode $p.Code -Prefix $Config.namingPrefix -Suffix $Config.namingSuffix
                                if ($expectedName -eq $policy) {
                                    $scopeParam = $p.ScopeParam
                                    $scopeValue = $p.ScopeValue
                                    $policyCode = $p.Code
                                    break
                                }
                            }
                        }

                        $condition = New-DLPSITCondition -ClassifierList $classifierList -ScopeParam $scopeParam -ScopeValue $scopeValue
                        $ruleParams = @{
                            Name                = $identity
                            Policy              = $policy
                            Comment             = "$labelCode ($($classifierList.Count) classifiers)"
                            ReportSeverityLevel = "Low"
                            Disabled            = $false
                        }
                        if ($condition.Format -eq "AdvancedRule") {
                            $ruleParams["AdvancedRule"] = $condition.Value
                        } else {
                            $ruleParams["ContentContainsSensitiveInformation"] = $condition.Value
                            if ($scopeParam) { $ruleParams[$scopeParam] = $scopeValue }
                        }
                        if ($Overrides) {
                            $ruleParams = Get-MergedRuleParams -BaseParams $ruleParams -Overrides $Overrides -LabelCode $labelCode -PolicyCode $policyCode -RuleName $identity
                        }

                        if ($PSCmdlet.ShouldProcess($identity, "New-DlpComplianceRule")) {
                            try {
                                Invoke-WithRetry -OperationName "Add $identity" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                                    $null = New-DlpComplianceRule @ruleParams -ErrorAction Stop
                                }
                                Write-Host "  $tag ADD     Rule: $identity ($labelCode, $($classifierList.Count) classifiers)" -ForegroundColor Green
                                $results.success++
                            } catch {
                                Write-Warning "  $tag FAILED  Rule: $identity -- $($_.Exception.Message)"
                                $results.failed++
                            }
                        } else { $results.skipped++ }
                    }

                    "update" {
                        if (-not $Classifiers -or -not $Classifiers.ContainsKey($labelCode)) {
                            Write-Warning "  $tag SKIP    Rule '$identity' - LabelCode '$labelCode' not in classifiers"
                            $results.skipped++
                            continue
                        }

                        $classifierList = $Classifiers[$labelCode]
                        # Handle chunk-suffixed rules (e.g., R02a) — use only the relevant chunk
                        if ($identity -match '-R\d{2}([a-z])-') {
                            $chunkLetter = $Matches[1]
                            $chunkIndex = [int][char]$chunkLetter - [int][char]'a'
                            $chunks = Split-ClassifierChunks -ClassifierList $classifierList -MaxPerRule 125
                            if ($chunkIndex -lt $chunks.Count) {
                                $classifierList = $chunks[$chunkIndex]
                            } else {
                                Write-Warning "  Chunk '$chunkLetter' out of range for $labelCode ($($chunks.Count) chunks). Using full list."
                            }
                        }
                        $scopeParam = $null
                        $scopeValue = $null
                        if ($Policies -and $Config) {
                            foreach ($p in $Policies) {
                                $expectedName = Get-PolicyName -PolicyNumber $p.Number -PolicyCode $p.Code -Prefix $Config.namingPrefix -Suffix $Config.namingSuffix
                                if ($expectedName -eq $policy) {
                                    $scopeParam = $p.ScopeParam
                                    $scopeValue = $p.ScopeValue
                                    break
                                }
                            }
                        }

                        $condition = New-DLPSITCondition -ClassifierList $classifierList -ScopeParam $scopeParam -ScopeValue $scopeValue
                        $updateParams = @{
                            Identity = $identity
                            Comment  = "$labelCode ($($classifierList.Count) classifiers)"
                        }
                        if ($condition.Format -eq "AdvancedRule") {
                            $updateParams["AdvancedRule"] = $condition.Value
                        } else {
                            $updateParams["ContentContainsSensitiveInformation"] = $condition.Value
                        }

                        if ($PSCmdlet.ShouldProcess($identity, "Set-DlpComplianceRule")) {
                            try {
                                Invoke-WithRetry -OperationName "Update $identity" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                                    Set-DlpComplianceRule @updateParams -Confirm:$false -ErrorAction Stop
                                }
                                Write-Host "  $tag UPDATE  Rule: $identity ($labelCode, $($classifierList.Count) classifiers)" -ForegroundColor Green
                                $results.success++
                            } catch {
                                Write-Warning "  $tag FAILED  Rule: $identity -- $($_.Exception.Message)"
                                $results.failed++
                            }
                        } else { $results.skipped++ }
                    }

                    "disable" {
                        if ($PSCmdlet.ShouldProcess($identity, "Set-DlpComplianceRule -Disabled `$true")) {
                            try {
                                Invoke-WithRetry -OperationName "Disable $identity" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                                    Set-DlpComplianceRule -Identity $identity -Disabled $true -Confirm:$false -ErrorAction Stop
                                }
                                Write-Host "  $tag DISABLE Rule: $identity" -ForegroundColor Green
                                $results.success++
                            } catch {
                                Write-Warning "  $tag FAILED  Rule: $identity -- $($_.Exception.Message)"
                                $results.failed++
                            }
                        } else { $results.skipped++ }
                    }

                    "enable" {
                        if ($PSCmdlet.ShouldProcess($identity, "Set-DlpComplianceRule -Disabled `$false")) {
                            try {
                                Invoke-WithRetry -OperationName "Enable $identity" -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -ScriptBlock {
                                    Set-DlpComplianceRule -Identity $identity -Disabled $false -Confirm:$false -ErrorAction Stop
                                }
                                Write-Host "  $tag ENABLE  Rule: $identity" -ForegroundColor Green
                                $results.success++
                            } catch {
                                Write-Warning "  $tag FAILED  Rule: $identity -- $($_.Exception.Message)"
                                $results.failed++
                            }
                        } else { $results.skipped++ }
                    }
                }
            }
        }
    }
    #endregion
}

#region Summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "  Success: $($results.success)" -ForegroundColor Green
if ($results.failed -gt 0) {
    Write-Host "  Failed:  $($results.failed)" -ForegroundColor Red
}
if ($results.skipped -gt 0) {
    Write-Host "  Skipped: $($results.skipped)" -ForegroundColor Yellow
}
Write-Host "  Total:   $($changes.Count)" -ForegroundColor Gray

try { Stop-Transcript } catch { }

exit $(if ($results.failed -eq 0) { 0 } else { 1 })
#endregion
