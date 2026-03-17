#==============================================================================
# Generate-ChangePack.ps1
# Diffs tenant state against local config to produce a CSV change pack.
# Covers Labels, SIT Packages, DLP Policies, and DLP Rules.
#
# CSV Format:
#   Component,Action,Identity,Policy,LabelCode,Detail
#
# Usage:
#   .\scripts\Generate-ChangePack.ps1 -Connect
#   .\scripts\Generate-ChangePack.ps1 -Components Labels -Connect
#   .\scripts\Generate-ChangePack.ps1 -Components Rules,Classifiers -Connect
#   .\scripts\Generate-ChangePack.ps1 -Connect -WhatIf   # show diff, don't write file
#==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("All", "Labels", "Classifiers", "Rules")]
    [string[]]$Components = @("All"),
    [string]$OutputPath,
    [switch]$Connect,
    [string]$UPN
)

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "config"
$XmlDir      = Join-Path $ProjectRoot "xml"

Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

$ErrorActionPreference = "Stop"

# Resolve component selection
$doLabels      = $Components -contains "All" -or $Components -contains "Labels"
$doClassifiers = $Components -contains "All" -or $Components -contains "Classifiers"
$doRules       = $Components -contains "All" -or $Components -contains "Rules"

#region Connection
if ($Connect) {
    $connected = Connect-DLPSession -UPN $UPN
    if (-not $connected) { return }
}

if (-not (Assert-DLPSession)) { return }
#endregion

#region Logging
$null = Start-DeploymentLog -ScriptName "Generate-ChangePack"
#endregion

#region Load Config
Write-Host "`n=== Loading Configuration ===" -ForegroundColor Cyan

$Defaults     = Get-ModuleDefaults
$settingsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
$Config       = Merge-GlobalConfig -Defaults $Defaults -GlobalJson $settingsJson

$labelsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "labels.json") -Description "label definitions"
if (-not $labelsJson) {
    Write-Error "Failed to load labels.json. Aborting."
    return
}

$Classifiers = $null
if ($doRules) {
    $classifiersJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "classifiers.json") -Description "classifier definitions"
    if ($classifiersJson) {
        $Classifiers = Resolve-ClassifierConfig -ClassifiersJson $classifiersJson -Defaults $Defaults
    }
}

$Policies = $null
if ($doRules) {
    $policiesJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "policies.json") -Description "policy definitions"
    if ($policiesJson) {
        $Policies = Resolve-PolicyConfig -PoliciesJson $policiesJson
    }
}

$registryJson = $null
if ($doClassifiers) {
    $registryJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "classifiers-registry.json") -Description "classifier registry"
}

$Labels = Resolve-LabelConfig -LabelsJson $labelsJson
#endregion

#region Helpers
function Get-XmlPackageInfo {
    <# Parses a local SIT XML file for entity count and version string. #>
    param([string]$FilePath)
    $result = @{ EntityCount = -1; VersionStr = "(unknown)" }
    if (-not (Test-Path $FilePath)) { return $result }
    $xml = $null
    try {
        $content = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::Unicode)
        $xml = [xml]$content
    } catch {
        try { $xml = [xml](Get-Content $FilePath -Raw) } catch { return $result }
    }
    $rp = $xml.RulePackage.RulePack
    if ($rp -and $rp.Version) {
        $v = $rp.Version
        $result.VersionStr = "$($v.major).$($v.minor).$($v.build).$($v.revision)"
    }
    $rules = $xml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq "Rules" }
    if ($rules) {
        $result.EntityCount = @($rules.ChildNodes | Where-Object { $_.LocalName -eq "Entity" }).Count
    }
    return $result
}

function Get-DeployedPkgInfo {
    <# Parses a deployed SIT package for entity count and version string. #>
    param([object]$Package)
    $result = @{ EntityCount = -1; VersionStr = "(unknown)" }
    if (-not $Package.SerializedClassificationRuleCollection) { return $result }
    try {
        $bytes = $Package.SerializedClassificationRuleCollection
        $xmlContent = [System.Text.Encoding]::Unicode.GetString($bytes)
        $xml = [xml]$xmlContent
        $rp = $xml.RulePackage.RulePack
        if ($rp -and $rp.Version) {
            $v = $rp.Version
            $result.VersionStr = "$($v.major).$($v.minor).$($v.build).$($v.revision)"
        }
        $rules = $xml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq "Rules" }
        if ($rules) {
            $result.EntityCount = @($rules.ChildNodes | Where-Object { $_.LocalName -eq "Entity" }).Count
        }
    } catch {}
    return $result
}

function Resolve-RegistryFile {
    <# Resolves the XML file path for a registry package given the deployment tier. #>
    param([object]$Package, [string]$Tier)
    $variants = @{}
    foreach ($prop in $Package.variants.PSObject.Properties) {
        $variants[$prop.Name] = $prop.Value
    }
    if ($variants.ContainsKey($Tier))   { return Join-Path $XmlDir $variants[$Tier] }
    if ($variants.ContainsKey("full"))  { return Join-Path $XmlDir $variants["full"] }
    $firstKey = $variants.Keys | Select-Object -First 1
    if ($firstKey) { return Join-Path $XmlDir $variants[$firstKey] }
    return $null
}

function Add-Row {
    param([string]$Component, [string]$Action, [string]$Identity,
          [string]$Policy = "", [string]$LabelCode = "", [string]$Detail = "")
    $script:rows.Add([PSCustomObject]@{
        Component = $Component
        Action    = $Action
        Identity  = $Identity
        Policy    = $Policy
        LabelCode = $LabelCode
        Detail    = $Detail
    })
}
#endregion

$rows = [System.Collections.Generic.List[PSCustomObject]]::new()

#region Labels Diff
if ($doLabels) {
    Write-Host "`n=== Diffing Labels ===" -ForegroundColor Cyan

    $tenantLabels = @(Get-Label -ErrorAction Stop)
    $tenantLabelMap = @{}
    foreach ($tl in $tenantLabels) { $tenantLabelMap[$tl.Name] = $tl }

    $configLabelNames = @{}

    # Process in priority order (parents before children)
    $sortedLabels = $labelsJson | Sort-Object { $_.priority }
    foreach ($label in $sortedLabels) {
        $configLabelNames[$label.name] = $true
        $deployed = $tenantLabelMap[$label.name]
        $lc = if ($label.code) { $label.code } else { "" }

        if (-not $deployed) {
            $kind = if ($label.isGroup) { "label group" } else { "label" }
            Add-Row -Component "Label" -Action "add" -Identity $label.name -LabelCode $lc -Detail "New $kind"
            Write-Host "  ADD    $($label.name)" -ForegroundColor Green
        } else {
            # Compare key properties
            $diffs = @()
            if ($deployed.DisplayName -ne $label.displayName) { $diffs += "displayName" }
            if ($deployed.Tooltip -ne $label.tooltip)         { $diffs += "tooltip" }
            if (-not $label.isGroup) {
                if ($label.headerText -and $deployed.ApplyContentMarkingHeaderText -ne $label.headerText) { $diffs += "headerText" }
                if ($label.footerText -and $deployed.ApplyContentMarkingFooterText -ne $label.footerText) { $diffs += "footerText" }
            }

            if ($diffs.Count -gt 0) {
                Add-Row -Component "Label" -Action "update" -Identity $label.name -LabelCode $lc -Detail "Changed: $($diffs -join ', ')"
                Write-Host "  UPDATE $($label.name) - $($diffs -join ', ')" -ForegroundColor Yellow
            } else {
                Add-Row -Component "Label" -Action "skip" -Identity $label.name -LabelCode $lc -Detail "Matches config"
                Write-Host "  SKIP   $($label.name)" -ForegroundColor Gray
            }
        }
    }

    # Detect deployed labels not in current config (by comment marker matching naming prefix)
    foreach ($tl in $tenantLabels) {
        if (-not $configLabelNames.ContainsKey($tl.Name) -and $tl.Comment -match [regex]::Escape($Config.namingPrefix)) {
            Add-Row -Component "Label" -Action "delete" -Identity $tl.Name -Detail "Deployed $($Config.namingPrefix) label not in config"
            Write-Host "  DELETE $($tl.Name) - not in config" -ForegroundColor Red
        }
    }
}
#endregion

#region SIT Packages Diff
if ($doClassifiers -and $registryJson) {
    Write-Host "`n=== Diffing SIT Packages ===" -ForegroundColor Cyan

    $deployedPkgs = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)

    # Build lookup by identity (rulePackId) and by displayName
    $deployedById   = @{}
    $deployedByName = @{}
    foreach ($dp in $deployedPkgs) {
        if ($dp.Identity) { $deployedById[$dp.Identity.ToLower()] = $dp }
        if ($dp.Name)     { $deployedByName[$dp.Name] = $dp }
    }

    $registryIds   = @{}
    $registryNames = @{}

    foreach ($pkg in $registryJson.packages) {
        if (-not $pkg.enabled) { continue }

        $registryNames[$pkg.displayName] = $true
        if ($pkg.rulePackId) { $registryIds[$pkg.rulePackId.ToLower()] = $true }

        # Find deployed match
        $deployed = $null
        if ($pkg.rulePackId) { $deployed = $deployedById[$pkg.rulePackId.ToLower()] }
        if (-not $deployed)  { $deployed = $deployedByName[$pkg.displayName] }

        if (-not $deployed) {
            # Not deployed — resolve local file for entity count note
            $localFile = Resolve-RegistryFile -Package $pkg -Tier $Config.deploymentTier
            $localInfo = if ($localFile) { Get-XmlPackageInfo -FilePath $localFile } else { @{ EntityCount = -1 } }
            $entityNote = if ($localInfo.EntityCount -ge 0) { " ($($localInfo.EntityCount) entities)" } else { "" }
            Add-Row -Component "SITPackage" -Action "add" -Identity $pkg.key -Detail "New package${entityNote}"
            Write-Host "  ADD    $($pkg.key) - $($pkg.displayName)$entityNote" -ForegroundColor Green
        } else {
            # Deployed — compare entity count and version
            $depInfo = Get-DeployedPkgInfo -Package $deployed
            $localFile = Resolve-RegistryFile -Package $pkg -Tier $Config.deploymentTier
            $localInfo = if ($localFile) { Get-XmlPackageInfo -FilePath $localFile } else { @{ EntityCount = -1; VersionStr = "(unknown)" } }

            $diffs = @()
            if ($localInfo.EntityCount -ge 0 -and $depInfo.EntityCount -ge 0 -and $localInfo.EntityCount -ne $depInfo.EntityCount) {
                $diffs += "entities: $($depInfo.EntityCount)->$($localInfo.EntityCount)"
            }
            if ($localInfo.VersionStr -ne "(unknown)" -and $depInfo.VersionStr -ne "(unknown)" -and $localInfo.VersionStr -ne $depInfo.VersionStr) {
                $diffs += "version: $($depInfo.VersionStr)->$($localInfo.VersionStr)"
            }

            if ($diffs.Count -gt 0) {
                Add-Row -Component "SITPackage" -Action "update" -Identity $pkg.key -Detail ($diffs -join "; ")
                Write-Host "  UPDATE $($pkg.key) - $($diffs -join '; ')" -ForegroundColor Yellow
            } else {
                Add-Row -Component "SITPackage" -Action "skip" -Identity $pkg.key -Detail "Matches deployed (v$($depInfo.VersionStr), $($depInfo.EntityCount) entities)"
                Write-Host "  SKIP   $($pkg.key)" -ForegroundColor Gray
            }
        }
    }

    # Detect deployed custom packages not in registry (skip Microsoft built-in)
    foreach ($dp in $deployedPkgs) {
        $idMatch   = $dp.Identity -and $registryIds.ContainsKey($dp.Identity.ToLower())
        $nameMatch = $dp.Name -and $registryNames.ContainsKey($dp.Name)
        if (-not $idMatch -and -not $nameMatch -and $dp.Publisher -ne "Microsoft Corporation") {
            $ident = if ($dp.Identity) { $dp.Identity } else { $dp.Name }
            Add-Row -Component "SITPackage" -Action "delete" -Identity $ident -Detail "Custom package not in registry: $($dp.Name)"
            Write-Host "  DELETE $($dp.Name) - not in registry" -ForegroundColor Red
        }
    }
}
#endregion

#region DLP Rules Diff
if ($doRules -and $Policies -and $Classifiers) {
    Write-Host "`n=== Diffing DLP Rules ===" -ForegroundColor Cyan

    # Build expected policy and rule names
    $expectedPolicies = [ordered]@{}
    $expectedRuleSet  = @{}

    foreach ($policy in $Policies) {
        $policyName = Get-PolicyName -PolicyNumber $policy.Number -PolicyCode $policy.Code -Prefix $Config.namingPrefix -Suffix $Config.namingSuffix
        $expectedPolicies[$policyName] = $policy

        $ruleNum = 0
        foreach ($label in $Labels) {
            $ruleNum++
            $labelCode = $label.code
            $classifierList = $Classifiers[$labelCode]
            $chunks = @(Split-ClassifierChunks -ClassifierList $classifierList -MaxPerRule 125)

            $chunkIndex = 0
            foreach ($chunk in $chunks) {
                $chunkIndex++
                if ($chunks.Count -gt 1) {
                    $chunkLetter = [char]([int][char]'a' + $chunkIndex - 1)
                    $ruleName = "P{0:D2}-R{1:D2}{2}-{3}-{4}-{5}" -f $policy.Number, $ruleNum, $chunkLetter, $policy.Code, $labelCode, $Config.namingSuffix
                } else {
                    $ruleName = Get-RuleName -PolicyNumber $policy.Number -RuleNumber $ruleNum -PolicyCode $policy.Code -LabelCode $labelCode -Suffix $Config.namingSuffix
                }
                $expectedRuleSet[$ruleName] = @{
                    PolicyName = $policyName
                    Policy     = $policy
                    Label      = $label
                    RuleNumber = $ruleNum
                    ChunkIndex = $chunkIndex
                    ChunkTotal = $chunks.Count
                    ClassCount = $chunk.Count
                }
            }
        }
    }

    # Query all DLP policies
    $tenantPolicies = @(Get-DlpCompliancePolicy -ErrorAction Stop)
    $tenantPolicyMap = @{}
    foreach ($tp in $tenantPolicies) { $tenantPolicyMap[$tp.Name] = $tp }

    # Process each expected policy
    foreach ($policyName in $expectedPolicies.Keys) {
        $policy = $expectedPolicies[$policyName]
        $deployedPolicy = $tenantPolicyMap[$policyName]

        if (-not $deployedPolicy) {
            # Policy missing — add policy row + all rule rows
            Add-Row -Component "DLPPolicy" -Action "add" -Identity $policyName -Detail "New policy: $($policy.Comment)"
            Write-Host "  ADD POLICY $policyName" -ForegroundColor Green

            $ruleNum = 0
            foreach ($label in $Labels) {
                $ruleNum++
                $labelCode = $label.code
                $classifierList = $Classifiers[$labelCode]
                $chunks = @(Split-ClassifierChunks -ClassifierList $classifierList -MaxPerRule 125)

                $chunkIndex = 0
                foreach ($chunk in $chunks) {
                    $chunkIndex++
                    if ($chunks.Count -gt 1) {
                        $chunkLetter = [char]([int][char]'a' + $chunkIndex - 1)
                        $ruleName = "P{0:D2}-R{1:D2}{2}-{3}-{4}-{5}" -f $policy.Number, $ruleNum, $chunkLetter, $policy.Code, $labelCode, $Config.namingSuffix
                        $chunkNote = " [chunk $chunkIndex/$($chunks.Count)]"
                    } else {
                        $ruleName = Get-RuleName -PolicyNumber $policy.Number -RuleNumber $ruleNum -PolicyCode $policy.Code -LabelCode $labelCode -Suffix $Config.namingSuffix
                        $chunkNote = ""
                    }
                    Add-Row -Component "DLPRule" -Action "add" -Identity $ruleName -Policy $policyName -LabelCode $labelCode -Detail "New rule$chunkNote ($($chunk.Count) classifiers)"
                    Write-Host "  ADD    $ruleName ($($chunk.Count) classifiers)" -ForegroundColor Green
                }
            }
        } else {
            # Policy exists — diff each rule
            $deployedRules = @(Get-DlpComplianceRule -Policy $policyName -ErrorAction SilentlyContinue)
            $deployedRuleMap = @{}
            foreach ($dr in $deployedRules) { $deployedRuleMap[$dr.Name] = $dr }

            $ruleNum = 0
            foreach ($label in $Labels) {
                $ruleNum++
                $labelCode = $label.code
                $classifierList = $Classifiers[$labelCode]
                $chunks = @(Split-ClassifierChunks -ClassifierList $classifierList -MaxPerRule 125)

                $chunkIndex = 0
                foreach ($chunk in $chunks) {
                    $chunkIndex++
                    if ($chunks.Count -gt 1) {
                        $chunkLetter = [char]([int][char]'a' + $chunkIndex - 1)
                        $ruleName = "P{0:D2}-R{1:D2}{2}-{3}-{4}-{5}" -f $policy.Number, $ruleNum, $chunkLetter, $policy.Code, $labelCode, $Config.namingSuffix
                    } else {
                        $ruleName = Get-RuleName -PolicyNumber $policy.Number -RuleNumber $ruleNum -PolicyCode $policy.Code -LabelCode $labelCode -Suffix $Config.namingSuffix
                    }
                    $classCount = $chunk.Count
                    $deployed   = $deployedRuleMap[$ruleName]

                    if (-not $deployed) {
                        Add-Row -Component "DLPRule" -Action "add" -Identity $ruleName -Policy $policyName -LabelCode $labelCode -Detail "New rule ($classCount classifiers)"
                        Write-Host "  ADD    $ruleName ($classCount classifiers)" -ForegroundColor Green
                    } else {
                        # Compare classifier count from Comment field
                        $deployedCount = -1
                        if ($deployed.Comment -match '\((\d+) classifiers?\)') {
                            $deployedCount = [int]$Matches[1]
                        }

                        if ($deployedCount -ge 0 -and $deployedCount -ne $classCount) {
                            Add-Row -Component "DLPRule" -Action "update" -Identity $ruleName -Policy $policyName -LabelCode $labelCode -Detail "Classifiers: $deployedCount->$classCount"
                            Write-Host "  UPDATE $ruleName - classifiers: $deployedCount->$classCount" -ForegroundColor Yellow
                        } elseif ($deployedCount -lt 0) {
                            Add-Row -Component "DLPRule" -Action "skip" -Identity $ruleName -Policy $policyName -LabelCode $labelCode -Detail "Comment not parseable - review manually"
                            Write-Host "  SKIP   $ruleName (comment not parseable)" -ForegroundColor DarkYellow
                        } else {
                            Add-Row -Component "DLPRule" -Action "skip" -Identity $ruleName -Policy $policyName -LabelCode $labelCode -Detail "Matches ($classCount classifiers)"
                            Write-Host "  SKIP   $ruleName" -ForegroundColor Gray
                        }

                        $deployedRuleMap.Remove($ruleName)
                    }
                }
            }

            # Detect orphan rules matching our naming pattern
            $escapedCode   = [regex]::Escape($policy.Code)
            $escapedSuffix = [regex]::Escape($Config.namingSuffix)
            $namingPattern = "^P\d{2}-R\d{2}[a-z]?-${escapedCode}-\w+-${escapedSuffix}$"
            foreach ($orphanName in @($deployedRuleMap.Keys)) {
                if ($orphanName -match $namingPattern) {
                    Add-Row -Component "DLPRule" -Action "delete" -Identity $orphanName -Policy $policyName -Detail "Not in expected rule set"
                    Write-Host "  DELETE $orphanName - orphan" -ForegroundColor Red
                }
            }
        }
    }
}
#endregion

#region Summary & Output
Write-Host "`n=== Change Pack Summary ===" -ForegroundColor Cyan

$actionable = $rows | Where-Object { $_.Action -ne "skip" }
$grouped = $rows | Group-Object Action

foreach ($grp in ($grouped | Sort-Object Name)) {
    $color = switch ($grp.Name) {
        "add"    { "Green" }
        "update" { "Yellow" }
        "delete" { "Red" }
        "skip"   { "Gray" }
        default  { "White" }
    }
    Write-Host "  $($grp.Name): $($grp.Count)" -ForegroundColor $color
}
Write-Host "  Total: $($rows.Count) rows ($($actionable.Count) actionable)" -ForegroundColor White

if ($actionable.Count -eq 0) {
    Write-Host "`n  Tenant matches config. No changes needed." -ForegroundColor Green
    try { Stop-Transcript } catch { }
    return
}

# Resolve output path
if (-not $OutputPath) {
    $cpDir = Join-Path $ProjectRoot "changepacks"
    if (-not (Test-Path $cpDir)) { New-Item -ItemType Directory -Path $cpDir -Force | Out-Null }
    $OutputPath = Join-Path $cpDir "changepack-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
}

if ($PSCmdlet.ShouldProcess($OutputPath, "Export CSV ($($rows.Count) rows)")) {
    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n  Change pack written to: $OutputPath" -ForegroundColor Green
    Write-Host "  Review the CSV, then apply with:" -ForegroundColor Gray
    Write-Host "    .\scripts\Invoke-ChangePack.ps1 -CsvPath `"$OutputPath`" -WhatIf" -ForegroundColor Gray
} else {
    Write-Host "`n  Dry run complete. No file written." -ForegroundColor Yellow
}

try { Stop-Transcript } catch { }
#endregion
