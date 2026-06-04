#==============================================================================
# Reset-DeploymentScope.ps1
# Single-session reset workflow for repo-managed DLP rules/policies and
# classifier rule packages in Microsoft Purview.
#
# Usage:
#   .\scripts\Reset-DeploymentScope.ps1 -Action Plan -Tenant <tenant> -TargetEnvironment <environment>
#   .\scripts\Reset-DeploymentScope.ps1 -Action Execute -Tenant <tenant> -TargetEnvironment <environment>
#   .\scripts\Reset-DeploymentScope.ps1 -Action Execute -Tenant <tenant> -TargetEnvironment <environment> -Force
#   .\scripts\Reset-DeploymentScope.ps1 -Action WaitThenDryRun -Tenant <tenant> -TargetEnvironment <environment> -WaitHours 4
#==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("Plan", "Execute", "Verify", "WaitThenDryRun")]
    [string]$Action = "Plan",

    [string]$Tenant,
    [string]$TargetEnvironment,
    [string]$ScopeName,
    [string]$UPN,
    [switch]$Delegated,

    [string[]]$PolicyNames,
    [string[]]$ClassifierPackageNames = @("All"),
    [string]$ClassifierRegistryPath,
    [string]$ClassifierXmlDir,
    [ValidateSet("narrow", "wide", "full", "small", "medium", "large")]
    [string]$Tier,
    [switch]$IncludeUnregisteredXmlPackages,

    [int]$WaitHours = 4,
    [switch]$SkipWait,
    [switch]$RunDryRunAfterWait,
    [switch]$Force,
    [switch]$RegisterFingerprint,
    [switch]$AllowBreakingExternalClassifierReferences,
    [int]$InterCallDelaySec = -1
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath = Join-Path $ProjectRoot "config"
$XmlDeployPath = Join-Path (Join-Path $ProjectRoot "xml") "deploy"
if (-not $ClassifierXmlDir) {
    $ClassifierXmlDir = $XmlDeployPath
} elseif (-not [System.IO.Path]::IsPathRooted($ClassifierXmlDir)) {
    $ClassifierXmlDir = Join-Path $ProjectRoot $ClassifierXmlDir
}
if (-not $ClassifierRegistryPath) {
    $ClassifierRegistryPath = Join-Path $ClassifierXmlDir "deploy-registry.json"
} elseif (-not [System.IO.Path]::IsPathRooted($ClassifierRegistryPath)) {
    $ClassifierRegistryPath = Join-Path $ProjectRoot $ClassifierRegistryPath
}

Import-Module (Join-Path $ProjectRoot "modules\DLP-Deploy.psm1") -Force

function Connect-DeploymentResetSession {
    try {
        Get-DlpCompliancePolicy -ErrorAction Stop | Select-Object -First 1 | Out-Null
        Write-Host "  Reusing existing Security & Compliance session." -ForegroundColor Green
        return
    } catch {
        Write-Host "  No active Security & Compliance session detected." -ForegroundColor Yellow
    }

    $previousWhatIf = $WhatIfPreference
    try {
        $script:WhatIfPreference = $false
        $connected = Connect-DLPSession -UPN $UPN -Tenant $Tenant -Delegated:$Delegated
    } finally {
        $script:WhatIfPreference = $previousWhatIf
    }

    if (-not $connected) {
        throw "Could not connect to Security & Compliance Center."
    }
}

function Assert-DeploymentResetTenant {
    $fingerprint = Test-DeploymentTenantFingerprint -ProjectRoot $ProjectRoot -TargetEnvironment $TargetEnvironment -RegisterIfMissing:$RegisterFingerprint

    Write-Host "`n=== Tenant Fingerprint ===" -ForegroundColor Cyan
    Write-Host "  Environment: $($fingerprint.environment)" -ForegroundColor Gray
    Write-Host "  Mode:        $($fingerprint.mode)" -ForegroundColor Gray
    if ($fingerprint.actual.guid) {
        Write-Host "  Tenant GUID: $($fingerprint.actual.guid)" -ForegroundColor Gray
    }
    if ($fingerprint.actual.userPrincipalName) {
        Write-Host "  User:        $($fingerprint.actual.userPrincipalName)" -ForegroundColor Gray
    }

    foreach ($message in @($fingerprint.messages)) {
        $color = if ($fingerprint.passed) { "Green" } else { "Red" }
        Write-Host "  $message" -ForegroundColor $color
    }
    foreach ($mismatch in @($fingerprint.mismatches)) {
        Write-Host "  MISMATCH $($mismatch.field): expected '$($mismatch.expected)', actual '$($mismatch.actual)'" -ForegroundColor Red
    }

    if (-not $fingerprint.passed) {
        throw "Tenant fingerprint check failed. Aborting reset."
    }

    return $fingerprint
}

function Read-DeploymentScopeConfig {
    $defaults = Get-ModuleDefaults
    $settingsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
    $policiesJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "policies.json") -Description "policy definitions"
    $labelsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "labels.json") -Description "label definitions"
    $classifiersJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "classifiers.json") -Description "classifier definitions"

    if (-not $settingsJson -or -not $policiesJson -or -not $labelsJson -or -not $classifiersJson) {
        throw "Required config files could not be loaded."
    }

    $config = Merge-GlobalConfig -Defaults $defaults -GlobalJson $settingsJson
    if ($InterCallDelaySec -ge 0) {
        $config.interCallDelaySec = $InterCallDelaySec
    }
    if (-not $ScopeName) {
        $script:ScopeName = if ($config.namingPrefix) { $config.namingPrefix } else { "deployment-scope" }
    }
    if (-not $Tier) {
        $script:Tier = if ($config.deploymentTier) { $config.deploymentTier } else { "medium" }
    }

    return @{
        Defaults    = $defaults
        Settings    = $config
        Policies    = Resolve-PolicyConfig -PoliciesJson $policiesJson
        Labels      = Resolve-LabelConfig -LabelsJson $labelsJson
        Classifiers = Resolve-ClassifierConfig -ClassifiersJson $classifiersJson -Defaults $defaults
        ScopeName   = $script:ScopeName
        Tier        = $script:Tier
    }
}

function Read-RulePackageText {
    param([Parameter(Mandatory)][string]$FilePath)

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode.GetString($bytes)
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        return [System.Text.Encoding]::BigEndianUnicode.GetString($bytes)
    }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

function Get-LocalClassifierTargets {
    param([Parameter(Mandatory)][hashtable]$ConfigData)

    function Resolve-ClassifierXmlPath {
        param([Parameter(Mandatory)][string]$Path)

        if ([System.IO.Path]::IsPathRooted($Path)) {
            return $Path
        }

        $projectRelative = Join-Path $ProjectRoot $Path
        if (Test-Path -LiteralPath $projectRelative) {
            return $projectRelative
        }

        return Join-Path $ClassifierXmlDir $Path
    }

    $targets = @()
    $candidateFiles = New-Object System.Collections.Generic.List[object]
    $selectedAll = (-not $ClassifierPackageNames -or $ClassifierPackageNames -contains "All")
    $selectedNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @($ClassifierPackageNames)) {
        if ($name -and $name -ne "All") {
            [void]$selectedNames.Add($name)
        }
    }

    if (Test-Path -LiteralPath $ClassifierRegistryPath) {
        $registry = Import-JsonConfig -FilePath $ClassifierRegistryPath -Description "classifier deploy registry"
        if ($registry -and $registry.tier -and -not $Tier) {
            $script:Tier = $registry.tier
        }

        foreach ($pkg in @($registry.packages)) {
            $key = if ($pkg.key) { $pkg.key } elseif ($pkg.displayName) { $pkg.displayName } else { $null }
            if (-not $key) { continue }
            $isExplicitlySelected = (-not $selectedAll -and ($selectedNames.Contains($key) -or ($pkg.displayName -and $selectedNames.Contains($pkg.displayName))))
            $isEnabled = (-not $pkg.PSObject.Properties["enabled"]) -or [bool]$pkg.enabled
            if (-not $isEnabled -and -not $isExplicitlySelected) {
                continue
            }
            if (-not $selectedAll -and -not $selectedNames.Contains($key) -and -not ($pkg.displayName -and $selectedNames.Contains($pkg.displayName))) {
                continue
            }

            $filePath = $null
            if ($pkg.path) {
                $filePath = Resolve-ClassifierXmlPath -Path $pkg.path
            } elseif ($pkg.variants) {
                $variantMap = @{}
                foreach ($prop in $pkg.variants.PSObject.Properties) {
                    $variantMap[$prop.Name] = $prop.Value
                }

                if ($script:Tier -and $variantMap.ContainsKey($script:Tier)) {
                    $filePath = Resolve-ClassifierXmlPath -Path $variantMap[$script:Tier]
                } elseif ($variantMap.ContainsKey("medium")) {
                    $filePath = Resolve-ClassifierXmlPath -Path $variantMap["medium"]
                } else {
                    $firstVariant = $variantMap.Keys | Sort-Object | Select-Object -First 1
                    if ($firstVariant) {
                        $filePath = Resolve-ClassifierXmlPath -Path $variantMap[$firstVariant]
                    }
                }
            } else {
                $filePath = Resolve-ClassifierXmlPath -Path "$key.xml"
            }

            if ($filePath -and (Test-Path -LiteralPath $filePath)) {
                $candidateFiles.Add([pscustomobject]@{ Package = $key; Path = $filePath }) | Out-Null
            } else {
                Write-Warning "Classifier package '$key' did not resolve to an XML file."
            }
        }
    }

    if ($IncludeUnregisteredXmlPackages -or -not (Test-Path -LiteralPath $ClassifierRegistryPath)) {
        foreach ($file in Get-ChildItem -Path $ClassifierXmlDir -Filter "*.xml" -File | Sort-Object Name) {
            if (-not $selectedAll -and -not $selectedNames.Contains($file.BaseName)) {
                continue
            }
            $candidateFiles.Add([pscustomobject]@{ Package = $file.BaseName; Path = $file.FullName }) | Out-Null
        }
    }

    $seenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($candidate in $candidateFiles) {
        $filePath = [System.IO.Path]::GetFullPath($candidate.Path)
        if (-not $seenPaths.Add($filePath)) { continue }
        $content = Read-RulePackageText -FilePath $filePath
        [xml]$xml = $content
        $rulePack = $xml.RulePackage.RulePack
        $entities = @($xml.RulePackage.Rules.Entity)
        $targets += [pscustomobject]@{
            Package     = $candidate.Package
            Path        = $filePath
            RulePackId  = $rulePack.id.ToString()
            Version     = "{0}.{1}.{2}.{3}" -f $rulePack.Version.major, $rulePack.Version.minor, $rulePack.Version.build, $rulePack.Version.revision
            EntityCount = $entities.Count
            EntityIds   = @($entities | ForEach-Object { $_.id.ToString() })
        }
    }
    return $targets
}

function Convert-SerializedRulePackageToText {
    param([object]$Raw)

    if ($null -eq $Raw) { return $null }
    if ($Raw -is [byte[]]) {
        $bytes = [byte[]]$Raw
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
            return [System.Text.Encoding]::Unicode.GetString($bytes)
        }
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
            return [System.Text.Encoding]::BigEndianUnicode.GetString($bytes)
        }
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            return [System.Text.Encoding]::UTF8.GetString($bytes)
        }
        if ($bytes -contains 0) {
            return [System.Text.Encoding]::Unicode.GetString($bytes)
        }
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    }

    return $Raw.ToString()
}

function Get-DeployedClassifierTargets {
    param([Parameter(Mandatory)][object[]]$LocalTargets)

    $targetIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($target in $LocalTargets) {
        [void]$targetIds.Add($target.RulePackId)
    }

    $deployed = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)
    $matched = @()
    foreach ($pkg in $deployed) {
        $rawText = Convert-SerializedRulePackageToText -Raw $pkg.SerializedClassificationRuleCollection
        $parsedId = $null
        $parsedName = $null
        $version = "(unknown)"
        $entityCount = -1
        if ($rawText) {
            try {
                [xml]$xml = $rawText
                $rulePack = $xml.RulePackage.RulePack
                $parsedId = $rulePack.id.ToString()
                $parsedName = ($rulePack.Details.LocalizedDetails | Select-Object -First 1).Name
                $version = "{0}.{1}.{2}.{3}" -f $rulePack.Version.major, $rulePack.Version.minor, $rulePack.Version.build, $rulePack.Version.revision
                $entityCount = @($xml.RulePackage.Rules.Entity).Count
            } catch {
                $rawText = $null
            }
        }

        $identityText = if ($pkg.Identity) { $pkg.Identity.ToString() } else { "" }
        $isMatch = $false
        if ($parsedId -and $targetIds.Contains($parsedId)) {
            $isMatch = $true
        } else {
            foreach ($id in $targetIds) {
                if ($identityText.IndexOf($id, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $isMatch = $true
                    break
                }
            }
        }

        if ($isMatch) {
            $local = @($LocalTargets | Where-Object { $_.RulePackId -eq $parsedId } | Select-Object -First 1)
            $matched += [pscustomobject]@{
                Package       = if ($local) { $local.Package } elseif ($parsedName) { $parsedName } else { $pkg.Name }
                Name          = $parsedName
                Identity      = $pkg.Identity.ToString()
                Publisher     = $pkg.Publisher
                RulePackId    = $parsedId
                Version       = $version
                EntityCount   = $entityCount
                RawXml        = $rawText
                RawBytes      = if ($pkg.SerializedClassificationRuleCollection -is [byte[]]) { [byte[]]$pkg.SerializedClassificationRuleCollection } else { $null }
                SourcePackage = $pkg
            }
        }
    }

    return $matched
}

function Get-ScopedDlpState {
    param([Parameter(Mandatory)][hashtable]$ConfigData)

    $config = $ConfigData.Settings
    $policyStates = @()
    $targetPolicies = @()
    if ($PolicyNames -and $PolicyNames.Count -gt 0) {
        $targetPolicies = @($PolicyNames | Sort-Object -Unique | ForEach-Object {
            [pscustomobject]@{
                Name     = $_
                Code     = $null
                Optional = $false
                Enabled  = $true
            }
        })
    } else {
        $targetPolicies = @($ConfigData.Policies | ForEach-Object {
            [pscustomobject]@{
                Name     = Get-PolicyName -PolicyNumber $_.Number -PolicyCode $_.Code -Config $config
                Code     = $_.Code
                Optional = [bool]$_.Optional
                Enabled  = [bool]$_.Enabled
            }
        })
    }

    foreach ($policy in $targetPolicies) {
        $policyName = $policy.Name
        $policyObj = $null
        try {
            $policyObj = Get-DlpCompliancePolicy -Identity $policyName -ErrorAction Stop
        } catch {
            $policyObj = $null
        }

        $rules = @()
        if ($policyObj) {
            try {
                $rules = @(Get-DlpComplianceRule -Policy $policyName -ErrorAction Stop | Sort-Object Priority, Name)
            } catch {
                $rules = @()
            }
        }

        $policyStates += [pscustomobject]@{
            Name      = $policyName
            Code      = $policy.Code
            Optional  = $policy.Optional
            Enabled   = $policy.Enabled
            Exists    = [bool]$policyObj
            Mode      = if ($policyObj) { $policyObj.Mode } else { $null }
            RuleCount = $rules.Count
            Policy    = $policyObj
            Rules     = @($rules)
        }
    }

    return $policyStates
}

function Get-DlpRulePolicyNames {
    param([Parameter(Mandatory)][object]$Rule)

    $names = New-Object System.Collections.Generic.List[string]
    if ($Rule.ParentPolicyName) {
        $names.Add($Rule.ParentPolicyName.ToString()) | Out-Null
    }
    foreach ($policy in @($Rule.Policy)) {
        if ($policy) {
            $names.Add($policy.ToString()) | Out-Null
        }
    }

    return @($names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
}

function Get-DlpRuleClassifierReferenceText {
    param([Parameter(Mandatory)][object]$Rule)

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($propertyName in @(
        "ContentContainsSensitiveInformation",
        "ExceptIfContentContainsSensitiveInformation",
        "AdvancedRule",
        "Conditions",
        "Exceptions"
    )) {
        $property = $Rule.PSObject.Properties[$propertyName]
        if (-not $property -or $null -eq $property.Value) { continue }
        try {
            $parts.Add(($property.Value | ConvertTo-Json -Depth 20 -Compress)) | Out-Null
        } catch {
            $parts.Add($property.Value.ToString()) | Out-Null
        }
    }

    return ($parts -join "`n")
}

function Get-ClassifierReferenceImpact {
    param(
        [Parameter(Mandatory)][object[]]$LocalClassifiers,
        [Parameter(Mandatory)][object[]]$DlpState
    )

    $candidateIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($classifier in @($LocalClassifiers)) {
        foreach ($id in @($classifier.EntityIds)) {
            if (-not [string]::IsNullOrWhiteSpace($id)) {
                $candidateIds.Add($id.ToString()) | Out-Null
            }
        }
    }

    $scopedRuleNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $scopedPolicyNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($state in @($DlpState)) {
        if ($state.Name) { $scopedPolicyNames.Add($state.Name.ToString()) | Out-Null }
        foreach ($rule in @($state.Rules)) {
            if ($rule.Name) { $scopedRuleNames.Add($rule.Name.ToString()) | Out-Null }
        }
    }

    $references = @()
    $rulesScanned = 0
    if ($candidateIds.Count -gt 0) {
        try {
            $allRules = @(Get-DlpComplianceRule -ErrorAction Stop)
        } catch {
            Write-Warning "Could not retrieve all DLP rules for classifier reference check: $($_.Exception.Message)"
            $allRules = @()
        }

        $guidPattern = '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
        foreach ($rule in $allRules) {
            $rulesScanned++
            $ruleText = Get-DlpRuleClassifierReferenceText -Rule $rule
            if (-not $ruleText) { continue }

            $matchedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($match in [regex]::Matches($ruleText, $guidPattern)) {
                if ($candidateIds.Contains($match.Value)) {
                    $matchedIds.Add($match.Value.ToLowerInvariant()) | Out-Null
                }
            }
            if ($matchedIds.Count -eq 0) { continue }

            $ruleName = if ($rule.Name) { $rule.Name.ToString() } elseif ($rule.Identity) { $rule.Identity.ToString() } else { "(unknown)" }
            $policyNames = @(Get-DlpRulePolicyNames -Rule $rule)
            $plannedForRemoval = $scopedRuleNames.Contains($ruleName)
            if (-not $plannedForRemoval) {
                foreach ($policyName in @($policyNames)) {
                    if ($scopedPolicyNames.Contains($policyName)) {
                        $plannedForRemoval = $true
                        break
                    }
                }
            }

            $references += [pscustomobject]@{
                RuleName              = $ruleName
                PolicyNames           = @($policyNames)
                MatchedClassifierIds  = @($matchedIds | Sort-Object)
                PlannedForRemoval     = [bool]$plannedForRemoval
                ExternalToResetScope  = [bool](-not $plannedForRemoval)
            }
        }
    }

    $externalReferences = @($references | Where-Object { $_.ExternalToResetScope })
    $plannedReferences = @($references | Where-Object { -not $_.ExternalToResetScope })

    return [pscustomobject]@{
        CandidateClassifierIdCount = $candidateIds.Count
        RulesScanned               = $rulesScanned
        MatchingRuleCount          = @($references).Count
        PlannedRemovalRuleCount    = @($plannedReferences).Count
        ExternalRuleCount          = @($externalReferences).Count
        References                 = @($references)
        ExternalReferences         = @($externalReferences)
    }
}

function New-DeploymentResetReportDir {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportRoot = Join-Path (Join-Path $ProjectRoot "reports") "resets"
    if (-not (Test-Path -LiteralPath $reportRoot)) {
        New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null
    }
    $tenantPart = if ($Tenant) { $Tenant } else { "connectedtenant" }
    $safeTenant = ($tenantPart -replace "[^a-zA-Z0-9_.-]", "_").Trim("_")
    $safeScope = ($ScopeName -replace "[^a-zA-Z0-9_.-]", "_").Trim("_")
    if (-not $safeScope) { $safeScope = "deployment_scope" }
    $dir = Join-Path $reportRoot "${timestamp}_${safeTenant}_${safeScope}_reset"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    return $dir
}

function Export-DeploymentResetEvidence {
    param(
        [Parameter(Mandatory)][string]$ReportDir,
        [Parameter(Mandatory)][object[]]$DlpState,
        [Parameter(Mandatory)][object[]]$LocalClassifiers,
        [Parameter(Mandatory)][object[]]$DeployedClassifiers,
        [Parameter(Mandatory)][object]$ClassifierReferenceImpact,
        [Parameter(Mandatory)][object]$Fingerprint
    )

    $classifierDir = Join-Path $ReportDir "classifier-packages"
    New-Item -ItemType Directory -Path $classifierDir -Force | Out-Null

    $policies = @($DlpState | Where-Object { $_.Policy } | ForEach-Object { $_.Policy })
    $rules = @($DlpState | ForEach-Object { $_.Rules })
    $policies | Export-Clixml -Path (Join-Path $ReportDir "dlp-policies.clixml")
    $rules | Export-Clixml -Path (Join-Path $ReportDir "dlp-rules.clixml")

    foreach ($pkg in $DeployedClassifiers) {
        $safeName = if ($pkg.Package) { $pkg.Package } elseif ($pkg.Name) { $pkg.Name } else { $pkg.RulePackId }
        $safeName = $safeName -replace "[^a-zA-Z0-9_.-]", "_"
        $outPath = Join-Path $classifierDir ("{0}_{1}.xml" -f $safeName, $pkg.RulePackId)
        if ($pkg.RawBytes) {
            [System.IO.File]::WriteAllBytes($outPath, $pkg.RawBytes)
        } elseif ($pkg.RawXml) {
            [System.IO.File]::WriteAllText($outPath, $pkg.RawXml, [System.Text.Encoding]::UTF8)
        }
    }

    Copy-Item -LiteralPath (Join-Path $ConfigPath "settings.json") -Destination (Join-Path $ReportDir "settings.json") -Force
    Copy-Item -LiteralPath (Join-Path $ConfigPath "policies.json") -Destination (Join-Path $ReportDir "policies.json") -Force
    Copy-Item -LiteralPath (Join-Path $ConfigPath "classifiers.json") -Destination (Join-Path $ReportDir "classifiers.json") -Force
    Copy-Item -LiteralPath (Join-Path $ConfigPath "labels.json") -Destination (Join-Path $ReportDir "labels.json") -Force

    [ordered]@{
        exportedUtc = (Get-Date).ToUniversalTime().ToString("o")
        tenantFingerprint = $Fingerprint
        dlp = @($DlpState | ForEach-Object {
            [ordered]@{
                name = $_.Name
                exists = $_.Exists
                mode = $_.Mode
                ruleCount = $_.RuleCount
                rules = @($_.Rules | ForEach-Object {
                    [ordered]@{
                        name = $_.Name
                        policy = $_.Policy
                        priority = $_.Priority
                    }
                })
            }
        })
        classifiers = [ordered]@{
            local = @($LocalClassifiers | ForEach-Object {
                [ordered]@{
                    package = $_.Package
                    rulePackId = $_.RulePackId
                    version = $_.Version
                    entityCount = $_.EntityCount
                }
            })
            deployed = @($DeployedClassifiers | ForEach-Object {
                [ordered]@{
                    package = $_.Package
                    name = $_.Name
                    identity = $_.Identity
                    rulePackId = $_.RulePackId
                    version = $_.Version
                    entityCount = $_.EntityCount
                }
            })
        }
        classifierReferences = [ordered]@{
            candidateClassifierIdCount = $ClassifierReferenceImpact.CandidateClassifierIdCount
            rulesScanned = $ClassifierReferenceImpact.RulesScanned
            matchingRuleCount = $ClassifierReferenceImpact.MatchingRuleCount
            plannedRemovalRuleCount = $ClassifierReferenceImpact.PlannedRemovalRuleCount
            externalRuleCount = $ClassifierReferenceImpact.ExternalRuleCount
            references = @($ClassifierReferenceImpact.References | ForEach-Object {
                [ordered]@{
                    ruleName = $_.RuleName
                    policyNames = @($_.PolicyNames)
                    matchedClassifierIds = @($_.MatchedClassifierIds)
                    plannedForRemoval = [bool]$_.PlannedForRemoval
                    externalToResetScope = [bool]$_.ExternalToResetScope
                }
            })
        }
    } | ConvertTo-Json -Depth 12 | Set-Content -Path (Join-Path $ReportDir "reset-inventory.json") -Encoding UTF8
}

function New-DeploymentResetSummary {
    param(
        [Parameter(Mandatory)][object[]]$DlpState,
        [Parameter(Mandatory)][object[]]$LocalClassifiers,
        [Parameter(Mandatory)][object[]]$DeployedClassifiers,
        [Parameter(Mandatory)][object]$ClassifierReferenceImpact,
        [Parameter(Mandatory)][object]$Fingerprint,
        [Parameter(Mandatory)][string]$ReportDir
    )

    $presentPolicies = @($DlpState | Where-Object { $_.Exists })
    $missingPolicies = @($DlpState | Where-Object { -not $_.Exists })
    $rules = @($presentPolicies | ForEach-Object { $_.Rules })
    $configuredEntityIds = @($LocalClassifiers | ForEach-Object { $_.EntityIds }) | Sort-Object -Unique

    return [ordered]@{
        generatedUtc = (Get-Date).ToUniversalTime().ToString("o")
        action = $Action
        tenant = [ordered]@{
            target = $Tenant
            environment = $TargetEnvironment
            guid = $Fingerprint.actual.guid
            userPrincipalName = $Fingerprint.actual.userPrincipalName
        }
        reportDir = $ReportDir
        scope = [ordered]@{
            name = $ScopeName
            source = if ($PolicyNames -and $PolicyNames.Count -gt 0) { "explicit-policy-names" } else { "repo-config" }
            dlpPolicyNames = @($DlpState.Name)
            classifierPackages = @($LocalClassifiers.Package)
            classifierRulePackIds = @($LocalClassifiers.RulePackId)
            configuredClassifierIds = $configuredEntityIds.Count
            classifierRegistryPath = $ClassifierRegistryPath
            classifierXmlDir = $ClassifierXmlDir
            classifierTier = $Tier
        }
        plannedOrder = @(
            "Export current DLP policy/rule and classifier package evidence",
            "Remove scoped DLP rules",
            "Remove scoped DLP policies",
            "Remove scoped classifier rule packages",
            "Verify removal state",
            "Wait before DLP dry run if requested"
        )
        dlp = [ordered]@{
            configuredPolicies = $DlpState.Count
            presentPolicies = $presentPolicies.Count
            missingPolicies = @($missingPolicies.Name)
            rulesToRemove = $rules.Count
            policies = @($DlpState | ForEach-Object {
                [ordered]@{
                    name = $_.Name
                    exists = $_.Exists
                    mode = $_.Mode
                    ruleCount = $_.RuleCount
                    rules = @($_.Rules | ForEach-Object { $_.Name })
                }
            })
        }
        classifiers = [ordered]@{
            localPackages = $LocalClassifiers.Count
            deployedPackagesToRemove = $DeployedClassifiers.Count
            deployedEntityCountFromPackageXml = (@($DeployedClassifiers | Measure-Object -Property EntityCount -Sum).Sum)
            packages = @($DeployedClassifiers | ForEach-Object {
                [ordered]@{
                    package = $_.Package
                    name = $_.Name
                    rulePackId = $_.RulePackId
                    version = $_.Version
                    entityCount = $_.EntityCount
                }
            })
        }
        classifierReferences = [ordered]@{
            rulesScanned = $ClassifierReferenceImpact.RulesScanned
            matchingRuleCount = $ClassifierReferenceImpact.MatchingRuleCount
            plannedRemovalRuleCount = $ClassifierReferenceImpact.PlannedRemovalRuleCount
            externalRuleCount = $ClassifierReferenceImpact.ExternalRuleCount
            externalReferences = @($ClassifierReferenceImpact.ExternalReferences | ForEach-Object {
                [ordered]@{
                    ruleName = $_.RuleName
                    policyNames = @($_.PolicyNames)
                    matchedClassifierIds = @($_.MatchedClassifierIds)
                }
            })
        }
        safeguards = @(
            "Tenant fingerprint must match '$TargetEnvironment' before any operation.",
            "DLP rules/policies are removed before classifiers to avoid live rules holding deleted classifier references.",
            "DLP removal is limited to exact scoped policy names.",
            "Classifier removal is limited to local RulePack IDs resolved from the classifier registry/XML files.",
            "Classifier removal is blocked when unscoped DLP rules still reference targeted classifier IDs unless -AllowBreakingExternalClassifierReferences is supplied.",
            "Microsoft built-in packages and unrelated tenant objects are not targeted."
        )
    }
}

function Write-DeploymentResetSummary {
    param([Parameter(Mandatory)][object]$Summary)

    Write-Host "`n=== Deployment Scope Reset Summary ===" -ForegroundColor Cyan
    Write-Host "  Scope:         $($Summary.scope.name)" -ForegroundColor Gray
    Write-Host "  Tenant:        $($Summary.tenant.target)" -ForegroundColor Gray
    Write-Host "  Environment:   $($Summary.tenant.environment)" -ForegroundColor Gray
    Write-Host "  Tenant GUID:   $($Summary.tenant.guid)" -ForegroundColor Gray
    Write-Host "  Report folder: $($Summary.reportDir)" -ForegroundColor Gray

    Write-Host "`n  DLP scope:" -ForegroundColor White
    Write-Host "    Present policies: $($Summary.dlp.presentPolicies)/$($Summary.dlp.configuredPolicies)" -ForegroundColor Gray
    Write-Host "    Rules to remove:  $($Summary.dlp.rulesToRemove)" -ForegroundColor Gray
    if ($Summary.dlp.missingPolicies.Count -gt 0) {
        Write-Host "    Missing policies: $($Summary.dlp.missingPolicies -join ', ')" -ForegroundColor Yellow
    }

    Write-Host "`n  Classifier scope:" -ForegroundColor White
    Write-Host "    Local packages:             $($Summary.classifiers.localPackages)" -ForegroundColor Gray
    Write-Host "    Deployed packages to remove: $($Summary.classifiers.deployedPackagesToRemove)" -ForegroundColor Gray
    Write-Host "    Configured classifier IDs:   $($Summary.scope.configuredClassifierIds)" -ForegroundColor Gray
    Write-Host "    DLP rules scanned for refs:  $($Summary.classifierReferences.rulesScanned)" -ForegroundColor Gray
    Write-Host "    Matching DLP rule refs:      $($Summary.classifierReferences.matchingRuleCount)" -ForegroundColor Gray
    $externalColor = if ($Summary.classifierReferences.externalRuleCount -gt 0) { "Red" } else { "Green" }
    Write-Host "    External DLP rule refs:      $($Summary.classifierReferences.externalRuleCount)" -ForegroundColor $externalColor
    foreach ($ref in @($Summary.classifierReferences.externalReferences | Select-Object -First 8)) {
        Write-Host "      - $($ref.ruleName) [$(@($ref.policyNames) -join ', ')]" -ForegroundColor Red
    }

    Write-Host "`n  Operation order:" -ForegroundColor White
    foreach ($step in $Summary.plannedOrder) {
        Write-Host "    - $step" -ForegroundColor Gray
    }
}

function Save-DeploymentResetSummary {
    param(
        [Parameter(Mandatory)][object]$Summary,
        [Parameter(Mandatory)][string]$ReportDir
    )

    $jsonPath = Join-Path $ReportDir "reset-summary.json"
    $mdPath = Join-Path $ReportDir "reset-summary.md"

    $Summary | ConvertTo-Json -Depth 12 | Set-Content -Path $jsonPath -Encoding UTF8

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# Deployment Scope Reset Summary")
    $lines.Add("")
    $lines.Add("- Scope: $($Summary.scope.name)")
    $lines.Add("- Tenant: $($Summary.tenant.target)")
    $lines.Add("- Environment: $($Summary.tenant.environment)")
    $lines.Add("- Tenant GUID: $($Summary.tenant.guid)")
    $lines.Add("- User: $($Summary.tenant.userPrincipalName)")
    $lines.Add("- Report folder: $($Summary.reportDir)")
    $lines.Add("")
    $lines.Add("## Planned Order")
    foreach ($step in $Summary.plannedOrder) { $lines.Add("- $step") }
    $lines.Add("")
    $lines.Add("## DLP Objects")
    $lines.Add("- Present policies: $($Summary.dlp.presentPolicies)/$($Summary.dlp.configuredPolicies)")
    $lines.Add("- Rules to remove: $($Summary.dlp.rulesToRemove)")
    if ($Summary.dlp.missingPolicies.Count -gt 0) {
        $lines.Add("- Missing policies: $($Summary.dlp.missingPolicies -join ', ')")
    }
    foreach ($policy in $Summary.dlp.policies) {
        $lines.Add("")
        $lines.Add("### $($policy.name)")
        $lines.Add("- Exists: $($policy.exists)")
        $lines.Add("- Mode: $($policy.mode)")
        $lines.Add("- Rule count: $($policy.ruleCount)")
        foreach ($rule in $policy.rules) { $lines.Add("  - $rule") }
    }
    $lines.Add("")
    $lines.Add("## Classifier Packages")
    $lines.Add("- Local packages: $($Summary.classifiers.localPackages)")
    $lines.Add("- Deployed packages to remove: $($Summary.classifiers.deployedPackagesToRemove)")
    $lines.Add("- Configured classifier IDs: $($Summary.scope.configuredClassifierIds)")
    $lines.Add("- DLP rules scanned for classifier references: $($Summary.classifierReferences.rulesScanned)")
    $lines.Add("- Matching DLP rule references: $($Summary.classifierReferences.matchingRuleCount)")
    $lines.Add("- External DLP rule references: $($Summary.classifierReferences.externalRuleCount)")
    foreach ($pkg in $Summary.classifiers.packages) {
        $lines.Add("- $($pkg.package): $($pkg.rulePackId), version $($pkg.version), package XML entities $($pkg.entityCount)")
    }
    if ($Summary.classifierReferences.externalRuleCount -gt 0) {
        $lines.Add("")
        $lines.Add("## External Classifier References")
        foreach ($ref in $Summary.classifierReferences.externalReferences) {
            $lines.Add("- $($ref.ruleName) [$(@($ref.policyNames) -join ', ')]: $(@($ref.matchedClassifierIds) -join ', ')")
        }
    }
    $lines.Add("")
    $lines.Add("## Safeguards")
    foreach ($guard in $Summary.safeguards) { $lines.Add("- $guard") }

    $lines | Set-Content -Path $mdPath -Encoding UTF8
}

function Remove-ScopedDlpObjects {
    param(
        [Parameter(Mandatory)][object[]]$DlpState,
        [Parameter(Mandatory)][hashtable]$ConfigData
    )

    $result = [ordered]@{
        rulesDeleted = 0
        rulesSkipped = 0
        rulesFailed = 0
        policiesDeleted = 0
        policiesSkipped = 0
        policiesFailed = 0
        details = @()
    }

    foreach ($state in $DlpState) {
        if (-not $state.Exists) {
            $result.policiesSkipped++
            $result.details += [ordered]@{ type = "DLPPolicy"; name = $state.Name; status = "not-found" }
            continue
        }

        foreach ($rule in @($state.Rules | Sort-Object Priority, Name)) {
            Write-Host "  Removing DLP rule: $($rule.Name)" -ForegroundColor Cyan
            $status = Remove-PurviewObject -Identity $rule.Name -InputObject $rule `
                -RemoveCommand "Remove-DlpComplianceRule" -OperationName "DLP rule" `
                -MaxRetries $ConfigData.Settings.maxRetries -BaseDelaySec $ConfigData.Settings.baseDelaySec `
                -WhatIf:$WhatIfPreference
            if ($status -eq "deleted" -or $status -eq "pending") { $result.rulesDeleted++ }
            elseif ($status -eq "not-found") { $result.rulesSkipped++ }
            else { $result.rulesFailed++ }
            $result.details += [ordered]@{ type = "DLPRule"; name = $rule.Name; policy = $state.Name; status = $status }
            if (-not $WhatIfPreference -and $ConfigData.Settings.interCallDelaySec -gt 0) {
                Start-Sleep -Seconds $ConfigData.Settings.interCallDelaySec
            }
        }

        Write-Host "  Removing DLP policy: $($state.Name)" -ForegroundColor Cyan
        $policyStatus = Remove-PurviewObject -Identity $state.Name -InputObject $state.Policy `
            -RemoveCommand "Remove-DlpCompliancePolicy" -OperationName "DLP policy" `
            -MaxRetries $ConfigData.Settings.maxRetries -BaseDelaySec $ConfigData.Settings.baseDelaySec `
            -WhatIf:$WhatIfPreference
        if ($policyStatus -eq "deleted" -or $policyStatus -eq "pending") { $result.policiesDeleted++ }
        elseif ($policyStatus -eq "not-found") { $result.policiesSkipped++ }
        else { $result.policiesFailed++ }
        $result.details += [ordered]@{ type = "DLPPolicy"; name = $state.Name; status = $policyStatus }
        if (-not $WhatIfPreference -and $ConfigData.Settings.interCallDelaySec -gt 0) {
            Start-Sleep -Seconds $ConfigData.Settings.interCallDelaySec
        }
    }

    return $result
}

function Remove-ScopedClassifierPackages {
    param(
        [Parameter(Mandatory)][object[]]$DeployedClassifiers,
        [Parameter(Mandatory)][hashtable]$ConfigData
    )

    $result = [ordered]@{
        deleted = 0
        skipped = 0
        failed = 0
        details = @()
    }

    foreach ($pkg in @($DeployedClassifiers | Sort-Object Package)) {
        Write-Host "  Removing classifier package: $($pkg.Package) ($($pkg.RulePackId))" -ForegroundColor Cyan
        $status = Remove-PurviewObject -Identity $pkg.Identity -InputObject $pkg.SourcePackage `
            -RemoveCommand "Remove-DlpSensitiveInformationTypeRulePackage" -OperationName "classifier package" `
            -MaxRetries $ConfigData.Settings.maxRetries -BaseDelaySec $ConfigData.Settings.baseDelaySec `
            -WhatIf:$WhatIfPreference
        if ($status -eq "deleted" -or $status -eq "pending") { $result.deleted++ }
        elseif ($status -eq "not-found") { $result.skipped++ }
        else { $result.failed++ }
        $result.details += [ordered]@{ type = "ClassifierPackage"; package = $pkg.Package; rulePackId = $pkg.RulePackId; identity = $pkg.Identity; status = $status }
        if (-not $WhatIfPreference -and $ConfigData.Settings.interCallDelaySec -gt 0) {
            Start-Sleep -Seconds $ConfigData.Settings.interCallDelaySec
        }
    }

    return $result
}

function Test-DeploymentResetState {
    param(
        [Parameter(Mandatory)][hashtable]$ConfigData,
        [Parameter(Mandatory)][object[]]$LocalClassifiers
    )

    $dlpState = Get-ScopedDlpState -ConfigData $ConfigData
    $remainingDlpPolicies = @($dlpState | Where-Object { $_.Exists })
    $remainingDlpRules = @($dlpState | ForEach-Object { $_.Rules })
    $remainingClassifiers = @(Get-DeployedClassifierTargets -LocalTargets $LocalClassifiers)

    return [ordered]@{
        checkedUtc = (Get-Date).ToUniversalTime().ToString("o")
        remainingDlpPolicies = @($remainingDlpPolicies.Name)
        remainingDlpRuleCount = $remainingDlpRules.Count
        remainingClassifierPackages = @($remainingClassifiers | ForEach-Object { $_.Package })
        passed = ($remainingDlpPolicies.Count -eq 0 -and $remainingDlpRules.Count -eq 0 -and $remainingClassifiers.Count -eq 0)
    }
}

function Invoke-ScopedDlpDryRun {
    Write-Host "`n=== DLP Dry Run (Same Session) ===" -ForegroundColor Cyan
    $scriptPath = Join-Path $PSScriptRoot "Deploy-DLPRules.ps1"
    & $scriptPath -TargetEnvironment $TargetEnvironment -WhatIf
}

function Confirm-DeploymentResetExecution {
    if ($Force -or $WhatIfPreference) { return $true }
    $expected = "RESET $ScopeName $Tenant"
    Write-Host ""
    Write-Host "This will remove scoped DLP rules/policies and classifier packages from $Tenant." -ForegroundColor Yellow
    $actual = Read-Host "Type '$expected' to continue"
    return ($actual -eq $expected)
}

Connect-DeploymentResetSession
$fingerprint = Assert-DeploymentResetTenant
$configData = Read-DeploymentScopeConfig
$ScopeName = $configData.ScopeName
$Tier = $configData.Tier
$localClassifiers = @(Get-LocalClassifierTargets -ConfigData $configData)
$dlpState = @(Get-ScopedDlpState -ConfigData $configData)
$deployedClassifiers = @(Get-DeployedClassifierTargets -LocalTargets $localClassifiers)
$classifierReferenceImpact = Get-ClassifierReferenceImpact -LocalClassifiers $localClassifiers -DlpState $dlpState
$reportDir = New-DeploymentResetReportDir

Export-DeploymentResetEvidence -ReportDir $reportDir -DlpState $dlpState -LocalClassifiers $localClassifiers -DeployedClassifiers $deployedClassifiers -ClassifierReferenceImpact $classifierReferenceImpact -Fingerprint $fingerprint
$summary = New-DeploymentResetSummary -DlpState $dlpState -LocalClassifiers $localClassifiers -DeployedClassifiers $deployedClassifiers -ClassifierReferenceImpact $classifierReferenceImpact -Fingerprint $fingerprint -ReportDir $reportDir
Save-DeploymentResetSummary -Summary $summary -ReportDir $reportDir
Write-DeploymentResetSummary -Summary $summary

switch ($Action) {
    "Plan" {
        Write-Host "`nPlan complete. No tenant objects were removed." -ForegroundColor Green
    }
    "Verify" {
        $verification = Test-DeploymentResetState -ConfigData $configData -LocalClassifiers $localClassifiers
        $verification | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $reportDir "verification.json") -Encoding UTF8
        Write-Host "`n=== Verification ===" -ForegroundColor Cyan
        Write-Host "  Remaining DLP policies:       $($verification.remainingDlpPolicies.Count)" -ForegroundColor Gray
        Write-Host "  Remaining DLP rules:          $($verification.remainingDlpRuleCount)" -ForegroundColor Gray
        Write-Host "  Remaining classifier packages: $($verification.remainingClassifierPackages.Count)" -ForegroundColor Gray
        if ($verification.passed) { Write-Host "  Reset state verified." -ForegroundColor Green } else { Write-Host "  Reset state is not clean yet." -ForegroundColor Yellow }
    }
    "Execute" {
        if ($summary.classifierReferences.externalRuleCount -gt 0 -and -not $AllowBreakingExternalClassifierReferences) {
            throw "Reset blocked: $($summary.classifierReferences.externalRuleCount) unscoped DLP rule(s) reference targeted classifier IDs. Review '$reportDir\reset-summary.md' and use classifier adoption/rebase instead of deleting the package, or rerun with -AllowBreakingExternalClassifierReferences after explicit approval."
        }

        if (-not (Confirm-DeploymentResetExecution)) {
            Write-Host "Reset aborted. No tenant objects were removed." -ForegroundColor Yellow
            return
        }

        Write-Host "`n=== Removing Scoped DLP Rules and Policies ===" -ForegroundColor Cyan
        $dlpResult = Remove-ScopedDlpObjects -DlpState $dlpState -ConfigData $configData
        $dlpResult | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $reportDir "dlp-removal-results.json") -Encoding UTF8

        Write-Host "`n=== Removing Scoped Classifier Packages ===" -ForegroundColor Cyan
        $classifierResult = Remove-ScopedClassifierPackages -DeployedClassifiers $deployedClassifiers -ConfigData $configData
        $classifierResult | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $reportDir "classifier-removal-results.json") -Encoding UTF8

        Write-Host "`n=== Post-Removal Verification ===" -ForegroundColor Cyan
        $verification = Test-DeploymentResetState -ConfigData $configData -LocalClassifiers $localClassifiers
        $verification | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $reportDir "verification.json") -Encoding UTF8
        Write-Host "  Remaining DLP policies:       $($verification.remainingDlpPolicies.Count)" -ForegroundColor Gray
        Write-Host "  Remaining DLP rules:          $($verification.remainingDlpRuleCount)" -ForegroundColor Gray
        Write-Host "  Remaining classifier packages: $($verification.remainingClassifierPackages.Count)" -ForegroundColor Gray

        if ($RunDryRunAfterWait) {
            if (-not $SkipWait -and $WaitHours -gt 0) {
                $resume = (Get-Date).AddHours($WaitHours)
                Write-Host "`nWaiting $WaitHours hour(s) before dry run. Resume at $resume." -ForegroundColor Yellow
                Start-Sleep -Seconds ($WaitHours * 3600)
            }
            Connect-DeploymentResetSession
            Assert-DeploymentResetTenant | Out-Null
            Invoke-ScopedDlpDryRun
        } else {
            Write-Host "`nReset execution complete. Run Action WaitThenDryRun after the backend cleanup window." -ForegroundColor Green
        }
    }
    "WaitThenDryRun" {
        if (-not $SkipWait -and $WaitHours -gt 0) {
            $resume = (Get-Date).AddHours($WaitHours)
            Write-Host "`nWaiting $WaitHours hour(s) before DLP dry run. Resume at $resume." -ForegroundColor Yellow
            Start-Sleep -Seconds ($WaitHours * 3600)
        }
        Connect-DeploymentResetSession
        Assert-DeploymentResetTenant | Out-Null
        Invoke-ScopedDlpDryRun
    }
}
