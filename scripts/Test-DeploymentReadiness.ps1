#==============================================================================
# Test-DeploymentReadiness.ps1
# Pre-deployment readiness gate for labels, classifier bundles, and DLP rules.
#
# Usage:
#   .\scripts\Test-DeploymentReadiness.ps1 -Scope All -Connect
#   .\scripts\Test-DeploymentReadiness.ps1 -Scope Classifiers -Tier narrow -Connect
#   .\scripts\Test-DeploymentReadiness.ps1 -Scope DLPRules -RequireTenant
#==============================================================================

[CmdletBinding()]
param(
    [ValidateSet("All", "Labels", "Classifiers", "DLPRules")]
    [string[]]$Scope = @("All"),

    [ValidateSet("narrow", "wide", "full", "small", "medium", "large")]
    [string]$Tier,

    [switch]$Connect,
    [string]$UPN,
    [string]$Tenant,
    [string]$TargetEnvironment,
    [string]$Prefix,
    [switch]$Delegated,
    [switch]$RequireTenant,
    [string]$TrainableClassifierInventory,
    [switch]$NoExit
)

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath = Join-Path $ProjectRoot "config"
$XmlDir = Join-Path $ProjectRoot "xml"
$DeployDir = Join-Path $XmlDir "deploy"
$ModulePath = Join-Path (Join-Path $ProjectRoot "modules") "DLP-Deploy.psm1"

Import-Module $ModulePath -Force

$script:Errors = [System.Collections.Generic.List[string]]::new()
$script:Warnings = [System.Collections.Generic.List[string]]::new()

function Add-ReadyError {
    param([string]$Message)
    $script:Errors.Add($Message)
}

function Add-ReadyWarning {
    param([string]$Message)
    $script:Warnings.Add($Message)
}

function Add-PurviewNameSafetyError {
    param([Parameter(Mandatory)][object]$Result)

    if ($Result.IsSafe) { return }

    $name = if ($null -eq $Result.Name) { "<null>" } else { $Result.Name }
    Add-ReadyError "$($Result.ObjectType) '$name' uses an unsafe Purview object name: $($Result.Reasons -join ' ')"
}

function Read-JsonFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description,
        [switch]$Required
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        if ($Required) { Add-ReadyError "Missing $Description JSON: $Path" }
        else { Add-ReadyWarning "Optional $Description JSON not found: $Path" }
        return $null
    }

    try {
        return (Get-Content -Raw -LiteralPath $Path -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        Add-ReadyError "Invalid $Description JSON ($Path): $($_.Exception.Message)"
        return $null
    }
}

function Read-TextWithBomDetection {
    param([Parameter(Mandatory)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $text = $null
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $text = [System.Text.Encoding]::Unicode.GetString($bytes)
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        $text = [System.Text.Encoding]::BigEndianUnicode.GetString($bytes)
    } elseif ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    } else {
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    return $text.TrimStart([char]0xFEFF)
}

function Test-GuidString {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $guid = [guid]::Empty
    return [guid]::TryParse($Value, [ref]$guid)
}

function Get-JsonProperties {
    param([object]$Object)
    if (-not $Object) { return @() }
    return @($Object.PSObject.Properties.Name)
}

function Test-RequiredProperty {
    param([object]$Object, [string]$Property, [string]$Context)
    if (-not (Get-JsonProperties $Object | Where-Object { $_ -eq $Property })) {
        Add-ReadyError "$Context missing required property '$Property'"
        return $false
    }
    return $true
}

function Resolve-ReadinessPackageFile {
    param([object]$Package, [string]$RequestedTier)

    if (-not $Package.variants) {
        return Join-Path $DeployDir "$($Package.key).xml"
    }

    $variants = @{}
    foreach ($prop in $Package.variants.PSObject.Properties) {
        $variants[$prop.Name] = $prop.Value
    }

    if ($RequestedTier -and $variants.ContainsKey($RequestedTier)) {
        return Join-Path $XmlDir $variants[$RequestedTier]
    }
    if ($RequestedTier -and -not $variants.ContainsKey($RequestedTier)) {
        Add-ReadyWarning "Package '$($Package.key)' has no '$RequestedTier' variant; validating fallback variant."
    }
    if ($variants.ContainsKey("full")) {
        return Join-Path $XmlDir $variants["full"]
    }
    $firstKey = $variants.Keys | Select-Object -First 1
    if ($firstKey) { return Join-Path $XmlDir $variants[$firstKey] }
    return $null
}

function Get-RulePackageEntities {
    param([Parameter(Mandatory)][string]$Path)

    $entities = @()
    try {
        $xml = [xml](Read-TextWithBomDetection -Path $Path)
        $rules = $xml.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq "Rules" }
        if (-not $rules) { return $entities }

        $nameMap = @{}
        $localizedStrings = $rules.ChildNodes | Where-Object { $_.LocalName -eq "LocalizedStrings" }
        if ($localizedStrings) {
            foreach ($resource in @($localizedStrings.ChildNodes)) {
                if ($resource.LocalName -eq "Resource") {
                    $nameNode = $resource.ChildNodes | Where-Object { $_.LocalName -eq "Name" } | Select-Object -First 1
                    if ($nameNode) { $nameMap[$resource.idRef] = $nameNode.InnerText }
                }
            }
        }

        foreach ($entity in @($rules.ChildNodes | Where-Object { $_.LocalName -eq "Entity" })) {
            $id = $entity.GetAttribute("id")
            $entities += [PSCustomObject]@{
                Id = $id
                Name = if ($nameMap.ContainsKey($id)) { $nameMap[$id] } else { "(unknown: $id)" }
                Path = $Path
            }
        }
    } catch {
        Add-ReadyError "Could not parse rule package XML '$Path': $($_.Exception.Message)"
    }
    return $entities
}

function Test-SettingsConfig {
    param([object]$SettingsJson)
    if (-not $SettingsJson) { return }

    $defaults = Get-ModuleDefaults
    $allowed = @($defaults.Keys) + @("mirrorLabels", "sitOverrides")
    foreach ($prop in $SettingsJson.PSObject.Properties) {
        if ($prop.Name -like "_*") { continue }
        if ($prop.Name -notin $allowed) {
            Add-ReadyWarning "settings.json contains unrecognized setting '$($prop.Name)'"
        }
    }

    if ($SettingsJson.deploymentTier -and $SettingsJson.deploymentTier -notin @("narrow", "wide", "full", "small", "medium", "large")) {
        Add-ReadyError "settings.json deploymentTier must be narrow, wide, full, small, medium, or large"
    }
}

function Test-LabelsConfig {
    param([array]$LabelsJson)

    $result = @{ LeafCodes = @{}; LabelNames = @{}; DlpCodes = @{} }
    if (-not $LabelsJson -or $LabelsJson.Count -eq 0) {
        Add-ReadyError "labels.json must contain at least one label"
        return $result
    }

    $names = @{}
    $codes = @{}
    $priorities = @{}
    $groupNames = @{}

    foreach ($label in $LabelsJson) {
        $context = "label '$($label.name)'"
        Test-RequiredProperty -Object $label -Property "name" -Context $context | Out-Null
        Test-RequiredProperty -Object $label -Property "displayName" -Context $context | Out-Null
        Test-RequiredProperty -Object $label -Property "priority" -Context $context | Out-Null
        Test-RequiredProperty -Object $label -Property "isGroup" -Context $context | Out-Null

        if ($label.name) {
            if ($names.ContainsKey($label.name)) { Add-ReadyWarning "Duplicate label name '$($label.name)'; verify this is intentional before label deployment." }
            $names[$label.name] = $true
            $result.LabelNames[$label.name] = $label
            Add-PurviewNameSafetyError -Result (Test-PurviewObjectNameSafety -Name $label.name -ObjectType "label name")
        }
        if ($null -ne $label.priority) {
            $p = $label.priority.ToString()
            if ($priorities.ContainsKey($p)) { Add-ReadyWarning "Duplicate label priority '$p'; verify this is intentional before label deployment." }
            $priorities[$p] = $true
        }
        if ($label.isGroup) {
            if ($label.code) { Add-ReadyWarning "Group label '$($label.name)' has a code; group labels are normally code-less" }
            $groupNames[$label.name] = $true
        } else {
            if ([string]::IsNullOrWhiteSpace($label.code)) {
                Add-ReadyError "Leaf label '$($label.name)' must have a code"
            } else {
                if ($codes.ContainsKey($label.code)) { Add-ReadyError "Duplicate label code '$($label.code)'" }
                $codes[$label.code] = $true
                $result.LeafCodes[$label.code] = $label
                if (-not $label.dlpExclude) { $result.DlpCodes[$label.code] = $label }
            }
        }
        if ($label.colour -and $label.colour -notmatch '^#[0-9a-fA-F]{6}$') {
            Add-ReadyWarning "Label '$($label.name)' colour '$($label.colour)' is not a #RRGGBB value"
        }
    }

    foreach ($label in $LabelsJson) {
        if ($label.parentGroup -and -not $groupNames.ContainsKey($label.parentGroup)) {
            Add-ReadyError "Label '$($label.name)' references missing parentGroup '$($label.parentGroup)'"
        }
    }

    return $result
}

function Test-PoliciesConfig {
    param([array]$PoliciesJson)

    $result = @{ PolicyCodes = @{} }
    if (-not $PoliciesJson -or $PoliciesJson.Count -eq 0) {
        Add-ReadyError "policies.json must contain at least one policy"
        return $result
    }

    $allowedLocations = @("ExchangeLocation", "OneDriveLocation", "SharePointLocation", "EndpointDlpLocation", "TeamsLocation")
    $numbers = @{}
    $codes = @{}

    foreach ($policy in $PoliciesJson) {
        $context = "policy '$($policy.code)'"
        Test-RequiredProperty -Object $policy -Property "number" -Context $context | Out-Null
        Test-RequiredProperty -Object $policy -Property "code" -Context $context | Out-Null
        Test-RequiredProperty -Object $policy -Property "location" -Context $context | Out-Null

        if ($null -ne $policy.number) {
            $n = $policy.number.ToString()
            if ($numbers.ContainsKey($n)) { Add-ReadyError "Duplicate policy number '$n'" }
            $numbers[$n] = $true
        }
        if ($policy.code) {
            if ($codes.ContainsKey($policy.code)) { Add-ReadyError "Duplicate policy code '$($policy.code)'" }
            $codes[$policy.code] = $true
            $result.PolicyCodes[$policy.code] = $policy
        }

        $locationProps = Get-JsonProperties $policy.location
        if ($locationProps.Count -eq 0) {
            Add-ReadyError "Policy '$($policy.code)' must define at least one location"
        }
        foreach ($loc in $locationProps) {
            if ($loc -notin $allowedLocations) {
                Add-ReadyError "Policy '$($policy.code)' uses unsupported location parameter '$loc'"
            }
        }

        if ($policy.scopeParam -and $policy.scopeParam -ne "AccessScope") {
            Add-ReadyError "Policy '$($policy.code)' has unsupported scopeParam '$($policy.scopeParam)'"
        }
        if ($policy.scopeParam -eq "AccessScope" -and [string]::IsNullOrWhiteSpace($policy.scopeValue)) {
            Add-ReadyError "Policy '$($policy.code)' has AccessScope but no scopeValue"
        }
    }

    return $result
}

function Test-ClassifiersConfig {
    param([object]$ClassifiersJson, [hashtable]$DlpCodes)

    $result = @{ SitIds = @{}; MlIds = @{}; ById = @{} }
    if (-not $ClassifiersJson) {
        Add-ReadyError "classifiers.json is missing or invalid"
        return $result
    }

    $classifierKeys = Get-JsonProperties $ClassifiersJson
    foreach ($code in $DlpCodes.Keys) {
        if ($classifierKeys -notcontains $code) {
            Add-ReadyWarning "DLP label code '$code' has no classifier list in classifiers.json; DLP rule generation will skip it."
        }
    }
    foreach ($code in $classifierKeys) {
        if (-not $DlpCodes.ContainsKey($code)) {
            Add-ReadyWarning "classifiers.json key '$code' does not match a non-excluded DLP label code"
        }

        $entries = @($ClassifiersJson.$code)
        if ($entries.Count -eq 0) {
            Add-ReadyError "Classifier list for '$code' is empty"
            continue
        }

        $idsInLabel = @{}
        foreach ($entry in $entries) {
            if ([string]::IsNullOrWhiteSpace($entry.name)) {
                Add-ReadyError "Classifier entry under '$code' is missing name"
            }
            if (-not (Test-GuidString -Value $entry.id)) {
                Add-ReadyError "Classifier '$($entry.name)' under '$code' has invalid GUID '$($entry.id)'"
                continue
            }

            $id = $entry.id.ToString().ToLowerInvariant()
            if ($idsInLabel.ContainsKey($id)) {
                Add-ReadyError "Duplicate classifier GUID '$($entry.id)' inside label '$code'"
            }
            $idsInLabel[$id] = $true

            if (-not $result.ById.ContainsKey($id)) {
                $result.ById[$id] = @{
                    Id = $entry.id
                    Name = $entry.name
                    Labels = @()
                    ClassifierType = if ($entry.classifierType -eq "MLModel") { "MLModel" } else { "SIT" }
                }
            }
            $result.ById[$id].Labels += $code

            if ($entry.classifierType) {
                if ($entry.classifierType -ne "MLModel") {
                    Add-ReadyError "Classifier '$($entry.name)' has unsupported classifierType '$($entry.classifierType)'"
                }
                $result.MlIds[$id] = $entry
            } else {
                $result.SitIds[$id] = $entry
                if ($entry.confidenceLevel -and $entry.confidenceLevel -notin @("Low", "Medium", "High")) {
                    Add-ReadyError "Classifier '$($entry.name)' has invalid confidenceLevel '$($entry.confidenceLevel)'"
                }
                if ($null -ne $entry.minCount -and [int]$entry.minCount -lt 1) {
                    Add-ReadyError "Classifier '$($entry.name)' minCount must be >= 1"
                }
                if ($null -ne $entry.maxCount -and [int]$entry.maxCount -ne -1 -and [int]$entry.maxCount -lt 1) {
                    Add-ReadyError "Classifier '$($entry.name)' maxCount must be -1 or >= 1"
                }
            }
        }
    }

    return $result
}

function Test-RuleOverridesConfig {
    param([object]$OverridesJson, [hashtable]$DlpCodes, [hashtable]$PolicyCodes)
    if (-not $OverridesJson) { return }

    $requiredSections = @("byLabel", "byPolicy", "byRule")
    foreach ($section in $requiredSections) {
        if ((Get-JsonProperties $OverridesJson) -notcontains $section) {
            Add-ReadyError "rule-overrides.json missing section '$section'"
        }
    }

    if ($OverridesJson.byLabel) {
        foreach ($prop in $OverridesJson.byLabel.PSObject.Properties) {
            if (-not $DlpCodes.ContainsKey($prop.Name)) {
                Add-ReadyError "rule-overrides.json byLabel key '$($prop.Name)' does not match a DLP label code"
            }
        }
    }
    if ($OverridesJson.byPolicy) {
        foreach ($prop in $OverridesJson.byPolicy.PSObject.Properties) {
            if (-not $PolicyCodes.ContainsKey($prop.Name)) {
                Add-ReadyError "rule-overrides.json byPolicy key '$($prop.Name)' does not match a policy code"
            }
        }
    }

    $knownRuleParams = @(
        "Disabled", "ReportSeverityLevel", "GenerateIncidentReport", "IncidentReportContent",
        "NotifyUser", "NotifyAllowOverride", "NotifyPolicyTipCustomText", "BlockAccess",
        "BlockAccessScope", "AccessScope", "StopPolicyProcessing", "ContentContainsSensitiveInformation",
        "AdvancedRule", "Comment"
    )
    foreach ($section in $requiredSections) {
        $sectionObj = $OverridesJson.$section
        if (-not $sectionObj) { continue }
        foreach ($outer in $sectionObj.PSObject.Properties) {
            foreach ($inner in $outer.Value.PSObject.Properties) {
                if ($inner.Name -notin $knownRuleParams) {
                    Add-ReadyWarning "rule-overrides.json $section/$($outer.Name) uses unverified rule parameter '$($inner.Name)'"
                }
            }
        }
    }
}

function Test-ClassifierRegistryAndXml {
    param([object]$RegistryJson, [string]$RequestedTier)

    $result = @{ LocalSitIds = @{}; PackageKeys = @{} }
    if (-not $RegistryJson -or -not $RegistryJson.packages) {
        Add-ReadyError "Package registry must contain packages"
        return $result
    }

    $keys = @{}
    $localIdOwners = @{}
    foreach ($pkg in @($RegistryJson.packages | Where-Object { (-not $_.PSObject.Properties["enabled"]) -or [bool]$_.enabled })) {
        if ([string]::IsNullOrWhiteSpace($pkg.key)) {
            Add-ReadyError "Enabled classifier package is missing key"
            continue
        }
        if ($keys.ContainsKey($pkg.key)) {
            Add-ReadyError "Duplicate classifier package key '$($pkg.key)'"
        }
        $keys[$pkg.key] = $true
        $result.PackageKeys[$pkg.key] = $pkg

        $filePath = Resolve-ReadinessPackageFile -Package $pkg -RequestedTier $RequestedTier
        if (-not $filePath) {
            Add-ReadyError "Classifier package '$($pkg.key)' has no usable XML variant"
            continue
        }

        $validation = Test-SITRulePackageXml -FilePath $filePath
        foreach ($err in $validation.Errors) {
            Add-ReadyError "Package '$($pkg.key)' XML invalid: $err"
        }
        foreach ($warn in $validation.Warnings) {
            Add-ReadyWarning "Package '$($pkg.key)' XML warning: $warn"
        }

        $entities = Get-RulePackageEntities -Path $filePath
        if ($null -ne $pkg.entities -and [int]$pkg.entities -ne $entities.Count) {
            Add-ReadyWarning "Package '$($pkg.key)' registry entity count is $($pkg.entities), XML contains $($entities.Count)"
        }
        if ($null -ne $pkg.sizeKB) {
            $actualSizeKb = [math]::Round((Get-Item -LiteralPath $filePath).Length / 1KB, 1)
            if ([math]::Abs([double]$pkg.sizeKB - $actualSizeKb) -gt 5.0) {
                Add-ReadyWarning "Package '$($pkg.key)' registry size is $($pkg.sizeKB)KB, XML is ${actualSizeKb}KB"
            }
        }
        foreach ($entity in $entities) {
            if (-not (Test-GuidString -Value $entity.Id)) {
                Add-ReadyError "Package '$($pkg.key)' entity '$($entity.Name)' has invalid GUID '$($entity.Id)'"
                continue
            }
            $id = $entity.Id.ToLowerInvariant()
            if ($localIdOwners.ContainsKey($id)) {
                Add-ReadyError "Classifier GUID '$($entity.Id)' appears in multiple local packages: $($localIdOwners[$id]) and $($pkg.key)"
            } else {
                $localIdOwners[$id] = $pkg.key
            }
            $result.LocalSitIds[$id] = $entity
        }
    }

    return $result
}

function Test-GeneratedDlpPayloads {
    param(
        [array]$LabelsJson,
        [array]$PoliciesJson,
        [object]$ClassifiersJson,
        [object]$OverridesJson,
        [object]$SettingsJson
    )

    if (-not $LabelsJson -or -not $PoliciesJson -or -not $ClassifiersJson) { return }

    try {
        $defaults = Get-ModuleDefaults
        $config = Merge-GlobalConfig -Defaults $defaults -GlobalJson $SettingsJson
        $labels = @(Resolve-LabelConfig -LabelsJson $LabelsJson)
        $policies = @(Resolve-PolicyConfig -PoliciesJson $PoliciesJson)
        $classifiers = Resolve-ClassifierConfig -ClassifiersJson $ClassifiersJson -Defaults $defaults
        $overrides = Resolve-RuleOverrides -OverridesJson $OverridesJson

        $ruleNames = @{}
        $policyNames = @{}
        foreach ($policy in $policies) {
            if (-not $policy.Enabled) { continue }
            $policyName = Get-PolicyName -PolicyNumber $policy.Number -PolicyCode $policy.Code -Prefix $config.namingPrefix -Suffix $config.namingSuffix
            if (-not $policyNames.ContainsKey($policyName)) {
                Add-PurviewNameSafetyError -Result (Test-PurviewObjectNameSafety -Name $policyName -ObjectType "generated DLP policy")
                $policyNames[$policyName] = $true
            }

            $ruleNum = 0
            foreach ($label in $labels) {
                $ruleNum++
                if (-not $classifiers.ContainsKey($label.code)) { continue }
                $ruleName = Get-RuleName -PolicyNumber $policy.Number -RuleNumber $ruleNum -PolicyCode $policy.Code -LabelCode $label.code -Suffix $config.namingSuffix
                Add-PurviewNameSafetyError -Result (Test-PurviewObjectNameSafety -Name $ruleName -ObjectType "generated DLP rule")
                if ($ruleNames.ContainsKey($ruleName)) {
                    Add-ReadyError "Generated duplicate DLP rule name '$ruleName'"
                }
                $ruleNames[$ruleName] = $true

                $condition = New-DLPSITCondition -ClassifierList $classifiers[$label.code] -ScopeParam $policy.ScopeParam -ScopeValue $policy.ScopeValue
                if ($condition.Format -eq "AdvancedRule") {
                    try {
                        $condition.Value | ConvertFrom-Json -ErrorAction Stop | Out-Null
                    } catch {
                        Add-ReadyError "Generated AdvancedRule JSON for '$ruleName' does not parse: $($_.Exception.Message)"
                    }
                }

                $baseRuleParams = @{
                    Name = $ruleName
                    Policy = $policyName
                    Comment = "$($label.fullName) ($($classifiers[$label.code].Count) classifiers)"
                    ReportSeverityLevel = if ($config.generateIncidentReport) { $config.incidentReportSeverity } else { "Low" }
                    Disabled = $false
                }
                Get-MergedRuleParams -BaseParams $baseRuleParams -Overrides $overrides -LabelCode $label.code -PolicyCode $policy.Code -RuleName $ruleName | Out-Null
            }
        }
    } catch {
        Add-ReadyError "Failed to build generated DLP rule payloads: $($_.Exception.Message)"
    }
}

function Test-TenantReadiness {
    param(
        [hashtable]$ClassifierIndex,
        [hashtable]$LocalSitIds,
        [switch]$CheckLabels,
        [switch]$CheckClassifiers,
        [switch]$CheckDlpRules
    )

    if ($CheckLabels) {
        try { Get-Label -ErrorAction Stop | Select-Object -First 1 | Out-Null }
        catch { Add-ReadyError "Tenant label cmdlets are not available or session is not connected: $($_.Exception.Message)" }
    }

    if ($CheckClassifiers) {
        try { Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop | Select-Object -First 1 | Out-Null }
        catch { Add-ReadyError "Tenant SIT rule package cmdlets are not available or session is not connected: $($_.Exception.Message)" }
    }

    if ($CheckDlpRules) {
        try { Get-DlpCompliancePolicy -ErrorAction Stop | Select-Object -First 1 | Out-Null }
        catch { Add-ReadyError "Tenant DLP policy cmdlets are not available or session is not connected: $($_.Exception.Message)" }
    }

    $tenantSits = @{}
    if ($CheckClassifiers -or $CheckDlpRules) {
        try {
            foreach ($sit in @(Get-DlpSensitiveInformationType -ErrorAction Stop)) {
                if ($sit.Id) { $tenantSits[$sit.Id.ToString().ToLowerInvariant()] = $sit }
            }
        } catch {
            Add-ReadyError "Could not retrieve tenant SIT inventory: $($_.Exception.Message)"
        }
    }

    if ($CheckDlpRules -and $ClassifierIndex) {
        foreach ($id in $ClassifierIndex.SitIds.Keys) {
            if (-not $tenantSits.ContainsKey($id)) {
                $entry = $ClassifierIndex.SitIds[$id]
                Add-ReadyError "Configured SIT '$($entry.name)' ($($entry.id)) is not present in the tenant"
            }
        }
    }

    if ($CheckClassifiers -and $ClassifierIndex -and $LocalSitIds) {
        foreach ($id in $ClassifierIndex.SitIds.Keys) {
            if (-not $LocalSitIds.ContainsKey($id) -and -not $tenantSits.ContainsKey($id)) {
                $entry = $ClassifierIndex.SitIds[$id]
                Add-ReadyError "Configured SIT '$($entry.name)' ($($entry.id)) is neither in local bundles nor tenant inventory"
            }
        }
    }

    if ($ClassifierIndex -and $ClassifierIndex.MlIds.Count -gt 0) {
        if ($TrainableClassifierInventory) {
            Test-TrainableClassifierInventory -MlIds $ClassifierIndex.MlIds -Path $TrainableClassifierInventory
        } else {
            Add-ReadyWarning "$($ClassifierIndex.MlIds.Count) trainable classifier reference(s) found; no trainable classifier inventory supplied. Use -TrainableClassifierInventory to validate MLModel IDs."
        }
    }
}

function Test-TrainableClassifierInventory {
    param([hashtable]$MlIds, [string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        Add-ReadyError "Trainable classifier inventory not found: $Path"
        return
    }

    $inventoryIds = @{}
    try {
        if ($Path -like "*.csv") {
            foreach ($row in @(Import-Csv -LiteralPath $Path -ErrorAction Stop)) {
                if ($row.Id) { $inventoryIds[$row.Id.ToString().ToLowerInvariant()] = $true }
            }
        } else {
            $json = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -ErrorAction Stop
            $items = @()
            if ($json.TrainableClassifiers.Aggregates) { $items = @($json.TrainableClassifiers.Aggregates) }
            elseif ($json.Aggregates) { $items = @($json.Aggregates) }
            else { $items = @($json) }
            foreach ($item in $items) {
                if ($item.Id) { $inventoryIds[$item.Id.ToString().ToLowerInvariant()] = $true }
            }
        }
    } catch {
        Add-ReadyError "Could not parse trainable classifier inventory '$Path': $($_.Exception.Message)"
        return
    }

    foreach ($id in $MlIds.Keys) {
        if (-not $inventoryIds.ContainsKey($id)) {
            $entry = $MlIds[$id]
            Add-ReadyError "Configured trainable classifier '$($entry.name)' ($($entry.id)) is not present in supplied inventory"
        }
    }
}

function Test-ClassifierBundleManifest {
    $manifestScript = Join-Path $PSScriptRoot "Update-ClassifierBundleManifest.ps1"
    if (-not (Test-Path -LiteralPath $manifestScript)) {
        Add-ReadyWarning "Classifier bundle manifest script not found; skipping version-increment manifest check."
        return
    }

    try {
        $result = @(& $manifestScript -CheckOnly -NoExit)
        if ($result.Count -eq 0 -or $result[-1] -ne $true) {
            Add-ReadyWarning "Classifier bundle manifest is missing, stale, or has XML changes without version increments"
        }
    } catch {
        Add-ReadyWarning "Classifier bundle manifest check failed: $($_.Exception.Message)"
    }
}

$expandedScope = @()
if ($Scope -contains "All") {
    $expandedScope = @("Labels", "Classifiers", "DLPRules")
} else {
    $expandedScope = @($Scope | Sort-Object -Unique)
}

Write-Host "=== Deployment Readiness Gate ===" -ForegroundColor Cyan
Write-Host "  Scope: $($expandedScope -join ', ')" -ForegroundColor Gray

$settingsJson = Read-JsonFile -Path (Join-Path $ConfigPath "settings.json") -Description "deployment settings" -Required
$labelsJson = Read-JsonFile -Path (Join-Path $ConfigPath "labels.json") -Description "label definitions" -Required
$policiesJson = Read-JsonFile -Path (Join-Path $ConfigPath "policies.json") -Description "policy definitions" -Required
$classifiersJson = Read-JsonFile -Path (Join-Path $ConfigPath "classifiers.json") -Description "classifier definitions" -Required
$deployRegistryPath = Join-Path $DeployDir "deploy-registry.json"
$legacyRegistryPath = Join-Path $ConfigPath "classifiers-registry.json"
$registryPath = if (Test-Path -LiteralPath $deployRegistryPath) { $deployRegistryPath } else { $legacyRegistryPath }
$registryJson = Read-JsonFile -Path $registryPath -Description "package registry" -Required
$overridesJson = Read-JsonFile -Path (Join-Path $ConfigPath "rule-overrides.json") -Description "rule overrides" -Required

if (-not $Tier -and $registryJson -and $registryJson.tier) { $Tier = $registryJson.tier }
if (-not $Tier -and $settingsJson -and $settingsJson.deploymentTier) { $Tier = $settingsJson.deploymentTier }
if (-not $Tier) { $Tier = "full" }
Write-Host "  Tier:  $Tier" -ForegroundColor Gray

$defaultsForPrefix = Get-ModuleDefaults
$effectiveSettings = Merge-GlobalConfig -Defaults $defaultsForPrefix -GlobalJson $settingsJson
$effectiveSettings = Set-DeploymentConfigPrefix -Config $effectiveSettings -Prefix $Prefix
if ($Prefix -and $settingsJson) {
    $settingsJson.namingPrefix = $effectiveSettings.namingPrefix
    $settingsJson.sitPrefix = $effectiveSettings.sitPrefix
    $settingsJson.labelPolicyName = $effectiveSettings.labelPolicyName
}

Test-SettingsConfig -SettingsJson $settingsJson
$labelResult = Test-LabelsConfig -LabelsJson @($labelsJson)
$policyResult = Test-PoliciesConfig -PoliciesJson @($policiesJson)
$classifierResult = Test-ClassifiersConfig -ClassifiersJson $classifiersJson -DlpCodes $labelResult.DlpCodes
Test-RuleOverridesConfig -OverridesJson $overridesJson -DlpCodes $labelResult.DlpCodes -PolicyCodes $policyResult.PolicyCodes
$registryResult = Test-ClassifierRegistryAndXml -RegistryJson $registryJson -RequestedTier $Tier
Test-ClassifierBundleManifest
Test-GeneratedDlpPayloads -LabelsJson @($labelsJson) -PoliciesJson @($policiesJson) -ClassifiersJson $classifiersJson -OverridesJson $overridesJson -SettingsJson $settingsJson

if ($Connect) {
    if (-not (Connect-DLPSession -UPN $UPN -Tenant $Tenant -Delegated:$Delegated)) {
        Add-ReadyError "Could not connect to Security & Compliance Center"
    }
}

if ($RequireTenant -or $Connect) {
    $fingerprint = Test-DeploymentTenantFingerprint -ProjectRoot $ProjectRoot -TargetEnvironment $TargetEnvironment
    Write-Host "`n=== Tenant Fingerprint ===" -ForegroundColor Cyan
    Write-Host "  Environment: $($fingerprint.environment)" -ForegroundColor Gray
    Write-Host "  Mode:        $($fingerprint.mode)" -ForegroundColor Gray
    if ($fingerprint.actual.name) { Write-Host "  Tenant:      $($fingerprint.actual.name)" -ForegroundColor Gray }
    if ($fingerprint.actual.guid) { Write-Host "  Tenant GUID: $($fingerprint.actual.guid)" -ForegroundColor Gray }
    foreach ($message in @($fingerprint.messages)) {
        $color = if (-not $fingerprint.passed) { "Red" } elseif ($fingerprint.configured -and $fingerprint.matched) { "Green" } else { "Yellow" }
        Write-Host "  $message" -ForegroundColor $color
    }
    foreach ($mismatch in @($fingerprint.mismatches)) {
        Write-Host "  MISMATCH $($mismatch.field): expected '$($mismatch.expected)', actual '$($mismatch.actual)'" -ForegroundColor Red
    }
    if (-not $fingerprint.passed) {
        Add-ReadyError "Tenant fingerprint check failed for environment '$($fingerprint.environment)'"
    }

    Test-TenantReadiness `
        -ClassifierIndex $classifierResult `
        -LocalSitIds $registryResult.LocalSitIds `
        -CheckLabels:($expandedScope -contains "Labels") `
        -CheckClassifiers:($expandedScope -contains "Classifiers") `
        -CheckDlpRules:($expandedScope -contains "DLPRules")
}

Write-Host "`n=== Readiness Summary ===" -ForegroundColor Cyan
if ($script:Errors.Count -eq 0) {
    Write-Host "  Errors:   0" -ForegroundColor Green
} else {
    Write-Host "  Errors:   $($script:Errors.Count)" -ForegroundColor Red
    foreach ($err in $script:Errors) {
        Write-Host "    - $err" -ForegroundColor Red
    }
}

if ($script:Warnings.Count -eq 0) {
    Write-Host "  Warnings: 0" -ForegroundColor Green
} else {
    Write-Host "  Warnings: $($script:Warnings.Count)" -ForegroundColor Yellow
    foreach ($warn in $script:Warnings) {
        Write-Host "    - $warn" -ForegroundColor Yellow
    }
}

$passed = ($script:Errors.Count -eq 0)
if ($passed) {
    Write-Host "`nRESULT: PASS" -ForegroundColor Green
} else {
    Write-Host "`nRESULT: FAIL" -ForegroundColor Red
}

if ($NoExit) {
    return $passed
}

exit $(if ($passed) { 0 } else { 1 })
