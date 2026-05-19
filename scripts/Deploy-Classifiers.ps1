#==============================================================================
# Deploy-Classifiers.ps1
# Deploys Australian Custom SIT Rule Packages to Microsoft Purview.
#
# Features:
#   - Pre-flight comparison of local vs deployed packages (version, entities, dates)
#   - Auto-backup of existing packages before overwriting
#   - DLP rule dependency checking for removed SITs
#   - Impact reporting across bundles, classifiers, DLP rules, policies, and labels
#   - Interactive prompts for conflict resolution (Replace/Skip/Abort)
#   - Auto-increment of XML version numbers when local <= deployed
#   - Tenant capacity estimation (packages, SITs, sizes)
#   - Guards against empty rulePackId matching all packages
#
# Usage:
#   .\scripts\Deploy-Classifiers.ps1                              # Guided plan-first workflow
#   .\scripts\Deploy-Classifiers.ps1 -Connect                     # Guided workflow, connect first
#   .\scripts\Deploy-Classifiers.ps1 -Action Validate               # Local XML check
#   .\scripts\Deploy-Classifiers.ps1 -Action Upload -Connect        # Upload all
#   .\scripts\Deploy-Classifiers.ps1 -Action Upload -Tier narrow -Connect
#   .\scripts\Deploy-Classifiers.ps1 -Action Impact -Connect        # Dependency/impact report
#   .\scripts\Deploy-Classifiers.ps1 -Action Impact -ImpactMode Remove -Connect
#   .\scripts\Deploy-Classifiers.ps1 -Action CapacityPlan -Connect  # Slot/refactor plan
#   .\scripts\Deploy-Classifiers.ps1 -Action AdoptPlan -Connect     # Existing tenant package adoption/rebase plan
#   .\scripts\Deploy-Classifiers.ps1 -Action Prune -Connect         # Select existing tenant packages to delete
#   .\scripts\Deploy-Classifiers.ps1 -Action Canary -Connect       # Create/update/remove disposable canary package
#   .\scripts\Deploy-Classifiers.ps1 -Action List -Connect
#   .\scripts\Deploy-Classifiers.ps1 -Action Remove -PackageNames DocClass -Connect
#   .\scripts\Deploy-Classifiers.ps1 -Action Rollback -PackageNames DocClass -Connect
#   .\scripts\Deploy-Classifiers.ps1 -Action Estimate -Connect      # Capacity report
#   .\scripts\Deploy-Classifiers.ps1 -Action Upload -WhatIf         # Dry run
#   .\scripts\Deploy-Classifiers.ps1 -Action Upload -SkipPreFlight  # Skip prompts
#   .\scripts\Deploy-Classifiers.ps1 -Action Remove -SkipPreFlight  # Skip dependency prompt
#==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("Interactive", "Upload", "Remove", "Rollback", "List", "Validate", "Estimate", "Impact", "CapacityPlan", "AdoptPlan", "Prune", "Canary")]
    [string]$Action = "Interactive",

    [string[]]$PackageNames = @("All"),

    [ValidateSet("Replace", "Remove")]
    [string]$ImpactMode = "Replace",

    [ValidateSet("narrow", "wide", "full", "small", "medium", "large")]
    [string]$Tier,

    [string]$Publisher,
    [string]$BackupPath,
    [string]$TargetEnvironment,
    [string]$Scope = "universal,en-government,au",

    [switch]$Connect,
    [string]$UPN,
    [string]$Tenant,
    [switch]$Delegated,
    [switch]$SkipPreFlight,
    [switch]$SkipDictionarySync,
    [switch]$CanaryKeepPackage
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "config"
$XmlDir      = Join-Path $ProjectRoot "xml"
$BackupDir   = Join-Path (Join-Path $ProjectRoot "backups") "classifiers"

# Import shared module
Import-Module (Join-Path (Join-Path $ProjectRoot "modules") "DLP-Deploy.psm1") -Force

#region Config
$Defaults  = Get-ModuleDefaults
$settingsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
$Config    = Merge-GlobalConfig -Defaults $Defaults -GlobalJson $settingsJson

# Load package registry. Compl8's packager writes xml/deploy/deploy-registry.json;
# the older registry shape is still accepted for migrated repos.
$DeployDir = Join-Path $XmlDir "deploy"
$deployRegistryPath = Join-Path $DeployDir "deploy-registry.json"
$legacyRegistryPath = Join-Path $ConfigPath "classifiers-registry.json"
$registryPath = if (Test-Path -LiteralPath $deployRegistryPath) { $deployRegistryPath } else { $legacyRegistryPath }
$registryDescription = if ($registryPath -eq $deployRegistryPath) { "deploy registry" } else { "classifier registry" }
$registryJson = Import-JsonConfig -FilePath $registryPath -Description $registryDescription
if (-not $registryJson) {
    Write-Error "Failed to load package registry. Run build-deploy-packages.py first or provide config/classifiers-registry.json."
    return
}

# Resolve tier and publisher from params, deploy registry, or config
if (-not $Tier -and $registryJson.tier) { $Tier = $registryJson.tier }
if (-not $Tier)      { $Tier      = $Config.deploymentTier }
if (-not $Publisher) { $Publisher = $Config.publisher }

# Build package lookup
$Packages = @{}
foreach ($pkg in $registryJson.packages) {
    if (-not $pkg.PSObject.Properties["displayName"]) {
        $pkg | Add-Member -NotePropertyName "displayName" -NotePropertyValue $pkg.key
    }
    if (-not $pkg.PSObject.Properties["description"]) {
        $pkg | Add-Member -NotePropertyName "description" -NotePropertyValue ""
    }
    if (-not $pkg.PSObject.Properties["rulePackId"]) {
        $pkg | Add-Member -NotePropertyName "rulePackId" -NotePropertyValue $null
    }
    $isEnabled = (-not $pkg.PSObject.Properties["enabled"]) -or [bool]$pkg.enabled
    if ($isEnabled) {
        $Packages[$pkg.key] = $pkg
    }
}
#endregion

function Invoke-ReadinessGate {
    param(
        [ValidateSet("All", "Labels", "Classifiers", "DLPRules")]
        [string[]]$Scope
    )

    $readinessScript = Join-Path $ProjectRoot "scripts\Test-DeploymentReadiness.ps1"
    if (-not (Test-Path -LiteralPath $readinessScript)) {
        Write-Error "Readiness gate script not found: $readinessScript"
        return $false
    }

    Write-Host "`n=== Pre-Deployment Readiness ===" -ForegroundColor Cyan
    $params = @{
        Scope         = $Scope
        Tier          = $Tier
        RequireTenant = $true
        NoExit        = $true
    }

    $result = @(& $readinessScript @params)
    if ($result.Count -eq 0 -or $result[-1] -ne $true) {
        Write-Error "Deployment readiness failed. Aborting before classifier bundle changes."
        return $false
    }

    return $true
}

function Test-DLPSessionAvailable {
    param([string]$CommandToTest = "Get-DlpSensitiveInformationTypeRulePackage")

    try {
        & $CommandToTest -ErrorAction Stop | Select-Object -First 1 | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Invoke-TenantFingerprintGate {
    $fingerprint = Test-DeploymentTenantFingerprint -ProjectRoot $ProjectRoot -TargetEnvironment $TargetEnvironment
    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.tenantFingerprint = $fingerprint
    }

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
        if ($script:DeploymentManifest) {
            Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Error" -Data @{
                message = "Tenant fingerprint mismatch"
                environment = $fingerprint.environment
                mode = $fingerprint.mode
            }
        }
        Write-Error "Tenant fingerprint check failed. Aborting before tenant changes."
        return $false
    }

    return $true
}

#region Helpers - Package Selection & File Resolution
function Get-SelectedPackages {
    if ($PackageNames -contains "All") {
        return $Packages.Keys
    }
    $valid = @()
    foreach ($name in $PackageNames) {
        if ($Packages.ContainsKey($name)) {
            $valid += $name
        } else {
            Write-Warning "Package '$name' not found in registry. Available: $($Packages.Keys -join ', ')"
        }
    }
    return $valid
}

function Resolve-PackageFile {
    param([object]$Package, [string]$RequestedTier)

    if (-not $Package.variants) {
        return Join-Path $DeployDir "$($Package.key).xml"
    }

    $variants = @{}
    foreach ($prop in $Package.variants.PSObject.Properties) {
        $variants[$prop.Name] = $prop.Value
    }

    if ($variants.ContainsKey($RequestedTier)) {
        return Join-Path $XmlDir $variants[$RequestedTier]
    }
    if ($variants.ContainsKey("full")) {
        Write-Host "    Tier '$RequestedTier' not available, using 'full'" -ForegroundColor Yellow
        return Join-Path $XmlDir $variants["full"]
    }
    $firstKey = $variants.Keys | Select-Object -First 1
    Write-Host "    Tier '$RequestedTier' not available, using '$firstKey'" -ForegroundColor Yellow
    return Join-Path $XmlDir $variants[$firstKey]
}
#endregion

#region Helpers - XML Parsing
function Read-RulePackageText {
    <#
    .SYNOPSIS
        Reads a rule package XML file using BOM detection, defaulting to UTF-8.
    #>
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

    # The narrow/wide generated packages are UTF-8 without BOM. Treat no-BOM
    # XML as UTF-8, then upload as UTF-16 as Purview expects.
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

function ConvertTo-PurviewUtf16Bytes {
    <#
    .SYNOPSIS
        Encodes rule-package XML as UTF-16LE with a BOM for Purview upload.
    #>
    param([Parameter(Mandatory)][string]$Content)

    $encoding = [System.Text.UnicodeEncoding]::new($false, $true)
    $body = $encoding.GetBytes($Content.TrimStart([char]0xFEFF))
    $preamble = $encoding.GetPreamble()
    $bytes = New-Object byte[] ($preamble.Length + $body.Length)
    [System.Array]::Copy($preamble, 0, $bytes, 0, $preamble.Length)
    [System.Array]::Copy($body, 0, $bytes, $preamble.Length, $body.Length)
    return ,$bytes
}

function Get-DictionaryPlaceholderMap {
    param([Parameter(Mandatory)][string[]]$Selected)

    if ($script:DictionaryGuidMap) { return $script:DictionaryGuidMap }

    $placeholders = @{}
    foreach ($name in @($Selected | Sort-Object)) {
        if (-not $Packages.ContainsKey($name)) { continue }
        $filePath = Resolve-PackageFile -Package $Packages[$name] -RequestedTier $Tier
        if (-not (Test-Path -LiteralPath $filePath)) { continue }
        $content = Read-RulePackageText -FilePath $filePath
        foreach ($match in [regex]::Matches($content, '\{\{DICT_[A-Z0-9_]+\}\}')) {
            $placeholders[$match.Value] = $true
        }
    }

    if ($placeholders.Count -eq 0) {
        $script:DictionaryGuidMap = @{}
        return $script:DictionaryGuidMap
    }

    Write-Host "`n=== Keyword Dictionary Placeholder Resolution ===" -ForegroundColor Cyan
    Write-Host "  Found $($placeholders.Count) dictionary placeholder(s) in selected packages." -ForegroundColor Gray
    if ($SkipDictionarySync) {
        Write-Warning "Dictionary sync skipped. Upload will fail if placeholders remain unresolved."
        $script:DictionaryGuidMap = @{}
        return $script:DictionaryGuidMap
    }

    $manifestUrl = "https://testpattern.dev/api/export/dictionary-manifest?scope=$Scope"
    $script:DictionaryGuidMap = Sync-DlpKeywordDictionaries -ManifestUrl $manifestUrl -WhatIf:$WhatIfPreference

    foreach ($placeholder in @($placeholders.Keys | Sort-Object)) {
        if (-not $script:DictionaryGuidMap.ContainsKey($placeholder)) {
            Write-Warning "No dictionary GUID resolved for $placeholder"
        }
    }

    return $script:DictionaryGuidMap
}

function Resolve-RulePackageUploadContent {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [hashtable]$DictionaryGuidMap
    )

    $content = Read-RulePackageText -FilePath $FilePath
    $content = $content -replace '<PublisherName>[^<]+</PublisherName>', "<PublisherName>$Publisher</PublisherName>"

    if ($Config.sitPrefix) {
        $content = $content -replace 'TestPattern - ', "$($Config.sitPrefix) - "
    }

    if ($DictionaryGuidMap) {
        foreach ($kv in $DictionaryGuidMap.GetEnumerator()) {
            $content = $content -replace [regex]::Escape($kv.Key), $kv.Value
        }
    }

    $unresolved = @([regex]::Matches($content, '\{\{DICT_[A-Z0-9_]+\}\}') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    if ($unresolved.Count -gt 0) {
        throw "Unresolved keyword dictionary placeholder(s): $($unresolved -join ', '). Run without -SkipDictionarySync or check dictionary manifest scope '$Scope'."
    }

    return $content
}

function Get-LocalPackageInfo {
    <#
    .SYNOPSIS
        Parses a local SIT rule package XML file and extracts metadata.
    #>
    param([string]$FilePath)

    try {
        $content = Read-RulePackageText -FilePath $FilePath
        $xml = [xml]$content
    } catch {
        try {
            $content = Get-Content $FilePath -Raw -ErrorAction Stop
            $xml = [xml]$content
        } catch {
            return $null
        }
    }

    $rulePack = $xml.RulePackage.RulePack
    if (-not $rulePack) { return $null }

    $version = $rulePack.Version
    $rulePackId = $rulePack.id

    $rules = $xml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq "Rules" }
    $nameMap = @{}
    $entities = @()

    if ($rules) {
        $entities = @($rules.ChildNodes | Where-Object { $_.LocalName -eq "Entity" })
        $localizedStrings = $rules.ChildNodes | Where-Object { $_.LocalName -eq "LocalizedStrings" }
        if ($localizedStrings) {
            foreach ($resource in @($localizedStrings.ChildNodes)) {
                if ($resource.LocalName -eq "Resource") {
                    $nameNode = $resource.ChildNodes | Where-Object { $_.LocalName -eq "Name" } | Select-Object -First 1
                    if ($nameNode) {
                        $nameMap[$resource.idRef] = $nameNode.InnerText
                    }
                }
            }
        }
    }

    $entityInfo = @()
    foreach ($e in $entities) {
        $entityInfo += @{
            Id   = $e.id
            Name = if ($nameMap.ContainsKey($e.id)) { $nameMap[$e.id] } else { "(unknown: $($e.id))" }
        }
    }

    return @{
        Version     = @{
            Major    = [int]$version.major
            Minor    = [int]$version.minor
            Build    = [int]$version.build
            Revision = [int]$version.revision
        }
        VersionStr  = "$($version.major).$($version.minor).$($version.build).$($version.revision)"
        RulePackId  = $rulePackId
        Entities    = $entityInfo
        EntityCount = $entityInfo.Count
        FileSize    = (Get-Item $FilePath).Length
    }
}

function Get-DeployedPackageInfo {
    <#
    .SYNOPSIS
        Extracts metadata from a deployed rule package object.
        Tries to parse SerializedClassificationRuleCollection for version and entity detail.
    #>
    param([object]$DeployedPackage)

    $info = @{
        Identity    = $DeployedPackage.Identity
        Name        = $DeployedPackage.Name
        Publisher   = $DeployedPackage.Publisher
        RulePackId  = $null
        Description = $null
        CreatedUTC  = $DeployedPackage.WhenCreatedUTC
        ModifiedUTC = $DeployedPackage.WhenChangedUTC
        Version     = $null
        VersionStr  = "(unknown)"
        Entities    = @()
        EntityCount = -1
        RawXml      = $null
        RawBytes    = $null
    }

    if (-not $DeployedPackage.SerializedClassificationRuleCollection) { return $info }

    try {
        $bytes = $DeployedPackage.SerializedClassificationRuleCollection
        $info.RawBytes = $bytes
        $xmlContent = [System.Text.Encoding]::Unicode.GetString($bytes)
        $info.RawXml = $xmlContent
        $xml = [xml]$xmlContent

        $rulePack = $xml.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq "RulePack" } | Select-Object -First 1
        if ($rulePack -and $rulePack.Version) {
            $info.RulePackId = $rulePack.id
            $v = $rulePack.Version
            $info.Version = @{
                Major    = [int]$v.major
                Minor    = [int]$v.minor
                Build    = [int]$v.build
                Revision = [int]$v.revision
            }
            $info.VersionStr = "$($v.major).$($v.minor).$($v.build).$($v.revision)"
        }
        if ($rulePack) {
            $details = $rulePack.ChildNodes | Where-Object { $_.LocalName -eq "Details" } | Select-Object -First 1
            $localized = if ($details) { $details.ChildNodes | Where-Object { $_.LocalName -eq "LocalizedDetails" } | Select-Object -First 1 } else { $null }
            if ($localized) {
                $publisherNode = $localized.ChildNodes | Where-Object { $_.LocalName -eq "PublisherName" } | Select-Object -First 1
                $nameNode = $localized.ChildNodes | Where-Object { $_.LocalName -eq "Name" } | Select-Object -First 1
                $descriptionNode = $localized.ChildNodes | Where-Object { $_.LocalName -eq "Description" } | Select-Object -First 1
                if (-not $info.Publisher -and $publisherNode) { $info.Publisher = $publisherNode.InnerText }
                if (-not $info.Name -and $nameNode) { $info.Name = $nameNode.InnerText }
                if ($descriptionNode) { $info.Description = $descriptionNode.InnerText }
            }
        }

        $rules = $xml.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq "Rules" }
        if ($rules) {
            $entities = @($rules.ChildNodes | Where-Object { $_.LocalName -eq "Entity" })
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
            $entityInfo = @()
            foreach ($e in $entities) {
                $entityInfo += @{
                    Id   = $e.id
                    Name = if ($nameMap.ContainsKey($e.id)) { $nameMap[$e.id] } else { "(unknown: $($e.id))" }
                }
            }
            $info.Entities = $entityInfo
            $info.EntityCount = $entityInfo.Count
        }
    } catch {
        Write-Host "    Could not parse deployed package XML: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    return $info
}
#endregion

#region Helpers - Comparison & Diffing
function Compare-PackageVersions {
    <#
    .SYNOPSIS
        Compares two version hashtables. Returns -1 (local older), 0 (same), 1 (local newer).
    #>
    param([hashtable]$Local, [hashtable]$Deployed)

    if (-not $Local -or -not $Deployed) { return $null }
    if ($Local.Major -ne $Deployed.Major) { return [math]::Sign($Local.Major - $Deployed.Major) }
    if ($Local.Minor -ne $Deployed.Minor) { return [math]::Sign($Local.Minor - $Deployed.Minor) }
    if ($Local.Build -ne $Deployed.Build) { return [math]::Sign($Local.Build - $Deployed.Build) }
    return [math]::Sign($Local.Revision - $Deployed.Revision)
}

function Get-EntityDiff {
    <#
    .SYNOPSIS
        Compares local and deployed entity lists. Returns added, removed, unchanged arrays.
    #>
    param([array]$LocalEntities, [array]$DeployedEntities)

    $localIds    = @{}
    foreach ($e in $LocalEntities)    { $localIds[$e.Id.ToLower()] = $e.Name }
    $deployedIds = @{}
    foreach ($e in $DeployedEntities) { $deployedIds[$e.Id.ToLower()] = $e.Name }

    $added     = @()
    $removed   = @()
    $unchanged = @()

    foreach ($id in $localIds.Keys) {
        if ($deployedIds.ContainsKey($id)) {
            $unchanged += @{ Id = $id; Name = $localIds[$id] }
        } else {
            $added += @{ Id = $id; Name = $localIds[$id] }
        }
    }
    foreach ($id in $deployedIds.Keys) {
        if (-not $localIds.ContainsKey($id)) {
            $removed += @{ Id = $id; Name = $deployedIds[$id] }
        }
    }

    return @{
        Added     = $added
        Removed   = $removed
        Unchanged = $unchanged
    }
}

function Test-SITRuleDependencies {
    <#
    .SYNOPSIS
        Checks all DLP compliance rules for references to the given SIT GUIDs.
        Returns array of @{ RuleName; PolicyName; MatchedGuids }.
    #>
    param([string[]]$SitGuids)

    if ($SitGuids.Count -eq 0) { return @() }

    $dependencies = @()
    try {
        $rules = @(Get-DlpComplianceRule -ErrorAction Stop)
    } catch {
        Write-Warning "Could not retrieve DLP rules for dependency check: $($_.Exception.Message)"
        return @()
    }

    foreach ($rule in $rules) {
        $ruleContent = ""
        if ($rule.ContentContainsSensitiveInformation) {
            try { $ruleContent += ($rule.ContentContainsSensitiveInformation | ConvertTo-Json -Depth 10 -Compress) } catch { }
        }
        if ($rule.AdvancedRule) {
            $ruleContent += $rule.AdvancedRule
        }
        if (-not $ruleContent) { continue }

        $matchedGuids = @()
        foreach ($guid in $SitGuids) {
            if ($ruleContent -match [regex]::Escape($guid)) {
                $matchedGuids += $guid
            }
        }

        if ($matchedGuids.Count -gt 0) {
            $dependencies += @{
                RuleName     = $rule.Name
                PolicyName   = $rule.ParentPolicyName
                MatchedGuids = $matchedGuids
            }
        }
    }

    return $dependencies
}
#endregion

#region Helpers - Backup, Version Bump, Package Matching
function Backup-DeployedPackage {
    <#
    .SYNOPSIS
        Saves the deployed package XML to a timestamped backup file.
    #>
    param(
        [string]$PackageName,
        [hashtable]$DeployedInfo
    )

    if (-not $DeployedInfo.RawBytes -and -not $DeployedInfo.RawXml) {
        Write-Host "    No XML content available for backup." -ForegroundColor Yellow
        return $null
    }

    if (-not (Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeId = ($DeployedInfo.Identity -replace '[^a-zA-Z0-9\-]', '')
    $backupFile = Join-Path $BackupDir "${PackageName}_${safeId}_${timestamp}.xml"

    try {
        if ($DeployedInfo.RawBytes) {
            [System.IO.File]::WriteAllBytes($backupFile, $DeployedInfo.RawBytes)
        } else {
            [System.IO.File]::WriteAllText($backupFile, $DeployedInfo.RawXml, [System.Text.Encoding]::Unicode)
        }
        Write-Host "    Backed up to: $(Split-Path $backupFile -Leaf)" -ForegroundColor Gray
        return $backupFile
    } catch {
        Write-Warning "    Failed to create backup: $($_.Exception.Message)"
        return $null
    }
}

function Get-BumpedVersion {
    <#
    .SYNOPSIS
        Returns a new version hashtable with revision incremented past the deployed version.
        Returns $null if no bump is needed (local already newer).
    #>
    param(
        [hashtable]$LocalVersion,
        [hashtable]$DeployedVersion
    )

    $cmp = Compare-PackageVersions -Local $LocalVersion -Deployed $DeployedVersion
    if ($null -eq $cmp -or $cmp -gt 0) {
        return $null  # Local is already newer
    }

    # Bump: take the deployed version and increment revision
    return @{
        Major    = $DeployedVersion.Major
        Minor    = $DeployedVersion.Minor
        Build    = $DeployedVersion.Build
        Revision = $DeployedVersion.Revision + 1
    }
}

function Update-ContentVersion {
    <#
    .SYNOPSIS
        Replaces the <Version> element in an XML content string with the given version.
    #>
    param(
        [string]$Content,
        [hashtable]$NewVersion
    )

    $pattern = '<Version\s+major="\d+"\s+minor="\d+"\s+build="\d+"\s+revision="\d+"\s*/>'
    $replacement = "<Version major=`"$($NewVersion.Major)`" minor=`"$($NewVersion.Minor)`" build=`"$($NewVersion.Build)`" revision=`"$($NewVersion.Revision)`"/>"
    return $Content -replace $pattern, $replacement
}

function Find-DeployedMatch {
    <#
    .SYNOPSIS
        Finds a deployed package matching the given registry entry.
        Guards against empty rulePackId matching everything.
    #>
    param(
        [object]$RegistryPackage,
        [hashtable]$DeployedLookup
    )

    foreach ($key in $DeployedLookup.Keys) {
        $deployed = $DeployedLookup[$key]

        # Match by GUID - only if rulePackId is non-empty
        if ($RegistryPackage.rulePackId -and $RegistryPackage.rulePackId.Trim() -ne "") {
            if ($key -match [regex]::Escape($RegistryPackage.rulePackId)) {
                return $deployed
            }
        }

        # Match by display name
        if ($deployed.Name -and $RegistryPackage.displayName) {
            if ($deployed.Name -match [regex]::Escape($RegistryPackage.displayName)) {
                return $deployed
            }
        }

        # Match by registry key for deploy-registry.json packages.
        if ($RegistryPackage.key -and $deployed.Name) {
            if ($deployed.Name -match [regex]::Escape($RegistryPackage.key)) {
                return $deployed
            }
        }
    }

    return $null
}

function Format-VersionString {
    param([hashtable]$Version)
    if (-not $Version) { return "(unknown)" }
    return "$($Version.Major).$($Version.Minor).$($Version.Build).$($Version.Revision)"
}

function Add-ClassifierIndexEntry {
    param(
        [Parameter(Mandatory)][hashtable]$Index,
        [Parameter(Mandatory)][string]$Id,
        [string]$Name,
        [string]$PackageKey,
        [string]$Source
    )

    if ([string]::IsNullOrWhiteSpace($Id)) { return }
    $key = $Id.ToLowerInvariant()
    if (-not $Index.ContainsKey($key)) {
        $Index[$key] = @{
            Id       = $Id
            Name     = $Name
            Packages = @()
            Sources  = @()
        }
    }
    if ($Name -and -not $Index[$key].Name) {
        $Index[$key].Name = $Name
    }
    if ($PackageKey -and $Index[$key].Packages -notcontains $PackageKey) {
        $Index[$key].Packages += $PackageKey
    }
    if ($Source -and $Index[$key].Sources -notcontains $Source) {
        $Index[$key].Sources += $Source
    }
}

function Get-NormalizedClassifierName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    return (($Name.ToLowerInvariant() -replace '[^a-z0-9]+', ' ').Trim() -replace '\s+', ' ')
}

function Get-LocalPackageIndex {
    param([Parameter(Mandatory)][string[]]$PackageKeys)

    $result = @{
        ById     = @{}
        Packages = @{}
        Missing  = @()
    }

    foreach ($name in @($PackageKeys | Sort-Object)) {
        if (-not $Packages.ContainsKey($name)) { continue }
        $pkg = $Packages[$name]
        $filePath = Resolve-PackageFile -Package $pkg -RequestedTier $Tier
        if (-not (Test-Path $filePath)) {
            $result.Missing += $name
            continue
        }

        $localInfo = Get-LocalPackageInfo -FilePath $filePath
        if (-not $localInfo) {
            $result.Missing += $name
            continue
        }

        $result.Packages[$name] = $localInfo
        foreach ($entity in @($localInfo.Entities)) {
            Add-ClassifierIndexEntry -Index $result.ById -Id $entity.Id -Name $entity.Name -PackageKey $name -Source "local"
        }
    }

    return $result
}

function Get-DeployedPackageLookup {
    $deployed = @()
    try {
        $deployed = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)
    } catch {
        Write-Warning "Could not retrieve deployed SIT rule packages: $($_.Exception.Message)"
    }

    $lookup = @{}
    foreach ($d in $deployed) {
        if ($d -and $d.Identity) {
            $lookup[$d.Identity] = $d
        }
    }
    return $lookup
}

function Get-DeployedPackageIndex {
    param(
        [Parameter(Mandatory)][hashtable]$DeployedLookup,
        [Parameter(Mandatory)][string[]]$PackageKeys
    )

    $result = @{
        ById       = @{}
        Packages   = @{}
        Missing    = @()
        MatchedIds = @{}
    }

    foreach ($name in @($PackageKeys | Sort-Object)) {
        if (-not $Packages.ContainsKey($name)) { continue }
        $pkg = $Packages[$name]
        $match = Find-DeployedMatch -RegistryPackage $pkg -DeployedLookup $DeployedLookup
        if (-not $match) {
            $result.Missing += $name
            continue
        }

        $info = Get-DeployedPackageInfo -DeployedPackage $match
        $result.Packages[$name] = $info
        if ($match.Identity) {
            $result.MatchedIds[$match.Identity.ToString()] = $name
        }
        foreach ($entity in @($info.Entities)) {
            Add-ClassifierIndexEntry -Index $result.ById -Id $entity.Id -Name $entity.Name -PackageKey $name -Source "deployed"
        }
    }

    return $result
}

function Get-ConfiguredClassifierIndex {
    $result = @{
        ById       = @{}
        LabelNames = @{}
        Loaded     = $false
    }

    $labelsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "labels.json") -Description "label definitions"
    if ($labelsJson) {
        foreach ($label in $labelsJson) {
            if ($label.code) {
                $result.LabelNames[$label.code] = if ($label.displayName) { $label.displayName } else { $label.name }
            }
        }
    }

    $classifiersJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "classifiers.json") -Description "classifier definitions"
    if (-not $classifiersJson) {
        return $result
    }

    foreach ($prop in $classifiersJson.PSObject.Properties) {
        $labelCode = $prop.Name
        $labelName = if ($result.LabelNames.ContainsKey($labelCode)) { $result.LabelNames[$labelCode] } else { $labelCode }

        foreach ($item in @($prop.Value)) {
            if (-not $item.id) { continue }
            $id = $item.id.ToString()
            $key = $id.ToLowerInvariant()
            $classifierType = if ($item.classifierType -eq "MLModel") { "MLModel" } else { "SIT" }

            if (-not $result.ById.ContainsKey($key)) {
                $result.ById[$key] = @{
                    Id             = $id
                    Name           = $item.name
                    ClassifierType = $classifierType
                    LabelCodes     = @()
                    LabelNames     = @()
                }
            }

            if ($result.ById[$key].LabelCodes -notcontains $labelCode) {
                $result.ById[$key].LabelCodes += $labelCode
            }
            if ($result.ById[$key].LabelNames -notcontains $labelName) {
                $result.ById[$key].LabelNames += $labelName
            }
        }
    }

    $result.Loaded = $true
    return $result
}

function Get-TenantSitIndex {
    $index = @{}
    try {
        $tenantSits = @(Get-DlpSensitiveInformationType -ErrorAction Stop)
        foreach ($sit in $tenantSits) {
            if ($sit.Id) {
                $index[$sit.Id.ToString().ToLowerInvariant()] = $sit
            }
        }
    } catch {
        Write-Warning "Could not retrieve tenant SIT inventory: $($_.Exception.Message)"
    }
    return $index
}

function Get-DlpRuleReferenceIndex {
    param([Parameter(Mandatory)][string[]]$CandidateIds)

    $candidateLookup = @{}
    foreach ($id in $CandidateIds) {
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $candidateLookup[$id.ToLowerInvariant()] = $true
        }
    }

    $result = @{
        ById          = @{}
        RulesScanned  = 0
        MatchingRules = 0
    }
    if ($candidateLookup.Count -eq 0) { return $result }

    $rules = @()
    try {
        $rules = @(Get-DlpComplianceRule -ErrorAction Stop)
    } catch {
        Write-Warning "Could not retrieve DLP rules for impact analysis: $($_.Exception.Message)"
        return $result
    }

    $guidPattern = '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
    foreach ($rule in $rules) {
        $result.RulesScanned++
        $ruleContent = ""
        if ($rule.ContentContainsSensitiveInformation) {
            try { $ruleContent += ($rule.ContentContainsSensitiveInformation | ConvertTo-Json -Depth 20 -Compress) } catch { }
        }
        if ($rule.AdvancedRule) {
            $ruleContent += $rule.AdvancedRule
        }
        if (-not $ruleContent) { continue }

        $matchedInRule = @()
        foreach ($match in [regex]::Matches($ruleContent, $guidPattern)) {
            $id = $match.Value.ToLowerInvariant()
            if ($candidateLookup.ContainsKey($id) -and $matchedInRule -notcontains $id) {
                $matchedInRule += $id
            }
        }
        if ($matchedInRule.Count -eq 0) { continue }

        $result.MatchingRules++
        $policyName = if ($rule.ParentPolicyName) { $rule.ParentPolicyName } elseif ($rule.Policy) { ($rule.Policy -join ",") } else { "(unknown)" }
        foreach ($id in $matchedInRule) {
            if (-not $result.ById.ContainsKey($id)) {
                $result.ById[$id] = @()
            }
            $result.ById[$id] += [PSCustomObject]@{
                RuleName   = $rule.Name
                PolicyName = $policyName
            }
        }
    }

    return $result
}

function New-ClassifierImpactAnalysis {
    param(
        [ValidateSet("Replace", "Remove")][string]$Mode = "Replace",
        [Parameter(Mandatory)][string[]]$SelectedKeys
    )

    $deployedLookup = Get-DeployedPackageLookup
    $allPackageKeys = @($Packages.Keys | Sort-Object)
    $localIndex = Get-LocalPackageIndex -PackageKeys $allPackageKeys
    $deployedIndex = Get-DeployedPackageIndex -DeployedLookup $deployedLookup -PackageKeys $allPackageKeys
    $configIndex = Get-ConfiguredClassifierIndex
    $tenantSitIndex = Get-TenantSitIndex

    $packageImpacts = @()
    $removedIds = @()
    $addedIds = @()

    foreach ($name in @($SelectedKeys | Sort-Object)) {
        if (-not $Packages.ContainsKey($name)) { continue }

        $pkg = $Packages[$name]
        $localInfo = if ($localIndex.Packages.ContainsKey($name)) { $localIndex.Packages[$name] } else { $null }
        $existingPkg = Find-DeployedMatch -RegistryPackage $pkg -DeployedLookup $deployedLookup
        $deployedInfo = if ($existingPkg) { Get-DeployedPackageInfo -DeployedPackage $existingPkg } else { $null }

        $added = @()
        $removed = @()
        $unchanged = @()
        $status = "Unknown"

        if ($Mode -eq "Remove") {
            if ($deployedInfo) {
                $status = "RemoveDeployed"
                $removed = @($deployedInfo.Entities)
            } else {
                $status = "NotDeployed"
            }
        } else {
            if ($deployedInfo -and $localInfo) {
                $status = "Replace"
                $diff = Get-EntityDiff -LocalEntities $localInfo.Entities -DeployedEntities $deployedInfo.Entities
                $added = @($diff.Added)
                $removed = @($diff.Removed)
                $unchanged = @($diff.Unchanged)
            } elseif ($localInfo) {
                $status = "NewPackage"
                $added = @($localInfo.Entities)
            } elseif ($deployedInfo) {
                $status = "LocalMissing"
                $removed = @($deployedInfo.Entities)
            } else {
                $status = "MissingLocalAndTenant"
            }
        }

        foreach ($entity in $removed) {
            if ($entity.Id) { $removedIds += $entity.Id.ToString().ToLowerInvariant() }
        }
        foreach ($entity in $added) {
            if ($entity.Id) { $addedIds += $entity.Id.ToString().ToLowerInvariant() }
        }

        $packageImpacts += [PSCustomObject]@{
            PackageKey   = $name
            DisplayName  = $pkg.displayName
            Status       = $status
            LocalInfo    = $localInfo
            DeployedInfo = $deployedInfo
            Added        = $added
            Removed      = $removed
            Unchanged    = $unchanged
        }
    }

    $candidateIds = @{}
    foreach ($id in @($removedIds + $addedIds + $localIndex.ById.Keys + $deployedIndex.ById.Keys + $configIndex.ById.Keys)) {
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $candidateIds[$id.ToString().ToLowerInvariant()] = $true
        }
    }
    $ruleRefs = Get-DlpRuleReferenceIndex -CandidateIds @($candidateIds.Keys)

    return [PSCustomObject]@{
        Mode            = $Mode
        SelectedKeys    = @($SelectedKeys)
        PackageImpacts  = $packageImpacts
        RemovedIds      = @($removedIds | Sort-Object -Unique)
        AddedIds        = @($addedIds | Sort-Object -Unique)
        LocalIndex      = $localIndex
        DeployedIndex   = $deployedIndex
        ConfigIndex     = $configIndex
        TenantSitIndex  = $tenantSitIndex
        RuleRefs        = $ruleRefs
    }
}

function Get-ClassifierLabelsText {
    param([object]$ConfigEntry)
    if (-not $ConfigEntry) { return "(not referenced by classifiers.json)" }
    if ($ConfigEntry.LabelCodes.Count -eq 0) { return "(no labels)" }
    return ($ConfigEntry.LabelCodes | Sort-Object -Unique) -join ", "
}

function Get-ClassifierRuleRefs {
    param([object]$Analysis, [string]$Id)
    $key = $Id.ToLowerInvariant()
    if ($Analysis.RuleRefs.ById.ContainsKey($key)) {
        return @($Analysis.RuleRefs.ById[$key])
    }
    return @()
}

function Test-ImpactHasRuleDependencies {
    param([object]$Analysis)
    foreach ($id in @($Analysis.RemovedIds)) {
        if ((Get-ClassifierRuleRefs -Analysis $Analysis -Id $id).Count -gt 0) {
            return $true
        }
    }
    return $false
}

function Write-ClassifierImpactReport {
    param(
        [Parameter(Mandatory)][object]$Analysis,
        [switch]$IncludeServiceability
    )

    Write-Host "`n=== Classifier Bundle Impact ($($Analysis.Mode), Tier: $Tier) ===" -ForegroundColor Cyan
    Write-Host "  Packages selected: $($Analysis.SelectedKeys -join ', ')" -ForegroundColor Gray
    Write-Host "  DLP rules scanned: $($Analysis.RuleRefs.RulesScanned) ($($Analysis.RuleRefs.MatchingRules) with known classifier references)" -ForegroundColor Gray

    foreach ($impact in @($Analysis.PackageImpacts)) {
        Write-Host "`n--- $($impact.PackageKey): $($impact.Status) ---" -ForegroundColor White
        if ($impact.DeployedInfo) {
            Write-Host "  Deployed: v$($impact.DeployedInfo.VersionStr), $($impact.DeployedInfo.EntityCount) SITs" -ForegroundColor Gray
        } else {
            Write-Host "  Deployed: not found" -ForegroundColor Gray
        }
        if ($impact.LocalInfo) {
            Write-Host "  Local:    v$($impact.LocalInfo.VersionStr), $($impact.LocalInfo.EntityCount) SITs" -ForegroundColor Gray
        } else {
            Write-Host "  Local:    not found for tier '$Tier'" -ForegroundColor Yellow
        }

        Write-Host "  Changes:  +$($impact.Added.Count) / -$($impact.Removed.Count) / =$($impact.Unchanged.Count)" -ForegroundColor Gray

        if ($impact.Removed.Count -gt 0) {
            Write-Host "  Removed classifiers:" -ForegroundColor Red
            foreach ($entity in @($impact.Removed | Sort-Object Name)) {
                $id = $entity.Id.ToString().ToLowerInvariant()
                $configEntry = if ($Analysis.ConfigIndex.ById.ContainsKey($id)) { $Analysis.ConfigIndex.ById[$id] } else { $null }
                $refs = Get-ClassifierRuleRefs -Analysis $Analysis -Id $id
                $labelText = Get-ClassifierLabelsText -ConfigEntry $configEntry
                $ruleText = if ($refs.Count -gt 0) { "$($refs.Count) DLP rule(s)" } else { "no DLP rule refs found" }
                $color = if ($refs.Count -gt 0) { "Red" } elseif ($configEntry) { "Yellow" } else { "DarkGray" }
                Write-Host "    - $($entity.Name) ($($entity.Id))" -ForegroundColor $color
                Write-Host "      Labels: $labelText; Rules: $ruleText" -ForegroundColor $color
                foreach ($ref in @($refs | Select-Object -First 8)) {
                    Write-Host "        Rule: $($ref.RuleName) / Policy: $($ref.PolicyName)" -ForegroundColor Red
                }
                if ($refs.Count -gt 8) {
                    Write-Host "        ... $($refs.Count - 8) more rule reference(s)" -ForegroundColor Red
                }
            }
        }

        if ($impact.Added.Count -gt 0) {
            Write-Host "  Added classifiers:" -ForegroundColor Green
            foreach ($entity in @($impact.Added | Sort-Object Name)) {
                $id = $entity.Id.ToString().ToLowerInvariant()
                $configEntry = if ($Analysis.ConfigIndex.ById.ContainsKey($id)) { $Analysis.ConfigIndex.ById[$id] } else { $null }
                $labelText = Get-ClassifierLabelsText -ConfigEntry $configEntry
                $color = if ($configEntry) { "Green" } else { "Yellow" }
                Write-Host "    + $($entity.Name) ($($entity.Id))" -ForegroundColor $color
                Write-Host "      Labels: $labelText" -ForegroundColor $color
            }
        }
    }

    $affectedLabels = @{}
    $affectedRules = @{}
    foreach ($id in @($Analysis.RemovedIds)) {
        if ($Analysis.ConfigIndex.ById.ContainsKey($id)) {
            foreach ($label in @($Analysis.ConfigIndex.ById[$id].LabelCodes)) {
                $affectedLabels[$label] = $true
            }
        }
        foreach ($ref in Get-ClassifierRuleRefs -Analysis $Analysis -Id $id) {
            $affectedRules[$ref.RuleName] = $ref.PolicyName
        }
    }

    Write-Host "`n=== Impact Summary ===" -ForegroundColor Cyan
    Write-Host "  Removed classifier IDs: $($Analysis.RemovedIds.Count)" -ForegroundColor $(if ($Analysis.RemovedIds.Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Added classifier IDs:   $($Analysis.AddedIds.Count)" -ForegroundColor Gray
    Write-Host "  Affected labels:        $($affectedLabels.Count)" -ForegroundColor $(if ($affectedLabels.Count -gt 0) { "Yellow" } else { "Green" })
    if ($affectedLabels.Count -gt 0) {
        Write-Host "    $((@($affectedLabels.Keys) | Sort-Object) -join ', ')" -ForegroundColor Yellow
    }
    Write-Host "  Affected DLP rules:     $($affectedRules.Count)" -ForegroundColor $(if ($affectedRules.Count -gt 0) { "Red" } else { "Green" })
    foreach ($ruleName in @($affectedRules.Keys | Sort-Object)) {
        Write-Host "    $ruleName / Policy: $($affectedRules[$ruleName])" -ForegroundColor Red
    }

    if (-not $IncludeServiceability) { return }

    $configSitIds = @($Analysis.ConfigIndex.ById.Keys | Where-Object { $Analysis.ConfigIndex.ById[$_].ClassifierType -ne "MLModel" })
    $configMlIds = @($Analysis.ConfigIndex.ById.Keys | Where-Object { $Analysis.ConfigIndex.ById[$_].ClassifierType -eq "MLModel" })
    $missingConfigSits = @()
    $externalConfigSits = @()
    foreach ($id in $configSitIds) {
        $inLocal = $Analysis.LocalIndex.ById.ContainsKey($id)
        $inTenant = $Analysis.TenantSitIndex.ContainsKey($id)
        if (-not $inLocal -and -not $inTenant) {
            $missingConfigSits += $id
        } elseif (-not $inLocal -and $inTenant) {
            $externalConfigSits += $id
        }
    }

    $unusedLocalSits = @($Analysis.LocalIndex.ById.Keys | Where-Object { -not $Analysis.ConfigIndex.ById.ContainsKey($_) })
    $tenantDriftSits = @($Analysis.DeployedIndex.ById.Keys | Where-Object { -not $Analysis.LocalIndex.ById.ContainsKey($_) })

    Write-Host "`n=== Serviceability Checks ===" -ForegroundColor Cyan
    Write-Host "  Configured SITs:        $($configSitIds.Count)" -ForegroundColor Gray
    Write-Host "  Configured ML models:   $($configMlIds.Count) (not managed by XML bundles)" -ForegroundColor Gray
    Write-Host "  Config SITs external to local bundles but present in tenant: $($externalConfigSits.Count)" -ForegroundColor Yellow
    Write-Host "  Config SITs missing from both tenant and local bundles:      $($missingConfigSits.Count)" -ForegroundColor $(if ($missingConfigSits.Count -gt 0) { "Red" } else { "Green" })
    foreach ($id in @($missingConfigSits | Select-Object -First 15)) {
        $entry = $Analysis.ConfigIndex.ById[$id]
        Write-Host "    MISSING: $($entry.Name) ($($entry.Id)) labels: $(Get-ClassifierLabelsText -ConfigEntry $entry)" -ForegroundColor Red
    }
    if ($missingConfigSits.Count -gt 15) {
        Write-Host "    ... $($missingConfigSits.Count - 15) more missing configured SIT(s)" -ForegroundColor Red
    }

    Write-Host "  Local bundled SITs not referenced by classifiers.json:       $($unusedLocalSits.Count)" -ForegroundColor $(if ($unusedLocalSits.Count -gt 0) { "Yellow" } else { "Green" })
    foreach ($id in @($unusedLocalSits | Select-Object -First 15)) {
        $entry = $Analysis.LocalIndex.ById[$id]
        Write-Host "    UNUSED: $($entry.Name) ($($entry.Id)) packages: $(($entry.Packages | Sort-Object -Unique) -join ', ')" -ForegroundColor Yellow
    }
    if ($unusedLocalSits.Count -gt 15) {
        Write-Host "    ... $($unusedLocalSits.Count - 15) more unused local SIT(s)" -ForegroundColor Yellow
    }

    Write-Host "  Deployed package SITs not represented by local tier files:    $($tenantDriftSits.Count)" -ForegroundColor $(if ($tenantDriftSits.Count -gt 0) { "Yellow" } else { "Green" })
    foreach ($id in @($tenantDriftSits | Select-Object -First 15)) {
        $entry = $Analysis.DeployedIndex.ById[$id]
        Write-Host "    DRIFT: $($entry.Name) ($($entry.Id)) packages: $(($entry.Packages | Sort-Object -Unique) -join ', ')" -ForegroundColor Yellow
    }
    if ($tenantDriftSits.Count -gt 15) {
        Write-Host "    ... $($tenantDriftSits.Count - 15) more deployed drift SIT(s)" -ForegroundColor Yellow
    }
}

function Get-ImpactStats {
    param([Parameter(Mandatory)][object]$Analysis)

    $affectedLabels = @{}
    $affectedRules = @{}
    foreach ($id in @($Analysis.RemovedIds)) {
        if ($Analysis.ConfigIndex.ById.ContainsKey($id)) {
            foreach ($label in @($Analysis.ConfigIndex.ById[$id].LabelCodes)) {
                $affectedLabels[$label] = $true
            }
        }
        foreach ($ref in Get-ClassifierRuleRefs -Analysis $Analysis -Id $id) {
            $affectedRules[$ref.RuleName] = $ref.PolicyName
        }
    }

    $recreateRecommended = $false
    foreach ($impact in @($Analysis.PackageImpacts)) {
        if ($impact.Status -eq "Replace" -and $impact.Removed.Count -gt 0) {
            $recreateRecommended = $true
            break
        }
    }

    return [PSCustomObject]@{
        RemovedIds          = $Analysis.RemovedIds.Count
        AddedIds            = $Analysis.AddedIds.Count
        AffectedLabels      = $affectedLabels.Count
        AffectedRules       = $affectedRules.Count
        HasRuleDependencies = ($affectedRules.Count -gt 0)
        RecreateRecommended = $recreateRecommended
    }
}

function New-ClassifierCapacityPlan {
    param([Parameter(Mandatory)][string[]]$SelectedKeys)

    $deployedLookup = Get-DeployedPackageLookup
    $localIndex = Get-LocalPackageIndex -PackageKeys $SelectedKeys

    $localNameIndex = @{}
    foreach ($packageKey in @($localIndex.Packages.Keys)) {
        foreach ($entity in @($localIndex.Packages[$packageKey].Entities)) {
            $nameKey = Get-NormalizedClassifierName -Name $entity.Name
            if (-not $nameKey) { continue }
            if (-not $localNameIndex.ContainsKey($nameKey)) {
                $localNameIndex[$nameKey] = @()
            }
            $localNameIndex[$nameKey] += [PSCustomObject]@{
                Id         = $entity.Id
                Name       = $entity.Name
                PackageKey = $packageKey
            }
        }
    }

    $candidateIds = @{}
    foreach ($id in @($localIndex.ById.Keys)) {
        $candidateIds[$id] = $true
    }

    $deployedPackages = @()
    foreach ($deployed in @($deployedLookup.Values)) {
        $info = Get-DeployedPackageInfo -DeployedPackage $deployed
        foreach ($entity in @($info.Entities)) {
            if ($entity.Id) { $candidateIds[$entity.Id.ToString().ToLowerInvariant()] = $true }
        }
        $deployedPackages += [PSCustomObject]@{
            Deployed = $deployed
            Info     = $info
        }
    }

    $ruleRefs = Get-DlpRuleReferenceIndex -CandidateIds @($candidateIds.Keys)
    $existingPlans = @()
    foreach ($entry in @($deployedPackages | Sort-Object { $_.Info.Name }, { $_.Info.RulePackId })) {
        $info = $entry.Info
        $idOverlaps = @()
        $nameOverlaps = @()
        $packageRuleNames = @{}

        foreach ($entity in @($info.Entities)) {
            if (-not $entity.Id) { continue }
            $idKey = $entity.Id.ToString().ToLowerInvariant()
            if ($localIndex.ById.ContainsKey($idKey)) {
                $idOverlaps += [PSCustomObject]@{
                    Id              = $entity.Id
                    Name            = $entity.Name
                    LocalPackages   = @($localIndex.ById[$idKey].Packages)
                    LocalEntityName = $localIndex.ById[$idKey].Name
                }
            }

            $nameKey = Get-NormalizedClassifierName -Name $entity.Name
            if ($nameKey -and $localNameIndex.ContainsKey($nameKey)) {
                foreach ($localMatch in @($localNameIndex[$nameKey])) {
                    if ($localMatch.Id.ToString().ToLowerInvariant() -ne $idKey) {
                        $nameOverlaps += [PSCustomObject]@{
                            DeployedId  = $entity.Id
                            LocalId     = $localMatch.Id
                            Name        = $entity.Name
                            LocalPackage = $localMatch.PackageKey
                        }
                    }
                }
            }

            foreach ($ref in @(Get-ClassifierRuleRefs -Analysis ([PSCustomObject]@{ RuleRefs = $ruleRefs }) -Id $entity.Id)) {
                $packageRuleNames[$ref.RuleName] = $ref.PolicyName
            }
        }

        $recommendation = "KeepCandidate"
        $reason = "No ID/name overlap with selected local bundles."
        if ($idOverlaps.Count -gt 0) {
            $recommendation = "RemoveBeforeDeploy"
            $reason = "Contains classifier IDs that are also in selected local bundles."
        } elseif ($nameOverlaps.Count -gt 0) {
            $recommendation = "ReviewNameClash"
            $reason = "Contains classifier names that also exist locally with different IDs."
        } elseif ($info.EntityCount -eq 0) {
            $recommendation = "InspectOrRemove"
            $reason = "No entities were parsed from the package; inspect before keeping."
        }

        $existingPlans += [PSCustomObject]@{
            Identity       = $info.Identity
            Name           = $info.Name
            Publisher      = $info.Publisher
            RulePackId     = $info.RulePackId
            Version        = $info.VersionStr
            EntityCount    = $info.EntityCount
            SizeBytes      = if ($info.RawBytes) { $info.RawBytes.Length } else { $null }
            IdOverlaps     = @($idOverlaps)
            NameOverlaps   = @($nameOverlaps)
            ReferencedRules = @($packageRuleNames.Keys | Sort-Object | ForEach-Object {
                [PSCustomObject]@{ RuleName = $_; PolicyName = $packageRuleNames[$_] }
            })
            Recommendation = $recommendation
            Reason         = $reason
            DeployedPackage = $entry.Deployed
            Info           = $info
        }
    }

    $localPackages = @()
    foreach ($packageKey in @($SelectedKeys | Sort-Object)) {
        if (-not $localIndex.Packages.ContainsKey($packageKey)) { continue }
        $info = $localIndex.Packages[$packageKey]
        $overlappingExisting = @()
        foreach ($existing in @($existingPlans)) {
            $idHit = @($existing.IdOverlaps | Where-Object { $_.LocalPackages -contains $packageKey }).Count
            $nameHit = @($existing.NameOverlaps | Where-Object { $_.LocalPackage -eq $packageKey }).Count
            if ($idHit -gt 0 -or $nameHit -gt 0) {
                $overlappingExisting += [PSCustomObject]@{
                    RulePackId   = $existing.RulePackId
                    Name         = $existing.Name
                    IdOverlaps   = $idHit
                    NameOverlaps = $nameHit
                }
            }
        }

        $localPackages += [PSCustomObject]@{
            PackageKey          = $packageKey
            Version             = $info.VersionStr
            EntityCount         = $info.EntityCount
            SizeBytes           = $info.FileSize
            OverlappingExisting = @($overlappingExisting)
        }
    }

    $customSlotsUsed = @($existingPlans).Count
    $selectedLocalCount = @($localPackages).Count
    $slotsAvailable = 10 - $customSlotsUsed
    $removalsRequiredForAll = [math]::Max(0, $selectedLocalCount - $slotsAvailable)
    $maxExistingCanKeepForAll = [math]::Max(0, 10 - $selectedLocalCount)

    return [PSCustomObject]@{
        SelectedKeys              = @($SelectedKeys)
        CustomSlotsUsed           = $customSlotsUsed
        SlotsAvailable            = $slotsAvailable
        SelectedLocalPackageCount = $selectedLocalCount
        RemovalsRequiredForAll    = $removalsRequiredForAll
        MaxExistingCanKeepForAll  = $maxExistingCanKeepForAll
        ExistingPackages          = @($existingPlans)
        LocalPackages             = @($localPackages)
        RuleRefsScanned           = $ruleRefs.RulesScanned
        MatchingRuleCount         = $ruleRefs.MatchingRules
    }
}

function Convert-CapacityPlanForManifest {
    param([Parameter(Mandatory)][object]$Plan)

    return [ordered]@{
        customSlotsUsed = $Plan.CustomSlotsUsed
        slotsAvailable = $Plan.SlotsAvailable
        selectedLocalPackageCount = $Plan.SelectedLocalPackageCount
        removalsRequiredForAll = $Plan.RemovalsRequiredForAll
        maxExistingCanKeepForAll = $Plan.MaxExistingCanKeepForAll
        ruleRefsScanned = $Plan.RuleRefsScanned
        matchingRuleCount = $Plan.MatchingRuleCount
        existingPackages = @($Plan.ExistingPackages | ForEach-Object {
            [ordered]@{
                name = $_.Name
                rulePackId = $_.RulePackId
                version = $_.Version
                entityCount = $_.EntityCount
                sizeBytes = $_.SizeBytes
                idOverlapCount = @($_.IdOverlaps).Count
                nameOverlapCount = @($_.NameOverlaps).Count
                referencedRuleCount = @($_.ReferencedRules).Count
                recommendation = $_.Recommendation
                reason = $_.Reason
                referencedRules = @($_.ReferencedRules | ForEach-Object { [ordered]@{ ruleName = $_.RuleName; policyName = $_.PolicyName } })
            }
        })
        localPackages = @($Plan.LocalPackages | ForEach-Object {
            [ordered]@{
                packageKey = $_.PackageKey
                version = $_.Version
                entityCount = $_.EntityCount
                sizeBytes = $_.SizeBytes
                overlappingExisting = @($_.OverlappingExisting | ForEach-Object {
                    [ordered]@{
                        name = $_.Name
                        rulePackId = $_.RulePackId
                        idOverlaps = $_.IdOverlaps
                        nameOverlaps = $_.NameOverlaps
                    }
                })
            }
        })
    }
}

function Write-ClassifierCapacityPlanReport {
    param([Parameter(Mandatory)][object]$Plan)

    Write-Host "`n=== Classifier Capacity / Refactor Plan ===" -ForegroundColor Cyan
    Write-Host "  Existing custom packages: $($Plan.CustomSlotsUsed)/10" -ForegroundColor Gray
    Write-Host "  Selected local bundles:   $($Plan.SelectedLocalPackageCount)" -ForegroundColor Gray
    Write-Host "  Available slots now:      $($Plan.SlotsAvailable)" -ForegroundColor Gray
    Write-Host "  DLP rules scanned:        $($Plan.RuleRefsScanned) ($($Plan.MatchingRuleCount) with selected/deployed classifier refs)" -ForegroundColor Gray

    if ($Plan.RemovalsRequiredForAll -gt 0) {
        Write-Host "  Required change: remove at least $($Plan.RemovalsRequiredForAll) existing custom package(s) to deploy all selected local bundles." -ForegroundColor Red
        Write-Host "  You can keep at most $($Plan.MaxExistingCanKeepForAll) existing custom package(s) if all $($Plan.SelectedLocalPackageCount) local bundles are deployed." -ForegroundColor Yellow
    } else {
        Write-Host "  Required change: enough package slots are available for selected local bundles." -ForegroundColor Green
    }

    Write-Host "`n--- Existing Package Keep/Remove View ---" -ForegroundColor White
    $idx = 0
    foreach ($existing in @($Plan.ExistingPackages)) {
        $idx++
        $name = if ($existing.Name) { $existing.Name } else { "(unnamed package)" }
        $sizeText = if ($existing.SizeBytes) { "$([math]::Round($existing.SizeBytes / 1KB, 1))KB" } else { "unknown size" }
        $idOverlapCount = @($existing.IdOverlaps).Count
        $nameOverlapCount = @($existing.NameOverlaps).Count
        $refCount = @($existing.ReferencedRules).Count
        $color = switch ($existing.Recommendation) {
            "RemoveBeforeDeploy" { "Red" }
            "ReviewNameClash"    { "Yellow" }
            "InspectOrRemove"    { "Yellow" }
            default              { "Green" }
        }

        Write-Host ("  {0}. [{1}] {2}" -f $idx, $existing.Recommendation, $name) -ForegroundColor $color
        Write-Host "     RulePackId: $($existing.RulePackId)" -ForegroundColor DarkGray
        Write-Host "     Version: $($existing.Version); Entities: $($existing.EntityCount); Size: $sizeText; Referenced rules: $refCount" -ForegroundColor DarkGray
        Write-Host "     Reason: $($existing.Reason)" -ForegroundColor $color
        if ($idOverlapCount -gt 0) {
            Write-Host "     ID overlaps with local bundles: $idOverlapCount" -ForegroundColor Red
            foreach ($hit in @($existing.IdOverlaps | Select-Object -First 8)) {
                Write-Host "       - $($hit.Name) ($($hit.Id)) -> $($hit.LocalPackages -join ', ')" -ForegroundColor Red
            }
        }
        if ($nameOverlapCount -gt 0) {
            Write-Host "     Name clashes with different IDs: $nameOverlapCount" -ForegroundColor Yellow
            foreach ($hit in @($existing.NameOverlaps | Select-Object -First 8)) {
                Write-Host "       - $($hit.Name): deployed $($hit.DeployedId), local $($hit.LocalId) in $($hit.LocalPackage)" -ForegroundColor Yellow
            }
        }
        if ($refCount -gt 0) {
            Write-Host "     Referenced by DLP rules:" -ForegroundColor Red
            foreach ($ref in @($existing.ReferencedRules | Select-Object -First 8)) {
                Write-Host "       - $($ref.RuleName) / $($ref.PolicyName)" -ForegroundColor Red
            }
        }
    }

    Write-Host "`n--- Local Bundle View ---" -ForegroundColor White
    foreach ($local in @($Plan.LocalPackages | Sort-Object PackageKey)) {
        $overlapCount = @($local.OverlappingExisting).Count
        $color = if ($overlapCount -gt 0) { "Yellow" } else { "Green" }
        Write-Host "  $($local.PackageKey): $($local.EntityCount) SITs, v$($local.Version), $([math]::Round($local.SizeBytes / 1KB, 1))KB" -ForegroundColor $color
        if ($overlapCount -gt 0) {
            foreach ($overlap in @($local.OverlappingExisting)) {
                $pkgName = if ($overlap.Name) { $overlap.Name } else { $overlap.RulePackId }
                Write-Host "     overlaps existing '$pkgName' (ID: $($overlap.IdOverlaps), name: $($overlap.NameOverlaps))" -ForegroundColor Yellow
            }
        }
    }
}

function Get-XmlChildElement {
    param(
        [Parameter(Mandatory)][System.Xml.XmlNode]$Node,
        [Parameter(Mandatory)][string]$LocalName
    )

    return @($Node.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -eq $LocalName } | Select-Object -First 1)
}

function Get-RulePackageRulesElement {
    param([Parameter(Mandatory)][xml]$Xml)
    return Get-XmlChildElement -Node $Xml.DocumentElement -LocalName "Rules"
}

function Get-RulePackageRulePackElement {
    param([Parameter(Mandatory)][xml]$Xml)
    return Get-XmlChildElement -Node $Xml.DocumentElement -LocalName "RulePack"
}

function Get-RulePackageLocalizedStringsElement {
    param([Parameter(Mandatory)][xml]$Xml)

    $rules = Get-RulePackageRulesElement -Xml $Xml
    if (-not $rules) { return $null }
    return Get-XmlChildElement -Node $rules -LocalName "LocalizedStrings"
}

function Get-XmlIdRefValues {
    param([Parameter(Mandatory)][System.Xml.XmlNode]$Node)

    $values = @()
    if ($Node.Attributes) {
        foreach ($attr in @($Node.Attributes)) {
            if ($attr.LocalName -in @("idRef", "filters", "validators") -and -not [string]::IsNullOrWhiteSpace($attr.Value)) {
                foreach ($value in @($attr.Value -split '\s*,\s*|\s+')) {
                    if (-not [string]::IsNullOrWhiteSpace($value)) {
                        $values += $value
                    }
                }
            }
        }
    }
    foreach ($child in @($Node.ChildNodes)) {
        $values += @(Get-XmlIdRefValues -Node $child)
    }
    return @($values | Sort-Object -Unique)
}

function Get-RulePackageTopLevelIdIndex {
    param([Parameter(Mandatory)][xml]$Xml)

    $index = @{}
    $rules = Get-RulePackageRulesElement -Xml $Xml
    if (-not $rules) { return $index }
    foreach ($node in @($rules.ChildNodes)) {
        if ($node.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        if ($node.LocalName -eq "LocalizedStrings") { continue }
        if (-not $node.HasAttribute("id")) { continue }
        $id = $node.GetAttribute("id")
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $index[$id.ToLowerInvariant()] = $node
        }
    }
    return $index
}

function Get-RulePackageResourceIndex {
    param([Parameter(Mandatory)][xml]$Xml)

    $index = @{}
    $localized = Get-RulePackageLocalizedStringsElement -Xml $Xml
    if (-not $localized) { return $index }
    foreach ($node in @($localized.ChildNodes)) {
        if ($node.NodeType -ne [System.Xml.XmlNodeType]::Element -or $node.LocalName -ne "Resource") { continue }
        if (-not $node.HasAttribute("idRef")) { continue }
        $id = $node.GetAttribute("idRef")
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $index[$id.ToLowerInvariant()] = $node
        }
    }
    return $index
}

function Get-RulePackageEntityIdSet {
    param([Parameter(Mandatory)][xml]$Xml)

    $ids = @{}
    $rules = Get-RulePackageRulesElement -Xml $Xml
    if (-not $rules) { return $ids }
    foreach ($node in @($rules.ChildNodes)) {
        if ($node.NodeType -ne [System.Xml.XmlNodeType]::Element -or $node.LocalName -ne "Entity") { continue }
        if (-not $node.HasAttribute("id")) { continue }
        $id = $node.GetAttribute("id")
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $ids[$id.ToLowerInvariant()] = $true
        }
    }
    return $ids
}

function Get-RulePackageVersionForRebase {
    param(
        [hashtable]$LocalVersion,
        [hashtable]$DeployedVersion
    )

    $bumped = Get-BumpedVersion -LocalVersion $LocalVersion -DeployedVersion $DeployedVersion
    if ($bumped) { return $bumped }
    if ($LocalVersion) { return $LocalVersion }
    if ($DeployedVersion) {
        return @{
            Major    = $DeployedVersion.Major
            Minor    = $DeployedVersion.Minor
            Build    = $DeployedVersion.Build
            Revision = $DeployedVersion.Revision + 1
        }
    }
    return @{ Major = 1; Minor = 0; Build = 0; Revision = 0 }
}

function Set-RulePackageMetadataForRebase {
    param(
        [Parameter(Mandatory)][xml]$Xml,
        [Parameter(Mandatory)][string]$RulePackId,
        [Parameter(Mandatory)][hashtable]$Version
    )

    $rulePack = Get-RulePackageRulePackElement -Xml $Xml
    if (-not $rulePack) { throw "Missing RulePack element in rebase XML." }
    $rulePack.SetAttribute("id", $RulePackId)
    $versionNode = Get-XmlChildElement -Node $rulePack -LocalName "Version"
    if (-not $versionNode) { throw "Missing Version element in rebase XML." }
    $versionNode.SetAttribute("major", $Version.Major.ToString())
    $versionNode.SetAttribute("minor", $Version.Minor.ToString())
    $versionNode.SetAttribute("build", $Version.Build.ToString())
    $versionNode.SetAttribute("revision", $Version.Revision.ToString())
}

function Add-PreservedEntityToRebaseXml {
    param(
        [Parameter(Mandatory)][xml]$DraftXml,
        [Parameter(Mandatory)][xml]$ExistingXml,
        [string[]]$PreserveEntityIds = @()
    )

    $draftRules = Get-RulePackageRulesElement -Xml $DraftXml
    if (-not $draftRules) { throw "Missing Rules element in draft XML." }

    $draftLocalized = Get-RulePackageLocalizedStringsElement -Xml $DraftXml
    if ($draftLocalized) {
        $draftRules.RemoveChild($draftLocalized) | Out-Null
    } else {
        $draftLocalized = $DraftXml.CreateElement("LocalizedStrings", $DraftXml.DocumentElement.NamespaceURI)
    }

    $draftTopLevelIndex = Get-RulePackageTopLevelIdIndex -Xml $DraftXml
    $draftResourceIndex = Get-RulePackageResourceIndex -Xml $DraftXml
    $existingTopLevelIndex = Get-RulePackageTopLevelIdIndex -Xml $ExistingXml
    $existingResourceIndex = Get-RulePackageResourceIndex -Xml $ExistingXml
    $queue = New-Object System.Collections.Generic.Queue[string]
    $preserved = @()

    if (@($PreserveEntityIds).Count -eq 0) {
        $draftRules.AppendChild($draftLocalized) | Out-Null
        return [PSCustomObject]@{
            PreservedEntityIds = @()
            PreservedDependencyIds = @()
        }
    }

    foreach ($entityId in @($PreserveEntityIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)) {
        $key = $entityId.ToLowerInvariant()
        if ($draftTopLevelIndex.ContainsKey($key)) { continue }
        if (-not $existingTopLevelIndex.ContainsKey($key)) { continue }
        $sourceEntity = $existingTopLevelIndex[$key]
        if ($sourceEntity.LocalName -ne "Entity") { continue }

        $importedEntity = $DraftXml.ImportNode($sourceEntity, $true)
        $draftRules.AppendChild($importedEntity) | Out-Null
        $draftTopLevelIndex[$key] = $importedEntity
        $preserved += $entityId
        foreach ($idRef in @(Get-XmlIdRefValues -Node $sourceEntity)) {
            $queue.Enqueue($idRef)
        }

        if ($existingResourceIndex.ContainsKey($key) -and -not $draftResourceIndex.ContainsKey($key)) {
            $resource = $DraftXml.ImportNode($existingResourceIndex[$key], $true)
            $draftLocalized.AppendChild($resource) | Out-Null
            $draftResourceIndex[$key] = $resource
        }
    }

    $dependencyIds = @()
    while ($queue.Count -gt 0) {
        $idRef = $queue.Dequeue()
        if ([string]::IsNullOrWhiteSpace($idRef)) { continue }
        $key = $idRef.ToLowerInvariant()
        if ($draftTopLevelIndex.ContainsKey($key)) { continue }
        if (-not $existingTopLevelIndex.ContainsKey($key)) { continue }

        $sourceNode = $existingTopLevelIndex[$key]
        if ($sourceNode.LocalName -eq "Entity") { continue }
        $importedNode = $DraftXml.ImportNode($sourceNode, $true)
        $draftRules.AppendChild($importedNode) | Out-Null
        $draftTopLevelIndex[$key] = $importedNode
        $dependencyIds += $idRef
        foreach ($childRef in @(Get-XmlIdRefValues -Node $sourceNode)) {
            $queue.Enqueue($childRef)
        }
    }

    $draftRules.AppendChild($draftLocalized) | Out-Null

    return [PSCustomObject]@{
        PreservedEntityIds = @($preserved | Sort-Object -Unique)
        PreservedDependencyIds = @($dependencyIds | Sort-Object -Unique)
    }
}

function New-RebasedPackageDraft {
    param(
        [Parameter(Mandatory)][string]$LocalPackageKey,
        [Parameter(Mandatory)][object]$TargetPackagePlan,
        [string[]]$PreserveEntityIds = @(),
        [Parameter(Mandatory)][string]$OutputDir
    )

    $pkg = $Packages[$LocalPackageKey]
    $localPath = Resolve-PackageFile -Package $pkg -RequestedTier $Tier
    $localText = (Read-RulePackageText -FilePath $localPath).TrimStart([char]0xFEFF)
    $draftXml = [xml]$localText
    $existingXml = [xml]($TargetPackagePlan.Info.RawXml.ToString().TrimStart([char]0xFEFF))
    $localInfo = Get-LocalPackageInfo -FilePath $localPath
    $targetRulePackId = $TargetPackagePlan.RulePackId
    if ([string]::IsNullOrWhiteSpace($targetRulePackId)) {
        throw "Target package '$($TargetPackagePlan.Name)' has no parsed RulePackId."
    }

    $newVersion = Get-RulePackageVersionForRebase -LocalVersion $localInfo.Version -DeployedVersion $TargetPackagePlan.Info.Version
    Set-RulePackageMetadataForRebase -Xml $draftXml -RulePackId $targetRulePackId -Version $newVersion
    $preserveResult = Add-PreservedEntityToRebaseXml -DraftXml $draftXml -ExistingXml $existingXml -PreserveEntityIds $PreserveEntityIds

    $safeLocal = $LocalPackageKey -replace '[^a-zA-Z0-9\-]', '_'
    $safeTarget = if ($TargetPackagePlan.Name) { $TargetPackagePlan.Name } else { $TargetPackagePlan.RulePackId }
    $safeTarget = $safeTarget -replace '[^a-zA-Z0-9\-]', '_'
    $draftPath = Join-Path $OutputDir ("rebase_{0}_into_{1}.xml" -f $safeLocal, $safeTarget)
    $bytes = ConvertTo-PurviewUtf16Bytes -Content $draftXml.OuterXml
    [System.IO.File]::WriteAllBytes($draftPath, $bytes)

    $validation = Test-SITRulePackageXml -FilePath $draftPath
    $draftInfo = Get-LocalPackageInfo -FilePath $draftPath
    return [PSCustomObject]@{
        Path              = $draftPath
        LocalPackageKey   = $LocalPackageKey
        TargetName        = $TargetPackagePlan.Name
        TargetRulePackId  = $targetRulePackId
        Version           = Format-VersionString -Version $newVersion
        EntityCount       = if ($draftInfo) { $draftInfo.EntityCount } else { 0 }
        SizeBytes         = (Get-Item -LiteralPath $draftPath).Length
        Valid             = [bool]$validation.Valid
        Errors            = @($validation.Errors)
        Warnings          = @($validation.Warnings)
        PreservedEntityIds = @($preserveResult.PreservedEntityIds)
        PreservedDependencyIds = @($preserveResult.PreservedDependencyIds)
    }
}

function New-ClassifierAdoptionPlan {
    param(
        [Parameter(Mandatory)][string[]]$SelectedKeys,
        [Parameter(Mandatory)][string]$OutputDir
    )

    $capacityPlan = New-ClassifierCapacityPlan -SelectedKeys $SelectedKeys
    $candidateIds = @()
    foreach ($existing in @($capacityPlan.ExistingPackages)) {
        foreach ($entity in @($existing.Info.Entities)) {
            if ($entity.Id) { $candidateIds += $entity.Id.ToString().ToLowerInvariant() }
        }
    }
    foreach ($localKey in @($SelectedKeys)) {
        if (-not $Packages.ContainsKey($localKey)) { continue }
        $localPath = Resolve-PackageFile -Package $Packages[$localKey] -RequestedTier $Tier
        $localInfo = Get-LocalPackageInfo -FilePath $localPath
        foreach ($entity in @($localInfo.Entities)) {
            if ($entity.Id) { $candidateIds += $entity.Id.ToString().ToLowerInvariant() }
        }
    }
    $ruleRefs = Get-DlpRuleReferenceIndex -CandidateIds @($candidateIds | Sort-Object -Unique)

    $localInfos = @()
    foreach ($localKey in @($SelectedKeys | Sort-Object)) {
        if (-not $Packages.ContainsKey($localKey)) { continue }
        $localPath = Resolve-PackageFile -Package $Packages[$localKey] -RequestedTier $Tier
        $localInfo = Get-LocalPackageInfo -FilePath $localPath
        if (-not $localInfo) { continue }
        $localInfos += [PSCustomObject]@{
            Key = $localKey
            Path = $localPath
            Info = $localInfo
        }
    }

    $targets = @()
    foreach ($existing in @($capacityPlan.ExistingPackages)) {
        $referencedIds = @()
        foreach ($entity in @($existing.Info.Entities)) {
            if (-not $entity.Id) { continue }
            $idKey = $entity.Id.ToString().ToLowerInvariant()
            if ($ruleRefs.ById.ContainsKey($idKey)) {
                $referencedIds += $entity.Id
            }
        }
        $refCount = @($referencedIds | Sort-Object -Unique).Count
        $priority = if (@($existing.IdOverlaps).Count -gt 0) {
            0
        } elseif ($refCount -eq 0 -and $existing.EntityCount -eq 0) {
            1
        } elseif ($refCount -eq 0) {
            2
        } else {
            3
        }

        $targets += [PSCustomObject]@{
            Package = $existing
            Priority = $priority
            ReferencedEntityIds = @($referencedIds | Sort-Object -Unique)
        }
    }

    $assignedTargets = @{}
    $assignments = @()
    $orderedLocals = @($localInfos | Sort-Object @{ Expression = { $_.Info.FileSize }; Descending = $true }, Key)
    foreach ($local in @($orderedLocals)) {
        $match = $null
        foreach ($target in @($targets | Sort-Object Priority, { @($_.ReferencedEntityIds).Count }, { $_.Package.EntityCount }, { $_.Package.Name })) {
            $targetId = if ($target.Package.RulePackId) { $target.Package.RulePackId } else { $target.Package.Identity }
            if ($assignedTargets.ContainsKey($targetId)) { continue }

            $idOverlapForLocal = @($target.Package.IdOverlaps | Where-Object { $_.LocalPackages -contains $local.Key }).Count
            if ($target.Priority -eq 0 -and $idOverlapForLocal -eq 0) { continue }
            $match = $target
            break
        }
        if (-not $match) {
            foreach ($target in @($targets | Sort-Object Priority, { @($_.ReferencedEntityIds).Count }, { $_.Package.EntityCount }, { $_.Package.Name })) {
                $targetId = if ($target.Package.RulePackId) { $target.Package.RulePackId } else { $target.Package.Identity }
                if ($assignedTargets.ContainsKey($targetId)) { continue }
                $match = $target
                break
            }
        }

        if ($match) {
            $targetId = if ($match.Package.RulePackId) { $match.Package.RulePackId } else { $match.Package.Identity }
            $assignedTargets[$targetId] = $true
            $draft = $null
            $draftError = $null
            try {
                $draft = New-RebasedPackageDraft -LocalPackageKey $local.Key -TargetPackagePlan $match.Package -PreserveEntityIds $match.ReferencedEntityIds -OutputDir $OutputDir
            } catch {
                $draftError = $_.Exception.Message
            }

            $assignments += [PSCustomObject]@{
                LocalPackageKey = $local.Key
                LocalEntityCount = $local.Info.EntityCount
                LocalSizeBytes = $local.Info.FileSize
                TargetName = $match.Package.Name
                TargetRulePackId = $match.Package.RulePackId
                TargetEntityCount = $match.Package.EntityCount
                TargetReferencedEntityIds = @($match.ReferencedEntityIds)
                TargetReferencedRuleCount = @($match.Package.ReferencedRules).Count
                Recommendation = if (@($match.ReferencedEntityIds).Count -gt 0) { "RebasePreserveReferenced" } else { "RebaseReplaceContents" }
                Draft = $draft
                DraftError = $draftError
                ReadyToUpload = ($draft -and $draft.Valid)
            }
        } else {
            $assignments += [PSCustomObject]@{
                LocalPackageKey = $local.Key
                LocalEntityCount = $local.Info.EntityCount
                LocalSizeBytes = $local.Info.FileSize
                TargetName = $null
                TargetRulePackId = $null
                TargetEntityCount = 0
                TargetReferencedEntityIds = @()
                TargetReferencedRuleCount = 0
                Recommendation = "NeedsPackageSlot"
                Draft = $null
                DraftError = "No existing package slot was available for adoption."
                ReadyToUpload = $false
            }
        }
    }

    $unassignedExisting = @()
    foreach ($target in @($targets)) {
        $targetId = if ($target.Package.RulePackId) { $target.Package.RulePackId } else { $target.Package.Identity }
        if ($assignedTargets.ContainsKey($targetId)) { continue }
        $unassignedExisting += [PSCustomObject]@{
            Name = $target.Package.Name
            RulePackId = $target.Package.RulePackId
            EntityCount = $target.Package.EntityCount
            ReferencedEntityIds = @($target.ReferencedEntityIds)
            ReferencedRuleCount = @($target.Package.ReferencedRules).Count
            Recommendation = if (@($target.ReferencedEntityIds).Count -gt 0) { "KeepReferenced" } elseif ($target.Package.EntityCount -eq 0) { "RetireCandidate" } else { "ReviewOrRetire" }
        }
    }

    return [PSCustomObject]@{
        OutputDir = $OutputDir
        CapacityPlan = $capacityPlan
        RuleRefsScanned = $ruleRefs.RulesScanned
        Assignments = @($assignments)
        UnassignedExisting = @($unassignedExisting)
    }
}

function ConvertTo-ProjectRelativePath {
    param([Parameter(Mandatory)][string]$Path)

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $resolvedRoot = [System.IO.Path]::GetFullPath($ProjectRoot)
    if ($resolvedPath.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return ($resolvedPath.Substring($resolvedRoot.Length).TrimStart('\', '/') -replace '\\', '/')
    }
    return ($resolvedPath -replace '\\', '/')
}

function Write-ClassifierPackagerInput {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][string[]]$SelectedKeys
    )

    if (-not (Test-Path -LiteralPath $Plan.OutputDir)) {
        New-Item -ItemType Directory -Path $Plan.OutputDir -Force | Out-Null
    }

    $tenantSnapshotDir = Join-Path $Plan.OutputDir "tenant-packages"
    if (-not (Test-Path -LiteralPath $tenantSnapshotDir)) {
        New-Item -ItemType Directory -Path $tenantSnapshotDir -Force | Out-Null
    }

    $referencedIdsByRulePack = @{}
    foreach ($assignment in @($Plan.Assignments)) {
        if ([string]::IsNullOrWhiteSpace($assignment.TargetRulePackId)) { continue }
        $referencedIdsByRulePack[$assignment.TargetRulePackId.ToString().ToLowerInvariant()] = @($assignment.TargetReferencedEntityIds)
    }
    foreach ($existing in @($Plan.UnassignedExisting)) {
        if ([string]::IsNullOrWhiteSpace($existing.RulePackId)) { continue }
        $referencedIdsByRulePack[$existing.RulePackId.ToString().ToLowerInvariant()] = @($existing.ReferencedEntityIds)
    }

    $localBundles = @()
    foreach ($packageKey in @($SelectedKeys | Sort-Object)) {
        if (-not $Packages.ContainsKey($packageKey)) { continue }
        $pkg = $Packages[$packageKey]
        $path = Resolve-PackageFile -Package $pkg -RequestedTier $Tier
        $info = if (Test-Path -LiteralPath $path) { Get-LocalPackageInfo -FilePath $path } else { $null }
        $artifact = if (Test-Path -LiteralPath $path) { Get-DeploymentFileArtifact -Path $path -Role "source-local-bundle" -ProjectRoot $ProjectRoot } else { $null }

        $localBundles += [ordered]@{
            packageKey  = $packageKey
            displayName = $pkg.displayName
            description = $pkg.description
            rulePackId  = $pkg.rulePackId
            tier        = $Tier
            path        = if ($artifact) { $artifact.path } else { ConvertTo-ProjectRelativePath -Path $path }
            sha256      = if ($artifact) { $artifact.sha256 } else { $null }
            version     = if ($info) { $info.VersionStr } else { $null }
            entityCount = if ($info) { $info.EntityCount } else { $null }
            sizeBytes   = if ($info) { $info.FileSize } elseif (Test-Path -LiteralPath $path) { (Get-Item -LiteralPath $path).Length } else { $null }
            entities    = if ($info) {
                @($info.Entities | ForEach-Object { [ordered]@{ id = $_.Id; name = $_.Name } })
            } else {
                @()
            }
        }
    }

    $tenantPackages = @()
    $snapshotArtifacts = @()
    $snapshotIndex = 0
    foreach ($existing in @($Plan.CapacityPlan.ExistingPackages)) {
        $snapshotIndex++
        $safeName = if ($existing.Name) { $existing.Name } elseif ($existing.RulePackId) { $existing.RulePackId } else { "package-$snapshotIndex" }
        $safeName = $safeName -replace '[^a-zA-Z0-9\-]', '_'
        $snapshotPath = $null
        $snapshotArtifact = $null

        if ($existing.Info -and ($existing.Info.RawBytes -or $existing.Info.RawXml)) {
            $snapshotPath = Join-Path $tenantSnapshotDir ("tenant_{0:D2}_{1}.xml" -f $snapshotIndex, $safeName)
            if ($existing.Info.RawBytes) {
                [System.IO.File]::WriteAllBytes($snapshotPath, $existing.Info.RawBytes)
            } else {
                [System.IO.File]::WriteAllBytes($snapshotPath, (ConvertTo-PurviewUtf16Bytes -Content $existing.Info.RawXml))
            }
            $snapshotArtifact = Get-DeploymentFileArtifact -Path $snapshotPath -Role "tenant-package-snapshot" -ProjectRoot $ProjectRoot
            $snapshotArtifacts += $snapshotArtifact
        }

        $rulePackKey = if ($existing.RulePackId) { $existing.RulePackId.ToString().ToLowerInvariant() } else { $null }
        $referencedEntityIds = if ($rulePackKey -and $referencedIdsByRulePack.ContainsKey($rulePackKey)) {
            @($referencedIdsByRulePack[$rulePackKey])
        } else {
            @()
        }

        $tenantPackages += [ordered]@{
            identity            = $existing.Identity
            name                = $existing.Name
            publisher           = $existing.Publisher
            rulePackId          = $existing.RulePackId
            version             = $existing.Version
            entityCount         = $existing.EntityCount
            sizeBytes           = $existing.SizeBytes
            snapshotPath        = if ($snapshotArtifact) { $snapshotArtifact.path } else { $null }
            snapshotSha256      = if ($snapshotArtifact) { $snapshotArtifact.sha256 } else { $null }
            recommendation      = $existing.Recommendation
            reason              = $existing.Reason
            referencedEntityIds = @($referencedEntityIds | Sort-Object -Unique)
            referencedRules     = @($existing.ReferencedRules | ForEach-Object { [ordered]@{ ruleName = $_.RuleName; policyName = $_.PolicyName } })
            idOverlaps          = @($existing.IdOverlaps | ForEach-Object {
                [ordered]@{
                    id              = $_.Id
                    name            = $_.Name
                    localPackages   = @($_.LocalPackages)
                    localEntityName = $_.LocalEntityName
                }
            })
            nameOverlaps        = @($existing.NameOverlaps | ForEach-Object {
                [ordered]@{
                    deployedId   = $_.DeployedId
                    localId      = $_.LocalId
                    name         = $_.Name
                    localPackage = $_.LocalPackage
                }
            })
            entities            = if ($existing.Info) {
                @($existing.Info.Entities | ForEach-Object { [ordered]@{ id = $_.Id; name = $_.Name } })
            } else {
                @()
            }
        }
    }

    $payload = [ordered]@{
        schemaVersion = "dlpdeploy.classifier-packager-input/v1"
        generatedUtc  = (Get-Date).ToUniversalTime().ToString("o")
        mode          = "AdoptPlan"
        tier          = $Tier
        publisher     = $Publisher
        project       = [ordered]@{
            root                 = "."
            registryPath         = ConvertTo-ProjectRelativePath -Path $registryPath
            classifierConfigPath = ConvertTo-ProjectRelativePath -Path (Join-Path $ConfigPath "classifiers.json")
        }
        limits        = [ordered]@{
            maxTenantRulePackages        = 10
            maxEntitiesPerRulePackage    = 50
            maxNewPackageBytes           = 153600
            maxSetPackageBytes           = 788480
            preferredPackageBytes        = 153600
            customSensitiveInfoTypeLimit = 500
        }
        requirements  = [ordered]@{
            emitUtf16LeBom                         = $true
            preserveExistingReferencedTenantSits   = $true
            preferExistingRulePackIdsForRebase     = $true
            avoidRemovingReferencedTenantSits      = $true
            avoidNameClashesWithDifferentEntityIds = $true
            validateEachDraftBeforeUpload          = $true
            deploymentConsumesDraftsOnlyAfterImpactConfirmation = $true
        }
        selectedLocalPackageKeys = @($SelectedKeys | Sort-Object)
        localBundles             = @($localBundles)
        tenantPackages           = @($tenantPackages)
        currentAdoptionProposal  = Convert-ClassifierAdoptionPlanForManifest -Plan $Plan
        notes                    = @(
            "This is a read-only handoff for package adaptation. It contains source local XML, tenant package snapshots, referenced SIT preservation constraints, and current dlpdeploy rebase assignments.",
            "A packager can emit a revised package plan/draft set from this payload; dlpdeploy should still run local XML validation, tenant impact assessment, canary where appropriate, and final confirmation before upload."
        )
    }

    $inputPath = Join-Path $Plan.OutputDir "packager-input.json"
    $payload | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $inputPath -Encoding UTF8

    return [PSCustomObject]@{
        Path              = $inputPath
        SnapshotArtifacts = @($snapshotArtifacts)
    }
}

function Convert-ClassifierAdoptionPlanForManifest {
    param([Parameter(Mandatory)][object]$Plan)

    return [ordered]@{
        outputDir = ConvertTo-ProjectRelativePath -Path $Plan.OutputDir
        ruleRefsScanned = $Plan.RuleRefsScanned
        assignments = @($Plan.Assignments | ForEach-Object {
            [ordered]@{
                localPackageKey = $_.LocalPackageKey
                recommendation = $_.Recommendation
                readyToUpload = [bool]$_.ReadyToUpload
                targetName = $_.TargetName
                targetRulePackId = $_.TargetRulePackId
                targetReferencedRuleCount = $_.TargetReferencedRuleCount
                targetReferencedEntityIds = @($_.TargetReferencedEntityIds)
                draft = if ($_.Draft) {
                    [ordered]@{
                        path = ConvertTo-ProjectRelativePath -Path $_.Draft.Path
                        version = $_.Draft.Version
                        entityCount = $_.Draft.EntityCount
                        sizeBytes = $_.Draft.SizeBytes
                        valid = [bool]$_.Draft.Valid
                        errors = @($_.Draft.Errors)
                        warnings = @($_.Draft.Warnings)
                        preservedEntityIds = @($_.Draft.PreservedEntityIds)
                    }
                } else { $null }
                draftError = $_.DraftError
            }
        })
        unassignedExisting = @($Plan.UnassignedExisting | ForEach-Object {
            [ordered]@{
                name = $_.Name
                rulePackId = $_.RulePackId
                entityCount = $_.EntityCount
                referencedRuleCount = $_.ReferencedRuleCount
                recommendation = $_.Recommendation
            }
        })
    }
}

function Write-ClassifierAdoptionPlanReport {
    param([Parameter(Mandatory)][object]$Plan)

    Write-Host "`n=== Classifier Adoption / Rebase Plan ===" -ForegroundColor Cyan
    Write-Host "  Draft output: $($Plan.OutputDir)" -ForegroundColor Gray
    Write-Host "  DLP rules scanned: $($Plan.RuleRefsScanned)" -ForegroundColor Gray
    Write-Host "  Existing slots: $($Plan.CapacityPlan.CustomSlotsUsed)/10; local bundles: $($Plan.CapacityPlan.SelectedLocalPackageCount)" -ForegroundColor Gray

    Write-Host "`n--- Proposed Rebase Assignments ---" -ForegroundColor White
    foreach ($assignment in @($Plan.Assignments)) {
        $color = if ($assignment.ReadyToUpload) { "Green" } elseif ($assignment.DraftError) { "Red" } else { "Yellow" }
        $target = if ($assignment.TargetName) { $assignment.TargetName } else { "(no target slot)" }
        Write-Host "  $($assignment.LocalPackageKey) -> $target [$($assignment.Recommendation)]" -ForegroundColor $color
        if ($assignment.TargetRulePackId) {
            Write-Host "     Target RulePackId: $($assignment.TargetRulePackId)" -ForegroundColor DarkGray
        }
        Write-Host "     Local entities: $($assignment.LocalEntityCount); target entities: $($assignment.TargetEntityCount); referenced target entities preserved: $(@($assignment.TargetReferencedEntityIds).Count)" -ForegroundColor DarkGray
        if ($assignment.Draft) {
            $draftName = Split-Path $assignment.Draft.Path -Leaf
            $draftColor = if ($assignment.Draft.Valid) { "Green" } else { "Red" }
            Write-Host "     Draft: $draftName; v$($assignment.Draft.Version); entities $($assignment.Draft.EntityCount); size $([math]::Round($assignment.Draft.SizeBytes / 1KB, 1))KB; valid=$($assignment.Draft.Valid)" -ForegroundColor $draftColor
            foreach ($err in @($assignment.Draft.Errors)) {
                Write-Host "       ERROR: $err" -ForegroundColor Red
            }
            foreach ($warn in @($assignment.Draft.Warnings | Select-Object -First 4)) {
                Write-Host "       WARN: $warn" -ForegroundColor Yellow
            }
        } elseif ($assignment.DraftError) {
            Write-Host "     Draft not created: $($assignment.DraftError)" -ForegroundColor Red
        }
    }

    Write-Host "`n--- Existing Packages Not Used For Rebase ---" -ForegroundColor White
    foreach ($existing in @($Plan.UnassignedExisting)) {
        $color = switch ($existing.Recommendation) {
            "KeepReferenced"  { "Green" }
            "RetireCandidate" { "Yellow" }
            default           { "Yellow" }
        }
        Write-Host "  [$($existing.Recommendation)] $($existing.Name)" -ForegroundColor $color
        Write-Host "     RulePackId: $($existing.RulePackId); entities: $($existing.EntityCount); referenced rules: $($existing.ReferencedRuleCount)" -ForegroundColor DarkGray
    }

    $readyCount = @($Plan.Assignments | Where-Object { $_.ReadyToUpload }).Count
    $blockedCount = @($Plan.Assignments | Where-Object { -not $_.ReadyToUpload }).Count
    Write-Host "`n--- Adoption Summary ---" -ForegroundColor White
    Write-Host "  Rebase drafts ready: $readyCount" -ForegroundColor $(if ($blockedCount -eq 0) { "Green" } else { "Yellow" })
    if ($blockedCount -gt 0) {
        Write-Host "  Blocked drafts:      $blockedCount" -ForegroundColor Red
    }
    Write-Host "  This action does not upload drafts. Review drafts before any tenant rebase." -ForegroundColor Gray
}

function Test-PruneRecommendedPackage {
    param([Parameter(Mandatory)][object]$PackagePlan)

    $refCount = @($PackagePlan.ReferencedRules).Count
    if ($refCount -gt 0) { return $false }
    return ($PackagePlan.Recommendation -in @("InspectOrRemove", "RemoveBeforeDeploy"))
}

function Get-PrunePackageLabel {
    param([Parameter(Mandatory)][object]$PackagePlan)

    if (Test-PruneRecommendedPackage -PackagePlan $PackagePlan) {
        return "RECOMMENDED DELETE"
    }
    if (@($PackagePlan.ReferencedRules).Count -gt 0) {
        return "RULES REFERENCE"
    }
    if ($PackagePlan.Recommendation -eq "ReviewNameClash") {
        return "REVIEW CLASH"
    }
    return "KEEP CANDIDATE"
}

function Select-PrunePackagesFromMenu {
    param([Parameter(Mandatory)][object]$Plan)

    $packages = @($Plan.ExistingPackages)
    if ($packages.Count -eq 0) {
        Write-Host "No existing custom packages found." -ForegroundColor Yellow
        return @()
    }

    Write-Host "`n=== Existing Package Delete Menu ===" -ForegroundColor Cyan
    Write-Host "  R = select recommended delete candidates" -ForegroundColor Gray
    Write-Host "  A = abort without deleting" -ForegroundColor Gray

    for ($i = 0; $i -lt $packages.Count; $i++) {
        $pkg = $packages[$i]
        $name = if ($pkg.Name) { $pkg.Name } else { "(unnamed package)" }
        $label = Get-PrunePackageLabel -PackagePlan $pkg
        $refCount = @($pkg.ReferencedRules).Count
        $sizeText = if ($pkg.SizeBytes) { "$([math]::Round($pkg.SizeBytes / 1KB, 1))KB" } else { "unknown size" }
        $color = switch ($label) {
            "RECOMMENDED DELETE" { "Green" }
            "RULES REFERENCE"    { "Red" }
            "REVIEW CLASH"       { "Yellow" }
            default              { "DarkGray" }
        }
        Write-Host ("  {0}. [{1}] {2}" -f ($i + 1), $label, $name) -ForegroundColor $color
        Write-Host ("     RulePackId: {0}; entities: {1}; refs: {2}; size: {3}" -f $pkg.RulePackId, $pkg.EntityCount, $refCount, $sizeText) -ForegroundColor DarkGray
    }

    $choice = Read-Host "Select packages to delete (comma-separated numbers), R for recommended, or A to abort"
    if ([string]::IsNullOrWhiteSpace($choice) -or $choice.Trim().ToUpperInvariant() -eq "A") {
        return @()
    }

    if ($choice.Trim().ToUpperInvariant() -eq "R") {
        return @($packages | Where-Object { Test-PruneRecommendedPackage -PackagePlan $_ })
    }

    $selected = @()
    foreach ($part in ($choice -split ",")) {
        $n = 0
        if ([int]::TryParse($part.Trim(), [ref]$n) -and $n -ge 1 -and $n -le $packages.Count) {
            $selected += $packages[$n - 1]
        } else {
            Write-Host "  Ignoring invalid selection '$part'." -ForegroundColor Yellow
        }
    }
    return @($selected | Sort-Object RulePackId -Unique)
}

function Confirm-PruneSelection {
    param([Parameter(Mandatory)][object[]]$SelectedPackages)

    if ($SelectedPackages.Count -eq 0) { return @() }

    $safe = @()
    foreach ($pkg in @($SelectedPackages)) {
        $refCount = @($pkg.ReferencedRules).Count
        if ($refCount -eq 0) {
            $safe += $pkg
            continue
        }

        $name = if ($pkg.Name) { $pkg.Name } else { $pkg.RulePackId }
        Write-Host "`nPackage '$name' is referenced by $refCount DLP rule(s)." -ForegroundColor Red
        foreach ($ref in @($pkg.ReferencedRules | Select-Object -First 12)) {
            Write-Host "  - $($ref.RuleName) / $($ref.PolicyName)" -ForegroundColor Red
        }
        if ($refCount -gt 12) {
            Write-Host "  ... $($refCount - 12) more rule reference(s)" -ForegroundColor Red
        }
        $phrase = Read-Host "Type I UNDERSTAND to include this referenced package, or press Enter to skip it"
        if ($phrase -eq "I UNDERSTAND") {
            $safe += $pkg
        } else {
            Write-Host "  Skipping '$name'." -ForegroundColor Yellow
        }
    }

    return @($safe)
}

function Update-PruneSelectionFromTenant {
    param(
        [Parameter(Mandatory)][object[]]$SelectedPackages,
        [Parameter(Mandatory)][string[]]$SelectedLocal
    )

    if ($SelectedPackages.Count -eq 0) { return @() }

    $selectedRulePackIds = @{}
    $selectedIdentities = @{}
    foreach ($pkg in @($SelectedPackages)) {
        if ($pkg.RulePackId) {
            $selectedRulePackIds[$pkg.RulePackId.ToString().ToLowerInvariant()] = $true
        }
        if ($pkg.Identity) {
            $selectedIdentities[$pkg.Identity.ToString().ToLowerInvariant()] = $true
        }
    }

    $freshPlan = New-ClassifierCapacityPlan -SelectedKeys $SelectedLocal
    $freshMatches = @()
    foreach ($pkg in @($freshPlan.ExistingPackages)) {
        $rulePackKey = if ($pkg.RulePackId) { $pkg.RulePackId.ToString().ToLowerInvariant() } else { $null }
        $identityKey = if ($pkg.Identity) { $pkg.Identity.ToString().ToLowerInvariant() } else { $null }
        if (($rulePackKey -and $selectedRulePackIds.ContainsKey($rulePackKey)) -or
            ($identityKey -and $selectedIdentities.ContainsKey($identityKey))) {
            $freshMatches += $pkg
        }
    }

    $freshRulePackIds = @{}
    $freshIdentities = @{}
    foreach ($pkg in @($freshMatches)) {
        if ($pkg.RulePackId) {
            $freshRulePackIds[$pkg.RulePackId.ToString().ToLowerInvariant()] = $true
        }
        if ($pkg.Identity) {
            $freshIdentities[$pkg.Identity.ToString().ToLowerInvariant()] = $true
        }
    }

    foreach ($pkg in @($SelectedPackages)) {
        $rulePackKey = if ($pkg.RulePackId) { $pkg.RulePackId.ToString().ToLowerInvariant() } else { $null }
        $identityKey = if ($pkg.Identity) { $pkg.Identity.ToString().ToLowerInvariant() } else { $null }
        $matched = (($rulePackKey -and $freshRulePackIds.ContainsKey($rulePackKey)) -or
            ($identityKey -and $freshIdentities.ContainsKey($identityKey)))
        if (-not $matched) {
            $name = if ($pkg.Name) { $pkg.Name } else { $pkg.RulePackId }
            Write-Host "  Skipping '$name' because it no longer exists in the tenant." -ForegroundColor Yellow
        }
    }

    return @($freshMatches | Sort-Object RulePackId -Unique)
}

function Get-PruneManifestTargets {
    param([Parameter(Mandatory)][object[]]$SelectedPackages)

    return @($SelectedPackages | ForEach-Object {
        [ordered]@{
            type = "DeployedClassifierBundle"
            name = $_.Name
            identity = $_.Identity
            rulePackId = $_.RulePackId
            version = $_.Version
            entityCount = $_.EntityCount
            sizeBytes = $_.SizeBytes
            referencedRuleCount = @($_.ReferencedRules).Count
            recommendation = $_.Recommendation
        }
    })
}

function Get-ClassifierManifestTargets {
    param([Parameter(Mandatory)][string[]]$Selected)

    $targets = @()
    foreach ($name in @($Selected | Sort-Object)) {
        if (-not $Packages.ContainsKey($name)) { continue }
        $pkg = $Packages[$name]
        $filePath = Resolve-PackageFile -Package $pkg -RequestedTier $Tier
        $target = [ordered]@{
            type        = "ClassifierBundle"
            packageKey  = $name
            displayName = $pkg.displayName
            rulePackId  = $pkg.rulePackId
            tier        = $Tier
            path        = $null
            version     = $null
            entityCount = $null
            sizeBytes   = $null
            sha256      = $null
        }

        if (Test-Path -LiteralPath $filePath) {
            $artifact = Get-DeploymentFileArtifact -Path $filePath -Role "classifier-xml" -ProjectRoot $ProjectRoot
            $localInfo = Get-LocalPackageInfo -FilePath $filePath
            $target.path = $artifact.path
            $target.sizeBytes = $artifact.sizeBytes
            $target.sha256 = $artifact.sha256
            if ($localInfo) {
                $target.version = $localInfo.VersionStr
                $target.entityCount = $localInfo.EntityCount
            }
        }

        $targets += $target
    }
    return $targets
}

function Convert-ClassifierImpactForManifest {
    param([Parameter(Mandatory)][object]$Analysis)

    $affectedLabels = @{}
    $affectedRules = @{}
    foreach ($id in @($Analysis.RemovedIds)) {
        if ($Analysis.ConfigIndex.ById.ContainsKey($id)) {
            foreach ($label in @($Analysis.ConfigIndex.ById[$id].LabelCodes)) {
                $affectedLabels[$label] = $true
            }
        }
        foreach ($ref in Get-ClassifierRuleRefs -Analysis $Analysis -Id $id) {
            $affectedRules[$ref.RuleName] = $ref.PolicyName
        }
    }

    return [ordered]@{
        mode           = $Analysis.Mode
        selectedKeys   = @($Analysis.SelectedKeys)
        removedIds     = @($Analysis.RemovedIds)
        addedIds       = @($Analysis.AddedIds)
        affectedLabels = @($affectedLabels.Keys | Sort-Object)
        affectedRules  = @($affectedRules.Keys | Sort-Object | ForEach-Object {
            [ordered]@{ ruleName = $_; policyName = $affectedRules[$_] }
        })
        packages       = @($Analysis.PackageImpacts | ForEach-Object {
            [ordered]@{
                packageKey      = $_.PackageKey
                status          = $_.Status
                localVersion    = if ($_.LocalInfo) { $_.LocalInfo.VersionStr } else { $null }
                deployedVersion = if ($_.DeployedInfo) { $_.DeployedInfo.VersionStr } else { $null }
                added           = @($_.Added | ForEach-Object { [ordered]@{ id = $_.Id; name = $_.Name } })
                removed         = @($_.Removed | ForEach-Object { [ordered]@{ id = $_.Id; name = $_.Name } })
                unchangedCount  = @($_.Unchanged).Count
            }
        })
    }
}

function Add-ClassifierDecision {
    param([string]$Decision, [hashtable]$Data)
    if (-not $script:DeploymentManifest) { return }
    $payload = if ($Data) { $Data } else { @{} }
    $payload.Decision = $Decision
    Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Decision" -Data $payload
}

function New-UploadPlanFromImpact {
    param([Parameter(Mandatory)][object]$Analysis)

    $plan = @{}
    foreach ($impact in @($Analysis.PackageImpacts)) {
        if ($impact.Status -in @("NewPackage", "Replace") -and $impact.LocalInfo) {
            $bumpedVersion = $null
            if ($impact.LocalInfo -and $impact.DeployedInfo -and $impact.LocalInfo.Version -and $impact.DeployedInfo.Version) {
                $bumpedVersion = Get-BumpedVersion -LocalVersion $impact.LocalInfo.Version -DeployedVersion $impact.DeployedInfo.Version
            }
            $plan[$impact.PackageKey] = @{
                Action       = if ($impact.DeployedInfo) { "Replace" } else { "New" }
                LocalInfo    = $impact.LocalInfo
                DeployedInfo = $impact.DeployedInfo
                BumpVersion  = $bumpedVersion
            }
        }
    }
    return $plan
}

function Get-UploadPlanStats {
    param(
        [Parameter(Mandatory)][hashtable]$UploadPlan,
        [Parameter(Mandatory)][string[]]$Selected
    )

    $newPackages = @()
    $replacePackages = @()
    $skipPackages = @()
    $missingPackages = @()

    foreach ($name in @($Selected | Sort-Object)) {
        if (-not $UploadPlan.ContainsKey($name)) {
            $missingPackages += $name
            continue
        }

        switch ($UploadPlan[$name].Action) {
            "New"     { $newPackages += $name }
            "Replace" { $replacePackages += $name }
            "Skip"    { $skipPackages += $name }
            default   { $skipPackages += $name }
        }
    }

    return [PSCustomObject]@{
        NewCount        = $newPackages.Count
        ReplaceCount    = $replacePackages.Count
        SkipCount       = $skipPackages.Count
        MissingCount    = $missingPackages.Count
        WorkCount       = $newPackages.Count + $replacePackages.Count
        NewPackages     = @($newPackages)
        ReplacePackages = @($replacePackages)
        SkipPackages    = @($skipPackages)
        MissingPackages = @($missingPackages)
    }
}

function Test-UploadCapacityGate {
    param(
        [Parameter(Mandatory)][hashtable]$UploadPlan,
        [Parameter(Mandatory)][string[]]$Selected,
        [int]$AdditionalSlotsFreed = 0,
        [string]$Context = "Upload"
    )

    $stats = Get-UploadPlanStats -UploadPlan $UploadPlan -Selected $Selected
    if ($stats.WorkCount -eq 0) {
        Write-Host "`n=== Upload Capacity Gate ===" -ForegroundColor Cyan
        Write-Host "  No package create/update work is selected." -ForegroundColor Yellow
        return $true
    }

    $deployedLookup = Get-DeployedPackageLookup
    $slotsUsed = @($deployedLookup.Values).Count
    $slotCredit = [math]::Max(0, $AdditionalSlotsFreed)
    $slotsAvailable = [math]::Max(0, 10 - $slotsUsed + $slotCredit)

    Write-Host "`n=== Upload Capacity Gate ===" -ForegroundColor Cyan
    Write-Host "  Context:             $Context" -ForegroundColor Gray
    Write-Host "  Current custom slots: $slotsUsed/10" -ForegroundColor Gray
    if ($slotCredit -gt 0) {
        Write-Host "  Planned removals:     $slotCredit slot(s) credited before upload" -ForegroundColor Gray
    }
    Write-Host "  New packages needed: $($stats.NewCount)" -ForegroundColor Gray
    Write-Host "  Replace operations:  $($stats.ReplaceCount)" -ForegroundColor Gray
    Write-Host "  Slots available:     $slotsAvailable" -ForegroundColor Gray

    $eventData = @{
        operation            = "UploadCapacityGate"
        context              = $Context
        currentSlotsUsed     = $slotsUsed
        additionalSlotsFreed = $slotCredit
        slotsAvailable       = $slotsAvailable
        newPackageCount      = $stats.NewCount
        replacePackageCount  = $stats.ReplaceCount
        newPackages          = @($stats.NewPackages)
        replacePackages      = @($stats.ReplacePackages)
    }

    if ($stats.NewCount -gt $slotsAvailable) {
        $removeRequired = $stats.NewCount - $slotsAvailable
        Write-Host "  BLOCKED: $($stats.NewCount) new package(s) need $($stats.NewCount) slot(s), but only $slotsAvailable slot(s) are available." -ForegroundColor Red
        Write-Host "  Remove at least $removeRequired existing package(s), reduce the local package selection, or consolidate bundles before upload." -ForegroundColor Red
        if ($stats.NewPackages.Count -gt 0) {
            Write-Host "  New package candidates: $($stats.NewPackages -join ', ')" -ForegroundColor Yellow
        }
        if ($script:DeploymentManifest) {
            $eventData.status = "Blocked"
            $eventData.removalsRequired = $removeRequired
            Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Error" -Data $eventData
        }
        return $false
    }

    Write-Host "  OK: selected new packages fit available package slots." -ForegroundColor Green
    if ($script:DeploymentManifest) {
        $eventData.status = "Passed"
        Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Result" -Data $eventData
    }
    return $true
}

function Write-EmbeddedWhatIfPlan {
    param(
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][string[]]$Selected,
        [hashtable]$UploadPlan
    )

    Write-Host "`n=== Planned Operation (WhatIf Preview) ===" -ForegroundColor Cyan
    Write-Host "  Operation: $Operation" -ForegroundColor White
    Write-Host "  Tier:      $Tier" -ForegroundColor Gray
    Write-Host "  Publisher: $Publisher" -ForegroundColor Gray
    Write-Host "  Packages:  $($Selected -join ', ')" -ForegroundColor Gray

    if ($Operation -in @("Replace", "Recreate") -and $UploadPlan) {
        foreach ($name in @($Selected | Sort-Object)) {
            if (-not $UploadPlan.ContainsKey($name)) { continue }
            $plan = $UploadPlan[$name]
            $verb = if ($plan.Action -eq "Replace") { "update existing package" } else { "create new package" }
            $version = if ($plan.BumpVersion) { "auto-bump to $(Format-VersionString -Version $plan.BumpVersion)" } else { "keep local version" }
            Write-Host "  WhatIf: $verb '$name' ($version)" -ForegroundColor Yellow
        }
    }

    if ($Operation -in @("Remove", "Recreate")) {
        foreach ($name in @($Selected | Sort-Object)) {
            Write-Host "  WhatIf: remove deployed package '$name' if present" -ForegroundColor Yellow
        }
    }

    if ($Operation -eq "Rollback") {
        foreach ($name in @($Selected | Sort-Object)) {
            Write-Host "  WhatIf: restore deployed package '$name' from selected backup and auto-bump version if needed" -ForegroundColor Yellow
        }
    }
}

function Confirm-GuidedExecution {
    param(
        [Parameter(Mandatory)][string]$Operation,
        [bool]$HasRuleDependencies
    )

    if ($HasRuleDependencies) {
        Write-Host ""
        Write-Host "This operation affects DLP rules that reference removed classifiers." -ForegroundColor Red
        Write-Host "Update or retire those DLP rules before proceeding unless this is an intentional breaking change." -ForegroundColor Red
        $phrase = Read-Host "Type I UNDERSTAND to continue, or press Enter to abort"
        if ($phrase -ne "I UNDERSTAND") { return $false }
    }

    $confirm = Read-Host "Execute '$Operation' now? [Y/N]"
    return ($confirm.Trim().ToUpper() -eq "Y")
}

function ConvertTo-XmlText {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Security.SecurityElement]::Escape($Text)
}

function Get-ByteArraySha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($sha256.ComputeHash($Bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha256.Dispose()
    }
}

function New-CanaryRulePackagePayload {
    param(
        [Parameter(Mandatory)][string]$RulePackId,
        [Parameter(Mandatory)][string]$PackageName,
        [Parameter(Mandatory)][string]$PublisherName,
        [Parameter(Mandatory)][int]$Revision,
        [Parameter(Mandatory)][string]$Suffix,
        [Parameter(Mandatory)][object[]]$Entities
    )

    $packageNameXml = ConvertTo-XmlText -Text $PackageName
    $publisherXml = ConvertTo-XmlText -Text $PublisherName
    $descriptionXml = ConvertTo-XmlText -Text "DLPDeploy disposable canary package. It should be removed by the canary workflow."
    $entityXml = @()
    $regexXml = @()
    $resourceXml = @()
    $entityResults = @()
    $idx = 0

    foreach ($entity in @($Entities)) {
        $idx++
        $entityId = $entity.Id
        $entityName = $entity.Name
        $token = if ($entity.Token) { $entity.Token } else { "E$idx" }
        $regexId = "Regex_canary_$($Suffix)_$($idx)_r$Revision"
        $entityNameXml = ConvertTo-XmlText -Text $entityName
        $patternXml = "\bQGISCF-CANARY-$Suffix-$token-[0-9]{6}\b"

        $entityXml += @"
    <Entity id="$entityId" patternsProximity="300" recommendedConfidence="85">
      <Pattern confidenceLevel="85" proximity="50">
        <IdMatch idRef="$regexId" />
      </Pattern>
    </Entity>
"@
        $regexXml += "    <Regex id=`"$regexId`">$patternXml</Regex>"
        $resourceXml += @"
      <Resource idRef="$entityId">
        <Name default="true" langcode="en-au">$entityNameXml</Name>
        <Description default="true" langcode="en-au">$descriptionXml</Description>
      </Resource>
"@
        $entityResults += [PSCustomObject]@{
            Id      = $entityId
            Name    = $entityName
            Token   = $token
            RegexId = $regexId
        }
    }

    $xml = @"
<?xml version='1.0' encoding="utf-16"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="$RulePackId">
    <Version major="1" minor="0" build="0" revision="$Revision" />
    <Publisher id="$RulePackId" />
    <Details defaultLangCode="en-au">
      <LocalizedDetails langcode="en-au">
        <PublisherName>$publisherXml</PublisherName>
        <Name>$packageNameXml</Name>
        <Description>$descriptionXml</Description>
      </LocalizedDetails>
    </Details>
  </RulePack>
  <Rules>
$($entityXml -join "`r`n")
$($regexXml -join "`r`n")
    <LocalizedStrings>
$($resourceXml -join "`r`n")
    </LocalizedStrings>
  </Rules>
</RulePackage>
"@

    $bytes = ConvertTo-PurviewUtf16Bytes -Content $xml
    return [PSCustomObject]@{
        Xml         = $xml
        Bytes       = $bytes
        Sha256      = Get-ByteArraySha256 -Bytes $bytes
        SizeBytes   = $bytes.Length
        Version     = "1.0.0.$Revision"
        Entities    = @($entityResults)
        PackageName = $PackageName
    }
}

function Test-CanaryRulePackagePayload {
    param([Parameter(Mandatory)][object]$Payload)

    try {
        $xml = [xml]$Payload.Xml
        $entities = @($xml.RulePackage.Rules.Entity)
        if ($xml.DocumentElement.LocalName -ne "RulePackage") { return $false }
        if ($entities.Count -ne @($Payload.Entities).Count) { return $false }
        return $true
    } catch {
        Write-Host "  Canary XML parse check failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Find-CanaryPackage {
    param([Parameter(Mandatory)][string]$RulePackId)

    $lookup = Get-DeployedPackageLookup
    foreach ($pkg in @($lookup.Values)) {
        if ($pkg.Identity -and $pkg.Identity.ToString().IndexOf($RulePackId, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return [PSCustomObject]@{ Package = $pkg; Info = Get-DeployedPackageInfo -DeployedPackage $pkg }
        }

        $info = Get-DeployedPackageInfo -DeployedPackage $pkg
        if ($info.RawXml -and $info.RawXml.IndexOf($RulePackId, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return [PSCustomObject]@{ Package = $pkg; Info = $info }
        }
    }
    return $null
}

function Wait-CanaryPackageState {
    param(
        [Parameter(Mandatory)][string]$RulePackId,
        [Parameter(Mandatory)][bool]$ShouldExist,
        [int]$TimeoutSeconds = 120,
        [int]$IntervalSeconds = 10
    )

    $deadline = (Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)
    do {
        $found = Find-CanaryPackage -RulePackId $RulePackId
        if ($ShouldExist -and $found) { return $found }
        if (-not $ShouldExist -and -not $found) { return $true }
        if ((Get-Date).ToUniversalTime() -lt $deadline) {
            Start-Sleep -Seconds $IntervalSeconds
        }
    } while ((Get-Date).ToUniversalTime() -lt $deadline)

    if ($ShouldExist) { return $found }
    return $false
}

function Wait-CanaryPackageEntity {
    param(
        [Parameter(Mandatory)][string]$RulePackId,
        [Parameter(Mandatory)][string]$EntityId,
        [int]$TimeoutSeconds = 120,
        [int]$IntervalSeconds = 10
    )

    $entityKey = $EntityId.ToLowerInvariant()
    $deadline = (Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)
    do {
        $found = Find-CanaryPackage -RulePackId $RulePackId
        if ($found) {
            $entityIds = @($found.Info.Entities | ForEach-Object { $_.Id.ToString().ToLowerInvariant() })
            if ($entityIds -contains $entityKey) {
                return $found
            }
        }
        if ((Get-Date).ToUniversalTime() -lt $deadline) {
            Start-Sleep -Seconds $IntervalSeconds
        }
    } while ((Get-Date).ToUniversalTime() -lt $deadline)

    return $null
}

function Wait-CanaryPackageEntityState {
    param(
        [Parameter(Mandatory)][string]$RulePackId,
        [Parameter(Mandatory)][string]$EntityId,
        [Parameter(Mandatory)][bool]$ShouldExist,
        [string]$ExpectedName,
        [int]$TimeoutSeconds = 120,
        [int]$IntervalSeconds = 10
    )

    $entityKey = $EntityId.ToLowerInvariant()
    $deadline = (Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)
    do {
        $found = Find-CanaryPackage -RulePackId $RulePackId
        $match = $null
        if ($found) {
            $match = @($found.Info.Entities | Where-Object { $_.Id.ToString().ToLowerInvariant() -eq $entityKey } | Select-Object -First 1)
        }

        if ($ShouldExist) {
            if ($match) {
                if (-not $ExpectedName -or $match.Name -eq $ExpectedName) {
                    return $found
                }
            }
        } elseif (-not $match) {
            return $true
        }

        if ((Get-Date).ToUniversalTime() -lt $deadline) {
            Start-Sleep -Seconds $IntervalSeconds
        }
    } while ((Get-Date).ToUniversalTime() -lt $deadline)

    if ($ShouldExist) { return $null }
    return $false
}

function Find-CanarySensitiveInformationType {
    param(
        [Parameter(Mandatory)][string]$EntityId,
        [string]$EntityName
    )

    try {
        $direct = Get-DlpSensitiveInformationType -Identity $EntityId -ErrorAction Stop
        if ($direct) { return $direct }
    } catch { }

    try {
        $allSits = @(Get-DlpSensitiveInformationType -ErrorAction Stop)
    } catch {
        return $null
    }

    foreach ($sit in @($allSits)) {
        $values = @(
            $sit.Identity,
            $sit.Id,
            $sit.Name,
            $sit.LocalizedName
        ) | Where-Object { $_ }
        $joined = ($values -join " ")
        if ($joined.IndexOf($EntityId, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $sit
        }
        if ($EntityName -and $joined.IndexOf($EntityName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $sit
        }
    }

    return $null
}

function Wait-CanarySensitiveInformationTypeState {
    param(
        [Parameter(Mandatory)][string]$EntityId,
        [Parameter(Mandatory)][bool]$ShouldExist,
        [string]$EntityName,
        [int]$TimeoutSeconds = 120,
        [int]$IntervalSeconds = 10
    )

    $deadline = (Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)
    do {
        $found = Find-CanarySensitiveInformationType -EntityId $EntityId -EntityName $EntityName
        if ($ShouldExist -and $found) { return $found }
        if (-not $ShouldExist -and -not $found) { return $true }
        if ((Get-Date).ToUniversalTime() -lt $deadline) {
            Start-Sleep -Seconds $IntervalSeconds
        }
    } while ((Get-Date).ToUniversalTime() -lt $deadline)

    if ($ShouldExist) { return $null }
    return $false
}

function Invoke-ClassifierUploadPlan {
    param(
        [Parameter(Mandatory)][hashtable]$UploadPlan,
        [Parameter(Mandatory)][string[]]$Selected,
        [int]$AdditionalSlotsFreed = 0
    )

    if (-not (Test-UploadCapacityGate -UploadPlan $UploadPlan -Selected $Selected -AdditionalSlotsFreed $AdditionalSlotsFreed -Context "Guided upload")) {
        return $false
    }

    $successCount = 0
    $failCount = 0
    $skipCount = 0
    $uploadIndex = 0
    $dictionaryGuidMap = Get-DictionaryPlaceholderMap -Selected $Selected

    foreach ($name in @($Selected | Sort-Object)) {
        if (-not $UploadPlan.ContainsKey($name)) {
            $skipCount++
            continue
        }
        $plan = $UploadPlan[$name]
        if ($plan.Action -eq "Skip") {
            $skipCount++
            continue
        }

        if ($uploadIndex -gt 0) {
            $delaySec = $Config.interCallDelaySec
            Write-Host ("    Waiting {0}s before next upload..." -f $delaySec) -ForegroundColor DarkGray
            Start-Sleep -Seconds $delaySec
        }
        $uploadIndex++

        $pkg = $Packages[$name]
        $filePath = Resolve-PackageFile -Package $pkg -RequestedTier $Tier
        $isUpdate = ($plan.Action -eq "Replace")
        Write-Host "`n--- $(if ($isUpdate) { 'Updating' } else { 'Creating' }): $name ---" -ForegroundColor Cyan

        if ($isUpdate -and $plan.DeployedInfo) {
            Backup-DeployedPackage -PackageName $name -DeployedInfo $plan.DeployedInfo
        }

        try {
            $content = Resolve-RulePackageUploadContent -FilePath $filePath -DictionaryGuidMap $dictionaryGuidMap

            if ($plan.BumpVersion) {
                $bumpStr = Format-VersionString -Version $plan.BumpVersion
                Write-Host "    Auto-bumping version to $bumpStr" -ForegroundColor Yellow
                $content = Update-ContentVersion -Content $content -NewVersion $plan.BumpVersion
            }

            $fileBytes = ConvertTo-PurviewUtf16Bytes -Content $content
            Write-Host "    Payload: $([math]::Round($fileBytes.Length / 1KB, 1))KB (publisher: $Publisher)" -ForegroundColor Gray

            if ($PSCmdlet.ShouldProcess($name, "$(if ($isUpdate) { 'Update' } else { 'Create' }) SIT Rule Package")) {
                if ($isUpdate) {
                    Invoke-WithRetry -OperationName "Update $name" -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec -ScriptBlock {
                        Set-DlpSensitiveInformationTypeRulePackage -FileData $fileBytes -Confirm:$false -ErrorAction Stop
                    }
                    Write-Host "    Updated successfully" -ForegroundColor Green
                } else {
                    Invoke-WithRetry -OperationName "Create $name" -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec -ScriptBlock {
                        New-DlpSensitiveInformationTypeRulePackage -FileData $fileBytes -Confirm:$false -ErrorAction Stop
                    }
                    Write-Host "    Created successfully" -ForegroundColor Green
                }
                $successCount++
            }
        } catch {
            $failCount++
            Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host "`n=== Upload Summary ===" -ForegroundColor Cyan
    Write-Host "  Succeeded: $successCount" -ForegroundColor Green
    if ($failCount -gt 0) { Write-Host "  Failed:    $failCount" -ForegroundColor Red }
    if ($skipCount -gt 0) { Write-Host "  Skipped:   $skipCount" -ForegroundColor Yellow }
    if ($script:DeploymentManifest) {
        Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Result" -Data @{
            operation = "Upload"
            succeeded = $successCount
            failed    = $failCount
            skipped   = $skipCount
        }
    }
    return ($failCount -eq 0)
}

function Invoke-ClassifierPackageRemoval {
    param(
        [Parameter(Mandatory)][string[]]$Selected,
        [hashtable]$DeployedLookup
    )

    if (-not $DeployedLookup) {
        $DeployedLookup = Get-DeployedPackageLookup
    }

    $successCount = 0
    $failCount = 0
    $skipCount = 0
    $stoppedOnFailure = $false

    foreach ($name in @($Selected | Sort-Object)) {
        $pkg = $Packages[$name]
        Write-Host "  Removing $name ($($pkg.rulePackId))..." -ForegroundColor Cyan

        $match = Find-DeployedMatch -RegistryPackage $pkg -DeployedLookup $DeployedLookup
        if (-not $match) {
            Write-Host "    Not found in tenant - skipping" -ForegroundColor Yellow
            $skipCount++
            continue
        }

        if ($PSCmdlet.ShouldProcess($name, "Remove SIT Rule Package")) {
            try {
                Remove-DlpSensitiveInformationTypeRulePackage -Identity $match.Identity -Confirm:$false -ErrorAction Stop
                Write-Host "    Removed successfully" -ForegroundColor Green
                $successCount++
            } catch {
                Write-Host "    Failed: $($_.Exception.Message)" -ForegroundColor Red
                $failCount++
                $stoppedOnFailure = $true
                Write-Host "    Stopping remaining package removals so the tenant can be reassessed." -ForegroundColor Red
                break
            }
        }
    }

    Write-Host "`n=== Removal Summary ===" -ForegroundColor Cyan
    Write-Host "  Removed: $successCount" -ForegroundColor Green
    if ($failCount -gt 0) { Write-Host "  Failed:  $failCount" -ForegroundColor Red }
    if ($skipCount -gt 0) { Write-Host "  Skipped: $skipCount" -ForegroundColor Yellow }
    if ($script:DeploymentManifest) {
        Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Result" -Data @{
            operation = "Remove"
            removed   = $successCount
            failed    = $failCount
            skipped   = $skipCount
            stoppedOnFailure = $stoppedOnFailure
        }
    }
    return ($failCount -eq 0)
}

function Get-GuidedSelectedPackages {
    $keys = @($Packages.Keys | Sort-Object)
    Write-Host "`n=== Target Package Selection ===" -ForegroundColor Cyan
    Write-Host "  0. All enabled packages" -ForegroundColor White
    for ($i = 0; $i -lt $keys.Count; $i++) {
        $pkg = $Packages[$keys[$i]]
        Write-Host ("  {0}. {1} - {2}" -f ($i + 1), $keys[$i], $pkg.displayName) -ForegroundColor Gray
    }

    if ($PackageNames -and $PackageNames -notcontains "All") {
        $selected = Get-SelectedPackages
        Write-Host "  Parameter selection: $($selected -join ', ')" -ForegroundColor Yellow
        $useParam = Read-Host "Use this package selection? [Y/N]"
        if ($useParam.Trim().ToUpper() -eq "Y") { return @($selected) }
    }

    $choice = Read-Host "Select packages by number/comma list, or 0 for all"
    if ([string]::IsNullOrWhiteSpace($choice) -or $choice.Trim() -eq "0") {
        return @($keys)
    }

    $selectedKeys = @()
    foreach ($part in $choice -split ',') {
        $n = 0
        if ([int]::TryParse($part.Trim(), [ref]$n) -and $n -ge 1 -and $n -le $keys.Count) {
            $selectedKeys += $keys[$n - 1]
        }
    }

    $selectedKeys = @($selectedKeys | Sort-Object -Unique)
    if ($selectedKeys.Count -eq 0) {
        Write-Host "No valid package selection. Aborting." -ForegroundColor Red
    }
    return $selectedKeys
}

function Test-SelectedPackageFiles {
    param([Parameter(Mandatory)][string[]]$Selected)

    Write-Host "`n=== Local Package Validation ===" -ForegroundColor Cyan
    $allValid = $true
    foreach ($name in @($Selected | Sort-Object)) {
        $pkg = $Packages[$name]
        $filePath = Resolve-PackageFile -Package $pkg -RequestedTier $Tier
        $validation = Test-SITRulePackageXml -FilePath $filePath
        $status = if ($validation.Valid) { "VALID" } else { "INVALID" }
        $color = if ($validation.Valid) { "Green" } else { "Red" }
        Write-Host "  [$status] $name - $(Split-Path $filePath -Leaf) ($([math]::Round($validation.FileSize / 1KB, 1))KB)" -ForegroundColor $color
        foreach ($err in $validation.Errors) { Write-Host "    ERROR: $err" -ForegroundColor Red }
        foreach ($warn in $validation.Warnings) { Write-Host "    WARNING: $warn" -ForegroundColor Yellow }
        if (-not $validation.Valid) { $allValid = $false }
    }
    return $allValid
}

function Show-GuidedOperationMenu {
    param([Parameter(Mandatory)][object]$ReplaceAnalysis)

    $stats = Get-ImpactStats -Analysis $ReplaceAnalysis
    Write-Host "`n=== Available Operations ===" -ForegroundColor Cyan
    Write-Host "  1. Impact only - stop after assessment" -ForegroundColor White

    if ($stats.HasRuleDependencies) {
        Write-Host "  2. Replace/update packages - BLOCKED until dependent DLP rules are updated" -ForegroundColor DarkGray
    } elseif ($stats.RecreateRecommended) {
        Write-Host "  2. Replace/update packages - BLOCKED because bundle shape changes require recreate" -ForegroundColor DarkGray
    } else {
        Write-Host "  2. Replace/update packages - recommended" -ForegroundColor Green
    }

    if ($stats.RecreateRecommended) {
        Write-Host "  3. Recreate packages (remove then upload) - recommended for bundle shape changes" -ForegroundColor Green
    } else {
        Write-Host "  3. Recreate packages (remove then upload) - available" -ForegroundColor Yellow
    }

    Write-Host "  4. Remove packages only - retire selected bundles" -ForegroundColor Yellow
    Write-Host "  5. Abort" -ForegroundColor White

    return Read-Host "Choose an operation (1-5)"
}
#endregion

#region Connection
if ($Connect) {
    $connected = Connect-DLPSession -UPN $UPN -Tenant $Tenant -Delegated:$Delegated
    if (-not $connected) { return }
}
#endregion

#region Logging
if ($Action -ne "Validate") {
    $script:TranscriptPath = Start-DeploymentLog -ScriptName "Deploy-Classifiers"
}

$script:DeploymentManifest = if ($Action -ne "Validate") {
    New-DeploymentManifest -ScriptName "Deploy-Classifiers" -Operation $Action -ProjectRoot $ProjectRoot -Parameters @{
        Action            = $Action
        PackageNames      = @($PackageNames)
        Tier              = $Tier
        Publisher         = $Publisher
        ImpactMode        = $ImpactMode
        BackupPath        = $BackupPath
        TargetEnvironment = $TargetEnvironment
        Scope             = $Scope
        Tenant            = $Tenant
        Delegated         = [bool]$Delegated
        SkipPreFlight     = [bool]$SkipPreFlight
        SkipDictionarySync = [bool]$SkipDictionarySync
        CanaryKeepPackage = [bool]$CanaryKeepPackage
        WhatIf            = [bool]$WhatIfPreference
    }
} else {
    $null
}
if ($script:DeploymentManifest) {
    foreach ($artifact in @("settings.json", "classifiers-registry.json", "classifiers.json", "labels.json", "policies.json", "tenant-fingerprints.json")) {
        $path = Join-Path $ConfigPath $artifact
        if (Test-Path -LiteralPath $path) {
            $script:DeploymentManifest.artifacts += Get-DeploymentFileArtifact -Path $path -Role "config" -ProjectRoot $ProjectRoot
        }
    }
    $deployRegistryArtifactPath = Join-Path $DeployDir "deploy-registry.json"
    if (Test-Path -LiteralPath $deployRegistryArtifactPath) {
        $script:DeploymentManifest.artifacts += Get-DeploymentFileArtifact -Path $deployRegistryArtifactPath -Role "config" -ProjectRoot $ProjectRoot
    }
    if ($script:TranscriptPath) {
        Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Artifact" -Data @{
            role = "live-transcript"
            path = ($script:TranscriptPath -replace '\\', '/')
        }
    }
}
#endregion

#region Actions - Interactive
function Test-GuidedSession {
    try {
        Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop | Select-Object -First 1 | Out-Null
        return $true
    } catch {
        Write-Host "  No active Security & Compliance session detected." -ForegroundColor Yellow
    }

    $choice = Read-Host "Connect now? [Y/N]"
    if ($choice.Trim().ToUpper() -ne "Y") {
        return $false
    }

    if (-not (Connect-DLPSession -UPN $UPN -Tenant $Tenant -Delegated:$Delegated)) {
        return $false
    }
    return (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")
}

function Invoke-Interactive {
    Write-Host "`n=== QGISCF Classifier Bundle Manager ===" -ForegroundColor Cyan
    Write-Host "This guided workflow always assesses tenant impact before making changes." -ForegroundColor Gray

    if (-not (Test-GuidedSession)) {
        Write-Host "Cannot assess tenant impact without a Security & Compliance session. Aborting." -ForegroundColor Red
        return
    }
    if (-not (Invoke-TenantFingerprintGate)) { return }

    Write-Host "`n=== Target Environment ===" -ForegroundColor Cyan
    $tierChoice = Read-Host "Deployment tier is '$Tier'. Press Enter to keep, or type narrow/wide/full/small/medium/large"
    if (-not [string]::IsNullOrWhiteSpace($tierChoice)) {
        $tierChoice = $tierChoice.Trim().ToLowerInvariant()
        if ($tierChoice -in @("narrow", "wide", "full", "small", "medium", "large")) {
            $script:Tier = $tierChoice
        } else {
            Write-Host "Invalid tier '$tierChoice'. Keeping '$Tier'." -ForegroundColor Yellow
        }
    }
    Write-Host "  Tier:      $Tier" -ForegroundColor Gray
    Write-Host "  Publisher: $Publisher" -ForegroundColor Gray

    $selected = Get-GuidedSelectedPackages
    if ($selected.Count -eq 0) { return }
    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.targets = @(Get-ClassifierManifestTargets -Selected $selected)
    }

    $localValid = Test-SelectedPackageFiles -Selected $selected
    if (-not $localValid) {
        Write-Host "`nOne or more selected local packages are invalid. Upload and recreate options will be blocked." -ForegroundColor Red
    }

    Write-Host "`n=== Tenant/Target Assessment ===" -ForegroundColor Cyan
    $replaceAnalysis = New-ClassifierImpactAnalysis -Mode "Replace" -SelectedKeys $selected
    Write-ClassifierImpactReport -Analysis $replaceAnalysis -IncludeServiceability
    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.impact = Convert-ClassifierImpactForManifest -Analysis $replaceAnalysis
    }
    $replaceStats = Get-ImpactStats -Analysis $replaceAnalysis

    $choice = Show-GuidedOperationMenu -ReplaceAnalysis $replaceAnalysis
    Add-ClassifierDecision -Decision "GuidedMenu" -Data @{ Choice = $choice }
    switch ($choice.Trim()) {
        "1" {
            Write-Host "Assessment complete. No changes made." -ForegroundColor Green
            return
        }
        "2" {
            if (-not $localValid) {
                Write-Host "Replace/update blocked because local package validation failed." -ForegroundColor Red
                return
            }
            if ($replaceStats.HasRuleDependencies) {
                Write-Host "Replace/update blocked because removed classifiers are still referenced by DLP rules." -ForegroundColor Red
                Write-Host "Update the affected rules, then rerun the guided workflow." -ForegroundColor Red
                return
            }
            if ($replaceStats.RecreateRecommended) {
                Write-Host "Replace/update blocked because the assessment found removed classifiers." -ForegroundColor Red
                Write-Host "Use recreate so the old bundle is removed and the replacement is uploaded cleanly." -ForegroundColor Red
                return
            }
            if (-not (Invoke-ReadinessGate -Scope Classifiers)) {
                return
            }

            $uploadPlan = New-UploadPlanFromImpact -Analysis $replaceAnalysis
            if (-not (Test-UploadCapacityGate -UploadPlan $uploadPlan -Selected $selected -Context "Guided replace")) {
                return
            }
            Write-EmbeddedWhatIfPlan -Operation "Replace" -Selected $selected -UploadPlan $uploadPlan
            if (-not (Confirm-GuidedExecution -Operation "Replace" -HasRuleDependencies:$false)) {
                Add-ClassifierDecision -Decision "ReplaceConfirmation" -Data @{ Confirmed = $false }
                Write-Host "No changes made." -ForegroundColor Yellow
                return
            }
            Add-ClassifierDecision -Decision "ReplaceConfirmation" -Data @{ Confirmed = $true }
            Invoke-ClassifierUploadPlan -UploadPlan $uploadPlan -Selected $selected | Out-Null
        }
        "3" {
            if (-not $localValid) {
                Write-Host "Recreate blocked because local package validation failed." -ForegroundColor Red
                return
            }

            if (-not (Invoke-ReadinessGate -Scope Classifiers)) {
                return
            }

            Write-Host "`nAssessing full package removal impact for recreate..." -ForegroundColor Cyan
            $removeAnalysis = New-ClassifierImpactAnalysis -Mode "Remove" -SelectedKeys $selected
            Write-ClassifierImpactReport -Analysis $removeAnalysis
            if ($script:DeploymentManifest) {
                $script:DeploymentManifest.impact = [ordered]@{
                    replace = Convert-ClassifierImpactForManifest -Analysis $replaceAnalysis
                    remove  = Convert-ClassifierImpactForManifest -Analysis $removeAnalysis
                }
            }
            $removeStats = Get-ImpactStats -Analysis $removeAnalysis

            $uploadPlan = New-UploadPlanFromImpact -Analysis $replaceAnalysis
            foreach ($name in @($uploadPlan.Keys)) {
                $uploadPlan[$name].Action = "New"
                $uploadPlan[$name].DeployedInfo = $null
            }

            $slotCredit = @($replaceAnalysis.PackageImpacts | Where-Object { $_.DeployedInfo }).Count
            if (-not (Test-UploadCapacityGate -UploadPlan $uploadPlan -Selected $selected -AdditionalSlotsFreed $slotCredit -Context "Guided recreate")) {
                return
            }
            Write-EmbeddedWhatIfPlan -Operation "Recreate" -Selected $selected -UploadPlan $uploadPlan
            $hasRuleDeps = ($replaceStats.HasRuleDependencies -or $removeStats.HasRuleDependencies)
            if (-not (Confirm-GuidedExecution -Operation "Recreate" -HasRuleDependencies:$hasRuleDeps)) {
                Add-ClassifierDecision -Decision "RecreateConfirmation" -Data @{ Confirmed = $false; HasRuleDependencies = $hasRuleDeps }
                Write-Host "No changes made." -ForegroundColor Yellow
                return
            }
            Add-ClassifierDecision -Decision "RecreateConfirmation" -Data @{ Confirmed = $true; HasRuleDependencies = $hasRuleDeps }

            $removed = Invoke-ClassifierPackageRemoval -Selected $selected
            if (-not $removed) {
                Write-Host "Removal failed. Upload step skipped." -ForegroundColor Red
                return
            }
            if (-not $WhatIfPreference -and $Config.interCallDelaySec) {
                Start-Sleep -Seconds $Config.interCallDelaySec
            }
            $postRemovalSlotCredit = if ($WhatIfPreference) { $slotCredit } else { 0 }
            Invoke-ClassifierUploadPlan -UploadPlan $uploadPlan -Selected $selected -AdditionalSlotsFreed $postRemovalSlotCredit | Out-Null
        }
        "4" {
            Write-Host "`nAssessing full package removal impact..." -ForegroundColor Cyan
            $removeAnalysis = New-ClassifierImpactAnalysis -Mode "Remove" -SelectedKeys $selected
            Write-ClassifierImpactReport -Analysis $removeAnalysis
            if ($script:DeploymentManifest) {
                $script:DeploymentManifest.impact = Convert-ClassifierImpactForManifest -Analysis $removeAnalysis
            }
            $removeStats = Get-ImpactStats -Analysis $removeAnalysis

            Write-EmbeddedWhatIfPlan -Operation "Remove" -Selected $selected
            if (-not (Confirm-GuidedExecution -Operation "Remove" -HasRuleDependencies:$removeStats.HasRuleDependencies)) {
                Add-ClassifierDecision -Decision "RemoveConfirmation" -Data @{ Confirmed = $false; HasRuleDependencies = $removeStats.HasRuleDependencies }
                Write-Host "No changes made." -ForegroundColor Yellow
                return
            }
            Add-ClassifierDecision -Decision "RemoveConfirmation" -Data @{ Confirmed = $true; HasRuleDependencies = $removeStats.HasRuleDependencies }
            Invoke-ClassifierPackageRemoval -Selected $selected | Out-Null
        }
        default {
            Write-Host "Aborted. No changes made." -ForegroundColor Yellow
        }
    }
}
#endregion

#region Actions - Validate
function Invoke-Validate {
    Write-Host "`n=== Validating Rule Packages (Tier: $Tier) ===" -ForegroundColor Cyan
    $selected = Get-SelectedPackages
    $allValid = $true

    foreach ($name in $selected) {
        $pkg = $Packages[$name]
        $filePath = Resolve-PackageFile -Package $pkg -RequestedTier $Tier
        Write-Host "`n--- $name ---" -ForegroundColor Cyan

        $validation = Test-SITRulePackageXml -FilePath $filePath

        if ($validation.FileSize -gt 0) {
            Write-Host "  File: $(Split-Path $filePath -Leaf)" -ForegroundColor Gray
            Write-Host "  Size: $([math]::Round($validation.FileSize / 1KB, 1))KB / 150KB" -ForegroundColor Gray
        }

        foreach ($err in $validation.Errors) {
            Write-Host "  ERROR: $err" -ForegroundColor Red
        }
        foreach ($warn in $validation.Warnings) {
            Write-Host "  WARNING: $warn" -ForegroundColor Yellow
        }

        if ($validation.Valid) {
            Write-Host "  VALID" -ForegroundColor Green
        } else {
            Write-Host "  INVALID - will not upload" -ForegroundColor Red
            $allValid = $false
        }
    }

    Write-Host ""
    if ($allValid) {
        Write-Host "All selected packages passed validation." -ForegroundColor Green
    } else {
        Write-Host "Some packages have errors. Fix before uploading." -ForegroundColor Red
    }
    return $allValid
}
#endregion

#region Actions - Upload
function Invoke-Upload {
    Write-Host "`n=== Uploading Rule Packages (Tier: $Tier, Publisher: $Publisher) ===" -ForegroundColor Cyan
    $selected = Get-SelectedPackages
    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.targets = @(Get-ClassifierManifestTargets -Selected $selected)
    }

    # Step 1: Validate
    Write-Host "`nStep 1: Validating files..." -ForegroundColor Cyan
    $valid = Invoke-Validate
    if (-not $valid) {
        Write-Error "Aborting upload due to validation errors."
        return
    }

    if ($WhatIfPreference -and -not (Test-DLPSessionAvailable -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) {
        Write-Host "`nWhatIf: The following local packages would be uploaded:" -ForegroundColor Yellow
        foreach ($name in $selected) {
            $pkg = $Packages[$name]
            $filePath = Resolve-PackageFile -Package $pkg -RequestedTier $Tier
            $localInfo = Get-LocalPackageInfo -FilePath $filePath
            if ($localInfo) {
                Write-Host "  - ${name}: $(Split-Path $filePath -Leaf) (v$($localInfo.VersionStr), $($localInfo.EntityCount) SITs)" -ForegroundColor Yellow
            } else {
                Write-Host "  - ${name}: $(Split-Path $filePath -Leaf)" -ForegroundColor Yellow
            }
        }
        Write-Host "  Tenant impact and capacity were not assessed because no active Security & Compliance session is available." -ForegroundColor Yellow
        Write-Host "  Re-run with -Connect to include tenant fingerprint, readiness, dependencies, and package-slot checks." -ForegroundColor Yellow
        if ($script:DeploymentManifest) {
            Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Result" -Data @{
                operation = "Upload"
                status    = "PlannedOnlyLocal"
                reason    = "NoActiveTenantSession"
            }
        }
        return
    }

    # Verify session
    if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) { return }
    if (-not (Invoke-TenantFingerprintGate)) { return }

    if (-not (Invoke-ReadinessGate -Scope Classifiers)) {
        return
    }

    # Step 2: Get existing deployments
    Write-Host "`nStep 2: Checking existing deployments..." -ForegroundColor Cyan
    $deployed = @()
    try {
        $deployed = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)
    } catch { }
    $deployedLookup = @{}
    foreach ($d in $deployed) {
        if ($d -and $d.Identity) {
            $deployedLookup[$d.Identity] = $d
        }
    }
    Write-Host "  Found $($deployedLookup.Count) existing rule package(s) in tenant" -ForegroundColor Gray

    # Step 3: Pre-flight comparison and user prompts
    $uploadPlan = @{}

    if (-not $SkipPreFlight) {
        Write-Host "`nStep 3: Overall impact assessment..." -ForegroundColor Cyan
        $overallAnalysis = New-ClassifierImpactAnalysis -Mode "Replace" -SelectedKeys $selected
        Write-ClassifierImpactReport -Analysis $overallAnalysis -IncludeServiceability
        if ($script:DeploymentManifest) {
            $script:DeploymentManifest.impact = Convert-ClassifierImpactForManifest -Analysis $overallAnalysis
        }

        Write-Host "`nStep 4: Per-package deployment choices..." -ForegroundColor Cyan
        $aborted = $false

        foreach ($name in $selected) {
            if ($aborted) { break }

            $pkg = $Packages[$name]
            $filePath = Resolve-PackageFile -Package $pkg -RequestedTier $Tier
            $localInfo = Get-LocalPackageInfo -FilePath $filePath
            $existingPkg = Find-DeployedMatch -RegistryPackage $pkg -DeployedLookup $deployedLookup

            if (-not $existingPkg) {
                # New package - no conflict
                Write-Host "`n  --- $name (NEW) ---" -ForegroundColor Green
                if ($localInfo) {
                    Write-Host "    Version:   $($localInfo.VersionStr)" -ForegroundColor Gray
                    Write-Host "    Entities:  $($localInfo.EntityCount) SITs" -ForegroundColor Gray
                    Write-Host "    Size:      $([math]::Round($localInfo.FileSize / 1KB, 1))KB / 150KB" -ForegroundColor Gray
                }
                $uploadPlan[$name] = @{
                    Action      = "New"
                    LocalInfo   = $localInfo
                    DeployedInfo = $null
                    BumpVersion = $null
                }
                continue
            }

            # Package exists - show detailed comparison
            $deployedInfo = Get-DeployedPackageInfo -DeployedPackage $existingPkg

            Write-Host "`n  --- $name (EXISTS IN TENANT) ---" -ForegroundColor Yellow
            Write-Host "    Deployed:" -ForegroundColor White
            Write-Host "      Identity:  $($deployedInfo.Identity)" -ForegroundColor Gray
            Write-Host "      Publisher: $($deployedInfo.Publisher)" -ForegroundColor Gray
            Write-Host "      Version:   $($deployedInfo.VersionStr)" -ForegroundColor Gray
            if ($deployedInfo.EntityCount -ge 0) {
                Write-Host "      Entities:  $($deployedInfo.EntityCount) SITs" -ForegroundColor Gray
            }
            if ($deployedInfo.CreatedUTC) {
                Write-Host "      Created:   $($deployedInfo.CreatedUTC)" -ForegroundColor Gray
            }
            if ($deployedInfo.ModifiedUTC) {
                Write-Host "      Modified:  $($deployedInfo.ModifiedUTC)" -ForegroundColor Gray
            }

            Write-Host "    Local:" -ForegroundColor White
            $bumpedVersion = $null
            if ($localInfo) {
                Write-Host "      Version:   $($localInfo.VersionStr)" -ForegroundColor Gray
                Write-Host "      Entities:  $($localInfo.EntityCount) SITs" -ForegroundColor Gray
                Write-Host "      Size:      $([math]::Round($localInfo.FileSize / 1KB, 1))KB / 150KB" -ForegroundColor Gray

                # Version comparison
                if ($localInfo.Version -and $deployedInfo.Version) {
                    $vCmp = Compare-PackageVersions -Local $localInfo.Version -Deployed $deployedInfo.Version
                    if ($null -ne $vCmp -and $vCmp -le 0) {
                        $bumpedVersion = Get-BumpedVersion -LocalVersion $localInfo.Version -DeployedVersion $deployedInfo.Version
                        $bumpStr = Format-VersionString -Version $bumpedVersion
                        Write-Host "      Version $($localInfo.VersionStr) <= deployed $($deployedInfo.VersionStr) - will auto-bump to $bumpStr" -ForegroundColor Yellow
                    } elseif ($null -ne $vCmp -and $vCmp -gt 0) {
                        Write-Host "      Version $($localInfo.VersionStr) > deployed $($deployedInfo.VersionStr) - OK" -ForegroundColor Green
                    }
                }

                # Entity diff
                if ($deployedInfo.Entities.Count -gt 0) {
                    $diff = Get-EntityDiff -LocalEntities $localInfo.Entities -DeployedEntities $deployedInfo.Entities
                    Write-Host "    Entity Changes:" -ForegroundColor White
                    Write-Host "      Unchanged: $($diff.Unchanged.Count)" -ForegroundColor Gray
                    if ($diff.Added.Count -gt 0) {
                        Write-Host "      Added:     $($diff.Added.Count)" -ForegroundColor Green
                        foreach ($e in $diff.Added) {
                            Write-Host "        + $($e.Name)" -ForegroundColor Green
                        }
                    }
                    if ($diff.Removed.Count -gt 0) {
                        Write-Host "      REMOVED:   $($diff.Removed.Count)" -ForegroundColor Red
                        foreach ($e in $diff.Removed) {
                            Write-Host "        - $($e.Name) ($($e.Id))" -ForegroundColor Red
                        }

                        # Check DLP dependencies for removed SITs
                        $removedGuids = @($diff.Removed | ForEach-Object { $_.Id })
                        Write-Host "    Checking DLP rule dependencies for removed SITs..." -ForegroundColor Cyan
                        $deps = Test-SITRuleDependencies -SitGuids $removedGuids

                        if ($deps.Count -gt 0) {
                            $guidNameMap = @{}
                            foreach ($e in $diff.Removed) { $guidNameMap[$e.Id.ToLower()] = $e.Name }

                            Write-Host "    DLP RULE DEPENDENCIES FOUND:" -ForegroundColor Red
                            foreach ($dep in $deps) {
                                $names = ($dep.MatchedGuids | ForEach-Object {
                                    $lower = $_.ToLower()
                                    if ($guidNameMap[$lower]) { $guidNameMap[$lower] } else { $_ }
                                }) -join ", "
                                Write-Host "      Rule: $($dep.RuleName)" -ForegroundColor Red
                                Write-Host "        Policy:     $($dep.PolicyName)" -ForegroundColor Red
                                Write-Host "        References: $names" -ForegroundColor Red
                            }
                            Write-Host ""
                            Write-Host "    WARNING: Replacing this package will cause these DLP rules to silently" -ForegroundColor Red
                            Write-Host "    stop matching the removed SIT types. Update the rules before or after." -ForegroundColor Red
                        } else {
                            Write-Host "    No DLP rules reference the removed SITs." -ForegroundColor Green
                        }
                    }
                }
            }

            # Prompt user
            Write-Host ""
            $choice = Read-Host "    Action for ${name}: [R]eplace, [S]kip, [A]bort all (R/S/A)"
            if (-not $choice) { $choice = "S" }
            switch ($choice.Trim().ToUpper()) {
                "R" {
                    $uploadPlan[$name] = @{
                        Action       = "Replace"
                        LocalInfo    = $localInfo
                        DeployedInfo = $deployedInfo
                        BumpVersion  = $bumpedVersion
                    }
                }
                "S" {
                    Write-Host "    Skipping $name." -ForegroundColor Yellow
                    $uploadPlan[$name] = @{ Action = "Skip" }
                }
                "A" {
                    Write-Host "    Aborting all uploads." -ForegroundColor Red
                    $aborted = $true
                }
                default {
                    Write-Host "    Invalid choice '$choice'. Skipping $name." -ForegroundColor Yellow
                    $uploadPlan[$name] = @{ Action = "Skip" }
                }
            }
        }

        if ($aborted) {
            Write-Host "`nUpload aborted by user." -ForegroundColor Red
            return
        }
    } else {
        # SkipPreFlight: auto-replace all, auto-bump versions
        Write-Host "`nStep 3: Pre-flight skipped (-SkipPreFlight)." -ForegroundColor Yellow
        foreach ($name in $selected) {
            $pkg = $Packages[$name]
            $filePath = Resolve-PackageFile -Package $pkg -RequestedTier $Tier
            $localInfo = Get-LocalPackageInfo -FilePath $filePath
            $existingPkg = Find-DeployedMatch -RegistryPackage $pkg -DeployedLookup $deployedLookup

            if ($existingPkg) {
                $deployedInfo = Get-DeployedPackageInfo -DeployedPackage $existingPkg
                $bumpedVersion = $null
                if ($localInfo -and $localInfo.Version -and $deployedInfo.Version) {
                    $bumpedVersion = Get-BumpedVersion -LocalVersion $localInfo.Version -DeployedVersion $deployedInfo.Version
                }
                $uploadPlan[$name] = @{
                    Action       = "Replace"
                    LocalInfo    = $localInfo
                    DeployedInfo = $deployedInfo
                    BumpVersion  = $bumpedVersion
                }
            } else {
                $uploadPlan[$name] = @{
                    Action       = "New"
                    LocalInfo    = $localInfo
                    DeployedInfo = $null
                    BumpVersion  = $null
                }
            }
        }
    }

    # Backup existing & Upload
    $hasWork = $false
    foreach ($name in $selected) {
        if ($uploadPlan.ContainsKey($name) -and $uploadPlan[$name].Action -in @("New", "Replace")) {
            $hasWork = $true
            break
        }
    }
    if (-not $hasWork) {
        Write-Host "`nNo packages selected for upload." -ForegroundColor Yellow
        return
    }

    if (-not (Test-UploadCapacityGate -UploadPlan $uploadPlan -Selected $selected -Context "Direct upload")) {
        return
    }

    if (-not $SkipPreFlight) {
        Write-EmbeddedWhatIfPlan -Operation "Replace" -Selected $selected -UploadPlan $uploadPlan
        if ($WhatIfPreference) {
            Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Result" -Data @{
                operation = "Upload"
                status    = "PlannedOnly"
            }
            return
        }
        $confirmUpload = Read-Host "Execute this upload/replace plan? [Y/N]"
        Add-ClassifierDecision -Decision "UploadConfirmation" -Data @{ Confirmed = ($confirmUpload.Trim().ToUpper() -eq "Y") }
        if ($confirmUpload.Trim().ToUpper() -ne "Y") {
            Write-Host "Upload aborted. No changes made." -ForegroundColor Yellow
            return
        }
    } elseif ($WhatIfPreference) {
        Write-EmbeddedWhatIfPlan -Operation "Replace" -Selected $selected -UploadPlan $uploadPlan
        Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Result" -Data @{
            operation = "Upload"
            status    = "PlannedOnly"
        }
        return
    }

    Write-Host "`nStep 5: Backup & Upload..." -ForegroundColor Cyan
    $successCount = 0
    $failCount    = 0
    $skipCount    = 0
    $uploadIndex  = 0
    $dictionaryGuidMap = Get-DictionaryPlaceholderMap -Selected $selected

    foreach ($name in $selected) {
        if (-not $uploadPlan.ContainsKey($name)) { continue }
        $plan = $uploadPlan[$name]

        if ($plan.Action -eq "Skip") {
            $skipCount++
            continue
        }

        # Inter-call delay between uploads (Purview throttles aggressively)
        if ($uploadIndex -gt 0) {
            $delaySec = $Config.interCallDelaySec
            Write-Host ("    Waiting {0}s before next upload..." -f $delaySec) -ForegroundColor DarkGray
            Start-Sleep -Seconds $delaySec
        }
        $uploadIndex++

        $pkg  = $Packages[$name]
        $filePath = Resolve-PackageFile -Package $pkg -RequestedTier $Tier
        $isUpdate = ($plan.Action -eq "Replace")
        Write-Host "`n--- $(if ($isUpdate) { 'Updating' } else { 'Creating' }): $name ---" -ForegroundColor Cyan

        # Backup existing package before overwriting
        if ($isUpdate -and $plan.DeployedInfo) {
            Backup-DeployedPackage -PackageName $name -DeployedInfo $plan.DeployedInfo
        }

        try {
            $content = Resolve-RulePackageUploadContent -FilePath $filePath -DictionaryGuidMap $dictionaryGuidMap

            # Auto-bump version if needed
            if ($plan.BumpVersion) {
                $bumpStr = Format-VersionString -Version $plan.BumpVersion
                Write-Host "    Auto-bumping version to $bumpStr" -ForegroundColor Yellow
                $content = Update-ContentVersion -Content $content -NewVersion $plan.BumpVersion
            }

            $fileBytes = ConvertTo-PurviewUtf16Bytes -Content $content
            Write-Host "    Payload: $([math]::Round($fileBytes.Length / 1KB, 1))KB (publisher: $Publisher)" -ForegroundColor Gray

            if ($PSCmdlet.ShouldProcess($name, "$(if ($isUpdate) { 'Update' } else { 'Create' }) SIT Rule Package")) {
                if ($isUpdate) {
                    Invoke-WithRetry -OperationName "Update $name" -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec -ScriptBlock {
                        Set-DlpSensitiveInformationTypeRulePackage -FileData $fileBytes -Confirm:$false -ErrorAction Stop
                    }
                    Write-Host "    Updated successfully" -ForegroundColor Green
                } else {
                    Invoke-WithRetry -OperationName "Create $name" -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec -ScriptBlock {
                        New-DlpSensitiveInformationTypeRulePackage -FileData $fileBytes -Confirm:$false -ErrorAction Stop
                    }
                    Write-Host "    Created successfully" -ForegroundColor Green
                }
                $successCount++
            }
        } catch {
            $failCount++
            $errMsg = $_.Exception.Message
            Write-Host "    FAILED: $errMsg" -ForegroundColor Red
            if ($errMsg -match "regex")    { Write-Host "    Hint: A regex pattern may be invalid for Boost.RegEx 5.1.3" -ForegroundColor Yellow }
            if ($errMsg -match "150")      { Write-Host "    Hint: File may exceed 150KB limit" -ForegroundColor Yellow }
            if ($errMsg -match "encoding") { Write-Host "    Hint: File may need UTF-16 encoding" -ForegroundColor Yellow }
            if ($errMsg -match "version")  { Write-Host "    Hint: Package version may need incrementing" -ForegroundColor Yellow }
        }
    }

    Write-Host "`n=== Upload Summary ===" -ForegroundColor Cyan
    Write-Host "  Succeeded: $successCount" -ForegroundColor Green
    if ($failCount -gt 0)  { Write-Host "  Failed:    $failCount" -ForegroundColor Red }
    if ($skipCount -gt 0)  { Write-Host "  Skipped:   $skipCount" -ForegroundColor Yellow }
    Write-Host "  Total:     $($successCount + $failCount + $skipCount)" -ForegroundColor Gray
    if ($script:DeploymentManifest) {
        Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Result" -Data @{
            operation = "Upload"
            succeeded = $successCount
            failed    = $failCount
            skipped   = $skipCount
        }
    }
}
#endregion

#region Actions - Estimate
function Invoke-Estimate {
    Write-Host "`n=== Tenant Package Capacity Estimate ===" -ForegroundColor Cyan

    if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) { return }
    if (-not (Invoke-TenantFingerprintGate)) { return }

    # Get deployed packages
    $deployed = @()
    try { $deployed = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop) } catch { }

    # Get all tenant SITs
    $allSITs = @()
    try { $allSITs = @(Get-DlpSensitiveInformationType -ErrorAction Stop) } catch { }
    $builtInCount = @($allSITs | Where-Object { $_.Publisher -eq "Microsoft Corporation" }).Count
    $customSITs   = @($allSITs | Where-Object { $_.Publisher -ne "Microsoft Corporation" })
    $customCount  = $customSITs.Count

    # --- Package slots gauge ---
    Write-Host "`n  Package Slots ($($deployed.Count)/10):" -ForegroundColor White
    $barLen = 40
    $filled = [math]::Min([math]::Round(($deployed.Count / 10) * $barLen), $barLen)
    $empty  = $barLen - $filled
    $pctPkg = [math]::Round(($deployed.Count / 10) * 100)
    $barColor = if ($deployed.Count -ge 9) { "Red" } elseif ($deployed.Count -ge 7) { "Yellow" } else { "Green" }
    Write-Host "  [$(('#' * $filled) + ('.' * $empty))]  $($deployed.Count)/10 (${pctPkg}%)" -ForegroundColor $barColor

    # --- Package details ---
    Write-Host "`n  Deployed Packages:" -ForegroundColor White
    if ($deployed.Count -eq 0) {
        Write-Host "    (none)" -ForegroundColor DarkGray
    }

    $idx = 0
    foreach ($d in $deployed) {
        $idx++
        $info = Get-DeployedPackageInfo -DeployedPackage $d
        $isMicrosoft = ($d.Publisher -eq "Microsoft Corporation" -or $d.Name -match "^Microsoft")
        $nameColor = if ($isMicrosoft) { "DarkGray" } else { "White" }
        $tag = if ($isMicrosoft) { " (built-in)" } else { "" }
        $entityStr = if ($info.EntityCount -ge 0) { "$($info.EntityCount)" } else { "?" }

        Write-Host ""
        Write-Host "    $idx. $($d.Name)${tag}" -ForegroundColor $nameColor
        Write-Host "       Identity:  $($d.Identity)" -ForegroundColor DarkGray
        Write-Host "       Publisher: $($d.Publisher)" -ForegroundColor DarkGray
        Write-Host "       Version:   $($info.VersionStr)" -ForegroundColor DarkGray
        Write-Host "       Entities:  $entityStr" -ForegroundColor DarkGray
        if ($d.WhenCreatedUTC) { Write-Host "       Created:   $($d.WhenCreatedUTC)" -ForegroundColor DarkGray }
        if ($d.WhenChangedUTC) { Write-Host "       Modified:  $($d.WhenChangedUTC)" -ForegroundColor DarkGray }
    }

    # --- Custom SIT gauge ---
    Write-Host "`n  Custom SIT Capacity ($customCount/500):" -ForegroundColor White
    $filled = [math]::Min([math]::Round(($customCount / 500) * $barLen), $barLen)
    $empty  = $barLen - $filled
    $pctSIT = [math]::Round(($customCount / 500) * 100)
    $barColor = if ($customCount -ge 450) { "Red" } elseif ($customCount -ge 350) { "Yellow" } else { "Green" }
    Write-Host "  [$(('#' * $filled) + ('.' * $empty))]  $customCount/500 (${pctSIT}%)" -ForegroundColor $barColor
    Write-Host "    Built-in SITs: $builtInCount (do not count against 500 limit)" -ForegroundColor DarkGray

    # --- Per-package size and entity gauges ---
    $customPkgs = @($deployed | Where-Object { $_.Publisher -ne "Microsoft Corporation" -and $_.Name -notmatch "^Microsoft" })
    if ($customPkgs.Count -gt 0) {
        Write-Host "`n  Per-Package Limits (custom packages):" -ForegroundColor White
        foreach ($d in $customPkgs) {
            $info = Get-DeployedPackageInfo -DeployedPackage $d
            Write-Host "    $($d.Name):" -ForegroundColor White

            if ($info.EntityCount -ge 0) {
                $entPct = [math]::Round(($info.EntityCount / 50) * 100)
                $entColor = if ($info.EntityCount -ge 45) { "Red" } elseif ($info.EntityCount -ge 35) { "Yellow" } else { "Green" }
                Write-Host "      Entities: $($info.EntityCount)/50 (${entPct}%)" -ForegroundColor $entColor
            }
            if ($info.RawBytes) {
                $sizeKB = [math]::Round($info.RawBytes.Length / 1KB, 1)
                $sizePct = [math]::Round(($info.RawBytes.Length / 153600) * 100)
                $szColor = if ($sizePct -ge 90) { "Red" } elseif ($sizePct -ge 70) { "Yellow" } else { "Green" }
                Write-Host ("      Size:     {0}KB/150KB ({1}%)" -f $sizeKB, $sizePct) -ForegroundColor $szColor
            }
        }
    }

    # --- Local packages status ---
    Write-Host "`n  Local Packages (registry):" -ForegroundColor White
    $newCount = 0
    $deployedLookup = @{}
    foreach ($d in $deployed) {
        if ($d -and $d.Identity) { $deployedLookup[$d.Identity] = $d }
    }

    foreach ($name in $Packages.Keys) {
        $pkg = $Packages[$name]
        $filePath = Resolve-PackageFile -Package $pkg -RequestedTier $Tier
        $exists = Test-Path $filePath
        $localInfo = if ($exists) { Get-LocalPackageInfo -FilePath $filePath } else { $null }
        $match = Find-DeployedMatch -RegistryPackage $pkg -DeployedLookup $deployedLookup
        $status = if ($match) { "DEPLOYED" } else { "NEW"; $newCount++ }
        $statusColor = if ($match) { "Green" } else { "Yellow" }

        $sizeStr = if ($localInfo) { "$([math]::Round($localInfo.FileSize / 1KB, 1))KB" } elseif ($exists) { "$([math]::Round((Get-Item $filePath).Length / 1KB, 1))KB" } else { "MISSING" }
        $entityStr = if ($localInfo) { "$($localInfo.EntityCount) SITs" } else { "?" }
        $versionStr = if ($localInfo) { "v$($localInfo.VersionStr)" } else { "" }

        Write-Host "    [$status] $name - $entityStr, $sizeStr $versionStr" -ForegroundColor $statusColor
    }

    # --- Remaining capacity ---
    $slotsRemaining = 10 - $deployed.Count
    $sitsRemaining  = 500 - $customCount
    $maxNewSITs     = [math]::Min($slotsRemaining * 50, $sitsRemaining)
    $constrainedBy  = if ($slotsRemaining * 50 -le $sitsRemaining) { "package slots ($slotsRemaining x 50)" } else { "SIT limit ($sitsRemaining remaining)" }

    Write-Host "`n  Remaining Capacity:" -ForegroundColor White
    Write-Host "    Package slots:    $slotsRemaining of 10 available" -ForegroundColor $(if ($slotsRemaining -le 1) { "Red" } elseif ($slotsRemaining -le 3) { "Yellow" } else { "Green" })
    Write-Host "    Custom SIT slots: $sitsRemaining of 500 available" -ForegroundColor $(if ($sitsRemaining -le 50) { "Red" } elseif ($sitsRemaining -le 150) { "Yellow" } else { "Green" })
    Write-Host "    Max new SITs:     $maxNewSITs (constrained by $constrainedBy)" -ForegroundColor Gray

    if ($newCount -gt 0 -and $newCount -gt $slotsRemaining) {
        Write-Host "`n  WARNING: $newCount undeployed local packages but only $slotsRemaining slot(s) remaining." -ForegroundColor Red
        Write-Host "  Consider consolidating packages or removing unused ones." -ForegroundColor Red
    }

    $selected = Get-SelectedPackages
    if ($selected.Count -gt 0) {
        $capacityPlan = New-ClassifierCapacityPlan -SelectedKeys $selected
        Write-ClassifierCapacityPlanReport -Plan $capacityPlan
        if ($script:DeploymentManifest) {
            $script:DeploymentManifest.impact = [ordered]@{
                capacityPlan = Convert-CapacityPlanForManifest -Plan $capacityPlan
            }
        }
    }

    # --- Reference limits ---
    Write-Host "`n  Purview Hard Limits (reference):" -ForegroundColor DarkGray
    Write-Host "    Rule packages/tenant:      10          Entities/package:           50" -ForegroundColor DarkGray
    Write-Host "    Package file size:         150KB       Custom SITs/tenant:         500" -ForegroundColor DarkGray
    Write-Host "    Regex length:              1,024ch     Regexes/SIT:                20" -ForegroundColor DarkGray
    Write-Host "    Keyword terms/list:        2,048       Keyword dicts (tenant):     1MB" -ForegroundColor DarkGray
    Write-Host "    Keyword dict SITs/tenant:  50          Capturing groups/regex:     1" -ForegroundColor DarkGray
}
#endregion

#region Actions - Capacity Plan
function Invoke-CapacityPlan {
    Write-Host "`n=== Classifier Capacity Planning ===" -ForegroundColor Cyan

    if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) { return }
    if (-not (Invoke-TenantFingerprintGate)) { return }

    $selected = Get-SelectedPackages
    if ($selected.Count -eq 0) {
        Write-Host "No valid packages selected." -ForegroundColor Yellow
        return
    }

    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.targets = @(Get-ClassifierManifestTargets -Selected $selected)
    }

    $capacityPlan = New-ClassifierCapacityPlan -SelectedKeys $selected
    Write-ClassifierCapacityPlanReport -Plan $capacityPlan
    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.impact = [ordered]@{
            capacityPlan = Convert-CapacityPlanForManifest -Plan $capacityPlan
        }
    }
}
#endregion

#region Actions - Adopt / Rebase Plan
function Invoke-AdoptPlan {
    Write-Host "`n=== Classifier Adoption Planning ===" -ForegroundColor Cyan

    if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) { return }
    if (-not (Invoke-TenantFingerprintGate)) { return }

    $selected = Get-SelectedPackages
    if ($selected.Count -eq 0) {
        Write-Host "No valid packages selected." -ForegroundColor Yellow
        return
    }

    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.targets = @(Get-ClassifierManifestTargets -Selected $selected)
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $runId = if ($script:DeploymentManifest -and $script:DeploymentManifest.runId) { $script:DeploymentManifest.runId } else { [guid]::NewGuid().ToString() }
    $outputDir = Join-Path (Join-Path $ProjectRoot "reports") ("adoption-drafts\{0}_{1}" -f $timestamp, $runId)
    if (-not (Test-Path -LiteralPath $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    $plan = New-ClassifierAdoptionPlan -SelectedKeys $selected -OutputDir $outputDir
    $packagerInput = Write-ClassifierPackagerInput -Plan $plan -SelectedKeys $selected
    Write-ClassifierAdoptionPlanReport -Plan $plan
    Write-Host "  Packager input: $(ConvertTo-ProjectRelativePath -Path $packagerInput.Path)" -ForegroundColor Gray
    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.impact = [ordered]@{
            adoptionPlan = Convert-ClassifierAdoptionPlanForManifest -Plan $plan
            packagerInput = ConvertTo-ProjectRelativePath -Path $packagerInput.Path
        }
        $script:DeploymentManifest.artifacts += Get-DeploymentFileArtifact -Path $packagerInput.Path -Role "packager-input" -ProjectRoot $ProjectRoot
        foreach ($snapshotArtifact in @($packagerInput.SnapshotArtifacts)) {
            $script:DeploymentManifest.artifacts += $snapshotArtifact
        }
        foreach ($assignment in @($plan.Assignments)) {
            if ($assignment.Draft -and (Test-Path -LiteralPath $assignment.Draft.Path)) {
                $script:DeploymentManifest.artifacts += Get-DeploymentFileArtifact -Path $assignment.Draft.Path -Role "rebase-draft" -ProjectRoot $ProjectRoot
            }
        }
        Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Result" -Data @{
            operation = "AdoptPlan"
            outputDir = ConvertTo-ProjectRelativePath -Path $outputDir
            packagerInput = ConvertTo-ProjectRelativePath -Path $packagerInput.Path
            readyDrafts = @($plan.Assignments | Where-Object { $_.ReadyToUpload }).Count
            blockedDrafts = @($plan.Assignments | Where-Object { -not $_.ReadyToUpload }).Count
        }
    }
}
#endregion

#region Actions - Prune Existing Packages
function Invoke-PrunePackages {
    Write-Host "`n=== Existing Classifier Package Prune ===" -ForegroundColor Cyan

    if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) { return }
    if (-not (Invoke-TenantFingerprintGate)) { return }

    $selectedLocal = Get-SelectedPackages
    if ($selectedLocal.Count -eq 0) {
        Write-Host "No valid local package selection. Capacity context will use all deployed packages only." -ForegroundColor Yellow
    }

    $capacityPlan = New-ClassifierCapacityPlan -SelectedKeys $selectedLocal
    Write-ClassifierCapacityPlanReport -Plan $capacityPlan
    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.impact = [ordered]@{
            capacityPlan = Convert-CapacityPlanForManifest -Plan $capacityPlan
        }
    }

    $selectedForDelete = Select-PrunePackagesFromMenu -Plan $capacityPlan
    if ($selectedForDelete.Count -eq 0) {
        Write-Host "No packages selected. Nothing deleted." -ForegroundColor Yellow
        Add-ClassifierDecision -Decision "PruneSelection" -Data @{ SelectedCount = 0; Aborted = $true }
        return
    }

    Write-Host "`nRechecking selected packages and DLP rule references before delete..." -ForegroundColor Cyan
    $selectedForDelete = Update-PruneSelectionFromTenant -SelectedPackages $selectedForDelete -SelectedLocal $selectedLocal
    if ($selectedForDelete.Count -eq 0) {
        Write-Host "No selected packages still exist in the tenant. Nothing deleted." -ForegroundColor Yellow
        Add-ClassifierDecision -Decision "PruneSelection" -Data @{ SelectedCount = 0; Aborted = $true; Reason = "NoCurrentPackagesAfterRecheck" }
        return
    }
    Add-ClassifierDecision -Decision "PruneDependencyRecheck" -Data @{
        SelectedCount = $selectedForDelete.Count
        RulePackIds = @($selectedForDelete | ForEach-Object { $_.RulePackId })
        ReferencedRuleCount = @($selectedForDelete | ForEach-Object { @($_.ReferencedRules).Count } | Measure-Object -Sum).Sum
    }

    $selectedForDelete = Confirm-PruneSelection -SelectedPackages $selectedForDelete
    if ($selectedForDelete.Count -eq 0) {
        Write-Host "No confirmed packages. Nothing deleted." -ForegroundColor Yellow
        Add-ClassifierDecision -Decision "PruneSelection" -Data @{ SelectedCount = 0; Aborted = $true; Reason = "NoConfirmedPackages" }
        return
    }

    Write-Host "`n=== Delete Plan ===" -ForegroundColor Cyan
    foreach ($pkg in @($selectedForDelete)) {
        $name = if ($pkg.Name) { $pkg.Name } else { $pkg.RulePackId }
        Write-Host "  WhatIf: remove existing package '$name' ($($pkg.RulePackId)); refs: $(@($pkg.ReferencedRules).Count)" -ForegroundColor Yellow
    }

    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.targets = @(Get-PruneManifestTargets -SelectedPackages $selectedForDelete)
    }
    Add-ClassifierDecision -Decision "PruneSelection" -Data @{
        SelectedCount = $selectedForDelete.Count
        RulePackIds = @($selectedForDelete | ForEach-Object { $_.RulePackId })
    }

    if ($WhatIfPreference) {
        Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Result" -Data @{
            operation = "Prune"
            status = "PlannedOnly"
            selected = $selectedForDelete.Count
        }
        return
    }

    $finalConfirm = Read-Host "Delete these existing tenant packages now? [Y/N]"
    Add-ClassifierDecision -Decision "PruneConfirmation" -Data @{ Confirmed = ($finalConfirm.Trim().ToUpperInvariant() -eq "Y") }
    if ($finalConfirm.Trim().ToUpperInvariant() -ne "Y") {
        Write-Host "Prune aborted. No packages deleted." -ForegroundColor Yellow
        return
    }

    $successCount = 0
    $failCount = 0
    $stoppedOnFailure = $false
    foreach ($pkg in @($selectedForDelete)) {
        $name = if ($pkg.Name) { $pkg.Name } else { $pkg.RulePackId }
        Write-Host "`nRemoving existing package: $name" -ForegroundColor Cyan
        try {
            if ($pkg.Info -and ($pkg.Info.RawBytes -or $pkg.Info.RawXml)) {
                $backup = Backup-DeployedPackage -PackageName ($name -replace '[^a-zA-Z0-9\-]', '_') -DeployedInfo $pkg.Info
                if ($backup -and $script:DeploymentManifest) {
                    $script:DeploymentManifest.artifacts += Get-DeploymentFileArtifact -Path $backup -Role "prune-backup" -ProjectRoot $ProjectRoot
                }
            }

            if ($PSCmdlet.ShouldProcess($name, "Remove existing SIT Rule Package")) {
                Remove-DlpSensitiveInformationTypeRulePackage -Identity $pkg.Identity -Confirm:$false -ErrorAction Stop
                Write-Host "  Removed." -ForegroundColor Green
                $successCount++
            }
        } catch {
            Write-Host "  Failed: $($_.Exception.Message)" -ForegroundColor Red
            $failCount++
            $stoppedOnFailure = $true
            Write-Host "  Stopping remaining deletes so the tenant can be reassessed." -ForegroundColor Red
            break
        }
    }

    Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Result" -Data @{
        operation = "Prune"
        removed = $successCount
        failed = $failCount
        stoppedOnFailure = $stoppedOnFailure
    }

    Write-Host "`n=== Prune Summary ===" -ForegroundColor Cyan
    Write-Host "  Removed: $successCount" -ForegroundColor Green
    if ($failCount -gt 0) {
        Write-Host "  Failed:  $failCount" -ForegroundColor Red
    }
}
#endregion

#region Actions - Impact
function Invoke-Impact {
    Write-Host "`n=== Classifier Impact Analysis ===" -ForegroundColor Cyan

    if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) { return }
    if (-not (Invoke-TenantFingerprintGate)) { return }

    $selected = Get-SelectedPackages
    if ($selected.Count -eq 0) {
        Write-Host "No valid packages selected." -ForegroundColor Yellow
        return
    }

    $analysis = New-ClassifierImpactAnalysis -Mode $ImpactMode -SelectedKeys $selected
    Write-ClassifierImpactReport -Analysis $analysis -IncludeServiceability
    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.targets = @(Get-ClassifierManifestTargets -Selected $selected)
        $script:DeploymentManifest.impact = Convert-ClassifierImpactForManifest -Analysis $analysis
    }
}
#endregion

#region Actions - Rollback
function Resolve-RollbackBackup {
    param([Parameter(Mandatory)][string]$PackageName)

    if ($BackupPath) {
        if (Test-Path -LiteralPath $BackupPath -PathType Leaf) {
            return (Resolve-Path -LiteralPath $BackupPath).Path
        }
        if (Test-Path -LiteralPath $BackupPath -PathType Container) {
            $match = Get-ChildItem -LiteralPath $BackupPath -Filter "${PackageName}_*.xml" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($match) { return $match.FullName }
        }
    }

    if (-not (Test-Path -LiteralPath $BackupDir)) { return $null }
    $latest = Get-ChildItem -LiteralPath $BackupDir -Filter "${PackageName}_*.xml" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) { return $latest.FullName }
    return $null
}

function New-RollbackImpactAnalysis {
    param(
        [Parameter(Mandatory)][hashtable]$RollbackPlan,
        [Parameter(Mandatory)][hashtable]$DeployedLookup
    )

    $configIndex = Get-ConfiguredClassifierIndex
    $packageImpacts = @()
    $removedIds = @()
    $addedIds = @()

    foreach ($name in @($RollbackPlan.Keys | Sort-Object)) {
        $pkg = $Packages[$name]
        $deployed = Find-DeployedMatch -RegistryPackage $pkg -DeployedLookup $DeployedLookup
        $deployedInfo = if ($deployed) { Get-DeployedPackageInfo -DeployedPackage $deployed } else { $null }
        $rollbackInfo = $RollbackPlan[$name].BackupInfo

        $added = @()
        $removed = @()
        $unchanged = @()
        if ($deployedInfo -and $rollbackInfo) {
            $diff = Get-EntityDiff -LocalEntities $rollbackInfo.Entities -DeployedEntities $deployedInfo.Entities
            $added = @($diff.Added)
            $removed = @($diff.Removed)
            $unchanged = @($diff.Unchanged)
        } elseif ($rollbackInfo) {
            $added = @($rollbackInfo.Entities)
        }

        foreach ($entity in $removed) {
            if ($entity.Id) { $removedIds += $entity.Id.ToString().ToLowerInvariant() }
        }
        foreach ($entity in $added) {
            if ($entity.Id) { $addedIds += $entity.Id.ToString().ToLowerInvariant() }
        }

        $packageImpacts += [PSCustomObject]@{
            PackageKey   = $name
            DisplayName  = $pkg.displayName
            Status       = "Rollback"
            LocalInfo    = $rollbackInfo
            DeployedInfo = $deployedInfo
            Added        = $added
            Removed      = $removed
            Unchanged    = $unchanged
        }
    }

    $candidateIds = @{}
    foreach ($id in @($removedIds + $addedIds + $configIndex.ById.Keys)) {
        if (-not [string]::IsNullOrWhiteSpace($id)) { $candidateIds[$id.ToString().ToLowerInvariant()] = $true }
    }

    return [PSCustomObject]@{
        Mode           = "Rollback"
        SelectedKeys   = @($RollbackPlan.Keys)
        PackageImpacts = $packageImpacts
        RemovedIds     = @($removedIds | Sort-Object -Unique)
        AddedIds       = @($addedIds | Sort-Object -Unique)
        ConfigIndex    = $configIndex
        RuleRefs       = Get-DlpRuleReferenceIndex -CandidateIds @($candidateIds.Keys)
    }
}

function Write-RollbackImpactReport {
    param([Parameter(Mandatory)][object]$Analysis)

    Write-Host "`n=== Rollback Impact (Tier: $Tier) ===" -ForegroundColor Cyan
    Write-Host "  Packages selected: $($Analysis.SelectedKeys -join ', ')" -ForegroundColor Gray
    foreach ($impact in @($Analysis.PackageImpacts)) {
        Write-Host "`n--- $($impact.PackageKey) ---" -ForegroundColor White
        Write-Host "  Current deployed: $(if ($impact.DeployedInfo) { "v$($impact.DeployedInfo.VersionStr), $($impact.DeployedInfo.EntityCount) SITs" } else { "not found" })" -ForegroundColor Gray
        Write-Host "  Rollback backup:  $(if ($impact.LocalInfo) { "v$($impact.LocalInfo.VersionStr), $($impact.LocalInfo.EntityCount) SITs" } else { "not found" })" -ForegroundColor Gray
        Write-Host "  Restore changes:  +$($impact.Added.Count) / -$($impact.Removed.Count) / =$($impact.Unchanged.Count)" -ForegroundColor Gray
        foreach ($entity in @($impact.Removed | Sort-Object Name)) {
            $refs = Get-ClassifierRuleRefs -Analysis $Analysis -Id $entity.Id
            $color = if ($refs.Count -gt 0) { "Red" } else { "Yellow" }
            Write-Host "    - $($entity.Name) ($($entity.Id))" -ForegroundColor $color
            foreach ($ref in @($refs | Select-Object -First 8)) {
                Write-Host "      Rule: $($ref.RuleName) / Policy: $($ref.PolicyName)" -ForegroundColor Red
            }
        }
        foreach ($entity in @($impact.Added | Sort-Object Name)) {
            Write-Host "    + $($entity.Name) ($($entity.Id))" -ForegroundColor Green
        }
    }
}

function Invoke-Rollback {
    Write-Host "`n=== Rolling Back Rule Packages ===" -ForegroundColor Cyan
    $selected = Get-SelectedPackages
    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.targets = @(Get-ClassifierManifestTargets -Selected $selected)
    }

    if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) { return }
    if (-not (Invoke-TenantFingerprintGate)) { return }

    $deployedLookup = Get-DeployedPackageLookup
    $rollbackPlan = @{}
    foreach ($name in @($selected | Sort-Object)) {
        $backup = Resolve-RollbackBackup -PackageName $name
        if (-not $backup) {
            Write-Host "No backup found for $name. Skipping." -ForegroundColor Yellow
            continue
        }

        $validation = Test-SITRulePackageXml -FilePath $backup -MaxFileSizeBytes 788480
        if (-not $validation.Valid) {
            Write-Host "Backup XML invalid for ${name}: $backup" -ForegroundColor Red
            foreach ($err in $validation.Errors) { Write-Host "  - $err" -ForegroundColor Red }
            continue
        }

        $backupInfo = Get-LocalPackageInfo -FilePath $backup
        $rollbackPlan[$name] = @{
            BackupPath = $backup
            BackupInfo = $backupInfo
        }
    }

    if ($rollbackPlan.Count -eq 0) {
        Write-Host "No valid rollback backups found." -ForegroundColor Yellow
        return
    }

    $analysis = New-RollbackImpactAnalysis -RollbackPlan $rollbackPlan -DeployedLookup $deployedLookup
    Write-RollbackImpactReport -Analysis $analysis
    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.impact = Convert-ClassifierImpactForManifest -Analysis $analysis
        foreach ($name in @($rollbackPlan.Keys | Sort-Object)) {
            $script:DeploymentManifest.artifacts += Get-DeploymentFileArtifact -Path $rollbackPlan[$name].BackupPath -Role "rollback-backup" -ProjectRoot $ProjectRoot
        }
    }

    Write-EmbeddedWhatIfPlan -Operation "Rollback" -Selected @($rollbackPlan.Keys)
    $hasRuleDeps = Test-ImpactHasRuleDependencies -Analysis $analysis
    if (-not (Confirm-GuidedExecution -Operation "Rollback" -HasRuleDependencies:$hasRuleDeps)) {
        Add-ClassifierDecision -Decision "RollbackConfirmation" -Data @{ Confirmed = $false; HasRuleDependencies = $hasRuleDeps }
        Write-Host "Rollback aborted. No changes made." -ForegroundColor Yellow
        return
    }
    Add-ClassifierDecision -Decision "RollbackConfirmation" -Data @{ Confirmed = $true; HasRuleDependencies = $hasRuleDeps }

    $successCount = 0
    $failCount = 0
    foreach ($name in @($rollbackPlan.Keys | Sort-Object)) {
        $pkg = $Packages[$name]
        $match = Find-DeployedMatch -RegistryPackage $pkg -DeployedLookup $deployedLookup
        if (-not $match) {
            Write-Host "No deployed package found for $name. Skipping." -ForegroundColor Yellow
            continue
        }

        $deployedInfo = Get-DeployedPackageInfo -DeployedPackage $match
        Backup-DeployedPackage -PackageName $name -DeployedInfo $deployedInfo | Out-Null

        $content = Read-RulePackageText -FilePath $rollbackPlan[$name].BackupPath
        $content = $content -replace '<PublisherName>[^<]+</PublisherName>', "<PublisherName>$Publisher</PublisherName>"

        $backupInfo = $rollbackPlan[$name].BackupInfo
        $bumpVersion = $null
        if ($backupInfo -and $backupInfo.Version -and $deployedInfo.Version) {
            $bumpVersion = Get-BumpedVersion -LocalVersion $backupInfo.Version -DeployedVersion $deployedInfo.Version
        }
        if ($bumpVersion) {
            Write-Host "  $name rollback version auto-bumped to $(Format-VersionString -Version $bumpVersion)" -ForegroundColor Yellow
            $content = Update-ContentVersion -Content $content -NewVersion $bumpVersion
        }

        $fileBytes = ConvertTo-PurviewUtf16Bytes -Content $content
        try {
            if ($PSCmdlet.ShouldProcess($name, "Rollback SIT Rule Package from backup")) {
                Invoke-WithRetry -OperationName "Rollback $name" -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec -ScriptBlock {
                    Set-DlpSensitiveInformationTypeRulePackage -FileData $fileBytes -Confirm:$false -ErrorAction Stop
                }
                Write-Host "  Rolled back $name from $(Split-Path $rollbackPlan[$name].BackupPath -Leaf)" -ForegroundColor Green
                $successCount++
            }
        } catch {
            Write-Host "  Rollback failed for ${name}: $($_.Exception.Message)" -ForegroundColor Red
            $failCount++
        }
    }

    Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Result" -Data @{
        operation = "Rollback"
        succeeded = $successCount
        failed = $failCount
    }
}
#endregion

#region Actions - Remove
function Invoke-Remove {
    Write-Host "`n=== Removing Rule Packages ===" -ForegroundColor Cyan
    $selected = Get-SelectedPackages
    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.targets = @(Get-ClassifierManifestTargets -Selected $selected)
    }

    if ($WhatIfPreference) {
        Write-Host "WhatIf: The following packages would be removed:" -ForegroundColor Yellow
        foreach ($name in $selected) {
            $pkg = $Packages[$name]
            Write-Host "  - $name (RulePackId: $($pkg.rulePackId))" -ForegroundColor Yellow
        }
        return
    }

    if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) { return }
    if (-not (Invoke-TenantFingerprintGate)) { return }

    if (-not $SkipPreFlight) {
        Write-Host "`n=== Remove Pre-flight Impact Check ===" -ForegroundColor Cyan
        $analysis = New-ClassifierImpactAnalysis -Mode "Remove" -SelectedKeys $selected
        Write-ClassifierImpactReport -Analysis $analysis
        if ($script:DeploymentManifest) {
            $script:DeploymentManifest.impact = Convert-ClassifierImpactForManifest -Analysis $analysis
        }

        if (Test-ImpactHasRuleDependencies -Analysis $analysis) {
            Write-Host ""
            Write-Host "DLP rule dependencies were found for classifier(s) that would be removed." -ForegroundColor Red
            Write-Host "Remove anyway only if those DLP rules have already been updated or are intentionally being retired." -ForegroundColor Red
            $choice = Read-Host "Proceed with package removal? [R]emove, [A]bort (R/A)"
            Add-ClassifierDecision -Decision "RemoveDependencyOverride" -Data @{ Choice = $choice }
            if ($choice.Trim().ToUpper() -ne "R") {
                Write-Host "Removal aborted." -ForegroundColor Red
                return
            }
        }
    } else {
        Write-Host "Pre-flight dependency check skipped (-SkipPreFlight)." -ForegroundColor Yellow
    }

    Write-EmbeddedWhatIfPlan -Operation "Remove" -Selected $selected
    $confirmRemove = Read-Host "Execute this removal plan? [Y/N]"
    Add-ClassifierDecision -Decision "RemoveConfirmation" -Data @{ Confirmed = ($confirmRemove.Trim().ToUpper() -eq "Y") }
    if ($confirmRemove.Trim().ToUpper() -ne "Y") {
        Write-Host "Removal aborted. No changes made." -ForegroundColor Yellow
        return
    }

    Invoke-ClassifierPackageRemoval -Selected $selected | Out-Null
}
#endregion

#region Actions - List
function Invoke-List {
    Write-Host "`n=== Deployed Rule Packages ===" -ForegroundColor Cyan

    if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) { return }
    if (-not (Invoke-TenantFingerprintGate)) { return }

    $deployed = @()
    try { $deployed = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop) } catch { }

    if ($deployed.Count -eq 0) {
        Write-Host "  No custom rule packages found in tenant." -ForegroundColor Yellow
    } else {
        Write-Host "  Found $($deployed.Count) rule package(s):" -ForegroundColor Gray
        foreach ($d in $deployed) {
            $info = Get-DeployedPackageInfo -DeployedPackage $d
            Write-Host ""
            Write-Host "  Identity:  $($d.Identity)" -ForegroundColor Gray
            Write-Host "  Name:      $($d.Name)" -ForegroundColor Gray
            Write-Host "  Publisher: $($d.Publisher)" -ForegroundColor Gray
            Write-Host "  Version:   $($info.VersionStr)" -ForegroundColor Gray
            if ($info.EntityCount -ge 0) {
                Write-Host "  Entities:  $($info.EntityCount) SITs" -ForegroundColor Gray
            }
            if ($d.WhenCreatedUTC) {
                Write-Host "  Created:   $($d.WhenCreatedUTC)" -ForegroundColor Gray
            }
            if ($d.WhenChangedUTC) {
                Write-Host "  Modified:  $($d.WhenChangedUTC)" -ForegroundColor Gray
            }
        }
    }

    Write-Host "`n--- Local Package Registry ---" -ForegroundColor Cyan
    foreach ($name in $Packages.Keys) {
        $pkg = $Packages[$name]
        $filePath = Resolve-PackageFile -Package $pkg -RequestedTier $Tier
        $exists = Test-Path $filePath
        $localInfo = if ($exists) { Get-LocalPackageInfo -FilePath $filePath } else { $null }
        $size = if ($localInfo) { "$([math]::Round($localInfo.FileSize / 1KB, 1))KB" } elseif ($exists) { "$([math]::Round((Get-Item $filePath).Length / 1KB, 1))KB" } else { "MISSING" }
        $entityStr = if ($localInfo) { "$($localInfo.EntityCount) SITs, " } else { "" }
        $versionStr = if ($localInfo) { " v$($localInfo.VersionStr)" } else { "" }
        $status = if ($exists) { "OK" } else { "MISSING" }
        $statusColor = if ($exists) { "Gray" } else { "Red" }
        Write-Host "  [$status] $name - ${entityStr}${size}${versionStr}" -ForegroundColor $statusColor
    }
}
#endregion

#region Actions - Canary
function Invoke-Canary {
    Write-Host "`n=== Classifier Deployment Canary ===" -ForegroundColor Cyan
    Write-Host "  This creates a disposable SIT rule package, mutates its entity set, then removes it." -ForegroundColor Gray

    $suffix = Get-Date -Format "yyyyMMddHHmmss"
    $rulePackId = [guid]::NewGuid().ToString()
    $entitySurvivor = [guid]::NewGuid().ToString()
    $entityRemoved = [guid]::NewGuid().ToString()
    $packageName = "QGISCF DLPDeploy Canary $suffix"
    $survivorV1Name = "QGISCF DLPDeploy Canary Survivor V1"
    $survivorV2Name = "QGISCF DLPDeploy Canary Survivor V2"
    $removedV1Name = "QGISCF DLPDeploy Canary Removed V1"
    $payloadV1 = New-CanaryRulePackagePayload -RulePackId $rulePackId -PackageName $packageName -PublisherName $Publisher -Revision 0 -Suffix $suffix -Entities @(
        [ordered]@{ Id = $entitySurvivor; Name = $survivorV1Name; Token = "KEEP-V1" },
        [ordered]@{ Id = $entityRemoved; Name = $removedV1Name; Token = "DROP-V1" }
    )
    $payloadV2 = New-CanaryRulePackagePayload -RulePackId $rulePackId -PackageName $packageName -PublisherName $Publisher -Revision 1 -Suffix $suffix -Entities @(
        [ordered]@{ Id = $entitySurvivor; Name = $survivorV2Name; Token = "KEEP-V2" }
    )

    if ($script:DeploymentManifest) {
        $script:DeploymentManifest.targets = @(
            [ordered]@{
                type        = "ClassifierCanary"
                packageName = $packageName
                rulePackId  = $rulePackId
                publisher   = $Publisher
                keepPackage = [bool]$CanaryKeepPackage
                payloads    = @(
                    [ordered]@{ phase = "create"; version = $payloadV1.Version; entities = @($payloadV1.Entities | ForEach-Object { [ordered]@{ id = $_.Id; name = $_.Name } }); sizeBytes = $payloadV1.SizeBytes; sha256 = $payloadV1.Sha256 },
                    [ordered]@{ phase = "replace"; version = $payloadV2.Version; entities = @($payloadV2.Entities | ForEach-Object { [ordered]@{ id = $_.Id; name = $_.Name } }); sizeBytes = $payloadV2.SizeBytes; sha256 = $payloadV2.Sha256 }
                )
            }
        )
        $script:DeploymentManifest.impact = [ordered]@{
            mode            = "Canary"
            removedIds      = @($entityRemoved)
            addedIds        = @()
            changedIds      = @($entitySurvivor)
            affectedRules   = @()
            affectedLabels  = @()
            servicePath     = @("New-DlpSensitiveInformationTypeRulePackage", "Set-DlpSensitiveInformationTypeRulePackage", "Remove-DlpSensitiveInformationTypeRulePackage")
        }
    }

    Write-Host "`nStep 1: Local canary payload parse check..." -ForegroundColor Cyan
    $payloadsValid = (Test-CanaryRulePackagePayload -Payload $payloadV1) -and (Test-CanaryRulePackagePayload -Payload $payloadV2)
    if (-not $payloadsValid) {
        Write-Error "Canary payload XML did not pass local parse checks."
        return
    }
    Write-Host "  Canary payloads are parseable UTF-16LE+BOM XML." -ForegroundColor Green
    Write-Host "  RulePackId: $rulePackId" -ForegroundColor Gray
    Write-Host "  Survivor entity: $entitySurvivor" -ForegroundColor Gray
    Write-Host "  Removed entity:  $entityRemoved" -ForegroundColor Gray

    if ($WhatIfPreference) {
        Write-Host "`nWhatIf: Canary would run these tenant operations:" -ForegroundColor Yellow
        Write-Host "  - Create disposable rule package '$packageName' with two canary SITs" -ForegroundColor Yellow
        Write-Host "  - Verify the package appears in Get-DlpSensitiveInformationTypeRulePackage" -ForegroundColor Yellow
        Write-Host "  - Verify both canary SITs appear in Get-DlpSensitiveInformationType" -ForegroundColor Yellow
        Write-Host "  - Replace it with a new version that removes one SIT and changes the surviving SIT in place" -ForegroundColor Yellow
        Write-Host "  - Verify the removed SIT disappears and the survivor remains under the same entity ID" -ForegroundColor Yellow
        if ($CanaryKeepPackage) {
            Write-Host "  - Leave the package deployed for inspection (-CanaryKeepPackage)" -ForegroundColor Yellow
        } else {
            Write-Host "  - Remove the canary package and verify it disappears" -ForegroundColor Yellow
        }
        Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Result" -Data @{
            operation = "Canary"
            status = "PlannedOnly"
            rulePackId = $rulePackId
        }
        return
    }

    if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) { return }
    if (-not (Invoke-TenantFingerprintGate)) { return }

    Write-Host "`nStep 2: Tenant capacity check..." -ForegroundColor Cyan
    $existingLookup = Get-DeployedPackageLookup
    $existingCanary = Find-CanaryPackage -RulePackId $rulePackId
    if (-not $existingCanary -and $existingLookup.Count -ge 10) {
        Write-Error "Tenant already has $($existingLookup.Count) custom rule package slots in use. Canary cannot create a disposable package."
        return
    }
    Write-Host "  Package slots in use: $($existingLookup.Count)/10" -ForegroundColor Gray

    Write-Host "`nStep 3: Confirmation..." -ForegroundColor Cyan
    Write-Host "  Target environment: $(if ($TargetEnvironment) { $TargetEnvironment } else { '(default fingerprint environment)' })" -ForegroundColor Gray
    Write-Host "  Package name:       $packageName" -ForegroundColor Gray
    Write-Host "  Cleanup:            $(if ($CanaryKeepPackage) { 'leave deployed for inspection' } else { 'remove automatically' })" -ForegroundColor Gray
    $confirm = Read-Host "Run canary now? [Y/N]"
    Add-ClassifierDecision -Decision "CanaryConfirmation" -Data @{ Confirmed = ($confirm.Trim().ToUpper() -eq "Y"); KeepPackage = [bool]$CanaryKeepPackage }
    if ($confirm.Trim().ToUpper() -ne "Y") {
        Write-Host "Canary aborted. No changes made." -ForegroundColor Yellow
        return
    }

    $created = $false
    $removed = $false
    $stepResults = @()
    try {
        Write-Host "`nStep 4: Create canary package..." -ForegroundColor Cyan
        if ($PSCmdlet.ShouldProcess($packageName, "Create canary SIT rule package")) {
            Invoke-WithRetry -OperationName "Canary create package" -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec -ScriptBlock {
                New-DlpSensitiveInformationTypeRulePackage -FileData $payloadV1.Bytes -Confirm:$false -ErrorAction Stop
            }
            $created = $true
            $stepResults += [ordered]@{ step = "Create"; status = "Completed"; version = $payloadV1.Version; entityIds = @($entitySurvivor, $entityRemoved) }
            Write-Host "  Created canary package." -ForegroundColor Green
        }

        $createdPackage = Wait-CanaryPackageState -RulePackId $rulePackId -ShouldExist $true
        if (-not $createdPackage) {
            throw "Canary package was not visible after creation within the wait window."
        }
        Write-Host "  Verified package is visible: $($createdPackage.Package.Identity)" -ForegroundColor Green

        $createdSurvivor = Wait-CanaryPackageEntityState -RulePackId $rulePackId -EntityId $entitySurvivor -ShouldExist $true -ExpectedName $survivorV1Name
        $createdRemoved = Wait-CanaryPackageEntityState -RulePackId $rulePackId -EntityId $entityRemoved -ShouldExist $true -ExpectedName $removedV1Name
        if (-not $createdSurvivor -or -not $createdRemoved) {
            throw "Canary creation verification did not find both v1 entities in the deployed package XML."
        }
        Write-Host "  Verified both v1 entities in deployed package XML." -ForegroundColor Green

        $tenantSurvivor = Wait-CanarySensitiveInformationTypeState -EntityId $entitySurvivor -EntityName $survivorV1Name -ShouldExist $true
        $tenantRemoved = Wait-CanarySensitiveInformationTypeState -EntityId $entityRemoved -EntityName $removedV1Name -ShouldExist $true
        if (-not $tenantSurvivor -or -not $tenantRemoved) {
            throw "Canary creation verification did not find both v1 entities in Get-DlpSensitiveInformationType."
        }
        Write-Host "  Verified both v1 entities are visible as tenant SITs." -ForegroundColor Green

        Write-Host "`nStep 5: Replace canary package with entity mutation..." -ForegroundColor Cyan
        if ($PSCmdlet.ShouldProcess($packageName, "Replace canary SIT rule package")) {
            Invoke-WithRetry -OperationName "Canary replace package" -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec -ScriptBlock {
                Set-DlpSensitiveInformationTypeRulePackage -FileData $payloadV2.Bytes -Confirm:$false -ErrorAction Stop
            }
            $stepResults += [ordered]@{ step = "Replace"; status = "Completed"; version = $payloadV2.Version; removedEntityId = $entityRemoved; changedEntityId = $entitySurvivor }
            Write-Host "  Replaced canary package." -ForegroundColor Green
        }

        $updatedPackage = Wait-CanaryPackageEntityState -RulePackId $rulePackId -EntityId $entitySurvivor -ShouldExist $true -ExpectedName $survivorV2Name
        if (-not $updatedPackage) {
            throw "Canary replacement verification did not find the survivor entity '$entitySurvivor' with its v2 name."
        }
        $removedAbsent = Wait-CanaryPackageEntityState -RulePackId $rulePackId -EntityId $entityRemoved -ShouldExist $false
        if (-not $removedAbsent) {
            throw "Canary replacement verification still found removed entity '$entityRemoved' in the package XML."
        }
        Write-Host "  Verified deployed package XML has the survivor changed and removed entity absent." -ForegroundColor Green

        $tenantSurvivorUpdated = Wait-CanarySensitiveInformationTypeState -EntityId $entitySurvivor -EntityName $survivorV2Name -ShouldExist $true
        $tenantRemovedAbsent = Wait-CanarySensitiveInformationTypeState -EntityId $entityRemoved -EntityName $removedV1Name -ShouldExist $false
        if (-not $tenantSurvivorUpdated) {
            throw "Canary replacement verification did not find the survivor entity '$entitySurvivor' in Get-DlpSensitiveInformationType."
        }
        if (-not $tenantRemovedAbsent) {
            throw "Canary replacement verification still found removed entity '$entityRemoved' in Get-DlpSensitiveInformationType."
        }
        Write-Host "  Verified tenant SIT list reflects the entity mutation." -ForegroundColor Green

        if ($CanaryKeepPackage) {
            Write-Host "`nStep 6: Cleanup skipped by -CanaryKeepPackage." -ForegroundColor Yellow
            $stepResults += [ordered]@{ step = "Cleanup"; status = "Skipped"; identity = $updatedPackage.Package.Identity }
        } else {
            Write-Host "`nStep 6: Remove canary package..." -ForegroundColor Cyan
            if ($PSCmdlet.ShouldProcess($packageName, "Remove canary SIT rule package")) {
                Remove-DlpSensitiveInformationTypeRulePackage -Identity $updatedPackage.Package.Identity -Confirm:$false -ErrorAction Stop
                $removed = $true
                $stepResults += [ordered]@{ step = "Cleanup"; status = "Completed"; identity = $updatedPackage.Package.Identity }
                Write-Host "  Removed canary package." -ForegroundColor Green
            }

            $gone = Wait-CanaryPackageState -RulePackId $rulePackId -ShouldExist $false
            if (-not $gone) {
                throw "Canary package was still visible after cleanup wait window."
            }
            Write-Host "  Verified canary package is no longer visible." -ForegroundColor Green

            $survivorGone = Wait-CanarySensitiveInformationTypeState -EntityId $entitySurvivor -EntityName $survivorV2Name -ShouldExist $false
            $removedStillGone = Wait-CanarySensitiveInformationTypeState -EntityId $entityRemoved -EntityName $removedV1Name -ShouldExist $false
            if (-not $survivorGone -or -not $removedStillGone) {
                throw "Canary cleanup verification still found one or more canary SITs in Get-DlpSensitiveInformationType."
            }
            Write-Host "  Verified canary SITs are no longer visible." -ForegroundColor Green
        }

        Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Result" -Data @{
            operation = "Canary"
            status = "Completed"
            rulePackId = $rulePackId
            packageName = $packageName
            steps = @($stepResults)
        }
        Write-Host "`nCanary completed successfully." -ForegroundColor Green
    } catch {
        Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Error" -Data @{
            operation = "Canary"
            rulePackId = $rulePackId
            message = $_.Exception.Message
        }
        throw
    } finally {
        if ($created -and -not $removed -and -not $CanaryKeepPackage -and -not $WhatIfPreference) {
            try {
                $leftover = Find-CanaryPackage -RulePackId $rulePackId
                if ($leftover) {
                    Write-Host "  Attempting canary cleanup after failure..." -ForegroundColor Yellow
                    Remove-DlpSensitiveInformationTypeRulePackage -Identity $leftover.Package.Identity -Confirm:$false -ErrorAction Stop
                }
            } catch {
                Write-Warning "Canary cleanup failed: $($_.Exception.Message)"
            }
        }
    }
}
#endregion

#region Main
$script:DeploymentFinalStatus = "Completed"
try {
    switch ($Action) {
        "Interactive" { Invoke-Interactive }
        "Upload"     { Invoke-Upload }
        "Remove"     { Invoke-Remove }
        "Rollback"   { Invoke-Rollback }
        "List"       { Invoke-List }
        "Validate"   { Invoke-Validate | Out-Null }
        "Estimate"   { Invoke-Estimate }
        "Impact"     { Invoke-Impact }
        "CapacityPlan" { Invoke-CapacityPlan }
        "AdoptPlan"  { Invoke-AdoptPlan }
        "Prune"      { Invoke-PrunePackages }
        "Canary"     { Invoke-Canary }
    }
} catch {
    $script:DeploymentFinalStatus = "Failed"
    if ($script:DeploymentManifest) {
        Add-DeploymentManifestEvent -Manifest $script:DeploymentManifest -Type "Error" -Data @{
            message = $_.Exception.Message
            category = $_.CategoryInfo.Category.ToString()
        }
    }
    throw
} finally {
    if ($Action -ne "Validate") {
        Stop-DeploymentLog
    }
    if ($script:DeploymentManifest) {
        Complete-DeploymentManifest -Manifest $script:DeploymentManifest -Status $script:DeploymentFinalStatus | Out-Null
        Save-DeploymentManifest -Manifest $script:DeploymentManifest -ProjectRoot $ProjectRoot -TranscriptPath $script:TranscriptPath | Out-Null
    }
}
#endregion
