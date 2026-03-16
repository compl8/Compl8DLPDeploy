#==============================================================================
# Deploy-Classifiers.ps1
# Deploys Custom SIT Rule Packages to Microsoft Purview.
#
# Features:
#   - Pre-flight comparison of local vs deployed packages (version, entities, dates)
#   - Auto-backup of existing packages before overwriting
#   - DLP rule dependency checking for removed SITs
#   - Interactive prompts for conflict resolution (Replace/Skip/Abort)
#   - Auto-increment of XML version numbers when local <= deployed
#   - Tenant capacity estimation (packages, SITs, sizes)
#   - Guards against empty rulePackId matching all packages
#
# Usage:
#   .\scripts\Deploy-Classifiers.ps1 -Action Validate               # Local XML check
#   .\scripts\Deploy-Classifiers.ps1 -Action Upload -Connect        # Upload all
#   .\scripts\Deploy-Classifiers.ps1 -Action Upload -Tier narrow -Connect
#   .\scripts\Deploy-Classifiers.ps1 -Action List -Connect
#   .\scripts\Deploy-Classifiers.ps1 -Action Remove -PackageNames DocClass -Connect
#   .\scripts\Deploy-Classifiers.ps1 -Action Estimate -Connect      # Capacity report
#   .\scripts\Deploy-Classifiers.ps1 -Action Upload -WhatIf         # Dry run
#   .\scripts\Deploy-Classifiers.ps1 -Action Upload -SkipPreFlight  # Skip prompts
#==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("Upload", "Remove", "List", "Validate", "Estimate")]
    [string]$Action = "Upload",

    [string[]]$PackageNames = @("All"),

    [ValidateSet("narrow", "wide", "full")]
    [string]$Tier,

    [string]$Publisher,

    [switch]$Connect,
    [string]$UPN,
    [switch]$SkipPreFlight
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "config"
$XmlDir      = Join-Path $ProjectRoot "xml"
$BackupDir   = Join-Path (Join-Path $ProjectRoot "backups") "classifiers"

# Import shared module
Import-Module (Join-Path (Join-Path $ProjectRoot "modules") "DLP-Deploy.psm1") -Force

#region Config
$Defaults = Get-ModuleDefaults

# Only load settings.json for actions that need it (Upload, Validate)
if ($Action -in @("Upload", "Validate")) {
    $settingsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
    $Config = Merge-GlobalConfig -Defaults $Defaults -GlobalJson $settingsJson
} else {
    $Config = $Defaults.Clone()
}

# Resolve tier and publisher from params or config
if (-not $Tier)      { $Tier      = $Config.deploymentTier }
if (-not $Publisher) { $Publisher = $Config.publisher }

# Load package registry
$registryJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "classifiers-registry.json") -Description "classifier registry"
if (-not $registryJson) {
    Write-Error "Failed to load classifiers-registry.json. Aborting."
    return
}

# Build package lookup
$Packages = @{}
foreach ($pkg in $registryJson.packages) {
    if ($pkg.enabled) {
        $Packages[$pkg.key] = $pkg
    }
}
#endregion

#region Helpers — Package Selection & File Resolution
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

#region Helpers — XML Parsing
function Get-LocalPackageInfo {
    <#
    .SYNOPSIS
        Parses a local SIT rule package XML file and extracts metadata.
    #>
    param([string]$FilePath)

    try {
        $content = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::Unicode)
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

        $rulePack = $xml.RulePackage.RulePack
        if ($rulePack -and $rulePack.Version) {
            $v = $rulePack.Version
            $info.Version = @{
                Major    = [int]$v.major
                Minor    = [int]$v.minor
                Build    = [int]$v.build
                Revision = [int]$v.revision
            }
            $info.VersionStr = "$($v.major).$($v.minor).$($v.build).$($v.revision)"
        }

        $rules = $xml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq "Rules" }
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

#region Helpers — Comparison & Diffing
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

#region Helpers — Backup, Version Bump, Package Matching
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

        # Match by GUID — only if rulePackId is non-empty
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
    }

    return $null
}

function Format-VersionString {
    param([hashtable]$Version)
    if (-not $Version) { return "(unknown)" }
    return "$($Version.Major).$($Version.Minor).$($Version.Build).$($Version.Revision)"
}
#endregion

#region Connection
if ($Connect) {
    $connected = Connect-DLPSession -UPN $UPN
    if (-not $connected) { return }
}
#endregion

#region Logging
if ($Action -ne "Validate") {
    $null = Start-DeploymentLog -ScriptName "Deploy-Classifiers"
}
#endregion

#region Actions — Validate
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

#region Actions — Upload
function Invoke-Upload {
    Write-Host "`n=== Uploading Rule Packages (Tier: $Tier, Publisher: $Publisher) ===" -ForegroundColor Cyan
    $selected = Get-SelectedPackages

    # Step 1: Validate
    Write-Host "`nStep 1: Validating files..." -ForegroundColor Cyan
    $valid = Invoke-Validate
    if (-not $valid) {
        Write-Error "Aborting upload due to validation errors."
        return
    }

    if ($WhatIfPreference) {
        Write-Host "`nWhatIf: The following packages would be uploaded:" -ForegroundColor Yellow
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
        return
    }

    # Verify session
    if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) { return }

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
        Write-Host "`nStep 3: Pre-flight comparison..." -ForegroundColor Cyan
        $aborted = $false

        foreach ($name in $selected) {
            if ($aborted) { break }

            $pkg = $Packages[$name]
            $filePath = Resolve-PackageFile -Package $pkg -RequestedTier $Tier
            $localInfo = Get-LocalPackageInfo -FilePath $filePath
            $existingPkg = Find-DeployedMatch -RegistryPackage $pkg -DeployedLookup $deployedLookup

            if (-not $existingPkg) {
                # New package — no conflict
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

            # Package exists — show detailed comparison
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

    # Step 4: Backup existing & Upload
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

    Write-Host "`nStep 4: Backup & Upload..." -ForegroundColor Cyan
    $successCount = 0
    $failCount    = 0
    $skipCount    = 0
    $uploadIndex  = 0

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
            Write-Host "    Waiting ${delaySec}s before next upload..." -ForegroundColor DarkGray
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
            $content = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::Unicode)
            $content = $content -replace '<PublisherName>[^<]+</PublisherName>', "<PublisherName>$Publisher</PublisherName>"

            # Auto-bump version if needed
            if ($plan.BumpVersion) {
                $bumpStr = Format-VersionString -Version $plan.BumpVersion
                Write-Host "    Auto-bumping version to $bumpStr" -ForegroundColor Yellow
                $content = Update-ContentVersion -Content $content -NewVersion $plan.BumpVersion
            }

            $fileBytes = [System.Text.Encoding]::Unicode.GetBytes($content)
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
}
#endregion

#region Actions — Estimate
function Invoke-Estimate {
    Write-Host "`n=== Tenant Package Capacity Estimate ===" -ForegroundColor Cyan

    if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) { return }

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
                Write-Host "      Size:     ${sizeKB}KB/150KB (${sizePct}%)" -ForegroundColor $szColor
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
    $msPackages = @($deployed | Where-Object { $_.Publisher -eq "Microsoft Corporation" -or $_.Name -match "^Microsoft" }).Count
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

    # --- Reference limits ---
    Write-Host "`n  Purview Hard Limits (reference):" -ForegroundColor DarkGray
    Write-Host "    Rule packages/tenant:      10          Entities/package:           50" -ForegroundColor DarkGray
    Write-Host "    Package file size:         150KB       Custom SITs/tenant:         500" -ForegroundColor DarkGray
    Write-Host "    Regex length:              1,024ch     Regexes/SIT:                20" -ForegroundColor DarkGray
    Write-Host "    Keyword terms/list:        2,048       Keyword dicts (tenant):     1MB" -ForegroundColor DarkGray
    Write-Host "    Keyword dict SITs/tenant:  50          Capturing groups/regex:     1" -ForegroundColor DarkGray
}
#endregion

#region Actions — Remove
function Invoke-Remove {
    Write-Host "`n=== Removing Rule Packages ===" -ForegroundColor Cyan
    $selected = Get-SelectedPackages

    if ($WhatIfPreference) {
        Write-Host "WhatIf: The following packages would be removed:" -ForegroundColor Yellow
        foreach ($name in $selected) {
            $pkg = $Packages[$name]
            Write-Host "  - $name (RulePackId: $($pkg.rulePackId))" -ForegroundColor Yellow
        }
        return
    }

    if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) { return }

    $deployed = @()
    try { $deployed = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop) } catch { }
    $deployedLookup = @{}
    foreach ($d in $deployed) {
        if ($d -and $d.Identity) { $deployedLookup[$d.Identity] = $d }
    }

    foreach ($name in $selected) {
        $pkg = $Packages[$name]
        Write-Host "  Removing $name ($($pkg.rulePackId))..." -ForegroundColor Cyan

        $match = Find-DeployedMatch -RegistryPackage $pkg -DeployedLookup $deployedLookup

        if ($match) {
            if ($PSCmdlet.ShouldProcess($name, "Remove SIT Rule Package")) {
                try {
                    Remove-DlpSensitiveInformationTypeRulePackage -Identity $match.Identity -Confirm:$false -ErrorAction Stop
                    Write-Host "    Removed successfully" -ForegroundColor Green
                } catch {
                    Write-Host "    Failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "    Not found in tenant - skipping" -ForegroundColor Yellow
        }
    }
}
#endregion

#region Actions — List
function Invoke-List {
    Write-Host "`n=== Deployed Rule Packages ===" -ForegroundColor Cyan

    if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationTypeRulePackage")) { return }

    $deployed = @()
    try { $deployed = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop) } catch { }

    # Filter out Microsoft built-in packages (null/empty Identity)
    $deployed = @($deployed | Where-Object { $_.Identity })

    if ($deployed.Count -eq 0) {
        Write-Host "  No custom rule packages found in tenant." -ForegroundColor Yellow
    } else {
        Write-Host "  Found $($deployed.Count) custom rule package(s):" -ForegroundColor Gray
        Write-Host ""
        foreach ($d in $deployed) {
            $info = Get-DeployedPackageInfo -DeployedPackage $d
            # Get human name from RulePack > Details > LocalizedDetails > Name
            $displayName = $d.Identity
            if ($info.RawXml) {
                try {
                    $xml = [xml]$info.RawXml
                    $localized = $xml.RulePackage.RulePack.Details.LocalizedDetails
                    if ($localized -and $localized.Name) { $displayName = $localized.Name }
                } catch { }
            }
            $entityStr = if ($info.EntityCount -ge 0) { "$($info.EntityCount) SITs" } else { "unknown SITs" }
            $versionStr = "v$($info.VersionStr)"
            $modifiedStr = if ($d.WhenChangedUTC) { "  modified $($d.WhenChangedUTC)" } else { "" }
            Write-Host "  $displayName  ($entityStr, $versionStr)$modifiedStr" -ForegroundColor Gray
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

#region Main
switch ($Action) {
    "Upload"   { Invoke-Upload }
    "Remove"   { Invoke-Remove }
    "List"     { Invoke-List }
    "Validate" { Invoke-Validate | Out-Null }
    "Estimate" { Invoke-Estimate }
}

if ($Action -ne "Validate") {
    try { Stop-Transcript } catch { }
}
#endregion
