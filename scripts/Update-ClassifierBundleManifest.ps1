#==============================================================================
# Update-ClassifierBundleManifest.ps1
# Maintains the classifier bundle manifest used to detect untracked XML updates.
#==============================================================================

[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [string]$RegistryPath,
    [string]$ManifestPath,

    [ValidateSet("narrow", "wide", "full", "small", "medium", "large")]
    [string]$Tier,

    [switch]$CheckOnly,
    [switch]$NoExit,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

if (-not $ProjectRoot) {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
}
$ProjectRoot = [System.IO.Path]::GetFullPath($ProjectRoot)
$XmlDir = Join-Path $ProjectRoot "xml"
$DeployDir = Join-Path $XmlDir "deploy"
if (-not $RegistryPath) {
    $RegistryPath = Join-Path $DeployDir "deploy-registry.json"
}
if (-not $ManifestPath) {
    $ManifestPath = Join-Path $DeployDir "classifier-bundle-manifest.json"
}

function ConvertTo-RelativeManifestPath {
    param([Parameter(Mandatory)][string]$Path)

    return ([System.IO.Path]::GetRelativePath($ProjectRoot, [System.IO.Path]::GetFullPath($Path)) -replace "\\", "/")
}

function Read-JsonFile {
    param([Parameter(Mandatory)][string]$Path)

    return (Get-Content -Raw -LiteralPath $Path -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
}

function Resolve-ClassifierPackageFile {
    param(
        [Parameter(Mandatory)][object]$Package,
        [string]$RequestedTier
    )

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
    if ($variants.ContainsKey("full")) {
        return Join-Path $XmlDir $variants["full"]
    }

    $firstKey = $variants.Keys | Select-Object -First 1
    if ($firstKey) {
        return Join-Path $XmlDir $variants[$firstKey]
    }
    return $null
}

function Get-XmlChildByName {
    param(
        [Parameter(Mandatory)][System.Xml.XmlNode]$Node,
        [Parameter(Mandatory)][string]$Name
    )

    return @($Node.ChildNodes | Where-Object {
        $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -eq $Name
    } | Select-Object -First 1)[0]
}

function Get-RulePackageVersionString {
    param([Parameter(Mandatory)][System.Xml.XmlNode]$VersionNode)

    $major = if ($VersionNode.major) { [int]$VersionNode.major } else { 0 }
    $minor = if ($VersionNode.minor) { [int]$VersionNode.minor } else { 0 }
    $build = if ($VersionNode.build) { [int]$VersionNode.build } else { 0 }
    $revision = if ($VersionNode.revision) { [int]$VersionNode.revision } else { 0 }
    return "{0}.{1}.{2}.{3}" -f $major, $minor, $build, $revision
}

function ConvertTo-VersionValue {
    param([string]$Version)

    if ([string]::IsNullOrWhiteSpace($Version)) {
        return [version]"0.0.0.0"
    }
    return [version]$Version
}

function Get-RulePackageLocalizedValue {
    param(
        [Parameter(Mandatory)][System.Xml.XmlNode]$RulePack,
        [Parameter(Mandatory)][string]$Name
    )

    $details = Get-XmlChildByName -Node $RulePack -Name "Details"
    if (-not $details) { return $null }
    $localized = Get-XmlChildByName -Node $details -Name "LocalizedDetails"
    if (-not $localized) { return $null }
    $valueNode = Get-XmlChildByName -Node $localized -Name $Name
    if (-not $valueNode) { return $null }
    return $valueNode.InnerText
}

function Get-ClassifierBundleInfo {
    param(
        [Parameter(Mandatory)][object]$Package,
        [Parameter(Mandatory)][string]$FilePath
    )

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        throw "Package '$($Package.key)' XML file not found: $FilePath"
    }

    [xml]$xml = Get-Content -Raw -LiteralPath $FilePath -ErrorAction Stop
    $rulePackage = $xml.DocumentElement
    if (-not $rulePackage -or $rulePackage.LocalName -ne "RulePackage") {
        throw "Package '$($Package.key)' is not a RulePackage XML file: $FilePath"
    }

    $rulePack = Get-XmlChildByName -Node $rulePackage -Name "RulePack"
    if (-not $rulePack) {
        throw "Package '$($Package.key)' XML is missing RulePack metadata: $FilePath"
    }
    $versionNode = Get-XmlChildByName -Node $rulePack -Name "Version"
    if (-not $versionNode) {
        throw "Package '$($Package.key)' XML is missing RulePack Version metadata: $FilePath"
    }
    $rules = Get-XmlChildByName -Node $rulePackage -Name "Rules"
    $entities = if ($rules) {
        @($rules.ChildNodes | Where-Object {
            $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -eq "Entity"
        })
    } else {
        @()
    }

    $item = Get-Item -LiteralPath $FilePath
    $version = Get-RulePackageVersionString -VersionNode $versionNode

    return [ordered]@{
        key           = $Package.key
        path          = ConvertTo-RelativeManifestPath -Path $FilePath
        rulePackId    = $rulePack.id
        version       = $version
        name          = Get-RulePackageLocalizedValue -RulePack $rulePack -Name "Name"
        publisherName = Get-RulePackageLocalizedValue -RulePack $rulePack -Name "PublisherName"
        entityCount   = $entities.Count
        sizeBytes     = $item.Length
        sha256        = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Complete-Script {
    param([bool]$Succeeded)

    if ($NoExit) {
        return $Succeeded
    }
    exit $(if ($Succeeded) { 0 } else { 1 })
}

$issues = [System.Collections.Generic.List[string]]::new()
$notes = [System.Collections.Generic.List[string]]::new()

try {
    if (-not (Test-Path -LiteralPath $RegistryPath -PathType Leaf)) {
        throw "Classifier deploy registry not found: $RegistryPath"
    }

    $registry = Read-JsonFile -Path $RegistryPath
    if (-not $Tier -and $registry.tier) {
        $Tier = $registry.tier
    }
    if (-not $Tier) {
        $Tier = "full"
    }

    $currentPackages = @()
    foreach ($pkg in @($registry.packages | Where-Object { (-not $_.PSObject.Properties["enabled"]) -or [bool]$_.enabled })) {
        if ([string]::IsNullOrWhiteSpace($pkg.key)) {
            $issues.Add("Enabled classifier package is missing a key in $RegistryPath")
            continue
        }
        $filePath = Resolve-ClassifierPackageFile -Package $pkg -RequestedTier $Tier
        if (-not $filePath) {
            $issues.Add("Package '$($pkg.key)' does not resolve to an XML file.")
            continue
        }
        try {
            $currentPackages += [pscustomobject](Get-ClassifierBundleInfo -Package $pkg -FilePath $filePath)
        } catch {
            $issues.Add($_.Exception.Message)
        }
    }

    $existingManifest = $null
    if (Test-Path -LiteralPath $ManifestPath -PathType Leaf) {
        try {
            $existingManifest = Read-JsonFile -Path $ManifestPath
        } catch {
            $issues.Add("Classifier bundle manifest could not be parsed: $($_.Exception.Message)")
        }
    } elseif ($CheckOnly) {
        $issues.Add("Classifier bundle manifest not found: $ManifestPath")
    }

    $existingByKey = @{}
    if ($existingManifest -and $existingManifest.packages) {
        foreach ($entry in @($existingManifest.packages)) {
            if ($entry.key) {
                $existingByKey[$entry.key] = $entry
            }
        }
    }

    $currentByKey = @{}
    foreach ($entry in @($currentPackages)) {
        $currentByKey[$entry.key] = $entry
        if (-not $existingByKey.ContainsKey($entry.key)) {
            if ($CheckOnly) {
                $issues.Add("Package '$($entry.key)' is not present in classifier-bundle-manifest.json.")
            } else {
                $notes.Add("Package '$($entry.key)' will be added to the manifest.")
            }
            continue
        }

        $old = $existingByKey[$entry.key]
        if ($old.sha256 -ne $entry.sha256) {
            $oldVersion = ConvertTo-VersionValue -Version $old.version
            $newVersion = ConvertTo-VersionValue -Version $entry.version
            if ($newVersion -le $oldVersion -and -not $Force) {
                $issues.Add("Package '$($entry.key)' XML changed but RulePack version did not increase ($($old.version) -> $($entry.version)).")
            } elseif ($CheckOnly) {
                $issues.Add("Package '$($entry.key)' XML changed and version is $($entry.version); run Update-ClassifierBundleManifest.ps1 to record the new hash.")
            } else {
                $notes.Add("Package '$($entry.key)' changed with version $($old.version) -> $($entry.version); manifest will be updated.")
            }
        }
    }

    foreach ($oldKey in @($existingByKey.Keys | Sort-Object)) {
        if (-not $currentByKey.ContainsKey($oldKey)) {
            if ($CheckOnly) {
                $issues.Add("Manifest contains package '$oldKey' that is not in the current deploy registry.")
            } else {
                $notes.Add("Package '$oldKey' is no longer in the registry and will be removed from the manifest.")
            }
        }
    }

    if ($issues.Count -gt 0) {
        Write-Host "Classifier bundle manifest check failed:" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "  - $issue" -ForegroundColor Red
        }
        return (Complete-Script -Succeeded $false)
    }

    if ($CheckOnly) {
        Write-Host "Classifier bundle manifest is current." -ForegroundColor Green
        return (Complete-Script -Succeeded $true)
    }

    if ($existingManifest -and $notes.Count -eq 0 -and -not $Force) {
        Write-Host "Classifier bundle manifest is already current." -ForegroundColor Green
        return (Complete-Script -Succeeded $true)
    }

    foreach ($note in $notes) {
        Write-Host "  $note" -ForegroundColor Yellow
    }

    $manifest = [ordered]@{
        schemaVersion = "dlpdeploy.classifier-bundle-manifest/v1"
        generatedUtc  = (Get-Date).ToUniversalTime().ToString("o")
        registryPath  = ConvertTo-RelativeManifestPath -Path $RegistryPath
        tier          = $Tier
        packages      = @($currentPackages | Sort-Object key)
    }

    $manifestDir = Split-Path -Parent $ManifestPath
    if (-not (Test-Path -LiteralPath $manifestDir -PathType Container)) {
        New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null
    }
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8
    Write-Host "Classifier bundle manifest updated: $(ConvertTo-RelativeManifestPath -Path $ManifestPath)" -ForegroundColor Green
    return (Complete-Script -Succeeded $true)
} catch {
    Write-Host "Classifier bundle manifest check failed: $($_.Exception.Message)" -ForegroundColor Red
    return (Complete-Script -Succeeded $false)
}
