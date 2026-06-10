#==============================================================================
# Test-TestPatternDrift.ps1
# Validates TestPattern API contracts with offline fixtures and optional live smoke.
#==============================================================================

[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [string]$PatternsFixturePath,
    [string]$BundleFixturePath,
    [string]$DictionaryManifestFixturePath,
    [switch]$Live,
    [string]$PatternsUrl = "https://testpattern.dev/api/export/purview",
    [string]$BundleUrl = "https://testpattern.dev/api/export/purview-bundle",
    [string]$DictionaryManifestUrl = "https://testpattern.dev/api/export/dictionary-manifest",
    [string]$DictionaryScope = "",
    [string[]]$LiveSlug = @(),
    [int]$MaxPackageSizeBytes = 0,
    [switch]$FailOnLocalNameDrift,
    [switch]$FailOnWarnings,
    [switch]$NoExit
)

$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot '..' 'modules' 'Compl8.Model') -Force
if (-not $PSBoundParameters.ContainsKey('MaxPackageSizeBytes')) {
    $MaxPackageSizeBytes = (Get-DeploymentLimits).PreferredRulePackageBytes  # 148 KB margin
}

if (-not $ProjectRoot) {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
}
$ProjectRoot = [System.IO.Path]::GetFullPath($ProjectRoot)
$FixtureRoot = Join-Path $ProjectRoot "tests/fixtures/testpattern"
if (-not $PatternsFixturePath) {
    $PatternsFixturePath = Join-Path $FixtureRoot "patterns.json"
}
if (-not $BundleFixturePath) {
    $BundleFixturePath = Join-Path $FixtureRoot "purview-bundle.xml"
}
if (-not $DictionaryManifestFixturePath) {
    $DictionaryManifestFixturePath = Join-Path $FixtureRoot "dictionary-manifest.json"
}

$script:Errors = [System.Collections.Generic.List[string]]::new()
$script:Warnings = [System.Collections.Generic.List[string]]::new()

function Add-DriftError {
    param([string]$Message)
    $script:Errors.Add($Message)
}

function Add-DriftWarning {
    param([string]$Message)
    $script:Warnings.Add($Message)
}

function Complete-DriftCheck {
    param([bool]$Succeeded)

    if ($NoExit) {
        return $Succeeded
    }
    exit $(if ($Succeeded) { 0 } else { 1 })
}

function Read-JsonFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-DriftError "$Description not found: $Path"
        return $null
    }

    try {
        return (Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        Add-DriftError "$Description is not valid JSON: $($_.Exception.Message)"
        return $null
    }
}

function Get-PropertyValue {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string[]]$Names
    )

    foreach ($name in $Names) {
        $prop = $InputObject.PSObject.Properties[$name]
        if ($prop -and -not [string]::IsNullOrWhiteSpace($prop.Value)) {
            return $prop.Value.ToString()
        }
    }
    return $null
}

function ConvertTo-PatternList {
    param([object]$Response)

    if ($null -eq $Response) { return @() }
    if ($Response -is [array]) { return @($Response) }
    if ($Response.PSObject.Properties["patterns"]) { return @($Response.patterns) }
    if ($Response.PSObject.Properties["data"]) { return @($Response.data) }
    Add-DriftError "Pattern catalogue response must be an array or contain a 'patterns' array."
    return @()
}

function Test-PatternCatalogue {
    param(
        [Parameter(Mandatory)][object]$Response,
        [Parameter(Mandatory)][string]$Source
    )

    $patterns = @(ConvertTo-PatternList -Response $Response)
    if ($patterns.Count -eq 0) {
        Add-DriftError "$Source pattern catalogue contains no patterns."
        return @()
    }

    $seenSlugs = @{}
    foreach ($pattern in $patterns) {
        $slug = Get-PropertyValue -InputObject $pattern -Names @("slug", "Slug")
        $name = Get-PropertyValue -InputObject $pattern -Names @("name", "Name", "displayName", "title")

        if ([string]::IsNullOrWhiteSpace($slug)) {
            Add-DriftError "$Source pattern entry is missing 'slug'."
        } elseif ($slug -notmatch '^[a-z0-9][a-z0-9-]*$') {
            Add-DriftError "$Source pattern slug '$slug' is not URL-safe lowercase kebab-case."
        } elseif ($seenSlugs.ContainsKey($slug)) {
            Add-DriftError "$Source pattern slug '$slug' appears more than once."
        } else {
            $seenSlugs[$slug] = $pattern
        }

        if ([string]::IsNullOrWhiteSpace($name)) {
            Add-DriftError "$Source pattern '$slug' is missing a display name."
        }
    }

    Write-Host "  $Source patterns: $($patterns.Count)" -ForegroundColor Gray
    return $patterns
}

function Test-DictionaryManifest {
    param(
        [Parameter(Mandatory)][object]$Response,
        [Parameter(Mandatory)][string]$Source
    )

    if (-not $Response.PSObject.Properties["dictionaries"]) {
        Add-DriftError "$Source dictionary manifest is missing a 'dictionaries' array."
        return
    }

    $seen = @{}
    $dictionaries = @($Response.dictionaries)
    if ($dictionaries.Count -eq 0) {
        Add-DriftError "$Source dictionary manifest contains no dictionaries."
        return
    }

    foreach ($dict in $dictionaries) {
        $placeholder = Get-PropertyValue -InputObject $dict -Names @("placeholder", "Placeholder")
        $name = Get-PropertyValue -InputObject $dict -Names @("name", "Name")
        $placeholderKey = $null
        if ($placeholder -match '^(DICT_[A-Z0-9_]+)$') {
            $placeholderKey = $Matches[1]
        } elseif ($placeholder -match '^\{\{(DICT_[A-Z0-9_]+)\}\}$') {
            $placeholderKey = $Matches[1]
        }

        if (-not $placeholderKey) {
            Add-DriftError "$Source dictionary placeholder '$placeholder' does not match DICT_* or {{DICT_*}} format."
        } elseif ($seen.ContainsKey($placeholderKey)) {
            Add-DriftError "$Source dictionary placeholder '$placeholder' appears more than once."
        } else {
            $seen[$placeholderKey] = $true
        }
        if ([string]::IsNullOrWhiteSpace($name)) {
            Add-DriftError "$Source dictionary '$placeholder' is missing a name."
        }
        if (-not $dict.PSObject.Properties["terms"] -or @($dict.terms).Count -eq 0) {
            Add-DriftWarning "$Source dictionary '$placeholder' contains no terms."
        }
    }

    Write-Host "  $Source dictionaries: $($dictionaries.Count)" -ForegroundColor Gray
}

function Get-XmlElementChild {
    param(
        [Parameter(Mandatory)][System.Xml.XmlNode]$Node,
        [Parameter(Mandatory)][string]$Name
    )

    return @($Node.ChildNodes | Where-Object {
        $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -eq $Name
    } | Select-Object -First 1)[0]
}

function Test-PurviewBundleXml {
    param(
        [Parameter(Mandatory)][string]$XmlText,
        [Parameter(Mandatory)][string]$Source,
        [switch]$RequireDictionaryPlaceholders
    )

    if ([string]::IsNullOrWhiteSpace($XmlText)) {
        Add-DriftError "$Source Purview bundle XML is empty."
        return
    }

    $sizeBytes = [System.Text.Encoding]::UTF8.GetByteCount($XmlText)
    if ($sizeBytes -gt $MaxPackageSizeBytes) {
        Add-DriftError "$Source Purview bundle is $sizeBytes bytes, above the configured $MaxPackageSizeBytes byte guardrail."
    }

    try {
        [xml]$xml = $XmlText
    } catch {
        Add-DriftError "$Source Purview bundle is not parseable XML: $($_.Exception.Message)"
        return
    }

    $root = $xml.DocumentElement
    if (-not $root -or $root.LocalName -ne "RulePackage") {
        Add-DriftError "$Source Purview bundle root must be RulePackage."
        return
    }
    if ($root.NamespaceURI -ne "http://schemas.microsoft.com/office/2011/mce") {
        Add-DriftWarning "$Source RulePackage namespace is '$($root.NamespaceURI)', expected Microsoft MCE namespace."
    }

    $rulePack = Get-XmlElementChild -Node $root -Name "RulePack"
    if (-not $rulePack) {
        Add-DriftError "$Source Purview bundle is missing RulePack metadata."
        return
    }
    $rulePackId = $rulePack.GetAttribute("id")
    $guid = [guid]::Empty
    if (-not [guid]::TryParse($rulePackId, [ref]$guid)) {
        Add-DriftError "$Source RulePack id '$rulePackId' is not a GUID."
    }
    if (-not (Get-XmlElementChild -Node $rulePack -Name "Version")) {
        Add-DriftError "$Source RulePack is missing Version."
    }

    $rules = Get-XmlElementChild -Node $root -Name "Rules"
    if (-not $rules) {
        Add-DriftError "$Source Purview bundle is missing Rules."
        return
    }
    $entities = @($rules.ChildNodes | Where-Object {
        $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -eq "Entity"
    })
    if ($entities.Count -eq 0) {
        Add-DriftError "$Source Purview bundle contains no Entity nodes."
    }
    if (-not (Get-XmlElementChild -Node $rules -Name "LocalizedStrings")) {
        Add-DriftError "$Source Purview bundle is missing LocalizedStrings."
    }

    $placeholders = @([regex]::Matches($XmlText, '\{\{DICT_[A-Z0-9_]+\}\}') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    if ($RequireDictionaryPlaceholders -and $placeholders.Count -eq 0) {
        Add-DriftError "$Source Purview bundle has no {{DICT_*}} placeholders even though dictionaries=true is expected."
    }
    if ([regex]::IsMatch($XmlText, '<(?:Entity|Regex|Keyword|LocalizedStrings|Resource)\b[^>]*\sxmlns=""')) {
        Add-DriftError "$Source Purview bundle contains namespace-resetting child elements."
    }

    Write-Host "  $Source bundle: $($entities.Count) entit$(if ($entities.Count -eq 1) { 'y' } else { 'ies' }), $sizeBytes bytes, $($placeholders.Count) dictionary placeholder(s)" -ForegroundColor Gray
}

function Invoke-TestPatternJson {
    param([Parameter(Mandatory)][string]$Uri)

    Invoke-RestMethod -Uri $Uri -Headers @{ "User-Agent" = "Compl8DLPDeploy/1.0" } -TimeoutSec 60
}

function Invoke-TestPatternText {
    param([Parameter(Mandatory)][string]$Uri)

    (Invoke-WebRequest -Uri $Uri -Headers @{ "User-Agent" = "Compl8DLPDeploy/1.0" } -TimeoutSec 120).Content
}

function Get-LocalTestPatternNames {
    $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $classifiersPath = Join-Path (Join-Path $ProjectRoot "config") "classifiers.json"
    if (Test-Path -LiteralPath $classifiersPath -PathType Leaf) {
        try {
            $classifiers = Get-Content -Raw -LiteralPath $classifiersPath | ConvertFrom-Json
            foreach ($group in $classifiers.PSObject.Properties) {
                foreach ($entry in @($group.Value)) {
                    if ($entry.name -and $entry.name -like "TestPattern - *") {
                        $names.Add(($entry.name -replace '^TestPattern - ', '').Trim()) | Out-Null
                    }
                }
            }
        } catch {
            Add-DriftWarning "Could not inspect local classifiers.json for TestPattern names: $($_.Exception.Message)"
        }
    }

    $tiersPath = Join-Path (Join-Path $ProjectRoot "config") "tier-assignments.json"
    if (Test-Path -LiteralPath $tiersPath -PathType Leaf) {
        try {
            $tiers = Get-Content -Raw -LiteralPath $tiersPath | ConvertFrom-Json
            foreach ($prop in @("small_custom", "medium_custom", "large_custom")) {
                foreach ($name in @($tiers.$prop)) {
                    if (-not [string]::IsNullOrWhiteSpace($name)) {
                        $names.Add($name.Trim()) | Out-Null
                    }
                }
            }
        } catch {
            Add-DriftWarning "Could not inspect tier-assignments.json for TestPattern names: $($_.Exception.Message)"
        }
    }

    return @($names | Sort-Object)
}

function Compare-LocalNamesToCatalogue {
    param([Parameter(Mandatory)][object[]]$Patterns)

    $catalogueNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($pattern in @($Patterns)) {
        $name = Get-PropertyValue -InputObject $pattern -Names @("name", "Name", "displayName", "title")
        if ($name) { $catalogueNames.Add($name.Trim()) | Out-Null }
    }

    $localNames = @(Get-LocalTestPatternNames)
    if ($localNames.Count -eq 0) {
        Add-DriftWarning "No local TestPattern names were found to compare with the live catalogue."
        return
    }

    $missing = @($localNames | Where-Object { -not $catalogueNames.Contains($_) })
    Write-Host "  Local TestPattern names: $($localNames.Count); missing from live catalogue by name: $($missing.Count)" -ForegroundColor Gray
    if ($missing.Count -gt 0) {
        $sample = @($missing | Select-Object -First 20) -join "; "
        $message = "Local TestPattern names not found in live catalogue by exact name: $sample"
        if ($missing.Count -gt 20) { $message += "; ... and $($missing.Count - 20) more" }
        if ($FailOnLocalNameDrift) {
            Add-DriftError $message
        } else {
            Add-DriftWarning $message
        }
    }
}

Write-Host "=== TestPattern Drift Gate ===" -ForegroundColor Cyan
Write-Host "  Mode: $(if ($Live) { 'offline fixtures + live smoke' } else { 'offline fixtures' })" -ForegroundColor Gray

$patternsFixture = Read-JsonFile -Path $PatternsFixturePath -Description "TestPattern patterns fixture"
if ($patternsFixture) {
    $null = @(Test-PatternCatalogue -Response $patternsFixture -Source "Fixture")
}

$dictionaryFixture = Read-JsonFile -Path $DictionaryManifestFixturePath -Description "TestPattern dictionary manifest fixture"
if ($dictionaryFixture) {
    Test-DictionaryManifest -Response $dictionaryFixture -Source "Fixture"
}

if (Test-Path -LiteralPath $BundleFixturePath -PathType Leaf) {
    Test-PurviewBundleXml -XmlText (Get-Content -Raw -LiteralPath $BundleFixturePath) -Source "Fixture" -RequireDictionaryPlaceholders
} else {
    Add-DriftError "TestPattern Purview bundle fixture not found: $BundleFixturePath"
}

if ($Live) {
    try {
        $livePatternsResponse = Invoke-TestPatternJson -Uri $PatternsUrl
        $livePatterns = @(Test-PatternCatalogue -Response $livePatternsResponse -Source "Live")
        Compare-LocalNamesToCatalogue -Patterns $livePatterns

        $dictionaryUri = $DictionaryManifestUrl
        if (-not [string]::IsNullOrWhiteSpace($DictionaryScope)) {
            $separator = if ($DictionaryManifestUrl -match '\?') { "&" } else { "?" }
            $dictionaryUri = "$DictionaryManifestUrl${separator}scope=$([uri]::EscapeDataString($DictionaryScope))"
        }
        $liveDictionaryManifest = Invoke-TestPatternJson -Uri $dictionaryUri
        Test-DictionaryManifest -Response $liveDictionaryManifest -Source "Live"

        $slugs = @($LiveSlug | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($slugs.Count -eq 0) {
            $slugs = @($livePatterns |
                ForEach-Object { Get-PropertyValue -InputObject $_ -Names @("slug", "Slug") } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Sort-Object |
                Select-Object -First 2)
        }
        if ($slugs.Count -eq 0) {
            Add-DriftError "Could not select live TestPattern slugs for Purview bundle smoke test."
        } else {
            $slugParam = [uri]::EscapeDataString(($slugs -join ","))
            $nameParam = [uri]::EscapeDataString("Compl8DriftSmoke")
            $bundleUri = "${BundleUrl}?slugs=$slugParam&name=$nameParam&dictionaries=true"
            $liveBundle = Invoke-TestPatternText -Uri $bundleUri
            Test-PurviewBundleXml -XmlText $liveBundle -Source "Live" -RequireDictionaryPlaceholders
        }
    } catch {
        Add-DriftError "Live TestPattern smoke check failed: $($_.Exception.Message)"
    }
}

Write-Host "`n=== TestPattern Drift Summary ===" -ForegroundColor Cyan
if ($script:Errors.Count -eq 0) {
    Write-Host "  Errors:   0" -ForegroundColor Green
} else {
    Write-Host "  Errors:   $($script:Errors.Count)" -ForegroundColor Red
    foreach ($err in $script:Errors) { Write-Host "    - $err" -ForegroundColor Red }
}

if ($script:Warnings.Count -eq 0) {
    Write-Host "  Warnings: 0" -ForegroundColor Green
} else {
    Write-Host "  Warnings: $($script:Warnings.Count)" -ForegroundColor Yellow
    foreach ($warn in $script:Warnings) { Write-Host "    - $warn" -ForegroundColor Yellow }
}

$passed = ($script:Errors.Count -eq 0 -and (-not $FailOnWarnings -or $script:Warnings.Count -eq 0))
if ($passed) {
    Write-Host "`nRESULT: PASS" -ForegroundColor Green
} else {
    Write-Host "`nRESULT: FAIL" -ForegroundColor Red
}

return (Complete-DriftCheck -Succeeded $passed)
