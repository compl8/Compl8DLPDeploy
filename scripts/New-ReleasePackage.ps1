#==============================================================================
# New-ReleasePackage.ps1
# Creates a release zip from PACKAGE-MANIFEST.json.
#==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ManifestPath,
    [string]$OutputDirectory,
    [string]$OutputName,
    [switch]$SkipValidation,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path $PSScriptRoot -Parent
if (-not $ManifestPath) {
    $ManifestPath = Join-Path $ProjectRoot "PACKAGE-MANIFEST.json"
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $ProjectRoot "dist"
}

function ConvertTo-PackageRelativePath {
    param([Parameter(Mandatory)][string]$Path)
    return ([System.IO.Path]::GetRelativePath($ProjectRoot, $Path) -replace "\\", "/")
}

function Test-PackagePattern {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string[]]$Patterns
    )

    foreach ($pattern in $Patterns) {
        $normalized = $pattern -replace "\\", "/"
        $wildcard = [System.Management.Automation.WildcardPattern]::new(
            $normalized,
            [System.Management.Automation.WildcardOptions]::IgnoreCase
        )
        if ($wildcard.IsMatch($RelativePath)) {
            return $true
        }
    }
    return $false
}

function Assert-SafeTempPath {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = [System.IO.Path]::GetFullPath($Path)
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if (-not $resolved.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean temporary package path outside the system temp directory: $resolved"
    }
}

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Package manifest not found: $ManifestPath"
}

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
if (-not $OutputName) {
    $OutputName = if ($manifest.defaultOutputName) { $manifest.defaultOutputName } else { "$($manifest.packageName).zip" }
}

$includePatterns = @($manifest.include)
$excludePatterns = @($manifest.exclude)
if ($includePatterns.Count -eq 0) {
    throw "Package manifest has no include patterns."
}

if (-not $SkipValidation) {
    Write-Host "Running package validation..." -ForegroundColor Cyan
    $validation = & pwsh -NoProfile -File (Join-Path $PSScriptRoot "Invoke-CIChecks.ps1")
    $validation | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE) {
        throw "Validation failed. Package was not created."
    }
}

$allFiles = Get-ChildItem -LiteralPath $ProjectRoot -File -Recurse -Force
$selected = @()
$matchedIncludes = @{}
foreach ($pattern in $includePatterns) {
    $matchedIncludes[$pattern] = $false
}

foreach ($file in $allFiles) {
    $relative = ConvertTo-PackageRelativePath -Path $file.FullName
    if (-not (Test-PackagePattern -RelativePath $relative -Patterns $includePatterns)) {
        continue
    }
    if ($excludePatterns.Count -gt 0 -and (Test-PackagePattern -RelativePath $relative -Patterns $excludePatterns)) {
        continue
    }

    foreach ($pattern in $includePatterns) {
        if (Test-PackagePattern -RelativePath $relative -Patterns @($pattern)) {
            $matchedIncludes[$pattern] = $true
        }
    }
    $selected += [pscustomobject]@{
        FullName = $file.FullName
        RelativePath = $relative
        Length = $file.Length
    }
}

if ($selected.Count -eq 0) {
    throw "No files matched package manifest include/exclude rules."
}

$unmatched = @($matchedIncludes.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object { $_.Key })
if ($unmatched.Count -gt 0) {
    Write-Host "Warning: include pattern(s) matched no files:" -ForegroundColor Yellow
    foreach ($pattern in $unmatched) {
        Write-Host "  - $pattern" -ForegroundColor Yellow
    }
}

$zipPath = Join-Path $OutputDirectory $OutputName
if ((Test-Path -LiteralPath $zipPath) -and -not $Force) {
    throw "Output package already exists. Use -Force to overwrite: $zipPath"
}

Write-Host "Package files selected: $($selected.Count)" -ForegroundColor Cyan
Write-Host "Output package: $zipPath" -ForegroundColor Gray

$createdPackage = $false
if ($PSCmdlet.ShouldProcess($zipPath, "Create release package")) {
    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("Compl8DLPDeploy-package-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null
    try {
        foreach ($entry in $selected) {
            $target = Join-Path $stagingRoot ($entry.RelativePath -replace "/", [System.IO.Path]::DirectorySeparatorChar)
            $targetDir = Split-Path $target -Parent
            if (-not (Test-Path -LiteralPath $targetDir -PathType Container)) {
                New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
            }
            Copy-Item -LiteralPath $entry.FullName -Destination $target -Force
        }

        if (Test-Path -LiteralPath $zipPath) {
            Remove-Item -LiteralPath $zipPath -Force
        }
        Compress-Archive -Path (Join-Path $stagingRoot "*") -DestinationPath $zipPath -Force
        $createdPackage = $true
    } finally {
        if (Test-Path -LiteralPath $stagingRoot) {
            Assert-SafeTempPath -Path $stagingRoot
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force
        }
    }
}

Write-Host "Package manifest: $(ConvertTo-PackageRelativePath -Path $ManifestPath)" -ForegroundColor Green
if ($createdPackage) {
    Write-Host "Package complete: $zipPath" -ForegroundColor Green
} else {
    Write-Host "Package not written because this was a WhatIf/preview run." -ForegroundColor Yellow
}
