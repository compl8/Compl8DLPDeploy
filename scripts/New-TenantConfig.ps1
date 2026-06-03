<#
.SYNOPSIS
    Seeds a per-tenant config directory (config/tenants/<env>) as a full copy of
    the scoped global config files. Non-scoped files (the fingerprint registry,
    transient state) are intentionally NOT copied.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [Parameter(Mandatory)][string]$Environment,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
if (-not $ProjectRoot) { $ProjectRoot = Split-Path $PSScriptRoot -Parent }

$ScopedFiles = @(
    'classifiers.json', 'policies.json', 'labels.json',
    'tier-assignments.json', 'rule-overrides.json', 'tenant-sits.json',
    'settings.json'
)

$globalDir = Join-Path $ProjectRoot 'config'
$tenantDir = Join-Path (Join-Path $globalDir 'tenants') $Environment

if ((Test-Path -LiteralPath $tenantDir) -and -not $Force) {
    throw "Tenant config already exists: $tenantDir. Use -Force to reseed."
}

New-Item -ItemType Directory -Path $tenantDir -Force | Out-Null

$copied = @()
foreach ($name in $ScopedFiles) {
    $src = Join-Path $globalDir $name
    if (Test-Path -LiteralPath $src -PathType Leaf) {
        Copy-Item -LiteralPath $src -Destination (Join-Path $tenantDir $name) -Force
        $copied += $name
    }
}

Write-Host "Seeded tenant config: $tenantDir" -ForegroundColor Green
Write-Host ("  Copied {0} file(s): {1}" -f $copied.Count, ($copied -join ', ')) -ForegroundColor Gray
Write-Host "  Not copied (global-only): tenant-fingerprints.json, last-classifier-upload.json" -ForegroundColor DarkGray
return $tenantDir
