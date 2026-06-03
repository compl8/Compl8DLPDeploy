<#
.SYNOPSIS
    Reports config skew between config/tenants/<env> and the global config/.
    Raw diff: every differing key is listed. Exit 0 (use -NoExit to return instead).
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [Parameter(Mandatory)][string]$Environment,
    [switch]$NoExit
)

$ErrorActionPreference = 'Stop'
if (-not $ProjectRoot) { $ProjectRoot = Split-Path $PSScriptRoot -Parent }
$repoRoot = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repoRoot 'modules' 'DLP-Deploy.psm1') -Force

$skew = @(Compare-TenantConfigSkew -ProjectRoot $ProjectRoot -Environment $Environment)

Write-Host "=== Config Skew ($Environment vs global) ===" -ForegroundColor Cyan
if ($skew.Count -eq 0) {
    Write-Host "  No tenant overrides or no differences." -ForegroundColor Green
} else {
    foreach ($d in $skew) {
        $g = if ($null -eq $d.global) { '(absent)' } else { [string]$d.global }
        $t = if ($null -eq $d.tenant) { '(absent)' } else { [string]$d.tenant }
        Write-Host ("  {0}: {1} [{2}] global='{3}' tenant='{4}'" -f $d.file, $d.path, $d.kind, $g, $t) -ForegroundColor Yellow
    }
    Write-Host ("  {0} difference(s)." -f $skew.Count) -ForegroundColor Yellow
}

if ($NoExit) { return $skew }
exit 0
