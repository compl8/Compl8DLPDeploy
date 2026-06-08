#==============================================================================
# Export-TenantSnapshot.ps1   (READ-ONLY — never mutates the tenant)
#
# Captures a rebuild-grade "old config" snapshot before any destructive change:
#   classifiers/   deployed SIT rule-package XML (full definitions)
#   live/          DLP policies+rules, labels+label policies (incl. IRM/encryption),
#                  auto-labeling policies+rules, keyword dictionaries, SIT inventory
#   config/        the redeployable deploy config (settings/policies/classifiers/labels/...)
#   xml-deploy/    source classifier XML packages + deploy-registry + bundle manifest
#   snapshot-manifest.json
#
# -> backups/tenant-snapshots/<env>-<timestamp>/
#
# Usage:
#   pwsh -File scripts/Export-TenantSnapshot.ps1 -Connect -Tenant compl8.dev -TargetEnvironment nonprod
#   pwsh -File scripts/Export-TenantSnapshot.ps1            # reuse an existing SCC session
#==============================================================================
[CmdletBinding()]
param(
    [switch]$Connect,
    [string]$UPN,
    [string]$Tenant,
    [switch]$Delegated,
    [string]$TargetEnvironment,
    [string]$OutputRoot
)

$ProjectRoot = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $ProjectRoot 'modules/DLP-Deploy.psm1') -Force
$ErrorActionPreference = 'Stop'

if (-not $OutputRoot) { $OutputRoot = Join-Path (Join-Path $ProjectRoot 'backups') 'tenant-snapshots' }

if ($Connect) {
    $connectArgs = @{}
    if ($UPN)      { $connectArgs.UPN = $UPN }
    if ($Tenant)   { $connectArgs.Tenant = $Tenant }
    if ($Delegated){ $connectArgs.Delegated = $true }
    if (-not (Connect-DLPSession @connectArgs)) { throw 'Connection failed; aborting snapshot.' }
}
if (-not (Assert-DLPSession -CommandToTest 'Get-DlpSensitiveInformationTypeRulePackage')) {
    throw 'Not connected to Security & Compliance Center. Re-run with -Connect.'
}

$info = Get-DeploymentTenantInfo
Write-Host "`n=== Tenant snapshot ===" -ForegroundColor Cyan
Write-Host "  Tenant:  $($info.name)  tenantId=$($info.tenantId)" -ForegroundColor Gray

# Read-only confidence check — display the fingerprint result; do NOT block (we capture
# whatever tenant is connected on purpose).
try {
    $fp = Test-DeploymentTenantFingerprint -ProjectRoot $ProjectRoot -TargetEnvironment $TargetEnvironment
    $fpColor = if ($fp.passed -and $fp.matched) { 'Green' } elseif ($fp.passed) { 'Gray' } else { 'Yellow' }
    Write-Host "  Profile: $($fp.environment)  mode=$($fp.mode)  matched=$($fp.matched)" -ForegroundColor $fpColor
} catch { Write-Host "  Fingerprint check skipped: $($_.Exception.Message)" -ForegroundColor Yellow }

function Get-LiveSafe {
    param([Parameter(Mandatory)][string]$Command)
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        Write-Host "    ($Command not available — skipped)" -ForegroundColor DarkYellow
        return @()
    }
    try { return @(& $Command -ErrorAction Stop) }
    catch { Write-Host "    ($Command failed: $($_.Exception.Message))" -ForegroundColor DarkYellow; return @() }
}

Write-Host "  Fetching deployed classifier packages..." -ForegroundColor Gray
$packages = @(Get-LiveSafe 'Get-DlpSensitiveInformationTypeRulePackage' |
    Where-Object { [string]$_.Name -notlike 'Microsoft Rule Package*' -and [string]$_.Publisher -ne 'Microsoft Corporation' })

Write-Host "  Fetching DLP, label, auto-label, dictionary, and SIT data..." -ForegroundColor Gray
$sections = [ordered]@{
    'dlp-policies'         = @(Get-LiveSafe 'Get-DlpCompliancePolicy')
    'dlp-rules'            = @(Get-LiveSafe 'Get-DlpComplianceRule')
    'labels'               = @(Get-LiveSafe 'Get-Label')                       # carries IRM/encryption settings
    'label-policies'       = @(Get-LiveSafe 'Get-LabelPolicy')
    'autolabel-policies'   = @(Get-LiveSafe 'Get-AutoSensitivityLabelPolicy')
    'autolabel-rules'      = @(Get-LiveSafe 'Get-AutoSensitivityLabelRule')
    'keyword-dictionaries' = @(Get-LiveSafe 'Get-DlpKeywordDictionary')        # needed to rebuild dict-backed SITs
    'sit-inventory'        = @(Get-LiveSafe 'Get-DlpSensitiveInformationType')
}

# Redeployable config + source classifier XML.
$configDir = Get-EffectiveConfigDir -ProjectRoot $ProjectRoot -Environment $TargetEnvironment
$deployDir = Join-Path (Join-Path $ProjectRoot 'xml') 'deploy'
$fileCopies = @()
foreach ($fn in @('settings.json','policies.json','classifiers.json','labels.json','rule-overrides.json','tier-assignments.json')) {
    $fileCopies += @{ Source = (Join-Path $configDir $fn); Dest = "config/$fn" }
}
if (Test-Path -LiteralPath $deployDir) {
    foreach ($x in @(Get-ChildItem -LiteralPath $deployDir -Filter *.xml -ErrorAction SilentlyContinue)) {
        $fileCopies += @{ Source = $x.FullName; Dest = "xml-deploy/$($x.Name)" }
    }
    foreach ($reg in @('deploy-registry.json','classifier-bundle-manifest.json')) {
        $fileCopies += @{ Source = (Join-Path $deployDir $reg); Dest = "xml-deploy/$reg" }
    }
}

$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$envKey = if ($TargetEnvironment) { $TargetEnvironment } else { 'default' }

$result = Write-TenantConfigSnapshot -DestinationRoot $OutputRoot -Environment $envKey -Timestamp $ts `
    -Packages $packages -LiveSections $sections -TenantInfo $info -FileCopies $fileCopies

Write-Host "`n=== Snapshot written ===" -ForegroundColor Green
Write-Host "  Path:        $($result.SnapshotPath)" -ForegroundColor Gray
Write-Host "  Classifiers: $($result.ClassifierCount) package XML" -ForegroundColor Gray
foreach ($k in @($result.Sections.Keys)) {
    Write-Host ("  {0,-22} {1}" -f $k, $result.Sections[$k]) -ForegroundColor Gray
}
Write-Host "  Config/source files copied: $($result.FileCount)" -ForegroundColor Gray
Write-Host "  Manifest:    $($result.ManifestPath)" -ForegroundColor Gray
Write-Host "`nKeep this bundle as the 'old config' baseline before any classifier/rule deletion." -ForegroundColor Cyan
