#==============================================================================
# record-engine-fixtures.ps1   (READ-ONLY — never mutates the tenant)
#
# OPERATOR step (out of CI; the single network touch per decision D7). Records the
# `actual/` workspace tree the Engine's assess/plan/apply + shadow trial consume, by
# reading the tenant's six SCC object families (Get-TenantInventory) and writing them
# into the workspace under:
#     <workspace>/<env>/actual/snapshots/<timestamp>/inventory.json
#     <workspace>/<env>/actual/inventory.json   (latest pointer copy)
#
# One-writer-per-domain (D8): the Tenant layer owns actual/; the Engine owns history/.
# This recorder is the Stage 4 analogue of Export-TenantSnapshot.ps1 — deliberately NOT
# unit-tested (it is the operator network run; its readers are mocked in CI).
#
# After recording, the shadow trial (Task 14 checklist) runs each Engine executor in
# -WhatIf/plan mode and confirms an EMPTY Get-Compl8ShadowDiff vs the live old leaf
# path's -WhatIf BEFORE any real cutover. Dictionaries cut over first (spec §6); the
# dictionary executor (Invoke-Compl8DictionaryExecutor) is the validated pilot.
#
# Usage:
#   pwsh -File scripts/record-engine-fixtures.ps1 -Connect -Tenant compl8.dev -TargetEnvironment nonprod -Prefix QGISCF
#   pwsh -File scripts/record-engine-fixtures.ps1 -TargetEnvironment nonprod -Prefix QGISCF   # reuse an existing SCC session
#==============================================================================
[CmdletBinding()]
param(
    [switch]$Connect,
    [string]$UPN,
    [string]$Tenant,
    [switch]$Delegated,
    [Parameter(Mandatory)][string]$TargetEnvironment,
    [Parameter(Mandatory)][string]$Prefix,
    # Snapshot folder name. Defaults to a UTC timestamp; pass an explicit value for a
    # reproducible folder name. (Get-Date is allowed HERE — this is an operator script,
    # not a deterministic library path; the library writer Export-TenantActualSnapshot
    # takes the timestamp as input and never calls Get-Date itself.)
    [string]$Timestamp = (Get-Date -Format 'yyyyMMdd_HHmmss')
)

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ErrorActionPreference = 'Stop'

# DLP-Deploy gives Connect-/Assert-DLPSession + Get-DeploymentTenantInfo + the fingerprint
# check; the Engine/Tenant/Content modules give the inventory reader + workspace resolver.
Import-Module (Join-Path $ProjectRoot 'modules/DLP-Deploy.psm1') -Force
Import-Module (Join-Path $ProjectRoot 'modules/Compl8.Engine') -Force   # pulls Tenant + Content + Model

if ($Connect) {
    $connectArgs = @{}
    if ($UPN)       { $connectArgs.UPN = $UPN }
    if ($Tenant)    { $connectArgs.Tenant = $Tenant }
    if ($Delegated) { $connectArgs.Delegated = $true }
    if (-not (Connect-DLPSession @connectArgs)) { throw 'Connection failed; aborting fixture recording.' }
}
if (-not (Assert-DLPSession -CommandToTest 'Get-DlpSensitiveInformationTypeRulePackage')) {
    throw 'Not connected to Security & Compliance Center. Re-run with -Connect.'
}

$info = Get-DeploymentTenantInfo
Write-Host "`n=== Record engine fixtures (actual/) ===" -ForegroundColor Cyan
Write-Host "  Tenant:      $($info.name)  tenantId=$($info.tenantId)" -ForegroundColor Gray
Write-Host "  Environment: $TargetEnvironment   Prefix: $Prefix" -ForegroundColor Gray

# Read-only confidence check — display the fingerprint; do NOT block (we record whatever
# tenant is connected on purpose, exactly like Export-TenantSnapshot.ps1).
try {
    $fp = Test-DeploymentTenantFingerprint -ProjectRoot $ProjectRoot -TargetEnvironment $TargetEnvironment
    $fpColor = if ($fp.passed -and $fp.matched) { 'Green' } elseif ($fp.passed) { 'Gray' } else { 'Yellow' }
    Write-Host "  Profile:     $($fp.environment)  mode=$($fp.mode)  matched=$($fp.matched)" -ForegroundColor $fpColor
} catch { Write-Host "  Fingerprint check skipped: $($_.Exception.Message)" -ForegroundColor Yellow }

# Resolve the workspace-environment root and read the inventory (read-only SCC cmdlets).
$workspacePath = Get-Compl8WorkspacePath -Environment $TargetEnvironment -EnsureExists
$generatedUtc  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

Write-Host "`n  Reading tenant inventory (read-only)..." -ForegroundColor Gray
$inventory = Get-TenantInventory -Prefix $Prefix -GeneratedUtc $generatedUtc -IncludeTenantHeader

# Write the timestamped snapshot (Tenant owns actual/, D8).
$written = Export-TenantActualSnapshot -WorkspacePath $workspacePath -Timestamp $Timestamp -Inventory $inventory

# Also drop a latest-pointer copy at actual/inventory.json (the path assess refreshes from).
$latest = Join-Path (Join-Path $workspacePath 'actual') 'inventory.json'
$inventory | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $latest -Encoding UTF8

Write-Host "`n  Snapshot:  $($written.SnapshotDir)" -ForegroundColor Green
Write-Host "  Inventory: $($written.InventoryPath)" -ForegroundColor Green
Write-Host "  Latest:    $latest" -ForegroundColor Green
Write-Host "`n  Next: run assess + plan, then the shadow trial — confirm an EMPTY Get-Compl8ShadowDiff" -ForegroundColor Cyan
Write-Host "        for each executor vs the live old path's -WhatIf BEFORE any real cutover." -ForegroundColor Cyan

[pscustomobject][ordered]@{
    Tenant        = $info.name
    Environment   = $TargetEnvironment
    Prefix        = $Prefix
    SnapshotDir   = $written.SnapshotDir
    InventoryPath = $written.InventoryPath
    LatestPath    = $latest
    Timestamp     = $Timestamp
}
