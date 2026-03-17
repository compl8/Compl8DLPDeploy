#==============================================================================
# Export-TenantSITs.ps1
# Exports Sensitive Information Types from a tenant for offline mapping.
#
# Connects to the tenant, retrieves all SITs via Get-DlpSensitiveInformationType,
# and writes them to a JSON file. This file can then be used with
# Build-ClassifierSchema.py to create a classifier-to-label mapping.
#
# Usage:
#   .\scripts\Export-TenantSITs.ps1 -Connect -UPN admin@tenant.com
#   .\scripts\Export-TenantSITs.ps1 -Connect -UPN admin@tenant.com -OutputPath sits.json
#   .\scripts\Export-TenantSITs.ps1                                  # use existing session
#==============================================================================

[CmdletBinding()]
param(
    [switch]$Connect,
    [string]$UPN,
    [string]$OutputPath
)

$ProjectRoot = Split-Path $PSScriptRoot -Parent

# Import shared module
Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

$ErrorActionPreference = "Stop"

#region Connection
if ($Connect) {
    $connected = Connect-DLPSession -UPN $UPN
    if (-not $connected) { return }
}

# Verify session
if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationType")) { return }
#endregion

#region Export
Write-Host "`n=== Exporting Sensitive Information Types ===" -ForegroundColor Cyan

$sits = Get-DlpSensitiveInformationType -ErrorAction Stop

# Build clean export objects
$export = @()
foreach ($sit in $sits) {
    $export += [PSCustomObject]@{
        Name      = $sit.Name
        Id        = $sit.Id.ToString()
        Publisher = $sit.Publisher
    }
}

$export = $export | Sort-Object Name

Write-Host "  Total SITs: $($export.Count)" -ForegroundColor Green
Write-Host "    Microsoft Built-in: $(($export | Where-Object { $_.Publisher -eq 'Microsoft Corporation' }).Count)" -ForegroundColor Gray
Write-Host "    Custom:             $(($export | Where-Object { $_.Publisher -ne 'Microsoft Corporation' }).Count)" -ForegroundColor Gray
#endregion

#region Output
# Resolve output path
if (-not $OutputPath) {
    $OutputPath = Join-Path $ProjectRoot "config" "tenant-sits.json"
}

$export | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding utf8
Write-Host "`n  Written to: $OutputPath" -ForegroundColor Green
Write-Host "  Use with: python scripts/Build-ClassifierSchema.py --init" -ForegroundColor Gray
#endregion
