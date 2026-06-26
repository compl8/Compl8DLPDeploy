<#
.SYNOPSIS
  Remove keyword dictionaries whose Name starts with a given prefix (default QGISCF) from the
  connected tenant. Removes via the LIVE Get-DlpKeywordDictionary object identity (the GUID
  from New-/Sync is NOT accepted by Remove-DlpKeywordDictionary). Read-then-delete; tenant-guarded.
.NOTES
  pwsh -File scripts/Remove-Compl8Dictionaries.ps1 -DeviceCode
#>
[CmdletBinding()]
param([switch]$DeviceCode, [string]$ExpectedTenantMatch = 'compl8', [string]$Prefix = 'QGISCF')

$ErrorActionPreference = 'Stop'
try {
    $conn = $null
    try { $conn = @(Get-ConnectionInformation | Where-Object { $_.UserPrincipalName })[0] } catch { $conn = $null }
    if (-not $conn) {
        if ($DeviceCode) {
            Write-Host "DEVICE CODE sign-in -- URL + code prints next..." -ForegroundColor Yellow
            Connect-ExchangeOnline -ConnectionUri 'https://ps.compliance.protection.outlook.com/powershell-liveid/' `
                -AzureADAuthorizationEndpointUri 'https://login.microsoftonline.com/organizations' -Device -ShowBanner:$false -ErrorAction Stop
        } else { Connect-IPPSSession -ErrorAction Stop }
        $conn = @(Get-ConnectionInformation | Where-Object { $_.UserPrincipalName })[0]
    }
    Write-Host "Connected: $($conn.UserPrincipalName)" -ForegroundColor Green
    if ("$($conn.UserPrincipalName) $($conn.TenantId)" -notmatch [regex]::Escape($ExpectedTenantMatch)) {
        throw "TENANT GUARD: connected tenant does not match '$ExpectedTenantMatch'. Aborting."
    }
    $dicts = @(Get-DlpKeywordDictionary -ErrorAction Stop | Where-Object { $_.Name -like "$Prefix*" })
    Write-Host "Dictionaries matching '$Prefix*': $($dicts.Count)"
    $dicts | ForEach-Object { Write-Host "  - $($_.Name)" }
    foreach ($d in $dicts) {
        try { Remove-DlpKeywordDictionary -Identity $d.Identity -Confirm:$false -ErrorAction Stop; Write-Host "  removed: $($d.Name)" -ForegroundColor DarkGreen }
        catch { Write-Warning "  failed $($d.Name): $($_.Exception.Message)" }
    }
    Start-Sleep 4
    $left = @(Get-DlpKeywordDictionary -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$Prefix*" })
    Write-Host "Remaining '$Prefix*' dictionaries: $($left.Count)" -ForegroundColor $(if ($left.Count) { 'Yellow' } else { 'Green' })
}
catch { Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red }
