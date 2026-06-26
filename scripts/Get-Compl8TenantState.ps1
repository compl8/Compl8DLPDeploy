<#
.SYNOPSIS
  READ-ONLY diagnostic. Connects (device code), then dumps the true shape + current state of
  rule packages and SITs so we can see what's actually on the tenant and what property names
  the REST connection populates. Makes NO changes.
#>
[CmdletBinding()]
param([switch]$DeviceCode, [string]$ExpectedTenantMatch = 'compl8', [string]$LogDir = 'logs')

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$logPath = Join-Path $LogDir ("compl8-state-" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".log")
Start-Transcript -Path $logPath | Out-Null
try {
    $conn = $null
    try { $conn = @(Get-ConnectionInformation | Where-Object { $_.UserPrincipalName })[0] } catch { $conn = $null }
    if (-not $conn) {
        if ($DeviceCode) {
            Write-Host "DEVICE CODE sign-in -- a URL + code will print next..." -ForegroundColor Yellow
            Connect-ExchangeOnline -ConnectionUri 'https://ps.compliance.protection.outlook.com/powershell-liveid/' `
                -AzureADAuthorizationEndpointUri 'https://login.microsoftonline.com/organizations' -Device -ShowBanner:$false -ErrorAction Stop
        } else { Connect-IPPSSession -ErrorAction Stop }
        $conn = @(Get-ConnectionInformation | Where-Object { $_.UserPrincipalName })[0]
    }
    Write-Host "Connected: UPN=$($conn.UserPrincipalName) Org=$($conn.Organization)"
    if ("$($conn.UserPrincipalName) $($conn.Organization) $($conn.TenantId)" -notmatch [regex]::Escape($ExpectedTenantMatch)) {
        throw "TENANT GUARD: not '$ExpectedTenantMatch'. Aborting (read-only anyway)."
    }

    Write-Host "`n=== RULE PACKAGES ===" -ForegroundColor Cyan
    $pkgs = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)
    Write-Host "Total rule packages: $($pkgs.Count)"
    Write-Host "`n--- property names on the rule-package object (Get-Member) ---"
    $pkgs | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object { Write-Host "  $_" }
    Write-Host "`n--- candidate name/identity fields per package ---"
    $idx = 0
    foreach ($p in $pkgs) {
        $idx++
        # Try the obvious fields plus parse the pack <Name> out of the serialized XML.
        $packName = ''
        try {
            $bytes = $p.SerializedClassificationRuleCollection
            if ($bytes) {
                $txt = [System.Text.Encoding]::Unicode.GetString($bytes)
                if ($txt -notmatch '<\?xml') { $txt = [System.Text.Encoding]::UTF8.GetString($bytes) }
                if ($txt -match '<RulePack id="([^"]+)"') { $packName = "rulePackId=$($Matches[1])" }
                $m = [regex]::Match($txt, '<Name>([^<]+)</Name>'); if ($m.Success) { $packName += "  name=<$($m.Groups[1].Value)>" }
            }
        } catch { $packName = "(could not parse XML: $($_.Exception.Message))" }
        Write-Host ("  [{0,2}] Identity='{1}' Name='{2}' Id='{3}' {4}" -f $idx, $p.Identity, $p.Name, $p.Id, $packName)
    }

    Write-Host "`n=== SITs (the critical check) ===" -ForegroundColor Cyan
    $sits = @(Get-DlpSensitiveInformationType -ErrorAction Stop)
    $msSits = @($sits | Where-Object { $_.Publisher -match 'Microsoft' })
    $custom = @($sits | Where-Object { $_.Publisher -and $_.Publisher -notmatch 'Microsoft' })
    Write-Host "Total SITs: $($sits.Count)"
    Write-Host "Microsoft built-in SITs: $($msSits.Count)   <-- should be ~200+. If ~0, the built-in package was deleted!" -ForegroundColor $(if ($msSits.Count -ge 100) { 'Green' } else { 'Red' })
    Write-Host "Custom SITs (Publisher != Microsoft): $($custom.Count)"
    if ($custom.Count) { Write-Host "  custom SIT publishers: $((($custom | Select-Object -ExpandProperty Publisher -Unique) -join ', '))" }
    try { $t = Get-DlpSensitiveInformationType -Identity 'Testy McTest' -ErrorAction Stop; Write-Host "Testy McTest: EXISTS (Publisher='$($t.Publisher)')" -ForegroundColor Magenta }
    catch { Write-Host "Testy McTest: GONE" -ForegroundColor Magenta }

    Write-Host "`n=== DONE (read-only, nothing changed) ===" -ForegroundColor Cyan
}
catch { Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red }
finally { Stop-Transcript | Out-Null; Write-Host "Log: $logPath" }
