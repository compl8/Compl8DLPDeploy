<#
.SYNOPSIS
  READ-ONLY backup of EVERY SIT rule package on the connected tenant (built-in, portal
  'Microsoft.SCCManaged.CustomRulePack', and custom) so they can be restored if needed.

  Writes each package's raw SerializedClassificationRuleCollection bytes verbatim (the exact
  re-uploadable form) to backups/rulepackages/<tenant>-<timestamp>/, names files from the XML
  (because .Name comes back blank over REST), verifies each file is valid XML, and writes a
  manifest.json + RESTORE.md with the restore commands. Makes NO changes to the tenant.

.NOTES
  pwsh -File scripts/Export-AllRulePackages.ps1 -DeviceCode
#>
[CmdletBinding()]
param([switch]$DeviceCode, [string]$ExpectedTenantMatch = 'compl8', [string]$OutRoot = 'backups/rulepackages')

$ErrorActionPreference = 'Stop'

function Read-PackText([byte[]]$Bytes) {
    if (-not $Bytes) { return '' }
    $t = [System.Text.Encoding]::Unicode.GetString($Bytes)
    if ($t -notmatch '<RulePackage|<\?xml') { $t = [System.Text.Encoding]::UTF8.GetString($Bytes) }
    return $t.TrimStart([char]0xFEFF)
}
function Get-Field([string]$Text, [string]$Pattern) {
    $m = [regex]::Match($Text, $Pattern); if ($m.Success) { $m.Groups[1].Value } else { '' }
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
try {
    # ---- connect (read-only) ----
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
    $upn = if ($conn) { $conn.UserPrincipalName } else { 'unknown' }
    $tenantTag = ($upn -replace '.*@', '') -replace '[^a-zA-Z0-9.-]', '_'
    if ($tenantTag -notmatch [regex]::Escape($ExpectedTenantMatch)) {
        Write-Warning "Connected tenant '$upn' does not contain '$ExpectedTenantMatch' -- read-only export, continuing, but confirm this is the intended tenant."
    }

    $outDir = Join-Path $OutRoot "$tenantTag-$stamp"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $logPath = Join-Path $outDir 'export.log'
    Start-Transcript -Path $logPath | Out-Null
    Write-Host "=== Rule-package backup ===" -ForegroundColor Cyan
    Write-Host "Tenant: $upn" -ForegroundColor Green
    Write-Host "Output: $outDir`n"

    $pkgs = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)
    Write-Host "Rule packages on tenant: $($pkgs.Count)"
    $manifest = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($p in $pkgs) {
        $i++
        $bytes = $p.SerializedClassificationRuleCollection
        if (-not $bytes -or $bytes.Length -eq 0) {
            Write-Warning "  [$i] package has no SerializedClassificationRuleCollection -- skipped"
            $manifest.Add([ordered]@{ index = $i; name = '(no data)'; rulePackId = ''; publisher = ''; file = $null; bytes = 0; sha256 = ''; restorable = $false })
            continue
        }
        $txt = Read-PackText $bytes
        $name = Get-Field $txt '<Name>([^<]+)</Name>'
        $rid  = Get-Field $txt '<RulePack id="([^"]+)"'
        $pub  = Get-Field $txt '<PublisherName>([^<]+)</PublisherName>'
        if (-not $name) { $name = if ($rid) { $rid } else { "package-$i" } }
        $isBuiltIn = ($name -eq 'Microsoft Rule Package' -or $rid -eq '00000000-0000-0000-0000-000000000000')
        $safe = ($name -replace '[^a-zA-Z0-9._-]', '_')
        $ridShort = if ($rid) { ($rid -replace '[^a-zA-Z0-9]', '').Substring(0, [Math]::Min(8, ($rid -replace '[^a-zA-Z0-9]', '').Length)) } else { 'noid' }
        $file = "$safe.__$ridShort.xml"
        $path = Join-Path $outDir $file
        [System.IO.File]::WriteAllBytes($path, $bytes)   # verbatim restorable bytes
        # verify it loads as XML (BOM/declaration aware, like Purview will read it)
        $valid = $false
        try { $doc = New-Object System.Xml.XmlDocument; $doc.Load($path); $valid = ($doc.DocumentElement.Name -eq 'RulePackage') } catch { $valid = $false }
        $sha = (Get-FileHash -Path $path -Algorithm SHA256).Hash
        $tag = if ($isBuiltIn) { 'built-in (do NOT restore)' } elseif ($pub -match 'Microsoft') { 'portal/managed' } else { 'CUSTOM (restorable)' }
        Write-Host ("  [{0,2}] {1,-42} {2,7} KB  valid={3}  {4}" -f $i, $name, [int]($bytes.Length/1KB), $valid, $tag) -ForegroundColor $(if ($valid) { 'Green' } else { 'Red' })
        $manifest.Add([ordered]@{ index = $i; name = $name; rulePackId = $rid; publisher = $pub; isBuiltIn = $isBuiltIn; file = $file; bytes = $bytes.Length; sha256 = $sha; validXml = $valid; restorable = (-not $isBuiltIn) })
    }

    $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $outDir 'manifest.json') -Encoding UTF8
    @"
# Rule-package backup -- $upn -- $stamp

Each *.xml here is the verbatim SerializedClassificationRuleCollection of a deployed rule package.

## Restore a CUSTOM package
``````powershell
Connect-IPPSSession   # or device code
New-DlpSensitiveInformationTypeRulePackage -FileData ([IO.File]::ReadAllBytes("<file>.xml")) -Confirm:`$false
``````

## Notes
- Do NOT restore the built-in 'Microsoft Rule Package' (it can't be created/deleted; it's always present).
- Portal-created SITs were in 'Microsoft.SCCManaged.CustomRulePack'; re-uploading its backup recreates them as a custom package (verify naming/intent first).
- See manifest.json for name, rulePackId, publisher, size, SHA-256, and restorable flag per file.
"@ | Set-Content -Path (Join-Path $outDir 'RESTORE.md') -Encoding UTF8

    $bad = @($manifest | Where-Object { $_.file -and -not $_.validXml })
    Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Backed up $(@($manifest | Where-Object file).Count) package(s) to $outDir"
    Write-Host "Restorable (custom): $(@($manifest | Where-Object restorable).Count); built-in: $(@($manifest | Where-Object isBuiltIn).Count)"
    if ($bad.Count) { Write-Warning "$($bad.Count) file(s) did NOT validate as XML -- investigate before trusting them: $((${bad}.file) -join ', ')" }
    else { Write-Host "All backup files validated as well-formed RulePackage XML." -ForegroundColor Green }
}
catch { Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red }
finally { try { Stop-Transcript | Out-Null } catch {} }
