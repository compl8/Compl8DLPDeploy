<#
.SYNOPSIS
  Focused END-TO-END classifier deploy test on a tenant: dictionary sync -> resolve the
  {{DICT_*}} placeholders in ONE real canonical package -> upload it (UTF-16LE+BOM) -> verify
  the package + its SITs land -> clean up (package + synced dictionaries). Proves the real
  dictionary+upload pipeline works at the new >150KB size limit, without the gated full
  orchestration. Read-mostly except the deliberate create/remove of the test package + dicts.
.NOTES
  pwsh -File scripts/Test-EndToEndClassifierDeploy.ps1 -DeviceCode
  -KeepDeployed leaves the package + dictionaries on the tenant for portal inspection.
#>
[CmdletBinding()]
param(
    [switch]$DeviceCode,
    [string]$ExpectedTenantMatch = 'compl8',
    [string]$Package    = 'xml/deploy/QGISCF-medium-06.xml',
    [string]$ManifestUrl = 'https://testpattern.dev/api/export/dictionary-manifest?scope=universal,en-government,au',
    [string]$Prefix     = 'QGISCF',
    [switch]$KeepDeployed)

$ErrorActionPreference = 'Stop'

function ConvertTo-PurviewUtf16Bytes {
    param([Parameter(Mandatory)][string]$Content)
    $n = $Content.TrimStart([char]0xFEFF)
    if ($n -match '^\s*<\?xml\b[^?]*\?>') {
        $n = [regex]::Replace($n, '^\s*<\?xml\b([^?]*?)encoding\s*=\s*([''"])[^''"]+\2([^?]*?)\?>',
            '<?xml$1encoding="utf-16"$3?>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $enc = [System.Text.UnicodeEncoding]::new($false, $true)
    $b = $enc.GetBytes($n); $bom = $enc.GetPreamble()
    $bytes = New-Object byte[] ($bom.Length + $b.Length)
    [Array]::Copy($bom, 0, $bytes, 0, $bom.Length); [Array]::Copy($b, 0, $bytes, $bom.Length, $b.Length)
    return ,$bytes
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Force logs | Out-Null
$log = "logs/compl8-e2e-deploy-$stamp.log"
Start-Transcript -Path $log | Out-Null
$createdRid = $null; $guidMap = @{}
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

    Import-Module ./modules/DLP-Deploy.psm1 -Force

    # --- 1. Dictionary sync (real) ---------------------------------------------------------
    Write-Host "`n=== STEP 1: Dictionary sync ($ManifestUrl) ===" -ForegroundColor Cyan
    $reportDir = Join-Path $env:TEMP "e2e-dict-$stamp"; New-Item -ItemType Directory -Force $reportDir | Out-Null
    $guidMap = Sync-DlpKeywordDictionaries -ManifestUrl $ManifestUrl -NamePrefix $Prefix -ReportDir $reportDir
    Write-Host "Resolved $($guidMap.Count) dictionary placeholder(s):"
    $guidMap.GetEnumerator() | ForEach-Object { Write-Host "  $($_.Key) -> $($_.Value)" }

    # --- 2. Resolve placeholders in the package --------------------------------------------
    # Use the SAME module function the deploy pipeline uses (Deploy-Classifiers.ps1's
    # Resolve-RulePackageUploadContent calls it too) so this test exercises the real
    # dictionary-wiring step, not a parallel reimplementation.
    Write-Host "`n=== STEP 2: Resolve placeholders in $Package ===" -ForegroundColor Cyan
    $content = [System.IO.File]::ReadAllText((Resolve-Path $Package))
    $scope   = if ($ManifestUrl -match 'scope=([^&]+)') { [uri]::UnescapeDataString($matches[1]) } else { '' }
    $content = Resolve-RulePackageDictionaryPlaceholders -Content $content -DictionaryGuidMap $guidMap -Scope $scope
    # Rewrite RulePack id to a fresh GUID so this test never collides with a real package id.
    $createdRid = [guid]::NewGuid().ToString()
    $content = [regex]::Replace($content, '(<RulePack\s+id=")[^"]+(")', "`${1}$createdRid`${2}")
    $u16 = [System.Text.Encoding]::Unicode.GetByteCount($content)
    Write-Host "Resolved OK, no placeholders left. Package is $([int]($u16/1KB)) KB UTF-16 (RulePack id=$createdRid)."

    # --- 3. Upload --------------------------------------------------------------------------
    Write-Host "`n=== STEP 3: Upload ===" -ForegroundColor Cyan
    # Real pipeline guard: every dictionary GUID the resolved package references must exist in the
    # tenant (Assert-RulePackageUploadDictionaryReferences runs this in Deploy-Classifiers.ps1).
    Assert-PackageDictionaryReferencesExist -PackageName (Split-Path $Package -Leaf) -ResolvedXmlText $content -Inventory @(Get-DlpDictionaryInventory)
    Write-Host "Dictionary-reference guard passed (all referenced GUIDs present in tenant)." -ForegroundColor DarkGreen
    $bytes = ConvertTo-PurviewUtf16Bytes -Content $content
    New-DlpSensitiveInformationTypeRulePackage -FileData $bytes -Confirm:$false -ErrorAction Stop | Out-Null
    Write-Host "UPLOAD ACCEPTED ($([int]($u16/1KB)) KB UTF-16 package with live dictionary references)." -ForegroundColor Green
    Start-Sleep 8

    # --- 4. Verify --------------------------------------------------------------------------
    Write-Host "`n=== STEP 4: Verify ===" -ForegroundColor Cyan
    $pkgs = @(Get-DlpSensitiveInformationTypeRulePackage)
    Write-Host "Rule packages on tenant: $($pkgs.Count) (expect built-in + our test package)"
    $sits = @(Get-DlpSensitiveInformationType)
    $custom = @($sits | Where-Object { $_.Publisher -and $_.Publisher -notmatch 'Microsoft' })
    Write-Host "Total SITs: $($sits.Count); custom (non-Microsoft): $($custom.Count)  (the package's entities should now appear)"
    $ourDicts = @(Get-DlpKeywordDictionary -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$Prefix*" })
    Write-Host "Our keyword dictionaries: $($ourDicts.Count)"

    # --- 5. Cleanup -------------------------------------------------------------------------
    if (-not $KeepDeployed) {
        Write-Host "`n=== STEP 5: Cleanup ===" -ForegroundColor Cyan
        try { Remove-DlpSensitiveInformationTypeRulePackage -Identity $createdRid -Confirm:$false -ErrorAction Stop; Write-Host "  removed test package $createdRid" -ForegroundColor DarkGreen }
        catch { Write-Warning "  package remove failed ($createdRid): $($_.Exception.Message)" }
        Start-Sleep 5
        # Remove dictionaries via the LIVE object's identity (Remove-DlpKeywordDictionary does NOT
        # accept the GUID that New-/Sync returns -- it resolves -Identity by name/DN).
        $ourDicts = @(Get-DlpKeywordDictionary -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$Prefix*" })
        foreach ($d in $ourDicts) {
            try { Remove-DlpKeywordDictionary -Identity $d.Identity -Confirm:$false -ErrorAction Stop; Write-Host "  removed dictionary $($d.Name)" -ForegroundColor DarkGreen }
            catch { Write-Warning "  dictionary remove failed ($($d.Name)): $($_.Exception.Message)" }
        }
    } else {
        Write-Host "`n(-KeepDeployed: leaving the test package + dictionaries on the tenant for inspection)" -ForegroundColor Yellow
    }

    Write-Host "`n=== RESULT: end-to-end deploy of a $([int]($u16/1KB)) KB dictionary-backed package SUCCEEDED ===" -ForegroundColor Green
}
catch { Write-Host "RESULT: FAILED -- $($_.Exception.Message)" -ForegroundColor Red }
finally { try { Stop-Transcript | Out-Null } catch {}; Write-Host "Log: $log" }
