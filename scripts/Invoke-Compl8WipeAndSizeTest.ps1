<#
.SYNOPSIS
  ONE-SHOT (single session): connect to Security & Compliance PowerShell, optionally wipe all
  DLP rules/policies and all CUSTOM SIT rule packages, then upload the size-test packages to
  find the real per-package upload ceiling. Everything is written to a transcript log.

  SAFETY: a tenant guard aborts unless the connected tenant matches -ExpectedTenantMatch
  (default 'compl8'), so it cannot modify the wrong tenant. Nothing destructive runs before a
  successful, verified connection.

.NOTES
  Run interactively so you can complete MFA:
      pwsh -File scripts/Invoke-Compl8WipeAndSizeTest.ps1
  Connect-IPPSSession is called with NO -UPN/-Tenant pin (the browser picks the account).
  Switches: -SkipWipe (test only), -SkipSizeTest (wipe only), -WipeSits (also strip portal
  custom SITs from the Microsoft custom rule pack).
#>
[CmdletBinding()]
param(
    [string]$ExpectedTenantMatch = 'compl8',
    [switch]$SkipWipe,
    [switch]$SkipSizeTest,
    [switch]$WipeSits,
    [string]$PackageDir = 'test-packages',
    [string]$LogDir = 'logs',
    # Use device-code auth (no window handle needed -- works in a headless/automation shell).
    # Connects to the Security & Compliance endpoint via Connect-ExchangeOnline -Device.
    [switch]$DeviceCode,
    # Report whether this named SIT exists, at the start (baseline) and end (final) of the run.
    [string]$CheckSit)

$ErrorActionPreference = 'Stop'

function Get-PackInfo {
    # The REST connection often leaves .Name/.Identity blank on rule-package objects, so derive the
    # real name + RulePack GUID from the serialized XML (proven reliable). Built-in pack id = all zeros.
    param($Pkg)
    $name = $Pkg.RuleCollectionName; if (-not $name) { $name = $Pkg.Name }
    $id   = $Pkg.Identity
    try {
        $bytes = $Pkg.SerializedClassificationRuleCollection
        if ($bytes) {
            $txt = [System.Text.Encoding]::Unicode.GetString($bytes)
            if ($txt -notmatch '<\?xml') { $txt = [System.Text.Encoding]::UTF8.GetString($bytes) }
            if (-not $name) { $m = [regex]::Match($txt, '<Name>([^<]+)</Name>');   if ($m.Success) { $name = $m.Groups[1].Value } }
            if (-not $id)   { $m = [regex]::Match($txt, '<RulePack id="([^"]+)"'); if ($m.Success) { $id   = $m.Groups[1].Value } }
            if (-not ($Pkg.PSObject.Properties['RulePackId'])) {
                $m = [regex]::Match($txt, '<RulePack id="([^"]+)"'); if ($m.Success) { $Pkg | Add-Member -NotePropertyName RulePackId -NotePropertyValue $m.Groups[1].Value -Force }
            }
        }
    } catch {}
    [pscustomobject]@{ Id = $id; Name = $name; IsBuiltIn = ($name -eq 'Microsoft Rule Package' -or $id -eq '00000000-0000-0000-0000-000000000000') }
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$logPath = Join-Path $LogDir "compl8-wipe-sizetest-$stamp.log"
Start-Transcript -Path $logPath | Out-Null

try {
    # ---- 1. Connect ------------------------------------------------------------------------
    Write-Host "=== CONNECT (browser/MFA; no UPN/Tenant pin) ===" -ForegroundColor Cyan
    $conn = $null
    try { $conn = @(Get-ConnectionInformation | Where-Object { $_.UserPrincipalName })[0] } catch { $conn = $null }
    if ($conn) {
        Write-Host "Existing session found for $($conn.UserPrincipalName)."
    } else {
        if ($DeviceCode) {
            if (-not (Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue)) {
                throw "Connect-ExchangeOnline not available. Install ExchangeOnlineManagement: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
            }
            Write-Host "No active session -- DEVICE CODE sign-in. A URL + code will print next; open it and enter the code (MFA included)..." -ForegroundColor Yellow
            Connect-ExchangeOnline `
                -ConnectionUri 'https://ps.compliance.protection.outlook.com/powershell-liveid/' `
                -AzureADAuthorizationEndpointUri 'https://login.microsoftonline.com/organizations' `
                -Device -ShowBanner:$false -ErrorAction Stop
        } else {
            if (-not (Get-Command Connect-IPPSSession -ErrorAction SilentlyContinue)) {
                throw "Connect-IPPSSession not available. Install ExchangeOnlineManagement: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
            }
            Write-Host "No active session -- launching interactive sign-in. Complete MFA in the browser..."
            Connect-IPPSSession -ErrorAction Stop
        }
        $conn = @(Get-ConnectionInformation | Where-Object { $_.UserPrincipalName })[0]
    }
    if (-not $conn) {
        throw "No authenticated session after sign-in. Run this in an INTERACTIVE terminal (so MFA can complete) -- e.g. open PowerShell and run: pwsh -File scripts/Invoke-Compl8WipeAndSizeTest.ps1"
    }
    $identity = "UPN=$($conn.UserPrincipalName) Org=$($conn.Organization) Uri=$($conn.ConnectionUri)"
    Write-Host "Connected: $identity" -ForegroundColor Green

    # ---- 2. Tenant guard -------------------------------------------------------------------
    $hay = "$($conn.UserPrincipalName) $($conn.Organization) $($conn.ConnectionUri) $($conn.TenantId)"
    if ($hay -notmatch [regex]::Escape($ExpectedTenantMatch)) {
        throw "TENANT GUARD TRIPPED: connected tenant [$identity] does not contain '$ExpectedTenantMatch'. Refusing to modify it. Aborting."
    }
    Write-Host "Tenant guard OK (matches '$ExpectedTenantMatch')." -ForegroundColor Green

    if ($CheckSit) {
        try { $s = Get-DlpSensitiveInformationType -Identity $CheckSit -ErrorAction Stop
              Write-Host ("BASELINE: SIT '{0}' EXISTS (Publisher='{1}')" -f $CheckSit, $s.Publisher) -ForegroundColor Magenta }
        catch { Write-Host "BASELINE: SIT '$CheckSit' NOT found" -ForegroundColor Magenta }
    }

    # ---- 3. PHASE 1+2: wipe DLP rules/policies, then custom classifiers ---------------------
    if (-not $SkipWipe) {
        Write-Host "`n=== PHASE 1: DLP rules, then policies ===" -ForegroundColor Cyan
        $rules = @(Get-DlpComplianceRule -ErrorAction Stop)
        Write-Host "DLP compliance rules found: $($rules.Count)"
        foreach ($r in $rules) {
            try { Remove-DlpComplianceRule -Identity $r.Identity -Confirm:$false -ErrorAction Stop; Write-Host "  removed rule:   $($r.Name)" -ForegroundColor DarkGreen }
            catch { Write-Warning "  FAILED rule   $($r.Name): $($_.Exception.Message)" }
        }
        $pols = @(Get-DlpCompliancePolicy -ErrorAction Stop)
        Write-Host "DLP compliance policies found: $($pols.Count)"
        foreach ($p in $pols) {
            try { Remove-DlpCompliancePolicy -Identity $p.Identity -Confirm:$false -ErrorAction Stop; Write-Host "  removed policy: $($p.Name)" -ForegroundColor DarkGreen }
            catch { Write-Warning "  FAILED policy $($p.Name): $($_.Exception.Message)" }
        }

        Write-Host "`n=== PHASE 2: custom SIT rule packages ===" -ForegroundColor Cyan
        $allPkgs = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)
        $infos   = $allPkgs | ForEach-Object { $pi = Get-PackInfo $_; [pscustomobject]@{ Pkg = $_; Id = $pi.Id; Name = $pi.Name; IsBuiltIn = $pi.IsBuiltIn } }
        # "custom" = NOT the built-in 'Microsoft Rule Package' and NOT the portal container
        # 'Microsoft.SCCManaged.CustomRulePack' (handled separately by -WipeSits).
        $custom  = $infos | Where-Object { -not $_.IsBuiltIn -and $_.Name -ne 'Microsoft.SCCManaged.CustomRulePack' }
        Write-Host "Rule packages total: $($allPkgs.Count); deletable custom: $($custom.Count)"
        foreach ($i in $infos) {
            $tag = if ($i.IsBuiltIn) { 'skip-builtin' } elseif ($i.Name -eq 'Microsoft.SCCManaged.CustomRulePack') { 'skip-portal ' } else { 'DELETE      ' }
            Write-Host ("  [{0}] {1}  (id={2})" -f $tag, $i.Name, $i.Id)
        }
        foreach ($c in $custom) {
            $target = if ($c.Id) { $c.Id } else { $c.Name }
            try { Remove-DlpSensitiveInformationTypeRulePackage -Identity $target -Confirm:$false -ErrorAction Stop; Write-Host "  removed package: $($c.Name)" -ForegroundColor DarkGreen }
            catch { Write-Warning "  FAILED package '$($c.Name)' (id=$target): $($_.Exception.Message) (a live DLP rule may still reference it)" }
        }

        if ($WipeSits) {
            Write-Host "`n=== PHASE 2b: portal-created custom SITs ===" -ForegroundColor Cyan
            # Portal-created custom SITs all live in the system package 'Microsoft.SCCManaged.CustomRulePack'.
            # Removing that package removes them all. (Remove-DlpSensitiveInformationType only handles
            # document-fingerprint SITs per MS docs, so it is NOT used here.)
            $portalInfo = $infos | Where-Object { $_.Name -eq 'Microsoft.SCCManaged.CustomRulePack' } | Select-Object -First 1
            if ($portalInfo) {
                $target = if ($portalInfo.Id) { $portalInfo.Id } else { $portalInfo.Name }
                Write-Host "Found Microsoft.SCCManaged.CustomRulePack (id=$target). Attempting removal (removes all portal SITs)..."
                try {
                    Remove-DlpSensitiveInformationTypeRulePackage -Identity $target -Confirm:$false -ErrorAction Stop
                    Write-Host "  removed Microsoft.SCCManaged.CustomRulePack (all portal SITs gone)" -ForegroundColor DarkGreen
                } catch {
                    Write-Warning "  Could NOT remove Microsoft.SCCManaged.CustomRulePack: $($_.Exception.Message)"
                    Write-Warning "  Delete portal SITs in the portal UI instead: Information Protection > Classifiers > Sensitive info types."
                }
            } else {
                Write-Host "No Microsoft.SCCManaged.CustomRulePack present -- no portal-created custom SITs to remove."
            }
        }
        Write-Host "Waiting 20s for removals to propagate..." -ForegroundColor DarkGray; Start-Sleep 20
    }

    # ---- 4. PHASE 3: size-test uploads -----------------------------------------------------
    if (-not $SkipSizeTest) {
        Write-Host "`n=== PHASE 3: upload size-test packages ===" -ForegroundColor Cyan
        $files = @(Get-ChildItem (Join-Path $PackageDir '*.xml') -ErrorAction SilentlyContinue | Sort-Object Length)
        if (-not $files.Count) {
            Write-Warning "No packages in '$PackageDir'. Generate with: scripts/Test-RulePackageUploadLimit.ps1 -WriteFilesTo $PackageDir -TargetKB 600,770,800,900,1000"
        } else {
            $results = foreach ($f in $files) {
                $kb = [int]($f.Length / 1KB)
                Write-Host ("Uploading {0,-22} ({1,5} KB UTF-16) ... " -f $f.Name, $kb) -NoNewline
                $ok = $false; $err = ''
                try {
                    $o = New-DlpSensitiveInformationTypeRulePackage -FileData ([System.IO.File]::ReadAllBytes($f.FullName)) -Confirm:$false -ErrorAction Stop
                    $ok = $true; Write-Host "ACCEPTED" -ForegroundColor Green
                    Start-Sleep 4
                    # Cleanup: .Identity may be blank over REST, so remove by the RulePack GUID parsed from the file.
                    $cleanupId = $o.Identity
                    if (-not $cleanupId) { $m = [regex]::Match([System.IO.File]::ReadAllText($f.FullName), '<RulePack id="([^"]+)"'); if ($m.Success) { $cleanupId = $m.Groups[1].Value } }
                    try { Remove-DlpSensitiveInformationTypeRulePackage -Identity $cleanupId -Confirm:$false -ErrorAction Stop } catch { Write-Warning "    cleanup failed for '$cleanupId': $($_.Exception.Message)" }
                } catch { $err = $_.Exception.Message; Write-Host "REJECTED" -ForegroundColor Red; Write-Host "    $err" -ForegroundColor DarkYellow }
                [pscustomobject]@{ File = $f.Name; KB_UTF16 = $kb; Result = $(if ($ok) { 'ACCEPTED' } else { 'REJECTED' }); Error = $err }
                Start-Sleep 1
            }
            Write-Host "`n=== SIZE TEST RESULTS ===" -ForegroundColor Cyan
            $results | Format-Table File, KB_UTF16, Result -AutoSize
            $acc = @($results | Where-Object Result -eq 'ACCEPTED')
            $rej = @($results | Where-Object Result -eq 'REJECTED')
            if ($acc.Count) { $m = $acc | Sort-Object KB_UTF16 | Select-Object -Last 1;  Write-Host "Largest ACCEPTED : $($m.KB_UTF16) KB UTF-16" -ForegroundColor Green }
            if ($rej.Count) { $m = $rej | Sort-Object KB_UTF16 | Select-Object -First 1; Write-Host "Smallest REJECTED: $($m.KB_UTF16) KB UTF-16 - $($m.Error)" -ForegroundColor Yellow }
        }
    }

    if ($CheckSit) {
        Start-Sleep 5   # let removals settle before the final check
        try { $s = Get-DlpSensitiveInformationType -Identity $CheckSit -ErrorAction Stop
              Write-Host ("FINAL: SIT '{0}' STILL EXISTS (Publisher='{1}')" -f $CheckSit, $s.Publisher) -ForegroundColor Magenta }
        catch { Write-Host "FINAL: SIT '$CheckSit' is GONE" -ForegroundColor Magenta }
    }

    Write-Host "`n=== DONE ===" -ForegroundColor Cyan
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    Stop-Transcript | Out-Null
    Write-Host "Full transcript: $logPath"
}
