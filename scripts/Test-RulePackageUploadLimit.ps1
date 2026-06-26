<#
.SYNOPSIS
  Empirically resolve the REAL Purview rule-package upload-size ceiling on a TEST tenant.

  MS Learn gives two CONFLICTING numbers for the uploaded (Unicode/UTF-16) rule-package file:
    * https://learn.microsoft.com/purview/sit-limits  -> "Maximum size of a rule package 150KB"
    * https://learn.microsoft.com/purview/sit-create-a-custom-sensitive-information-type-in-scc-powershell
        item 13 -> "Keep the uploaded file limited to a 770 kilobyte maximum"
  This script removes all CUSTOM rule packages, then uploads test packages at target UTF-16
  sizes (default 150 / 250 / 300 KB) so you can see exactly which sizes Purview accepts.

  All test content respects the documented per-element limits (keyword terms <=50 chars,
  <=2048 terms/list, <=50 entities/package, no regexes) so a rejection can only be about
  the package SIZE, not a bad pattern.

.NOTES
  Operator runs this (Claude can't auth). Use a TEST tenant.
    Connect-IPPSSession            # no -UPN/-Tenant pin; the browser picks the account
    pwsh -File scripts/Test-RulePackageUploadLimit.ps1
  Add -WipeCustom to delete existing custom packages first (you'll be asked to type WIPE).
  Add -KeepTestPackages to leave the accepted test packages deployed for portal inspection.
#>
[CmdletBinding()]
param(
    [int[]]$TargetKB = @(600, 770, 800),
    [switch]$WipeCustom,
    [switch]$KeepTestPackages,
    [int]$SettleSeconds = 4,
    # If set, just WRITE the package files (UTF-16LE+BOM) to this folder and exit -- no tenant
    # connection, no upload. Upload them yourself with the standard cmdlet (printed at the end).
    [string]$WriteFilesTo
)

# Realistic-looking keyword terms so the packages read like genuine large keyword lists.
$script:WORDS = @('confidential','restricted','classified','sensitive','internal','proprietary',
    'privileged','protected','official','cabinet','treasury','ministerial','briefing','submission')

$ErrorActionPreference = 'Stop'

# --- Encoding: Purview wants the file as UTF-16LE + BOM, declaration encoding="utf-16" -------
function ConvertTo-PurviewUtf16Bytes {
    param([Parameter(Mandatory)][string]$Content)
    $n = $Content.TrimStart([char]0xFEFF)
    if ($n -match '^\s*<\?xml\b[^?]*\?>') {
        $n = [regex]::Replace($n,
            '^\s*<\?xml\b([^?]*?)encoding\s*=\s*([''"])[^''"]+\2([^?]*?)\?>',
            '<?xml$1encoding="utf-16"$3?>',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $enc  = [System.Text.UnicodeEncoding]::new($false, $true)   # UTF-16LE + BOM
    $body = $enc.GetBytes($n); $bom = $enc.GetPreamble()
    $bytes = New-Object byte[] ($bom.Length + $body.Length)
    [Array]::Copy($bom, 0, $bytes, 0, $bom.Length)
    [Array]::Copy($body, 0, $bytes, $bom.Length, $body.Length)
    return ,$bytes
}

# Build a rule package of $TermCount keyword terms spread over the fewest entities (<=2000
# terms/entity, <=50 entities). Keyword terms only -> respects every documented per-element
# limit, so size is the only thing under test.
function New-KeywordPackage {
    param([int]$TermCount, [string]$PackName)
    $perEntity = 2000
    $entityCount = [Math]::Min(50, [Math]::Max(1, [int][Math]::Ceiling($TermCount / $perEntity)))
    $rulePackId = [guid]::NewGuid(); $publisherId = [guid]::NewGuid()
    $entities = [System.Text.StringBuilder]::new()
    $keywords = [System.Text.StringBuilder]::new()
    $strings  = [System.Text.StringBuilder]::new()
    $remaining = $TermCount
    for ($e = 0; $e -lt $entityCount; $e++) {
        $eid = [guid]::NewGuid()
        $thisTerms = [Math]::Min($perEntity, $remaining); $remaining -= $thisTerms
        [void]$entities.Append(@"
    <Entity id="$eid" patternsProximity="300" recommendedConfidence="85" relaxProximity="false">
      <Pattern confidenceLevel="85"><IdMatch idRef="Keyword_$e" /></Pattern>
    </Entity>
"@)
        [void]$keywords.Append("`n    <Keyword id=`"Keyword_$e`">`n      <Group matchStyle=`"word`">")
        for ($t = 0; $t -lt $thisTerms; $t++) {
            # realistic word + unique index, <=50 chars (e.g. "confidential000123")
            $term = ("{0}{1:D6}" -f $script:WORDS[$t % $script:WORDS.Count], ($e * 100000 + $t))
            [void]$keywords.Append("`n        <Term>$term</Term>")
        }
        [void]$keywords.Append("`n      </Group>`n    </Keyword>")
        [void]$strings.Append(@"
      <Resource idRef="$eid">
        <Name default="true" langcode="en-us">$PackName E$e</Name>
        <Description default="true" langcode="en-us">size benchmark</Description>
      </Resource>
"@)
    }
@"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="$rulePackId">
    <Version major="1" minor="0" build="0" revision="0"/>
    <Publisher id="$publisherId"/>
    <Details defaultLangCode="en-us">
      <LocalizedDetails langcode="en-us">
        <PublisherName>SizeTest</PublisherName>
        <Name>$PackName</Name>
        <Description>Throwaway package for upload-size benchmarking</Description>
      </LocalizedDetails>
    </Details>
  </RulePack>
  <Rules>
$($entities.ToString())$($keywords.ToString())
    <LocalizedStrings>
$($strings.ToString())    </LocalizedStrings>
  </Rules>
</RulePackage>
"@
}

# Build a package whose UTF-16 size lands within ~1.5 KB of $TargetBytes (measure + adjust).
function New-PackageOfSize {
    param([int]$TargetBytes, [string]$PackName)
    $terms = [int]($TargetBytes / 118)          # ~118 UTF-16 bytes per padded term
    for ($i = 0; $i -lt 4; $i++) {
        $xml = New-KeywordPackage -TermCount $terms -PackName $PackName
        $u16 = [System.Text.Encoding]::Unicode.GetByteCount($xml)
        if ([Math]::Abs($u16 - $TargetBytes) -le 1500) { break }
        $terms = [Math]::Max(1, [int]($terms * $TargetBytes / $u16))
    }
    [pscustomobject]@{ Xml = $xml; Terms = $terms }
}

# --- Mode A: just write the package files to disk (no tenant needed) ------------------------
if ($WriteFilesTo) {
    New-Item -ItemType Directory -Force -Path $WriteFilesTo | Out-Null
    Write-Host "Writing rule-package files (UTF-16LE + BOM, declaration utf-16) to $WriteFilesTo`n" -ForegroundColor Cyan
    foreach ($kb in ($TargetKB | Sort-Object)) {
        $pkg   = New-PackageOfSize -TargetBytes ($kb * 1024) -PackName "SizeTest-${kb}kb"
        $bytes = ConvertTo-PurviewUtf16Bytes -Content $pkg.Xml
        $path  = Join-Path $WriteFilesTo "sizetest-${kb}kb.xml"
        [System.IO.File]::WriteAllBytes($path, $bytes)
        Write-Host ("  {0,-22}  {1,4} KB on disk (UTF-16)  {2,4} KB UTF-8  {3} terms" -f `
            (Split-Path $path -Leaf), [int]($bytes.Length/1KB), [int]([System.Text.Encoding]::UTF8.GetByteCount($pkg.Xml)/1KB), $pkg.Terms)
    }
    Write-Host "`nUpload one (the MS-documented way -- the file is already Unicode):" -ForegroundColor Cyan
    Write-Host '  Connect-IPPSSession' -ForegroundColor Gray
    Write-Host ('  New-DlpSensitiveInformationTypeRulePackage -FileData ([IO.File]::ReadAllBytes("{0}\sizetest-770kb.xml")) -Confirm:$false' -f $WriteFilesTo) -ForegroundColor Gray
    Write-Host '  Get-DlpSensitiveInformationTypeRulePackage | Format-Table Name,Identity' -ForegroundColor Gray
    Write-Host '  # remove after: Remove-DlpSensitiveInformationTypeRulePackage -Identity "SizeTest-770kb" -Confirm:$false' -ForegroundColor Gray
    return
}

# --- Preconditions -------------------------------------------------------------------------
try { Get-ConnectionInformation -ErrorAction Stop | Out-Null }
catch { Write-Error "Not connected to Security & Compliance PowerShell. Run Connect-IPPSSession first."; exit 1 }

Write-Host "MS Learn rule-package size limits (conflicting): 150 KB (sit-limits) vs 770 KB (PowerShell upload guidance)." -ForegroundColor Cyan
Write-Host "Uploaded file is Unicode/UTF-16. This test settles which actually binds.`n" -ForegroundColor DarkGray

# --- Optional wipe of existing CUSTOM rule packages ----------------------------------------
if ($WipeCustom) {
    $all = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)
    # The built-in container is "Microsoft Rule Package"; never touch Microsoft-published packs.
    $custom = $all | Where-Object { $_.Name -notmatch 'Microsoft' }
    Write-Host "Custom rule packages found: $($custom.Count)" -ForegroundColor Yellow
    $custom | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor DarkYellow }
    if ($custom.Count) {
        $confirm = Read-Host "Type WIPE to delete these $($custom.Count) custom rule package(s)"
        if ($confirm -ceq 'WIPE') {
            foreach ($p in $custom) {
                try {
                    Remove-DlpSensitiveInformationTypeRulePackage -Identity $p.Identity -Confirm:$false -ErrorAction Stop
                    Write-Host "  removed $($p.Name)" -ForegroundColor Green
                } catch {
                    Write-Warning "  could not remove $($p.Name): $($_.Exception.Message) (a live DLP rule may reference it)"
                }
            }
            Write-Host "Waiting 20s for removal to propagate..." -ForegroundColor DarkGray; Start-Sleep 20
        } else { Write-Host "Wipe skipped (you didn't type WIPE)." -ForegroundColor Yellow }
    }
}

# --- Upload test packages at each target size ----------------------------------------------
$created = New-Object System.Collections.Generic.List[object]
$results = foreach ($kb in ($TargetKB | Sort-Object)) {
    $packName = "ZZSIZETEST-$([guid]::NewGuid().ToString('N').Substring(0,8))-${kb}kb"
    $pkg  = New-PackageOfSize -TargetBytes ($kb * 1024) -PackName $packName
    $u16  = [int]([System.Text.Encoding]::Unicode.GetByteCount($pkg.Xml) / 1KB)
    $u8   = [int]([System.Text.Encoding]::UTF8.GetByteCount($pkg.Xml) / 1KB)
    $bytes = ConvertTo-PurviewUtf16Bytes -Content $pkg.Xml
    Write-Host ("Uploading target {0} KB -> actual {1} KB UTF-16 / {2} KB UTF-8 ({3} terms) ... " -f $kb, $u16, $u8, $pkg.Terms) -NoNewline
    $ok = $false; $err = ""; $id = $null
    try {
        $obj = New-DlpSensitiveInformationTypeRulePackage -FileData $bytes -Confirm:$false -ErrorAction Stop
        $ok = $true; $id = if ($obj -and $obj.Identity) { $obj.Identity } else { $packName }
        $created.Add([pscustomobject]@{ Id = $id; Name = $packName })
        Write-Host "ACCEPTED" -ForegroundColor Green
        Start-Sleep -Seconds $SettleSeconds
    } catch {
        $err = $_.Exception.Message
        Write-Host "REJECTED" -ForegroundColor Red
        Write-Host "    $err" -ForegroundColor DarkYellow
    }
    [pscustomobject]@{ TargetKB = $kb; KB_UTF16 = $u16; KB_UTF8 = $u8; Result = (if ($ok) { 'ACCEPTED' } else { 'REJECTED' }); Error = $err }
}

# --- Cleanup (unless -KeepTestPackages) ----------------------------------------------------
if (-not $KeepTestPackages -and $created.Count) {
    Write-Host "`nRemoving test packages..." -ForegroundColor DarkGray
    foreach ($c in $created) {
        try { Remove-DlpSensitiveInformationTypeRulePackage -Identity $c.Id -Confirm:$false -ErrorAction Stop; Write-Host "  removed $($c.Name)" -ForegroundColor DarkGray }
        catch { Write-Warning "  could not remove $($c.Name): $($_.Exception.Message)" }
    }
}

Write-Host "`n==================== RESULTS ====================" -ForegroundColor Cyan
$results | Format-Table TargetKB, KB_UTF16, KB_UTF8, Result -AutoSize
$acc = @($results | Where-Object Result -eq 'ACCEPTED')
$rej = @($results | Where-Object Result -eq 'REJECTED')
if ($acc.Count) { $m = $acc | Sort-Object KB_UTF16 | Select-Object -Last 1;  Write-Host ("Largest ACCEPTED : {0} KB UTF-16 ({1} KB UTF-8)" -f $m.KB_UTF16, $m.KB_UTF8) -ForegroundColor Green }
if ($rej.Count) { $m = $rej | Sort-Object KB_UTF16 | Select-Object -First 1; Write-Host ("Smallest REJECTED: {0} KB UTF-16 ({1} KB UTF-8) - {2}" -f $m.KB_UTF16, $m.KB_UTF8, $m.Error) -ForegroundColor Yellow }
