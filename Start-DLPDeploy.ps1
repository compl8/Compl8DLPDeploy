#==============================================================================
# Start-DLPDeploy.ps1
# Interactive menu launcher for the DLP Deployment Toolkit.
#
# Usage:
#   .\Start-DLPDeploy.ps1               # Interactive menu
#   .\Start-DLPDeploy.ps1 -UPN admin@tenant.onmicrosoft.com
#==============================================================================

param(
    [string]$UPN
)

$ProjectRoot = $PSScriptRoot
$ScriptsDir  = Join-Path $ProjectRoot "scripts"
$ConfigPath  = Join-Path $ProjectRoot "config"

# Import shared module for connection helpers
Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

# Load config for naming prefix
$_Defaults     = Get-ModuleDefaults
$_SettingsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
$_Config       = Merge-GlobalConfig -Defaults $_Defaults -GlobalJson $_SettingsJson
$_Prefix       = $_Config.namingPrefix

#region Box Drawing
function Get-TerminalSize {
    try {
        @{
            Width  = [Math]::Max(40, [Console]::WindowWidth - 1)
            Height = [Math]::Max(10, [Console]::WindowHeight)
        }
    } catch {
        @{ Width = 119; Height = 30 }
    }
}

function Get-BoxInnerWidth {
    param([int]$MaxWidth = 58)
    $termWidth = (Get-TerminalSize).Width
    return [Math]::Min($MaxWidth, $termWidth - 6)
}

function Write-BoxTop {
    param([int]$InnerWidth, [string]$Color = 'Cyan')
    $h  = [char]0x2500  # ─
    $tl = [char]0x250C  # ┌
    $tr = [char]0x2510  # ┐
    Write-Host ("  {0}{1}{2}" -f $tl, ([string]$h * $InnerWidth), $tr) -ForegroundColor $Color
}

function Write-BoxBottom {
    param([int]$InnerWidth, [string]$Color = 'Cyan')
    $h  = [char]0x2500
    $bl = [char]0x2514  # └
    $br = [char]0x2518  # ┘
    Write-Host ("  {0}{1}{2}" -f $bl, ([string]$h * $InnerWidth), $br) -ForegroundColor $Color
}

function Write-BoxLine {
    param([string]$Text = '', [int]$InnerWidth, [string]$Color = 'Cyan')
    $v = [char]0x2502  # │
    $contentWidth = $InnerWidth - 2
    if ($Text.Length -gt $contentWidth) {
        $Text = $Text.Substring(0, $contentWidth - 1) + [char]0x2026
    }
    $padded = $Text.PadRight($contentWidth)
    Write-Host ("  {0} {1} {2}" -f $v, $padded, $v) -ForegroundColor $Color
}

function Write-BoxSeparator {
    param([int]$InnerWidth, [string]$Color = 'Cyan')
    $h  = [char]0x2500
    $ml = [char]0x251C  # ├
    $mr = [char]0x2524  # ┤
    Write-Host ("  {0}{1}{2}" -f $ml, ([string]$h * $InnerWidth), $mr) -ForegroundColor $Color
}
#endregion

#region Helpers
function Show-Menu {
    param([bool]$Connected)

    $w = Get-BoxInnerWidth -MaxWidth 78

    $status = if ($Connected) { "Connected" } else { "Not Connected" }
    $colour = if ($Connected) { "Green" } else { "Yellow" }

    # Two-column layout helper
    $col = [Math]::Floor(($w - 4) / 2)  # width per column with gutter
    function Fmt-Row { param([string]$L, [string]$R)
        ($L.PadRight($col) + "  " + $R).PadRight($w - 2)
    }

    Write-Host ""
    Write-BoxTop -InnerWidth $w -Color Cyan
    Write-BoxLine -Text "     $_Prefix DLP Deployment Toolkit" -InnerWidth $w -Color Cyan
    Write-BoxLine -Text "" -InnerWidth $w -Color Cyan
    Write-BoxLine -Text ("     Session: {0}" -f $status) -InnerWidth $w -Color $colour
    Write-BoxSeparator -InnerWidth $w -Color Cyan
    Write-BoxLine -Text (Fmt-Row "DEPLOY" "MANAGE") -InnerWidth $w -Color DarkCyan
    Write-BoxLine -Text (Fmt-Row " [1] Deploy Labels" " [4] Batch Operations (CSV)") -InnerWidth $w -Color Cyan
    Write-BoxLine -Text (Fmt-Row " [2] Deploy Classifiers (SITs)" " [5] Test Classifiers") -InnerWidth $w -Color Cyan
    Write-BoxLine -Text (Fmt-Row " [3] Deploy DLP Rules" " [6] List Deployed SIT Packages") -InnerWidth $w -Color Cyan
    Write-BoxLine -Text (Fmt-Row "" " [7] Estimate SIT Capacity") -InnerWidth $w -Color Cyan
    Write-BoxSeparator -InnerWidth $w -Color Cyan
    Write-BoxLine -Text (Fmt-Row "CLEANUP" "UTILITY") -InnerWidth $w -Color DarkCyan
    Write-BoxLine -Text (Fmt-Row " [8]  Remove DLP Rules" " [11] Validate SIT XML (offline)") -InnerWidth $w -Color Cyan
    Write-BoxLine -Text (Fmt-Row " [9]  Remove Labels" " [C]  Connect / Reconnect") -InnerWidth $w -Color Cyan
    Write-BoxLine -Text (Fmt-Row " [10] Remove SIT Packages" "") -InnerWidth $w -Color Cyan
    Write-BoxSeparator -InnerWidth $w -Color Cyan
    Write-BoxLine -Text " [Q]  Quit" -InnerWidth $w -Color DarkGray
    Write-BoxBottom -InnerWidth $w -Color Cyan
    Write-Host ""
}

function Read-Choice {
    param([string]$Prompt = "  Select")
    Write-Host "$Prompt`: " -NoNewline -ForegroundColor White
    return (Read-Host).Trim()
}

function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $false)
    $hint = if ($Default) { "(Y/n)" } else { "(y/N)" }
    Write-Host "  $Prompt $hint`: " -NoNewline
    $answer = (Read-Host).Trim().ToLower()
    if ($answer -eq "") { return $Default }
    return ($answer -eq "y" -or $answer -eq "yes")
}

function Pause-AfterRun {
    Write-Host ""
    Write-Host "  Press Enter to return to menu..." -ForegroundColor DarkGray -NoNewline
    Read-Host | Out-Null
}

function Test-Connected {
    try {
        Get-DlpCompliancePolicy -ErrorAction Stop | Select-Object -First 1 | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Require-Connection {
    param([ref]$Connected)
    if (-not $Connected.Value) {
        Write-Host ""
        Write-Host "  Not connected. Connecting first..." -ForegroundColor Yellow
        $result = Connect-DLPSession -UPN $script:UPN
        if ($result) {
            $Connected.Value = $true
        } else {
            Write-Host "  Connection failed. Aborting." -ForegroundColor Red
            return $false
        }
    }
    return $true
}
#endregion

#region Package XML Helpers
function Get-PackageEntities {
    <# Returns @( @{ Id; Name } ) for a deployed package's SIT entities #>
    param([object]$DeployedPackage)
    $results = @()
    if (-not $DeployedPackage.SerializedClassificationRuleCollection) { return $results }
    try {
        $bytes = $DeployedPackage.SerializedClassificationRuleCollection
        $xmlContent = [System.Text.Encoding]::Unicode.GetString($bytes)
        $xml = [xml]$xmlContent
        $rules = $xml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq "Rules" }
        if ($rules) {
            $nameMap = @{}
            $localizedStrings = $rules.ChildNodes | Where-Object { $_.LocalName -eq "LocalizedStrings" }
            if ($localizedStrings) {
                foreach ($resource in @($localizedStrings.ChildNodes)) {
                    if ($resource.LocalName -eq "Resource") {
                        $nameNode = $resource.ChildNodes | Where-Object { $_.LocalName -eq "Name" } | Select-Object -First 1
                        if ($nameNode) { $nameMap[$resource.idRef] = $nameNode.InnerText }
                    }
                }
            }
            foreach ($e in @($rules.ChildNodes | Where-Object { $_.LocalName -eq "Entity" })) {
                $results += @{
                    Id   = $e.id.ToLower()
                    Name = if ($nameMap.ContainsKey($e.id)) { $nameMap[$e.id] } else { $e.id }
                }
            }
        }
    } catch { }
    return $results
}

function Show-PackageSITs {
    <# Prompts for a package number and displays its SIT entities #>
    param([array]$PackageInfo)
    Write-Host "  Enter package number to inspect: " -NoNewline
    $num = (Read-Host).Trim()
    if ($num -match '^\d+$' -and [int]$num -ge 1 -and [int]$num -le $PackageInfo.Count) {
        $info = $PackageInfo[[int]$num - 1]
        $entities = Get-PackageEntities -DeployedPackage $info.Package
        Write-Host ""
        Write-Host "  $($info.DisplayName) — $($entities.Count) SIT(s):" -ForegroundColor Cyan
        $idx = 1
        foreach ($e in ($entities | Sort-Object { $_.Name })) {
            Write-Host "    $idx. $($e.Name)" -ForegroundColor Gray
            $idx++
        }
        Write-Host ""
    } else {
        Write-Host "  Invalid number." -ForegroundColor Red
    }
}
#endregion

#region Menu Actions

function Invoke-Connect {
    param([ref]$Connected)
    Write-Host ""
    if ($Connected.Value) {
        Write-Host "  Already connected." -ForegroundColor Green
        if (-not (Read-YesNo "Reconnect?")) { return }
    }
    $result = Connect-DLPSession -UPN $script:UPN
    $Connected.Value = [bool]$result
    if ($result) {
        Write-Host "  Connected successfully." -ForegroundColor Green
    }
}

function Invoke-DeployLabels {
    param([ref]$Connected)
    if (-not (Require-Connection $Connected)) { return }

    Write-Host ""
    Write-Host "  --- Deploy Labels ---" -ForegroundColor Cyan
    $dryRun   = Read-YesNo "Dry run (WhatIf)?" -Default $true
    $publish  = Read-YesNo "Publish labels after creation?"
    $noMark   = Read-YesNo "Skip visual markings?"

    $params = @()
    if ($dryRun)  { $params += "-WhatIf" }
    if ($noMark)  { $params += "-NoMarking" }
    if ($publish) {
        Write-Host '  Publish to (e.g. "All" or "user@domain.com"): ' -NoNewline
        $target = (Read-Host).Trim()
        if ($target) { $params += "-PublishTo `"$target`"" }
    } else {
        $params += "-SkipPublish"
    }

    $cmd = "& `"$(Join-Path $ScriptsDir 'Deploy-Labels.ps1')`" $($params -join ' ')"
    Write-Host ""
    Write-Host "  > $cmd" -ForegroundColor DarkGray
    Write-Host ""
    Invoke-Expression $cmd
}

function Invoke-DeployClassifiers {
    param([ref]$Connected)
    if (-not (Require-Connection $Connected)) { return }

    Write-Host ""
    Write-Host "  --- Deploy Classifiers ---" -ForegroundColor Cyan

    Write-Host "  Tier [narrow/wide/full] (Enter = all tiers): " -NoNewline
    $tier = (Read-Host).Trim().ToLower()

    $dryRun = Read-YesNo "Dry run (WhatIf)?" -Default $true
    $skip   = Read-YesNo "Skip pre-flight checks?"

    $params = @("-Action Upload")
    if ($tier -in @("narrow", "wide", "full")) { $params += "-Tier $tier" }
    if ($dryRun)  { $params += "-WhatIf" }
    if ($skip)    { $params += "-SkipPreFlight" }

    $cmd = "& `"$(Join-Path $ScriptsDir 'Deploy-Classifiers.ps1')`" $($params -join ' ')"
    Write-Host ""
    Write-Host "  > $cmd" -ForegroundColor DarkGray
    Write-Host ""
    Invoke-Expression $cmd
}

function Invoke-DeployDLPRules {
    param([ref]$Connected)
    if (-not (Require-Connection $Connected)) { return }

    Write-Host ""
    Write-Host "  --- Deploy DLP Rules ---" -ForegroundColor Cyan
    $dryRun    = Read-YesNo "Dry run (WhatIf)?" -Default $true
    $skipVal   = Read-YesNo "Skip SIT validation?"
    $skipVerif = Read-YesNo "Skip post-deploy verification?"

    $params = @()
    if ($dryRun)    { $params += "-WhatIf" }
    if ($skipVal)   { $params += "-SkipValidation" }
    if ($skipVerif) { $params += "-SkipVerification" }

    $cmd = "& `"$(Join-Path $ScriptsDir 'Deploy-DLPRules.ps1')`" $($params -join ' ')"
    Write-Host ""
    Write-Host "  > $cmd" -ForegroundColor DarkGray
    Write-Host ""
    Invoke-Expression $cmd
}

function Invoke-ChangePack {
    param([ref]$Connected)

    Write-Host ""
    Write-Host "  --- Batch Operations ---" -ForegroundColor Cyan
    Write-Host "    1. Generate change pack (diff tenant vs config)" -ForegroundColor Cyan
    Write-Host "    2. Apply change pack (from CSV)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Select: " -NoNewline
    $subChoice = (Read-Host).Trim()

    switch ($subChoice) {
        "1" {
            # Generate change pack
            if (-not (Require-Connection $Connected)) { return }

            Write-Host ""
            Write-Host "  --- Generate Change Pack ---" -ForegroundColor Cyan
            Write-Host "  Components [All/Labels/Classifiers/Rules] (Enter = All): " -NoNewline
            $compInput = (Read-Host).Trim()
            $compParam = if ($compInput) { $compInput } else { "All" }

            $dryRun = Read-YesNo "Dry run (show diff only, don't write CSV)?" -Default $false

            $params = @("-Components $compParam")
            if ($dryRun) { $params += "-WhatIf" }

            $cmd = "& `"$(Join-Path $ScriptsDir 'Generate-ChangePack.ps1')`" $($params -join ' ')"
            Write-Host ""
            Write-Host "  > $cmd" -ForegroundColor DarkGray
            Write-Host ""
            Invoke-Expression $cmd
        }

        "2" {
            # Apply change pack
            if (-not (Require-Connection $Connected)) { return }

            $cpDir = Join-Path $ProjectRoot "changepacks"
            $csvFiles = Get-ChildItem -Path $cpDir -Filter "*.csv" -ErrorAction SilentlyContinue
            if ($csvFiles.Count -eq 0) {
                Write-Host "  No CSV files found in changepacks/." -ForegroundColor Yellow
                return
            }

            Write-Host "  Available change packs:" -ForegroundColor Gray
            $i = 1
            foreach ($f in $csvFiles) {
                Write-Host "    $i. $($f.Name)" -ForegroundColor Gray
                $i++
            }
            Write-Host "  Select number or enter path: " -NoNewline
            $pick = (Read-Host).Trim()

            $csvPath = $null
            if ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $csvFiles.Count) {
                $csvPath = $csvFiles[[int]$pick - 1].FullName
            } elseif (Test-Path $pick) {
                $csvPath = (Resolve-Path $pick).Path
            } else {
                Write-Host "  Invalid selection." -ForegroundColor Red
                return
            }

            $dryRun = Read-YesNo "Dry run (WhatIf)?" -Default $true

            $params = @("-CsvPath `"$csvPath`"")
            if ($dryRun) { $params += "-WhatIf" }

            $cmd = "& `"$(Join-Path $ScriptsDir 'Invoke-ChangePack.ps1')`" $($params -join ' ')"
            Write-Host ""
            Write-Host "  > $cmd" -ForegroundColor DarkGray
            Write-Host ""
            Invoke-Expression $cmd
        }

        default {
            Write-Host "  Invalid selection." -ForegroundColor Red
        }
    }
}

function Invoke-TestClassifiers {
    param([ref]$Connected)
    if (-not (Require-Connection $Connected)) { return }

    Write-Host ""
    Write-Host "  --- Test Classifiers ---" -ForegroundColor Cyan
    Write-Host "  Filter to label code (Enter = all): " -NoNewline
    $label = (Read-Host).Trim()
    $showAll = Read-YesNo "Show all (verbose)?"

    $params = @()
    if ($label)   { $params += "-Label `"$label`"" }
    if ($showAll) { $params += "-ShowAll" }

    $cmd = "& `"$(Join-Path $ScriptsDir 'Test-Classifiers.ps1')`" $($params -join ' ')"
    Write-Host ""
    Write-Host "  > $cmd" -ForegroundColor DarkGray
    Write-Host ""
    Invoke-Expression $cmd
}

function Invoke-ListPackages {
    param([ref]$Connected)
    if (-not (Require-Connection $Connected)) { return }

    Write-Host ""
    Write-Host "  --- Deployed SIT Packages ---" -ForegroundColor Cyan
    Write-Host "  Fetching deployed packages..." -ForegroundColor Gray

    $deployed = @()
    try {
        $deployed = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)
    } catch {
        Write-Host "  Failed to retrieve packages: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Filter out Microsoft built-in packages
    $deployed = @($deployed | Where-Object { $_.Identity })

    if ($deployed.Count -eq 0) {
        Write-Host "  No custom SIT rule packages found in tenant." -ForegroundColor Yellow
        return
    }

    # Parse display info
    $packageInfo = @()
    foreach ($d in $deployed) {
        $displayName = $d.Identity
        $entityCount = 0
        if ($d.SerializedClassificationRuleCollection) {
            try {
                $bytes = $d.SerializedClassificationRuleCollection
                $xmlContent = [System.Text.Encoding]::Unicode.GetString($bytes)
                $xml = [xml]$xmlContent
                $localized = $xml.RulePackage.RulePack.Details.LocalizedDetails
                if ($localized -and $localized.Name) { $displayName = $localized.Name }
                $rules = $xml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq "Rules" }
                if ($rules) {
                    $entityCount = @($rules.ChildNodes | Where-Object { $_.LocalName -eq "Entity" }).Count
                }
            } catch { }
        }
        $modifiedStr = if ($d.WhenChangedUTC) { "  modified $($d.WhenChangedUTC)" } else { "" }
        $packageInfo += @{ Package = $d; DisplayName = $displayName; EntityCount = $entityCount; ModifiedStr = $modifiedStr }
    }

    # Interactive loop
    while ($true) {
        Write-Host ""
        Write-Host "  $($packageInfo.Count) custom rule package(s):" -ForegroundColor Gray
        $i = 1
        foreach ($info in $packageInfo) {
            Write-Host "    $i. $($info.DisplayName)  ($($info.EntityCount) SITs)$($info.ModifiedStr)" -ForegroundColor White
            $i++
        }
        Write-Host ""
        Write-Host "    S. See classifiers in a package" -ForegroundColor DarkGray
        Write-Host "    F. Find a classifier by name" -ForegroundColor DarkGray
        Write-Host "    Q. Back to menu" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Select (S, F, or Q): " -NoNewline
        $pick = (Read-Host).Trim().ToUpper()

        if (-not $pick -or $pick -eq "Q") { return }

        if ($pick -eq "S") {
            Show-PackageSITs -PackageInfo $packageInfo
            continue
        }

        if ($pick -eq "F") {
            Write-Host "  Search term: " -NoNewline
            $search = (Read-Host).Trim()
            if (-not $search) { continue }

            # Search all packages for matching SIT names
            $matches = @()
            foreach ($info in $packageInfo) {
                $entities = Get-PackageEntities -DeployedPackage $info.Package
                foreach ($e in $entities) {
                    if ($e.Name -like "*$search*") {
                        $matches += @{ SITName = $e.Name; SITId = $e.Id; PackageName = $info.DisplayName }
                    }
                }
            }

            if ($matches.Count -eq 0) {
                Write-Host "  No classifiers matching '$search'." -ForegroundColor Yellow
            } else {
                Write-Host ""
                Write-Host "  Found $($matches.Count) classifier(s) matching '$search':" -ForegroundColor Cyan
                $idx = 1
                foreach ($m in ($matches | Sort-Object { $_.SITName })) {
                    Write-Host "    $idx. $($m.SITName)" -ForegroundColor White
                    Write-Host "       Package: $($m.PackageName)" -ForegroundColor DarkGray
                    $idx++
                }
            }
            continue
        }

        Write-Host "  Invalid choice." -ForegroundColor Red
    }
}

function Invoke-EstimateCapacity {
    param([ref]$Connected)
    if (-not (Require-Connection $Connected)) { return }

    $cmd = "& `"$(Join-Path $ScriptsDir 'Deploy-Classifiers.ps1')`" -Action Estimate"
    Write-Host ""
    Write-Host "  > $cmd" -ForegroundColor DarkGray
    Write-Host ""
    Invoke-Expression $cmd
}

function Invoke-CleanupDLPRules {
    param([ref]$Connected)
    if (-not (Require-Connection $Connected)) { return }

    Write-Host ""
    Write-Host "  --- Remove DLP Rules ---" -ForegroundColor Cyan
    Write-Host "  Fetching DLP policies and rules..." -ForegroundColor Gray

    # Load config for deployment identification
    $prefix = $_Config.namingPrefix
    $suffix = $_Config.namingSuffix
    $deployPattern = "P0*-*-$prefix-$suffix"

    # Fetch all DLP policies
    $allPolicies = @()
    try { $allPolicies = @(Get-DlpCompliancePolicy -ErrorAction Stop) } catch {
        Write-Host "  Failed to retrieve policies: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($allPolicies.Count -eq 0) {
        Write-Host "  No DLP policies found in tenant." -ForegroundColor Yellow
        return
    }

    # Fetch rules for each policy
    $policyInfo = @()
    foreach ($pol in $allPolicies) {
        $rules = @()
        try { $rules = @(Get-DlpComplianceRule -Policy $pol.Name -ErrorAction Stop) } catch { }
        $isManaged = $pol.Name -like $deployPattern
        $policyInfo += @{ Policy = $pol; Rules = $rules; IsManaged = $isManaged }
    }

    # Interactive loop
    $pick = $null
    while ($true) {
        Write-Host ""
        Write-Host "  DLP Policies ($($policyInfo.Count)):" -ForegroundColor Cyan
        $i = 1
        foreach ($info in $policyInfo) {
            $ruleCount = $info.Rules.Count
            $mode = if ($info.Policy.Mode) { $info.Policy.Mode } else { "unknown" }
            $tag = if ($info.IsManaged) { " [$_Prefix]" } else { "" }
            $colour = if ($info.IsManaged) { "White" } else { "Gray" }
            Write-Host "    $i. $($info.Policy.Name)  ($ruleCount rules, mode: $mode)$tag" -ForegroundColor $colour
            $i++
        }
        Write-Host "    S. See rules in a policy" -ForegroundColor DarkGray
        Write-Host "    A. All policies + rules" -ForegroundColor DarkGray
        Write-Host "    Q. Back to menu" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Select policy to remove (number, comma-separated, S, A, or Q): " -NoNewline
        $pick = (Read-Host).Trim()

        if (-not $pick -or $pick.ToUpper() -eq "Q") {
            Write-Host "  Returning to menu." -ForegroundColor Yellow
            return
        }

        if ($pick.ToUpper() -eq "S") {
            Write-Host "  Enter policy number to inspect: " -NoNewline
            $num = (Read-Host).Trim()
            if ($num -match '^\d+$' -and [int]$num -ge 1 -and [int]$num -le $policyInfo.Count) {
                $info = $policyInfo[[int]$num - 1]
                Write-Host ""
                Write-Host "  $($info.Policy.Name) — $($info.Rules.Count) rule(s):" -ForegroundColor Cyan
                foreach ($r in ($info.Rules | Sort-Object Name)) {
                    $state = if ($r.Disabled) { " [DISABLED]" } else { "" }
                    Write-Host "    - $($r.Name)$state" -ForegroundColor Gray
                    if ($r.Comment) { Write-Host "      $($r.Comment)" -ForegroundColor DarkGray }
                }
                Write-Host ""
            } else {
                Write-Host "  Invalid number." -ForegroundColor Red
            }
            continue
        }
        break
    }

    # Resolve selection
    $selectedPolicies = @()
    if ($pick.ToUpper() -eq "A") {
        $selectedPolicies = $policyInfo
    } else {
        foreach ($token in ($pick -split ',')) {
            $token = $token.Trim()
            if ($token -match '^\d+$') {
                $idx = [int]$token
                if ($idx -ge 1 -and $idx -le $policyInfo.Count) {
                    $selectedPolicies += $policyInfo[$idx - 1]
                } else {
                    Write-Host "  Invalid number: $token (1-$($policyInfo.Count))" -ForegroundColor Red
                    return
                }
            } else {
                Write-Host "  Invalid input: '$token'" -ForegroundColor Red
                return
            }
        }
    }

    if ($selectedPolicies.Count -eq 0) {
        Write-Host "  No policies selected." -ForegroundColor Yellow
        return
    }

    # Confirm
    $totalRules = ($selectedPolicies | ForEach-Object { $_.Rules.Count } | Measure-Object -Sum).Sum
    Write-Host ""
    Write-Host "  Will remove $($selectedPolicies.Count) policy/policies and $totalRules rule(s)." -ForegroundColor Red
    if (-not (Read-YesNo "Proceed with removal?")) {
        Write-Host "  Aborted." -ForegroundColor Yellow
        return
    }

    $dryRun = Read-YesNo "Dry run (WhatIf)?" -Default $true
    $delay = $_Config.interCallDelaySec
    $index = 0

    foreach ($info in $selectedPolicies) {
        Write-Host ""
        Write-Host "  Policy: $($info.Policy.Name)" -ForegroundColor Cyan

        # Remove rules first
        foreach ($rule in $info.Rules) {
            if ($index -gt 0 -and -not $dryRun) { Start-Sleep -Seconds $delay }
            $index++
            if ($dryRun) {
                Write-Host "    WhatIf: Would remove rule $($rule.Name)" -ForegroundColor Yellow
            } else {
                try {
                    Remove-DlpComplianceRule -Identity $rule.Name -Confirm:$false -ErrorAction Stop
                    Write-Host "    Removed rule: $($rule.Name)" -ForegroundColor Green
                } catch {
                    Write-Host "    Failed to remove rule $($rule.Name): $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }

        # Remove policy
        if ($index -gt 0 -and -not $dryRun) { Start-Sleep -Seconds $delay }
        $index++
        if ($dryRun) {
            Write-Host "    WhatIf: Would remove policy $($info.Policy.Name)" -ForegroundColor Yellow
        } else {
            try {
                Remove-DlpCompliancePolicy -Identity $info.Policy.Name -Confirm:$false -ErrorAction Stop
                Write-Host "    Removed policy: $($info.Policy.Name)" -ForegroundColor Green
            } catch {
                Write-Host "    Failed to remove policy $($info.Policy.Name): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    Write-Host ""
    Write-Host "  Done." -ForegroundColor Green
}

function Invoke-CleanupLabels {
    param([ref]$Connected)
    if (-not (Require-Connection $Connected)) { return }

    Write-Host ""
    Write-Host "  --- Remove Sensitivity Labels ---" -ForegroundColor Cyan
    Write-Host "  Fetching labels from tenant..." -ForegroundColor Gray

    # Load labels.json config for matching and customisation checks
    $configPath = Join-Path $ProjectRoot "config"
    $labelsJsonPath = Join-Path $configPath "labels.json"
    $labelsJson = $null
    if (Test-Path $labelsJsonPath) {
        $labelsJson = Get-Content -Path $labelsJsonPath -Raw | ConvertFrom-Json
    }

    # Build lookup by label name (may be empty if labels.json missing)
    $configLookup = @{}
    if ($labelsJson) {
        foreach ($lbl in $labelsJson) {
            $configLookup[$lbl.name] = $lbl
        }
    }

    # Fetch all labels from tenant
    $allLabels = @()
    try { $allLabels = @(Get-Label -ErrorAction Stop) } catch {
        Write-Host "  Failed to retrieve labels: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($allLabels.Count -eq 0) {
        Write-Host "  No labels found in tenant." -ForegroundColor Yellow
        return
    }

    # Build display info with config matching and customisation check
    $labelInfo = @()
    foreach ($lbl in ($allLabels | Sort-Object Priority)) {
        $isManaged = $configLookup.ContainsKey($lbl.Name)
        $cfg = if ($isManaged) { $configLookup[$lbl.Name] } else { $null }
        $diffs = @()
        if ($cfg) {
            if ($lbl.DisplayName -ne $cfg.displayName) { $diffs += "displayName" }
            if ($lbl.Tooltip -and $cfg.tooltip -and $lbl.Tooltip -ne $cfg.tooltip) { $diffs += "tooltip" }
            if ($cfg.headerText -and $lbl.ContentMarkingHeaderText -and $lbl.ContentMarkingHeaderText -ne $cfg.headerText) { $diffs += "headerText" }
            if ($cfg.footerText -and $lbl.ContentMarkingFooterText -and $lbl.ContentMarkingFooterText -ne $cfg.footerText) { $diffs += "footerText" }
        }
        $isCustomised = $isManaged -and $diffs.Count -gt 0
        $typeStr = if ($cfg -and $cfg.isGroup) { "group" } elseif ($lbl.ParentId) { "sublabel" } else { "label" }
        $parentGroup = if ($cfg) { $cfg.parentGroup } else { $null }
        $labelInfo += @{
            Label        = $lbl
            Config       = $cfg
            DisplayName  = $lbl.DisplayName
            TypeStr      = $typeStr
            ParentGroup  = $parentGroup
            IsManaged    = $isManaged
            IsCustomised = $isCustomised
            Diffs        = $diffs
        }
    }

    # Interactive loop
    $pick = $null
    while ($true) {
        Write-Host ""
        Write-Host "  Sensitivity Labels ($($labelInfo.Count)):" -ForegroundColor Cyan
        $i = 1
        foreach ($info in $labelInfo) {
            $tag = ""
            if ($info.IsManaged -and $info.IsCustomised) { $tag = " [$_Prefix] [CUSTOMISED]" }
            elseif ($info.IsManaged) { $tag = " [$_Prefix]" }
            $indent = if ($info.ParentGroup -or $info.Label.ParentId) { "     " } else { "   " }
            $colour = if ($info.IsCustomised) { "Yellow" } elseif ($info.IsManaged) { "White" } else { "Gray" }
            Write-Host "  ${indent}$i. $($info.DisplayName)  ($($info.TypeStr))$tag" -ForegroundColor $colour
            $i++
        }
        Write-Host "    S. See label details" -ForegroundColor DarkGray
        Write-Host "    A. All labels" -ForegroundColor DarkGray
        Write-Host "    Q. Back to menu" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Select label(s) to remove (number, comma-separated, S, A, or Q): " -NoNewline
        $pick = (Read-Host).Trim()

        if (-not $pick -or $pick.ToUpper() -eq "Q") {
            Write-Host "  Returning to menu." -ForegroundColor Yellow
            return
        }

        if ($pick.ToUpper() -eq "S") {
            Write-Host "  Enter label number to inspect: " -NoNewline
            $num = (Read-Host).Trim()
            if ($num -match '^\d+$' -and [int]$num -ge 1 -and [int]$num -le $labelInfo.Count) {
                $info = $labelInfo[[int]$num - 1]
                Write-Host ""
                Write-Host "  $($info.DisplayName)" -ForegroundColor Cyan
                Write-Host "    Name:     $($info.Label.Name)" -ForegroundColor Gray
                Write-Host "    Type:     $($info.TypeStr)" -ForegroundColor Gray
                if ($info.ParentGroup) { Write-Host "    Parent:   $($info.ParentGroup)" -ForegroundColor Gray }
                Write-Host "    Tooltip:  $($info.Label.Tooltip)" -ForegroundColor DarkGray
                if ($info.IsManaged) {
                    if ($info.IsCustomised) {
                        Write-Host "    $_Prefix — CUSTOMISED (differs in: $($info.Diffs -join ', '))" -ForegroundColor Yellow
                    } else {
                        Write-Host "    $_Prefix — matches config" -ForegroundColor Green
                    }
                } else {
                    Write-Host "    Not a managed label" -ForegroundColor DarkGray
                }
                Write-Host ""
            } else {
                Write-Host "  Invalid number." -ForegroundColor Red
            }
            continue
        }
        break
    }

    # Resolve selection
    $selectedLabels = @()
    if ($pick.ToUpper() -eq "A") {
        # Skip customised managed labels
        $customised = @($labelInfo | Where-Object { $_.IsCustomised })
        $selectedLabels = @($labelInfo | Where-Object { -not $_.IsCustomised })
        if ($customised.Count -gt 0) {
            Write-Host ""
            Write-Host "  Skipping $($customised.Count) customised $_Prefix label(s):" -ForegroundColor Yellow
            foreach ($c in $customised) {
                Write-Host "    - $($c.DisplayName) (changed: $($c.Diffs -join ', '))" -ForegroundColor Yellow
            }
        }
    } else {
        foreach ($token in ($pick -split ',')) {
            $token = $token.Trim()
            if ($token -match '^\d+$') {
                $idx = [int]$token
                if ($idx -ge 1 -and $idx -le $labelInfo.Count) {
                    $selectedLabels += $labelInfo[$idx - 1]
                } else {
                    Write-Host "  Invalid number: $token (1-$($labelInfo.Count))" -ForegroundColor Red
                    return
                }
            } else {
                Write-Host "  Invalid input: '$token'" -ForegroundColor Red
                return
            }
        }
    }

    if ($selectedLabels.Count -eq 0) {
        Write-Host "  No labels selected." -ForegroundColor Yellow
        return
    }

    # Warn if any selected labels are customised (individual selection)
    $customSelected = @($selectedLabels | Where-Object { $_.IsCustomised })
    if ($customSelected.Count -gt 0) {
        Write-Host ""
        Write-Host "  WARNING: $($customSelected.Count) selected label(s) have been customised:" -ForegroundColor Red
        foreach ($c in $customSelected) {
            Write-Host "    - $($c.DisplayName) (changed: $($c.Diffs -join ', '))" -ForegroundColor Yellow
        }
        if (-not (Read-YesNo "Remove customised labels anyway?")) {
            $selectedLabels = @($selectedLabels | Where-Object { -not $_.IsCustomised })
            if ($selectedLabels.Count -eq 0) {
                Write-Host "  Nothing left to remove." -ForegroundColor Yellow
                return
            }
        }
    }

    # Confirm
    Write-Host ""
    Write-Host "  Will remove $($selectedLabels.Count) label(s):" -ForegroundColor White
    foreach ($s in $selectedLabels) {
        Write-Host "    - $($s.DisplayName)" -ForegroundColor Gray
    }
    if (-not (Read-YesNo "Proceed with removal?")) {
        Write-Host "  Aborted." -ForegroundColor Yellow
        return
    }

    $dryRun = Read-YesNo "Dry run (WhatIf)?" -Default $true

    # Check if label policy should be removed
    $policyName = $_Config.labelPolicyName
    $removePolicy = $false
    if ($pick.ToUpper() -eq "A") {
        # Removing all — also remove the label policy
        try {
            $existingPolicy = Get-LabelPolicy -Identity $policyName -ErrorAction Stop
            if ($existingPolicy) { $removePolicy = $true }
        } catch { }
    }

    $delay = $_Config.interCallDelaySec
    $index = 0

    # Remove label policy first (if removing all)
    if ($removePolicy) {
        if ($dryRun) {
            Write-Host "  WhatIf: Would remove label policy $policyName" -ForegroundColor Yellow
        } else {
            try {
                Remove-LabelPolicy -Identity $policyName -Confirm:$false -ErrorAction Stop
                Write-Host "  Removed label policy: $policyName" -ForegroundColor Green
            } catch {
                Write-Host "  Failed to remove label policy: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        $index++
    }

    # Remove sublabels before parents (reverse priority)
    $sorted = $selectedLabels | Sort-Object { $_.Config.priority } -Descending

    foreach ($info in $sorted) {
        if ($index -gt 0 -and -not $dryRun) { Start-Sleep -Seconds $delay }
        $index++
        if ($dryRun) {
            Write-Host "  WhatIf: Would remove label $($info.Label.Name) ($($info.DisplayName))" -ForegroundColor Yellow
        } else {
            try {
                Remove-Label -Identity $info.Label.Name -Confirm:$false -ErrorAction Stop
                Write-Host "  Removed: $($info.DisplayName)" -ForegroundColor Green
            } catch {
                Write-Host "  Failed to remove $($info.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    Write-Host ""
    Write-Host "  Done." -ForegroundColor Green
}

function Invoke-RemovePackages {
    param([ref]$Connected)
    if (-not (Require-Connection $Connected)) { return }

    Write-Host ""
    Write-Host "  --- Remove SIT Packages ---" -ForegroundColor Cyan

    # Step 1: Fetch deployed packages from tenant
    Write-Host "  Fetching deployed packages..." -ForegroundColor Gray
    $deployed = @()
    try {
        $deployed = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)
    } catch {
        Write-Host "  Failed to retrieve packages: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Filter out Microsoft built-in packages (null/empty Identity)
    $deployed = @($deployed | Where-Object { $_.Identity })

    if ($deployed.Count -eq 0) {
        Write-Host "  No custom SIT rule packages found in tenant." -ForegroundColor Yellow
        return
    }

    # Step 2: Parse display names and entity counts from package XML
    $packageInfo = @()
    foreach ($d in $deployed) {
        $displayName = $d.Identity
        $entityCount = 0
        if ($d.SerializedClassificationRuleCollection) {
            try {
                $bytes = $d.SerializedClassificationRuleCollection
                $xmlContent = [System.Text.Encoding]::Unicode.GetString($bytes)
                $xml = [xml]$xmlContent
                # Human name is in RulePack > Details > LocalizedDetails > Name
                $rulePack = $xml.RulePackage.RulePack
                if ($rulePack) {
                    $details = $rulePack.Details
                    if ($details) {
                        $localized = $details.LocalizedDetails
                        if ($localized -and $localized.Name) {
                            $displayName = $localized.Name
                        }
                    }
                }
                $rules = $xml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq "Rules" }
                if ($rules) {
                    $entities = @($rules.ChildNodes | Where-Object { $_.LocalName -eq "Entity" })
                    $entityCount = $entities.Count
                }
            } catch { }
        }
        $packageInfo += @{ Package = $d; DisplayName = $displayName; EntityCount = $entityCount }
    }

    # Show numbered list and selection loop
    $pick = $null
    while ($true) {
        Write-Host ""
        Write-Host "  Deployed packages:" -ForegroundColor Cyan
        $i = 1
        foreach ($info in $packageInfo) {
            Write-Host "    $i. $($info.DisplayName)  ($($info.EntityCount) SITs)" -ForegroundColor White
            $i++
        }
        Write-Host "    S. See classifiers in a package" -ForegroundColor DarkGray
        Write-Host "    A. All packages" -ForegroundColor DarkGray
        Write-Host "    Q. Back to menu" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Select package(s) to remove (number, comma-separated, S, A, or Q): " -NoNewline
        $pick = (Read-Host).Trim()

        if (-not $pick -or $pick.ToUpper() -eq "Q") {
            Write-Host "  Returning to menu." -ForegroundColor Yellow
            return
        }
        if ($pick.ToUpper() -eq "S") {
            Show-PackageSITs -PackageInfo $packageInfo
            continue
        }
        break
    }

    # Resolve selection
    $selectedPackages = @()
    if ($pick.ToUpper() -eq "A") {
        $selectedPackages = $deployed
    } else {
        foreach ($token in ($pick -split ',')) {
            $token = $token.Trim()
            if ($token -match '^\d+$') {
                $idx = [int]$token
                if ($idx -ge 1 -and $idx -le $deployed.Count) {
                    $selectedPackages += $deployed[$idx - 1]
                } else {
                    Write-Host "  Invalid number: $token (1-$($deployed.Count))" -ForegroundColor Red
                    return
                }
            } else {
                Write-Host "  Invalid input: '$token'" -ForegroundColor Red
                return
            }
        }
    }

    if ($selectedPackages.Count -eq 0) {
        Write-Host "  No packages selected." -ForegroundColor Yellow
        return
    }

    # Step 3: Load config for cross-referencing
    $configPath = Join-Path $ProjectRoot "config"
    $classifiersJsonPath = Join-Path $configPath "classifiers.json"
    $labelsJsonPath      = Join-Path $configPath "labels.json"

    $classifiersJson = $null
    $labelsJson      = $null
    if (Test-Path $classifiersJsonPath) {
        $classifiersJson = Get-Content -Path $classifiersJsonPath -Raw | ConvertFrom-Json
    }
    if (Test-Path $labelsJsonPath) {
        $labelsJson = Get-Content -Path $labelsJsonPath -Raw | ConvertFrom-Json
    }

    # Build label code → display name lookup
    $labelDisplayNames = @{}
    if ($labelsJson) {
        foreach ($lbl in $labelsJson) {
            if ($lbl.code) {
                $labelDisplayNames[$lbl.code] = if ($lbl.displayName) { $lbl.displayName } else { $lbl.name }
            }
        }
    }

    # Build SIT GUID → label codes lookup from classifiers.json
    $sitToLabels = @{}
    if ($classifiersJson) {
        foreach ($prop in $classifiersJson.PSObject.Properties) {
            $labelCode = $prop.Name
            foreach ($item in $prop.Value) {
                $guid = $item.id.ToLower()
                if (-not $sitToLabels.ContainsKey($guid)) {
                    $sitToLabels[$guid] = @()
                }
                $sitToLabels[$guid] += $labelCode
            }
        }
    }

    # Step 4: Impact analysis for each selected package
    $hasImpact = $false

    foreach ($pkg in $selectedPackages) {
        # Resolve display name
        $pkgDisplayName = $pkg.Identity
        foreach ($info in $packageInfo) {
            if ($info.Package -eq $pkg) { $pkgDisplayName = $info.DisplayName; break }
        }
        Write-Host ""
        Write-Host "  ============================================" -ForegroundColor Cyan
        Write-Host "  Package: $pkgDisplayName" -ForegroundColor White
        Write-Host "  ============================================" -ForegroundColor Cyan

        # Parse deployed XML for entity GUIDs
        $entityGuids = @()
        $entityNames = @{}
        if ($pkg.SerializedClassificationRuleCollection) {
            try {
                $bytes = $pkg.SerializedClassificationRuleCollection
                $xmlContent = [System.Text.Encoding]::Unicode.GetString($bytes)
                $xml = [xml]$xmlContent
                $rules = $xml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq "Rules" }
                if ($rules) {
                    # Build name map from LocalizedStrings
                    $nameMap = @{}
                    $localizedStrings = $rules.ChildNodes | Where-Object { $_.LocalName -eq "LocalizedStrings" }
                    if ($localizedStrings) {
                        foreach ($resource in @($localizedStrings.ChildNodes)) {
                            if ($resource.LocalName -eq "Resource") {
                                $nameNode = $resource.ChildNodes | Where-Object { $_.LocalName -eq "Name" } | Select-Object -First 1
                                if ($nameNode) { $nameMap[$resource.idRef] = $nameNode.InnerText }
                            }
                        }
                    }
                    $entities = @($rules.ChildNodes | Where-Object { $_.LocalName -eq "Entity" })
                    foreach ($e in $entities) {
                        $entityGuids += $e.id.ToLower()
                        $entityNames[$e.id.ToLower()] = if ($nameMap.ContainsKey($e.id)) { $nameMap[$e.id] } else { $e.id }
                    }
                }
            } catch {
                Write-Host "    Could not parse package XML: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        Write-Host "    SITs in package: $($entityGuids.Count)" -ForegroundColor Gray

        if ($entityGuids.Count -eq 0) {
            Write-Host "    (no SIT entities found — skipping dependency check)" -ForegroundColor Yellow
            continue
        }

        # 4a: Check DLP rule dependencies
        Write-Host ""
        Write-Host "    Checking DLP rule dependencies..." -ForegroundColor Cyan
        $dlpDeps = @()
        try {
            $allRules = @(Get-DlpComplianceRule -ErrorAction Stop)
            foreach ($rule in $allRules) {
                $ruleContent = ""
                if ($rule.ContentContainsSensitiveInformation) {
                    try { $ruleContent += ($rule.ContentContainsSensitiveInformation | ConvertTo-Json -Depth 10 -Compress) } catch { }
                }
                if ($rule.AdvancedRule) {
                    $ruleContent += $rule.AdvancedRule
                }
                if (-not $ruleContent) { continue }

                $matchedSits = @()
                foreach ($guid in $entityGuids) {
                    if ($ruleContent -match [regex]::Escape($guid)) {
                        $matchedSits += $guid
                    }
                }
                if ($matchedSits.Count -gt 0) {
                    $dlpDeps += @{
                        RuleName     = $rule.Name
                        PolicyName   = $rule.ParentPolicyName
                        MatchedGuids = $matchedSits
                    }
                }
            }
        } catch {
            Write-Host "    Could not check DLP rules: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        if ($dlpDeps.Count -gt 0) {
            $hasImpact = $true
            Write-Host "    DLP RULES AFFECTED: $($dlpDeps.Count)" -ForegroundColor Red
            foreach ($dep in $dlpDeps) {
                Write-Host "      Rule:   $($dep.RuleName)" -ForegroundColor Yellow
                Write-Host "      Policy: $($dep.PolicyName)" -ForegroundColor DarkGray
                $sitList = ($dep.MatchedGuids | ForEach-Object { if ($entityNames.ContainsKey($_)) { $entityNames[$_] } else { $_ } }) -join ", "
                Write-Host "      SITs:   $sitList" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "    DLP rules: none affected" -ForegroundColor Green
        }

        # 4b: Check classifier/label references
        Write-Host ""
        Write-Host "    Checking classifier/label references..." -ForegroundColor Cyan
        $affectedLabels = @{}
        foreach ($guid in $entityGuids) {
            if ($sitToLabels.ContainsKey($guid)) {
                foreach ($lc in $sitToLabels[$guid]) {
                    if (-not $affectedLabels.ContainsKey($lc)) {
                        $affectedLabels[$lc] = @()
                    }
                    $sitName = if ($entityNames.ContainsKey($guid)) { $entityNames[$guid] } else { $guid }
                    $affectedLabels[$lc] += $sitName
                }
            }
        }

        if ($affectedLabels.Count -gt 0) {
            $hasImpact = $true
            Write-Host "    LABEL CLASSIFIERS AFFECTED: $($affectedLabels.Count) label(s)" -ForegroundColor Red
            foreach ($lc in ($affectedLabels.Keys | Sort-Object)) {
                $displayName = if ($labelDisplayNames.ContainsKey($lc)) { $labelDisplayNames[$lc] } else { $lc }
                $sitCount = $affectedLabels[$lc].Count
                Write-Host "      $lc ($displayName) — $sitCount SIT(s) referenced:" -ForegroundColor Yellow
                foreach ($sitName in ($affectedLabels[$lc] | Sort-Object -Unique)) {
                    Write-Host "        - $sitName" -ForegroundColor DarkGray
                }
            }
        } else {
            Write-Host "    Classifier labels: none affected" -ForegroundColor Green
        }

        # 4c: Check for word list / keyword references in XML
        Write-Host ""
        Write-Host "    Checking keyword/word list references..." -ForegroundColor Cyan
        $keywordCount = 0
        if ($pkg.SerializedClassificationRuleCollection) {
            try {
                $bytes = $pkg.SerializedClassificationRuleCollection
                $xmlContent = [System.Text.Encoding]::Unicode.GetString($bytes)
                $xml = [xml]$xmlContent
                $rules = $xml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq "Rules" }
                if ($rules) {
                    $keywords = @($rules.ChildNodes | Where-Object { $_.LocalName -eq "Keyword" })
                    $keywordCount = $keywords.Count
                }
            } catch { }
        }
        if ($keywordCount -gt 0) {
            Write-Host "    Keyword lists in package: $keywordCount" -ForegroundColor Gray
            Write-Host "    (these will be removed with the package)" -ForegroundColor Yellow
        } else {
            Write-Host "    Keyword lists: none" -ForegroundColor Green
        }
    }

    # Step 5: Final confirmation
    Write-Host ""
    if ($hasImpact) {
        Write-Host "  !! DEPENDENCIES DETECTED !!" -ForegroundColor Red
        Write-Host "  Removing these packages may break the DLP rules and label" -ForegroundColor Red
        Write-Host "  classifier assignments listed above." -ForegroundColor Red
        Write-Host ""
    }

    # Show what will be removed using display names from packageInfo
    Write-Host ""
    Write-Host "  Packages to remove:" -ForegroundColor White
    foreach ($sel in $selectedPackages) {
        $displayName = $sel.Identity
        foreach ($info in $packageInfo) {
            if ($info.Package -eq $sel) { $displayName = $info.DisplayName; break }
        }
        Write-Host "    - $displayName" -ForegroundColor Gray
    }
    Write-Host ""
    if (-not (Read-YesNo "Proceed with removal?")) {
        Write-Host "  Aborted." -ForegroundColor Yellow
        return
    }

    $dryRun = Read-YesNo "Dry run (WhatIf)?" -Default $true
    $delay = $_Config.interCallDelaySec
    $index = 0

    foreach ($sel in $selectedPackages) {
        $displayName = $sel.Identity
        foreach ($info in $packageInfo) {
            if ($info.Package -eq $sel) { $displayName = $info.DisplayName; break }
        }

        if ($index -gt 0 -and -not $dryRun) { Start-Sleep -Seconds $delay }
        $index++

        if ($dryRun) {
            Write-Host "  WhatIf: Would remove $displayName ($($sel.Identity))" -ForegroundColor Yellow
        } else {
            try {
                Remove-DlpSensitiveInformationTypeRulePackage -Identity $sel.Identity -Confirm:$false -ErrorAction Stop
                Write-Host "  Removed: $displayName" -ForegroundColor Green
            } catch {
                Write-Host "  Failed to remove $displayName`: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    Write-Host ""
    Write-Host "  Done." -ForegroundColor Green
}

function Invoke-ValidateXML {
    $cmd = "& `"$(Join-Path $ScriptsDir 'Deploy-Classifiers.ps1')`" -Action Validate"
    Write-Host ""
    Write-Host "  > $cmd" -ForegroundColor DarkGray
    Write-Host ""
    Invoke-Expression $cmd
}

#endregion

#region Main Loop
# Check if we're already connected
$isConnected = Test-Connected

while ($true) {
    try { Clear-Host } catch { }
    Show-Menu -Connected $isConnected

    $choice = Read-Choice "  Enter selection [1-11, C, Q]"

    switch ($choice.ToUpper()) {
        "C"  { Invoke-Connect ([ref]$isConnected); Pause-AfterRun }
        "1"  { Invoke-DeployLabels ([ref]$isConnected); Pause-AfterRun }
        "2"  { Invoke-DeployClassifiers ([ref]$isConnected); Pause-AfterRun }
        "3"  { Invoke-DeployDLPRules ([ref]$isConnected); Pause-AfterRun }
        "4"  { Invoke-ChangePack ([ref]$isConnected); Pause-AfterRun }
        "5"  { Invoke-TestClassifiers ([ref]$isConnected); Pause-AfterRun }
        "6"  { Invoke-ListPackages ([ref]$isConnected); Pause-AfterRun }
        "7"  { Invoke-EstimateCapacity ([ref]$isConnected); Pause-AfterRun }
        "8"  { Invoke-CleanupDLPRules ([ref]$isConnected); Pause-AfterRun }
        "9"  { Invoke-CleanupLabels ([ref]$isConnected); Pause-AfterRun }
        "10" { Invoke-RemovePackages ([ref]$isConnected); Pause-AfterRun }
        "11" { Invoke-ValidateXML; Pause-AfterRun }
        "Q"  { Write-Host "  Bye." -ForegroundColor Gray; exit 0 }
        default { Write-Host "  Invalid choice." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }

}
#endregion
