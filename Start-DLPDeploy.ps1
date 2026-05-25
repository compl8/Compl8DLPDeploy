#==============================================================================
# Start-DLPDeploy.ps1
# Interactive menu launcher for the DLP Deployment Toolkit.
#
# Usage:
#   .\Start-DLPDeploy.ps1               # Interactive menu
#   .\Start-DLPDeploy.ps1 -UPN admin@tenant.onmicrosoft.com
#==============================================================================

param(
    [string]$UPN,
    [string]$Tenant,
    [string]$TargetEnvironment,
    [string]$Prefix,
    [switch]$Delegated
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
$_Config       = Set-DeploymentConfigPrefix -Config $_Config -Prefix $Prefix
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
    Write-BoxLine -Text " [12] TestPattern drift check / update" -InnerWidth $w -Color Yellow
    Write-BoxLine -Text " [R]  Customer rollout wizard (full: drift -> readiness -> cleanup -> labels -> classifiers -> rules)" -InnerWidth $w -Color Green
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

function Read-OptionalValue {
    param(
        [string]$Prompt,
        [string]$Current
    )

    $suffix = if ($Current) { " [$Current]" } else { "" }
    Write-Host "  $Prompt$suffix`: " -NoNewline
    $value = (Read-Host).Trim()
    if ($value) { return $value }
    return $Current
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
        $result = Connect-DLPSession -UPN $script:UPN -Tenant $script:Tenant -Delegated:$script:Delegated
        if ($result) {
            $Connected.Value = $true
        } else {
            Write-Host "  Connection failed. Aborting." -ForegroundColor Red
            return $false
        }
    }
    return $true
}

function Set-RolloutContext {
    Write-Host ""
    Write-Host "  --- Tenant / Rollout Context ---" -ForegroundColor Cyan
    $script:Tenant = Read-OptionalValue -Prompt "Tenant domain or GUID" -Current $script:Tenant
    $script:TargetEnvironment = Read-OptionalValue -Prompt "Target environment profile key" -Current $script:TargetEnvironment
    $script:Prefix = Read-OptionalValue -Prompt "Deployment prefix override" -Current $script:Prefix
    $script:UPN = Read-OptionalValue -Prompt "Admin UPN" -Current $script:UPN
    $script:Delegated = Read-YesNo -Prompt "Use delegated admin connection?" -Default ([bool]$script:Delegated)

    $script:_Config = Merge-GlobalConfig -Defaults $script:_Defaults -GlobalJson $script:_SettingsJson
    $script:_Config = Set-DeploymentConfigPrefix -Config $script:_Config -Prefix $script:Prefix
    $script:_Prefix = $script:_Config.namingPrefix

    Write-Host ""
    Write-Host "  Tenant:      $(if ($script:Tenant) { $script:Tenant } else { '(default connection)' })" -ForegroundColor Gray
    Write-Host "  Environment: $(if ($script:TargetEnvironment) { $script:TargetEnvironment } else { '(default fingerprint profile)' })" -ForegroundColor Gray
    Write-Host "  Prefix:      $script:_Prefix" -ForegroundColor Gray
}

function Get-CommonDeploymentArgs {
    $commonArgs = @()
    if ($script:Tenant) { $commonArgs += @("-Tenant", $script:Tenant) }
    if ($script:TargetEnvironment) { $commonArgs += @("-TargetEnvironment", $script:TargetEnvironment) }
    if ($script:Prefix) { $commonArgs += @("-Prefix", $script:Prefix) }
    if ($script:Delegated) { $commonArgs += "-Delegated" }
    return $commonArgs
}

function Get-ExpectedDlpPolicyNameSet {
    param([Parameter(Mandatory)][hashtable]$Config)

    $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $policiesPath = Join-Path $ConfigPath "policies.json"
    if (-not (Test-Path -LiteralPath $policiesPath -PathType Leaf)) {
        return $names
    }

    try {
        $policiesJson = Get-Content -Raw -LiteralPath $policiesPath | ConvertFrom-Json -ErrorAction Stop
        foreach ($policy in @(Resolve-PolicyConfig -PoliciesJson $policiesJson)) {
            $policyName = Get-PolicyName -PolicyNumber $policy.Number -PolicyCode $policy.Code -Config $Config
            if ($policyName) { [void]$names.Add($policyName) }
        }
    } catch {
        Write-Host "  Warning: could not derive configured DLP policy names: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    return $names
}

function Get-LatestRefitPlanPath {
    $root = Join-Path (Join-Path $ProjectRoot "reports") "refit-plans"
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        return $null
    }

    $plans = @(Get-ChildItem -LiteralPath $root -Filter "refit-plan.json" -File -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)
    if ($plans.Count -eq 0) { return $null }
    return $plans[0].FullName
}

function Read-RefitPlanPath {
    $latest = Get-LatestRefitPlanPath
    $prompt = if ($latest) {
        "Refit plan path (Enter = latest: $([System.IO.Path]::GetFileName((Split-Path -Parent $latest))))"
    } else {
        "Refit plan path"
    }
    Write-Host "  $prompt`: " -NoNewline
    $path = (Read-Host).Trim()
    if (-not $path) { $path = $latest }
    if (-not $path) { return $null }
    if (-not [System.IO.Path]::IsPathRooted($path)) {
        $path = Join-Path $ProjectRoot $path
    }
    return [System.IO.Path]::GetFullPath($path)
}

function Show-RefitPlanEvidence {
    param([string]$PlanPath)

    if (-not $PlanPath -or -not (Test-Path -LiteralPath $PlanPath -PathType Leaf)) {
        Write-Host "  Refit plan not found." -ForegroundColor Red
        return
    }

    $planDir = Split-Path -Parent $PlanPath
    $hashPath = Join-Path $planDir "refit-plan.sha256"
    $summaryPath = Join-Path $planDir "refit-summary.md"
    Write-Host ""
    Write-Host "  Refit plan:    $PlanPath" -ForegroundColor Gray
    if (Test-Path -LiteralPath $hashPath -PathType Leaf) {
        Write-Host "  Plan SHA256:   $((Get-Content -Raw -LiteralPath $hashPath).Trim())" -ForegroundColor Gray
    } else {
        Write-Host "  Plan SHA256:   missing" -ForegroundColor Red
    }
    if (Test-Path -LiteralPath $summaryPath -PathType Leaf) {
        Write-Host "  Summary:       $summaryPath" -ForegroundColor Gray
    }
}

function Format-CommandArgument {
    param([object]$Value)

    $text = [string]$Value
    if ($text -match '[\s"`$&|;<>]') {
        return '"' + ($text -replace '"', '\"') + '"'
    }

    return $text
}

function Convert-ArgumentListToSplat {
    param([object[]]$ArgumentList = @())

    $named = @{}
    $positional = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $ArgumentList.Count; $i++) {
        $item = $ArgumentList[$i]
        $text = [string]$item
        if ($text -match '^-[A-Za-z][A-Za-z0-9]*$') {
            $key = $text.TrimStart('-')
            $hasValue = ($i + 1 -lt $ArgumentList.Count) -and ([string]$ArgumentList[$i + 1] -notmatch '^-[A-Za-z][A-Za-z0-9]*$')
            if ($hasValue) {
                $named[$key] = $ArgumentList[$i + 1]
                $i++
            } else {
                $named[$key] = $true
            }
        } else {
            $positional.Add($item) | Out-Null
        }
    }

    return [pscustomobject]@{
        Named = $named
        Positional = @($positional.ToArray())
    }
}

function Invoke-ToolkitScript {
    param(
        [Parameter(Mandatory)]
        [string]$ScriptName,

        [object[]]$ArgumentList = @()
    )

    $scriptPath = Join-Path $ScriptsDir $ScriptName
    $displayArgs = @($ArgumentList | ForEach-Object { Format-CommandArgument $_ })
    $cmd = "& `"$scriptPath`""
    if ($displayArgs.Count -gt 0) {
        $cmd = "$cmd $($displayArgs -join ' ')"
    }

    Write-Host ""
    Write-Host "  > $cmd" -ForegroundColor DarkGray
    Write-Host ""
    $binding = Convert-ArgumentListToSplat -ArgumentList $ArgumentList
    $named = $binding.Named
    $positional = @($binding.Positional)
    if ($positional.Count -gt 0) {
        & $scriptPath @positional @named
    } else {
        & $scriptPath @named
    }
}

function Invoke-ExternalTool {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [object[]]$ArgumentList = @()
    )

    $displayArgs = @($ArgumentList | ForEach-Object { Format-CommandArgument $_ })
    $cmd = $FilePath
    if ($displayArgs.Count -gt 0) {
        $cmd = "$cmd $($displayArgs -join ' ')"
    }

    Write-Host ""
    Write-Host "  > $cmd" -ForegroundColor DarkGray
    Write-Host ""

    try {
        Push-Location $ProjectRoot
        & $FilePath @ArgumentList
        $exitCode = $LASTEXITCODE
    } catch {
        Write-Host "  Command failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    } finally {
        Pop-Location
    }

    if ($null -ne $exitCode -and $exitCode -ne 0) {
        Write-Host "  Command exited with code $exitCode." -ForegroundColor Red
        return $false
    }

    return $true
}

function Resolve-TestPatternDriftChoice {
    param([string]$Choice)

    switch (($Choice.Trim()).ToUpperInvariant()) {
        { $_ -in @("A", "U", "1", "UPDATE") } { return "Update" }
        { $_ -in @("B", "2", "CONTINUE") } { return "Continue" }
        { $_ -in @("C", "E", "Q", "3", "EXIT", "ABORT") } { return "Exit" }
        default { return $null }
    }
}

function Get-TestPatternUpdateTierDefault {
    if ($script:_Config.deploymentTier -in @("small", "medium", "large")) {
        return $script:_Config.deploymentTier
    }
    return "medium"
}

function Read-TestPatternUpdateTier {
    $defaultTier = Get-TestPatternUpdateTierDefault
    $tier = Read-OptionalValue -Prompt "TestPattern update tier [small/medium/large]" -Current $defaultTier
    $tier = $tier.ToLowerInvariant()
    if ($tier -notin @("small", "medium", "large")) {
        Write-Host "  Invalid tier '$tier'. Use small, medium, or large." -ForegroundColor Red
        return $null
    }
    return $tier
}

function Invoke-TestPatternUpdateWorkflow {
    Write-Host ""
    Write-Host "  --- Update From TestPattern ---" -ForegroundColor Cyan
    Write-Host "  This refreshes local classifier config and deploy XML from the live TestPattern API." -ForegroundColor Gray
    Write-Host "  Review the git diff before deploying changed content to a tenant." -ForegroundColor Yellow

    $tier = Read-TestPatternUpdateTier
    if (-not $tier) { return $false }

    $xlsPath = Read-OptionalValue -Prompt "Spreadsheet path override (Enter = settings/default)" -Current ""
    $xlsArgs = @()
    if ($xlsPath) { $xlsArgs = @("--xls", $xlsPath) }

    $ok = $true
    if (Read-YesNo "Show spreadsheet/live catalogue drift report first?" -Default $true) {
        $jurisdiction = Read-OptionalValue -Prompt "Jurisdiction filter for catalogue report (Enter = none)" -Current ""
        $syncArgs = @((Join-Path $ScriptsDir "sync-spreadsheet.py")) + $xlsArgs
        if ($jurisdiction) { $syncArgs += @("--jurisdiction", $jurisdiction) }
        $ok = (Invoke-ExternalTool -FilePath "python" -ArgumentList $syncArgs) -and $ok
    }

    if (Read-YesNo "Regenerate classifiers.json from spreadsheet?" -Default $true) {
        $buildConfigArgs = @((Join-Path $ScriptsDir "Build-FromXLS.py"), "--tier", $tier) + $xlsArgs
        $ok = (Invoke-ExternalTool -FilePath "python" -ArgumentList $buildConfigArgs) -and $ok
    }

    if (Read-YesNo "Regenerate deploy XML packages from TestPattern?" -Default $true) {
        $buildPackageArgs = @((Join-Path $ScriptsDir "build-deploy-packages.py"), "--tier", $tier) + $xlsArgs
        $ok = (Invoke-ExternalTool -FilePath "python" -ArgumentList $buildPackageArgs) -and $ok

        if ($ok -and (Read-YesNo "Refresh classifier bundle manifest for this intentional update?" -Default $true)) {
            $manifestResult = @(Invoke-ToolkitScript -ScriptName "Update-ClassifierBundleManifest.ps1" -ArgumentList @("-Tier", $tier, "-Force", "-NoExit"))
            $ok = ($manifestResult.Count -gt 0 -and $manifestResult[-1] -eq $true) -and $ok
        }
    }

    if ($ok) {
        Write-Host ""
        Write-Host "  TestPattern update workflow completed. Review changed files before tenant deployment." -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "  TestPattern update workflow did not complete cleanly." -ForegroundColor Red
    }
    return $ok
}

function Invoke-TestPatternDriftDecision {
    while ($true) {
        $driftResult = @(Invoke-ToolkitScript -ScriptName "Test-TestPatternDrift.ps1" -ArgumentList @("-Live", "-FailOnWarnings", "-NoExit"))
        $driftPassed = ($driftResult.Count -gt 0 -and $driftResult[-1] -eq $true)
        if ($driftPassed) {
            Write-Host ""
            Write-Host "  TestPattern live drift check passed." -ForegroundColor Green
            return $true
        }

        Write-Host ""
        Write-Host "  !! TESTPATTERN DRIFT DETECTED !!" -ForegroundColor Red
        Write-Host "  The live TestPattern catalogue or bundle output differs from the local expectations." -ForegroundColor Yellow
        Write-Host "  Choose how to proceed:" -ForegroundColor White
        Write-Host "    A. Update from TestPattern" -ForegroundColor Green
        Write-Host "    B. Continue with current local content" -ForegroundColor Yellow
        Write-Host "    C. Exit this workflow" -ForegroundColor Red

        while ($true) {
            $choice = Resolve-TestPatternDriftChoice -Choice (Read-Choice "  Select [A/B/C]")
            switch ($choice) {
                "Update" {
                    if (Invoke-TestPatternUpdateWorkflow) {
                        if (Read-YesNo "Re-run live TestPattern drift check now?" -Default $true) {
                            break
                        }
                        return $true
                    }
                    Write-Host "  Update failed or was cancelled." -ForegroundColor Red
                    if (-not (Read-YesNo "Return to the drift decision menu?" -Default $true)) {
                        return $false
                    }
                    break
                }
                "Continue" {
                    Write-Host ""
                    Write-Host "  Continuing despite drift will deploy LOCAL content that does NOT match the live TestPattern catalogue." -ForegroundColor Red
                    Write-Host "  Type the word PROCEED (uppercase) to confirm, anything else to cancel: " -NoNewline -ForegroundColor Yellow
                    $confirm = (Read-Host).Trim()
                    if ($confirm -cne 'PROCEED') {
                        Write-Host "  Continue cancelled." -ForegroundColor Yellow
                        return $false
                    }
                    Write-Host "  Continuing with current local content (operator-approved drift override)." -ForegroundColor Yellow
                    return $true
                }
                "Exit" {
                    Write-Host "  Exiting this workflow." -ForegroundColor Yellow
                    return $false
                }
                default {
                    Write-Host "  Invalid selection." -ForegroundColor Red
                }
            }
            if ($choice -eq "Update") { break }
        }
    }
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
    $result = Connect-DLPSession -UPN $script:UPN -Tenant $script:Tenant -Delegated:$script:Delegated
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
    if (Read-YesNo "Check live TestPattern drift before deploying labels?" -Default $true) {
        if (-not (Invoke-TestPatternDriftDecision)) { return }
    }
    $dryRun   = Read-YesNo "Dry run (WhatIf)?" -Default $true
    $publish  = Read-YesNo "Publish labels after creation?"
    $noMark   = Read-YesNo "Skip visual markings?"

    $params = @(Get-CommonDeploymentArgs)
    if ($dryRun)  { $params += "-WhatIf" }
    if ($noMark)  { $params += "-NoMarking" }
    if ($publish) {
        Write-Host '  Publish to (e.g. "All" or "user@domain.com"): ' -NoNewline
        $target = (Read-Host).Trim()
        if ($target) { $params += @("-PublishTo", $target) }
    } else {
        $params += "-SkipPublish"
    }

    Invoke-ToolkitScript -ScriptName "Deploy-Labels.ps1" -ArgumentList $params
}

function Invoke-DeployClassifiers {
    param([ref]$Connected)
    if (-not (Require-Connection $Connected)) { return }

    Write-Host ""
    Write-Host "  --- Deploy Classifiers ---" -ForegroundColor Cyan
    Write-Host "    1. Guided tenant impact manager" -ForegroundColor White
    Write-Host "    2. Generate refit plan" -ForegroundColor Green
    Write-Host "    3. Apply refit plan (WhatIf)" -ForegroundColor Green
    Write-Host "    4. Direct upload to confirmed greenfield tenant" -ForegroundColor Yellow
    Write-Host "    5. Validate local XML only" -ForegroundColor White
    Write-Host ""
    Write-Host "  Select: " -NoNewline
    $operation = (Read-Host).Trim()

    Write-Host "  Tier [narrow/wide/full] (Enter = all tiers): " -NoNewline
    $tier = (Read-Host).Trim().ToLower()
    $commonArgs = @(Get-CommonDeploymentArgs)
    if ($operation -in @("1", "2", "3", "4") -and (Read-YesNo "Check live TestPattern drift before using classifier content?" -Default $true)) {
        if (-not (Invoke-TestPatternDriftDecision)) { return }
    }

    switch ($operation) {
        "1" {
            $params = @("-Action", "Interactive") + $commonArgs
            if ($tier -in @("narrow", "wide", "full", "small", "medium", "large")) { $params += @("-Tier", $tier) }
            Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList $params
            return
        }
        "2" {
            $params = @("-Action", "RefitPlan") + $commonArgs
            if ($tier -in @("narrow", "wide", "full", "small", "medium", "large")) { $params += @("-Tier", $tier) }
            Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList $params
            Show-RefitPlanEvidence -PlanPath (Get-LatestRefitPlanPath)
            return
        }
        "3" {
            $planPath = Read-RefitPlanPath
            if (-not $planPath -or -not (Test-Path -LiteralPath $planPath -PathType Leaf)) {
                Write-Host "  No valid refit plan selected." -ForegroundColor Red
                return
            }
            Show-RefitPlanEvidence -PlanPath $planPath
            $params = @("-Action", "ApplyRefitPlan", "-RefitPlanPath", $planPath, "-WhatIf", "-ApproveRefitPlan") + $commonArgs
            Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList $params
            return
        }
        "4" {
            $dryRun = Read-YesNo "Dry run (WhatIf)?" -Default $true
            $greenfield = Read-YesNo "Confirm tenant is greenfield for direct classifier upload?" -Default $false
            if (-not $greenfield) {
                Write-Host "  Direct upload aborted. Use RefitPlan for tenants with existing custom packages." -ForegroundColor Yellow
                return
            }
            $skip = Read-YesNo "Skip pre-flight checks?"
            $params = @("-Action", "Upload", "-Greenfield") + $commonArgs
            if ($tier -in @("narrow", "wide", "full", "small", "medium", "large")) { $params += @("-Tier", $tier) }
            if ($dryRun)  { $params += "-WhatIf" }
            if ($skip)    { $params += "-SkipPreFlight" }
            Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList $params
            return
        }
        "5" {
            $params = @("-Action", "Validate")
            if ($tier -in @("narrow", "wide", "full", "small", "medium", "large")) { $params += @("-Tier", $tier) }
            Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList $params
            return
        }
        default {
            Write-Host "  Invalid selection." -ForegroundColor Red
            return
        }
    }
}

function Invoke-DeployDLPRules {
    param([ref]$Connected)
    if (-not (Require-Connection $Connected)) { return }

    Write-Host ""
    Write-Host "  --- Deploy DLP Rules ---" -ForegroundColor Cyan
    if (Read-YesNo "Check live TestPattern drift before deploying DLP rules?" -Default $true) {
        if (-not (Invoke-TestPatternDriftDecision)) { return }
    }
    $dryRun    = Read-YesNo "Dry run (WhatIf)?" -Default $true
    $skipVal   = Read-YesNo "Skip SIT validation?"
    $skipVerif = Read-YesNo "Skip post-deploy verification?"

    $params = @(Get-CommonDeploymentArgs)
    if ($dryRun)    { $params += "-WhatIf" }
    if ($skipVal)   { $params += "-SkipValidation" }
    if ($skipVerif) { $params += "-SkipVerification" }

    Invoke-ToolkitScript -ScriptName "Deploy-DLPRules.ps1" -ArgumentList $params
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

    if ($subChoice -in @("1", "2") -and (Read-YesNo "Check live TestPattern drift before running the change pack?" -Default $true)) {
        if (-not (Invoke-TestPatternDriftDecision)) { return }
    }

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

            $params = @("-Components", $compParam)
            if ($dryRun) { $params += "-WhatIf" }

            Invoke-ToolkitScript -ScriptName "Generate-ChangePack.ps1" -ArgumentList $params
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

            $params = @("-CsvPath", $csvPath)
            if ($dryRun) { $params += "-WhatIf" }

            Invoke-ToolkitScript -ScriptName "Invoke-ChangePack.ps1" -ArgumentList $params
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
    if ($label)   { $params += @("-Label", $label) }
    if ($showAll) { $params += "-ShowAll" }

    Invoke-ToolkitScript -ScriptName "Test-Classifiers.ps1" -ArgumentList $params
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

    $params = @("-Action", "Estimate") + @(Get-CommonDeploymentArgs)
    Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList $params
}

function Invoke-CleanupDLPRules {
    param([ref]$Connected)
    if (-not (Require-Connection $Connected)) { return }

    Write-Host ""
    Write-Host "  --- Remove DLP Rules ---" -ForegroundColor Cyan
    Write-Host "  Fetching DLP policies and rules..." -ForegroundColor Gray

    # Derive deployment-owned policies from the same naming helper used by Deploy-DLPRules.ps1.
    $prefix = $_Config.namingPrefix
    $suffix = $_Config.namingSuffix
    $expectedPolicyNames = Get-ExpectedDlpPolicyNameSet -Config $_Config
    $legacyDeployPattern = "P0*-*-$prefix-$suffix"

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
        $isManaged = $expectedPolicyNames.Contains($pol.Name) -or $pol.Name -like $legacyDeployPattern
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
            if ($lbl.name) { $configLookup[$lbl.name] = $lbl }
            $generatedName = Get-DeploymentObjectName -Config $_Config -ObjectType "label" -Name $lbl.name -Tokens @{
                labelCode   = $lbl.code
                displayName = $lbl.displayName
            }
            if ($generatedName) { $configLookup[$generatedName] = $lbl }
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
    $policyName = Get-DeploymentObjectName -Config $_Config -ObjectType "labelPolicy" -Name $_Config.labelPolicyName
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

function Invoke-CustomerRolloutWizard {
    param([ref]$Connected)

    Write-Host ""
    Write-Host "  --- Customer Rollout Wizard ---" -ForegroundColor Cyan
    Write-Host "  Full rollout: drift -> readiness -> [cleanup] -> labels -> classifiers -> DLP rules." -ForegroundColor Gray
    Write-Host "  Each phase is preview-first; you confirm before any real-apply step." -ForegroundColor Gray

    Set-RolloutContext

    # 1. Drift gate (unconditional pre-flight)
    Write-Host ""
    Write-Host "  Phase 1/6: TestPattern drift check" -ForegroundColor Cyan
    if (-not (Invoke-TestPatternDriftDecision)) {
        Write-Host "  Wizard aborted at drift gate." -ForegroundColor Yellow
        return
    }

    if (-not (Require-Connection $Connected)) { return }
    $commonArgs = @(Get-CommonDeploymentArgs)

    # Optional deployment-session lifecycle: bundle this rollout into a pinned package
    # (drift -> phases -> verify -> archive). When declined, the wizard runs without
    # session bookkeeping and skips the finalise step at the end.
    $sessionPath = $null
    if (Read-YesNo "Bundle this rollout into a tenant-pinned deployment package (audit trail + archive)?" -Default $false) {
        $basePackage = Get-ChildItem (Join-Path $ProjectRoot 'dist/compl8dlpdeploy-base-*.zip') -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $basePackage) {
            Write-Host "  No base package found in dist/. Building one now..." -ForegroundColor Yellow
            Invoke-ToolkitScript -ScriptName "New-ReleasePackage.ps1" -ArgumentList @()
            $basePackage = Get-ChildItem (Join-Path $ProjectRoot 'dist/compl8dlpdeploy-base-*.zip') -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        }
        if (-not $basePackage) {
            Write-Host "  Could not build a base package. Continuing without session bundling." -ForegroundColor Yellow
        } else {
            $initArgs = @("-BasePackagePath", $basePackage.FullName, "-Tenant", $script:Tenant, "-TargetEnvironment", $script:TargetEnvironment)
            if ($script:Prefix) { $initArgs += @("-Prefix", $script:Prefix) }
            $initResult = @(Invoke-ToolkitScript -ScriptName "Initialize-DeploymentSession.ps1" -ArgumentList $initArgs)
            $sessionPath = $initResult | Where-Object { $_ -is [string] -and (Test-Path -LiteralPath $_ -PathType Container) } | Select-Object -Last 1
            if ($sessionPath) {
                Write-Host "  Session: $sessionPath" -ForegroundColor Cyan
                $commonArgs += @("-DeploymentSessionPath", $sessionPath)
            } else {
                Write-Host "  Could not resolve session path from Initialize-DeploymentSession output. Continuing without session bundling." -ForegroundColor Yellow
            }
        }
    }

    # 2. Readiness gate (unconditional; OVERRIDE typed-confirm to bypass)
    Write-Host ""
    Write-Host "  Phase 2/6: Pre-deployment readiness" -ForegroundColor Cyan
    $readinessArgs = @("-Scope", "All", "-RequireTenant", "-NoExit") + $commonArgs
    $readinessResult = @(Invoke-ToolkitScript -ScriptName "Test-DeploymentReadiness.ps1" -ArgumentList $readinessArgs)
    $readinessPassed = ($readinessResult.Count -gt 0 -and $readinessResult[-1] -eq $true)
    if (-not $readinessPassed) {
        Write-Host ""
        Write-Host "  Readiness did not pass." -ForegroundColor Red
        Write-Host "  Bypassing readiness will deploy with unresolved validation errors." -ForegroundColor Red
        Write-Host "  Type the word OVERRIDE (uppercase) to bypass, anything else to abort: " -NoNewline -ForegroundColor Yellow
        $confirm = (Read-Host).Trim()
        if ($confirm -cne 'OVERRIDE') {
            Write-Host "  Wizard aborted at readiness gate." -ForegroundColor Yellow
            return
        }
        Write-Host "  Readiness override accepted." -ForegroundColor Yellow
    }

    # 3. Cleanup (optional)
    Write-Host ""
    Write-Host "  Phase 3/6: Cleanup of prior toolkit-owned objects (optional)" -ForegroundColor Cyan
    if (Read-YesNo "Run cleanup of any existing toolkit-stamped DLP policies/rules and classifier packages?" -Default $false) {
        Write-Host "  Cleanup is destructive. Type the word CLEANUP (uppercase) to confirm: " -NoNewline -ForegroundColor Yellow
        $confirm = (Read-Host).Trim()
        if ($confirm -cne 'CLEANUP') {
            Write-Host "  Cleanup skipped." -ForegroundColor Yellow
        } else {
            $cleanupArgs = @("-Action", "Execute", "-Force") + $commonArgs
            Invoke-ToolkitScript -ScriptName "Reset-DeploymentScope.ps1" -ArgumentList $cleanupArgs
        }
    }

    # 4. Labels
    Write-Host ""
    Write-Host "  Phase 4/6: Labels" -ForegroundColor Cyan
    if (Read-YesNo "Deploy labels (WhatIf preview first)?" -Default $true) {
        $labelArgs = @("-WhatIf", "-SkipPublish") + $commonArgs
        Invoke-ToolkitScript -ScriptName "Deploy-Labels.ps1" -ArgumentList $labelArgs
        if (Read-YesNo "WhatIf looked good — apply labels for real?" -Default $false) {
            Write-Host '  Publish to (e.g. "All" or "user@domain.com", Enter to skip publish): ' -NoNewline
            $target = (Read-Host).Trim()
            $applyArgs = @() + $commonArgs
            if ($target) { $applyArgs += @("-PublishTo", $target) } else { $applyArgs += "-SkipPublish" }
            Invoke-ToolkitScript -ScriptName "Deploy-Labels.ps1" -ArgumentList $applyArgs
        }
    }

    # 5. Classifiers (Greenfield Upload OR ApplyRefitPlan)
    Write-Host ""
    Write-Host "  Phase 5/6: Classifiers" -ForegroundColor Cyan
    Write-Host "    A. Greenfield Upload (clean tenant with no custom classifier packages)" -ForegroundColor White
    Write-Host "    B. Refit Plan + Apply (tenant has existing custom packages)" -ForegroundColor White
    Write-Host "    S. Skip classifiers phase" -ForegroundColor Gray
    Write-Host "  Select [A/B/S]: " -NoNewline
    $classifierChoice = (Read-Host).Trim().ToUpper()
    switch ($classifierChoice) {
        "A" {
            $greenArgs = @("-Action", "Upload", "-Greenfield", "-WhatIf") + $commonArgs
            Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList $greenArgs
            if (Read-YesNo "WhatIf looked good — apply Greenfield Upload for real?" -Default $false) {
                $applyArgs = @("-Action", "Upload", "-Greenfield") + $commonArgs
                Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList $applyArgs
            }
        }
        "B" {
            $refitArgs = @("-Action", "RefitPlan") + $commonArgs
            Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList $refitArgs
            $planPath = Read-RefitPlanPath
            if (-not $planPath -or -not (Test-Path -LiteralPath $planPath -PathType Leaf)) {
                Write-Host "  No valid refit plan selected; skipping classifiers." -ForegroundColor Red
            } else {
                Show-RefitPlanEvidence -PlanPath $planPath
                $whatifArgs = @("-Action", "ApplyRefitPlan", "-RefitPlanPath", $planPath, "-WhatIf", "-ApproveRefitPlan") + $commonArgs
                Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList $whatifArgs
                if (Read-YesNo "WhatIf looked good — apply refit plan for real?" -Default $false) {
                    $applyArgs = @("-Action", "ApplyRefitPlan", "-RefitPlanPath", $planPath, "-ApproveRefitPlan") + $commonArgs
                    Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList $applyArgs
                }
            }
        }
        "S" {
            Write-Host "  Skipping classifiers phase." -ForegroundColor Yellow
        }
        default {
            Write-Host "  Unrecognised selection; skipping classifiers phase." -ForegroundColor Yellow
        }
    }

    # 6. DLP rules
    Write-Host ""
    Write-Host "  Phase 6/6: DLP rules" -ForegroundColor Cyan
    if (Read-YesNo "Deploy DLP rules (WhatIf preview first)?" -Default $true) {
        $dlpWhatif = @("-WhatIf") + $commonArgs
        Invoke-ToolkitScript -ScriptName "Deploy-DLPRules.ps1" -ArgumentList $dlpWhatif
        if (Read-YesNo "WhatIf looked good — apply DLP rules for real?" -Default $false) {
            Invoke-ToolkitScript -ScriptName "Deploy-DLPRules.ps1" -ArgumentList $commonArgs
        }
    }

    # Finalise the deployment session (verify against tenant + archive).
    if ($sessionPath) {
        Write-Host ""
        Write-Host "  Finalising deployment session (verify + archive)..." -ForegroundColor Cyan
        $finalArgs = @("-SessionPath", $sessionPath, "-AcceptIncomplete")
        Invoke-ToolkitScript -ScriptName "Finalize-DeploymentSession.ps1" -ArgumentList $finalArgs
    }

    Write-Host ""
    Write-Host "  Customer rollout wizard complete." -ForegroundColor Green
}

function Invoke-ValidateXML {
    Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList @("-Action", "Validate")
}

function Invoke-TestPatternDriftMenu {
    [void](Invoke-TestPatternDriftDecision)
}

#endregion

#region Main Loop
# Check if we're already connected
$isConnected = Test-Connected

while ($true) {
    try { Clear-Host } catch { }
    Show-Menu -Connected $isConnected

    $choice = Read-Choice "  Enter selection [1-12, R, C, Q]"

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
        "12" { Invoke-TestPatternDriftMenu; Pause-AfterRun }
        "R"  { Invoke-CustomerRolloutWizard ([ref]$isConnected); Pause-AfterRun }
        "Q"  { Write-Host "  Bye." -ForegroundColor Gray; exit 0 }
        default { Write-Host "  Invalid choice." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }

}
#endregion
