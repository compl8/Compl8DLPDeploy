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
    [switch]$Delegated,
    # Stage 5 (D1/D4/D6): opt-in to the Engine path. When set, deploy menu items + the rollout
    # wizard route an object type through Invoke-Compl8Deploy IF that type's route is ON in the
    # New-Compl8Context (tenant.json engineRoutes; default ALL FALSE). Otherwise — and always
    # without -UseEngine — the TUI invokes the existing leaf scripts exactly as today.
    [switch]$UseEngine,
    [string]$WorkspaceRoot
)

$ProjectRoot = $PSScriptRoot
$ScriptsDir  = Join-Path $ProjectRoot "scripts"
$ConfigPath  = Join-Path $ProjectRoot "config"

# Import shared module for connection helpers
Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

# The interactive console is the orchestrator for everything it launches: leaf scripts
# invoked via Invoke-ToolkitScript (same-process &) must not re-trip the orchestration
# gate. This flag scopes to the console process and its children.
$env:COMPL8_ORCHESTRATED = '1'

# Load config for naming prefix
$_Defaults     = Get-ModuleDefaults
$_SettingsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
$_Config       = Merge-GlobalConfig -Defaults $_Defaults -GlobalJson $_SettingsJson
$_Config       = Set-DeploymentConfigPrefix -Config $_Config -Prefix $Prefix
$_Prefix       = $_Config.namingPrefix

# Session flag: when set, deploy scripts receive -RegisterFingerprint so an unknown
# TargetEnvironment bootstraps a warn-mode fingerprint entry from the connected tenant.
$script:RegisterFingerprint = $false
$script:FingerprintMode   = 'warn'
$script:ExpectedTenantId  = $null

# Stage 5 Engine path (opt-in). Import Compl8.Engine (New-Compl8Context + Invoke-Compl8Deploy) and
# stamp deterministic-within-this-session plan id / generatedUtc values ONLY under -UseEngine, so the
# default TUI startup is unchanged. (The TUI surface MAY call Get-Date; the determinism ban is on the
# pure Engine paths, which receive these as injected values.)
if ($UseEngine) {
    Import-Module (Join-Path $ProjectRoot "modules" "Compl8.Engine") -Force
    $script:DeployStamp        = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
    $script:DeployGeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
}

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
    Write-BoxLine -Text " [S]  Config skew (tenant vs global)" -InnerWidth $w -Color Cyan
    Write-BoxLine -Text " [E]  Edit config (global / tenant)" -InnerWidth $w -Color Cyan
    Write-BoxLine -Text " [12] TestPattern drift check / update" -InnerWidth $w -Color Yellow
    Write-BoxLine -Text " [R]  Customer rollout wizard (full: drift -> readiness -> cleanup -> labels -> classifiers -> rules)" -InnerWidth $w -Color Green
    if ($UseEngine) {
        Write-BoxLine -Text " [M]  Reconcile / Migrate (Engine: walk conflicts, claim/remove, preview impact)" -InnerWidth $w -Color Green
    }
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

function Get-FingerprintConfig {
    $path = Join-Path $ConfigPath "tenant-fingerprints.json"
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        Write-Host "  Could not parse tenant-fingerprints.json: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Select-TargetEnvironment {
    # Pick the deployment target from stored tenant fingerprints, or register a new
    # tenant. Sets $script:TargetEnvironment and $script:RegisterFingerprint. Selecting an
    # existing block-mode entry warns that the connected tenant must match; "New tenant"
    # flags the next deploy to bootstrap a warn-mode entry from the live tenant.
    $script:RegisterFingerprint = $false
    $script:FingerprintMode  = 'warn'
    $script:ExpectedTenantId = $null

    function Read-RegistrationDetails {
        $modeAns = (Read-Host "  Mode for this tenant [warn/block] (Enter = warn)").Trim().ToLowerInvariant()
        $script:FingerprintMode = if ($modeAns -eq 'block') { 'block' } else { 'warn' }
        while ($true) {
            $guid = (Read-Host "  Expected tenant GUID (Enter = capture from connected tenant on first deploy)").Trim()
            if ([string]::IsNullOrWhiteSpace($guid)) { $script:ExpectedTenantId = $null; break }
            $g = [guid]::Empty
            if ([guid]::TryParse($guid, [ref]$g)) { $script:ExpectedTenantId = $guid; break }
            Write-Host "  '$guid' is not a valid GUID; try again or press Enter to skip." -ForegroundColor Yellow
        }
    }

    $cfg = Get-FingerprintConfig
    $entries = @()
    if ($cfg -and $cfg.environments) { $entries = @($cfg.environments.PSObject.Properties) }

    Write-Host ""
    Write-Host "  --- Target Tenant Fingerprint ---" -ForegroundColor Cyan

    if ($entries.Count -eq 0) {
        Write-Host "  No stored fingerprints in config/tenant-fingerprints.json." -ForegroundColor Yellow
        $key = Read-OptionalValue -Prompt "New environment key for this tenant" -Current $script:TargetEnvironment
        if ($key) {
            $script:TargetEnvironment = $key
            $script:RegisterFingerprint = Read-YesNo "Register the connected tenant as '$key' on first deploy?" -Default $true
            if ($script:RegisterFingerprint) { Read-RegistrationDetails }
        }
        return
    }

    $default = $cfg.defaultEnvironment
    $i = 1
    foreach ($e in $entries) {
        $mode  = if ($e.Value.mode) { [string]$e.Value.mode } else { "warn" }
        $tid   = if ($e.Value.tenantId) { [string]$e.Value.tenantId } else { "(no tenantId)" }
        $isDef = if ($e.Name -eq $default) { " (default)" } else { "" }
        $modeColor = if ($mode -eq "block") { "Red" } else { "Yellow" }
        Write-Host ("    {0}. {1}{2}" -f $i, $e.Name, $isDef) -NoNewline -ForegroundColor White
        Write-Host ("   [{0}] {1}" -f $mode, $tid) -ForegroundColor $modeColor
        $i++
    }
    Write-Host "    N. New tenant -- register from connected tenant on first deploy" -ForegroundColor Green

    $current = if ($script:TargetEnvironment) { $script:TargetEnvironment } elseif ($default) { "$default (default)" } else { "default" }
    Write-Host ("  Select [1-{0}/N] (Enter = keep '{1}'): " -f $entries.Count, $current) -NoNewline
    $pick = (Read-Host).Trim()

    if ([string]::IsNullOrWhiteSpace($pick)) { return }

    if ($pick -match '^[Nn]$') {
        $key = Read-OptionalValue -Prompt "New environment key (e.g. acme-prod)" -Current ""
        if (-not $key) {
            Write-Host "  No key entered; keeping current target." -ForegroundColor Yellow
            return
        }
        if (@($entries.Name) -contains $key) {
            Write-Host "  '$key' already exists; selecting it instead of registering." -ForegroundColor Yellow
            $script:TargetEnvironment = $key
            return
        }
        $script:TargetEnvironment = $key
        $script:RegisterFingerprint = $true
        Read-RegistrationDetails
        Write-Host "  '$key' will be registered (mode=$script:FingerprintMode) on first deploy." -ForegroundColor Green
        return
    }

    if ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $entries.Count) {
        $sel = $entries[[int]$pick - 1]
        $script:TargetEnvironment = $sel.Name
        $selMode = if ($sel.Value.mode) { [string]$sel.Value.mode } else { "warn" }
        if ($selMode -eq "block") {
            Write-Host "  '$($sel.Name)' is BLOCK mode -- the connected tenant must be $($sel.Value.tenantId) or the deploy is refused." -ForegroundColor Yellow
        } else {
            Write-Host "  Target set to '$($sel.Name)' [$selMode]." -ForegroundColor Green
        }
        return
    }

    Write-Host "  Invalid selection; keeping current target." -ForegroundColor Yellow
}

function Get-SampleDeploymentNames {
    # Returns an ordered map of component -> sample generated object names, so the user
    # can eyeball the actual naming (not just the bare prefix) before deploying.
    param([hashtable]$Config)
    $samples = [ordered]@{}

    try {
        $policyNames = @(Get-ExpectedDlpPolicyNameSet -Config $Config | Sort-Object)
        if ($policyNames.Count -gt 0) {
            $samples['DLP policy'] = @($policyNames | Select-Object -First 3)
        }
    } catch { }

    $regPath = [System.IO.Path]::Combine($ProjectRoot, 'xml', 'deploy', 'deploy-registry.json')
    if (Test-Path -LiteralPath $regPath) {
        try {
            $reg = Get-Content -Raw -LiteralPath $regPath | ConvertFrom-Json
            $keys = @(@($reg.packages) | ForEach-Object { $_.key } | Where-Object { $_ } | Select-Object -First 3)
            if ($keys.Count -gt 0) { $samples['Classifier package'] = $keys }
        } catch { }
    }

    return $samples
}

function Confirm-ConfigSkew {
    # Show config skew (tenant vs global) for the selected environment and confirm.
    # No env or no tenant overrides -> no skew -> silent pass (zero friction).
    if (-not $script:TargetEnvironment) { return $true }
    $skew = @(Compare-TenantConfigSkew -ProjectRoot $ProjectRoot -Environment $script:TargetEnvironment)
    if ($skew.Count -eq 0) { return $true }

    Write-Host ""
    Write-Host "  --- Config Skew ($($script:TargetEnvironment) vs global) ---" -ForegroundColor Cyan
    foreach ($d in $skew) {
        $g = if ($null -eq $d.global) { '(absent)' } else { [string]$d.global }
        $t = if ($null -eq $d.tenant) { '(absent)' } else { [string]$d.tenant }
        Write-Host ("    {0}: {1} [{2}]  global='{3}'  tenant='{4}'" -f $d.file, $d.path, $d.kind, $g, $t) -ForegroundColor Yellow
    }
    Write-Host ("    {0} difference(s) from global." -f $skew.Count) -ForegroundColor Yellow
    Write-Host ""
    return (Read-YesNo "Proceed with this tenant config as-is?" -Default $false)
}

function Confirm-DeploymentNaming {
    # Show the resolved prefix/suffix + sample object names and confirm before deploying.
    # Declining lets the user override the prefix in place (re-derives + re-previews) or abort.
    while ($true) {
        $cfg    = $script:_Config
        $prefix = $cfg.namingPrefix
        $suffix = $cfg.namingSuffix

        Write-Host ""
        Write-Host "  --- Deployment Naming ---" -ForegroundColor Cyan
        Write-Host "    Prefix: $prefix" -NoNewline -ForegroundColor White
        if ($suffix) { Write-Host "    Suffix: $suffix" -ForegroundColor White } else { Write-Host "" }

        $samples = Get-SampleDeploymentNames -Config $cfg
        if ($samples.Count -eq 0) {
            Write-Host "    (no sample names available -- check config/policies.json and xml/deploy/deploy-registry.json)" -ForegroundColor DarkGray
        } else {
            foreach ($k in $samples.Keys) {
                Write-Host "    Example $k names:" -ForegroundColor DarkGray
                foreach ($n in $samples[$k]) { Write-Host "      - $n" -ForegroundColor Gray }
            }
        }
        Write-Host ""

        if (Read-YesNo "Proceed with this naming?" -Default $true) { return $true }

        $newPrefix = Read-OptionalValue -Prompt "New prefix (Enter = abort deploy)" -Current ""
        if (-not $newPrefix) {
            Write-Host "  Deploy aborted at naming confirmation." -ForegroundColor Yellow
            return $false
        }
        $script:Prefix  = $newPrefix
        $script:_Config = Set-DeploymentConfigPrefix -Config $script:_Config -Prefix $newPrefix
        $script:_Prefix = $script:_Config.namingPrefix
    }
}

function Set-RolloutContext {
    Write-Host ""
    Write-Host "  --- Tenant / Rollout Context ---" -ForegroundColor Cyan
    $script:Tenant = Read-OptionalValue -Prompt "Tenant domain or GUID" -Current $script:Tenant
    Select-TargetEnvironment
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
    if ($script:RegisterFingerprint) { $commonArgs += "-RegisterFingerprint" }
    if ($script:RegisterFingerprint) {
        $commonArgs += @("-FingerprintMode", $script:FingerprintMode)
        if ($script:ExpectedTenantId) { $commonArgs += @("-ExpectedTenantId", $script:ExpectedTenantId) }
    }
    return $commonArgs
}

# ── Engine routing (Stage 5 D1/D4/D6) ──────────────────────────────────────────
# Builds a New-Compl8Context from the current TUI selection (Tenant/Env/Prefix/UPN/Delegated). Pure
# file resolution; returns $null when -UseEngine is off, no environment is selected, or the env is not
# yet pinned (so the TUI silently keeps the leaf path until a workspace/tenant.json exists).
function Get-Compl8DeployContext {
    if (-not $UseEngine -or -not $script:TargetEnvironment) { return $null }
    $ctxArgs = @{ TargetEnvironment = $script:TargetEnvironment }
    if ($WorkspaceRoot)      { $ctxArgs["WorkspaceRoot"] = $WorkspaceRoot }
    if ($script:Prefix)      { $ctxArgs["Prefix"] = $script:Prefix }
    if ($script:UPN)         { $ctxArgs["UPN"] = $script:UPN }
    if ($script:Delegated)   { $ctxArgs["Delegated"] = $true }
    try {
        return New-Compl8Context @ctxArgs
    } catch {
        Write-Host "  (Engine context unavailable: $($_.Exception.Message) — using leaf path.)" -ForegroundColor DarkYellow
        return $null
    }
}

# True when the Engine should drive this object type (opt-in + a context + that type's route is ON).
function Test-Compl8PhaseRoutesToEngine {
    param([Parameter(Mandatory)][string]$RouteKey)
    if (-not $UseEngine) { return $false }
    $ctx = Get-Compl8DeployContext
    if (-not $ctx) { return $false }
    $prop = $ctx.EngineRoutes.PSObject.Properties[$RouteKey]
    return ($prop -and [bool]$prop.Value)
}

# Routes ONE object type through the Engine. The context is SCOPED to just this route (others forced
# off) so Invoke-Compl8Deploy applies only this type and defers the rest — preserving the menu/wizard
# per-type flow. Per-type apply content is threaded by that type's Stage-5C cutover slice; until then
# this is a safe plan/preview (and the default routes-off state never reaches here).
function Invoke-Compl8EnginePhase {
    param(
        [Parameter(Mandatory)][ValidateSet('dictionary', 'label', 'rulePackage', 'dlpRule', 'autoLabel')][string]$RouteKey,
        [Parameter(Mandatory)][string]$PhaseLabel,
        [switch]$WhatIf,
        [hashtable]$DesiredContent = @{}
    )
    $ctx = Get-Compl8DeployContext
    if (-not $ctx) { Write-Host "  Engine context unavailable; skipping $PhaseLabel." -ForegroundColor Yellow; return }
    $scopedRoutes = [pscustomobject]@{ dictionary = $false; label = $false; rulePackage = $false; dlpRule = $false; autoLabel = $false }
    $scopedRoutes.$RouteKey = $true
    $scoped = $ctx.PSObject.Copy()
    $scoped.EngineRoutes = $scopedRoutes

    # SAFETY (codex 5B P1): until a type's Stage-5C slice wires its per-step desired content, a routed
    # REAL apply would hand the executors $null content (broken create/update). So when NO DesiredContent
    # is supplied, force PLAN-ONLY (preview) regardless of -WhatIf; a 5C slice enables real apply by
    # passing -DesiredContent. (Routes default off, so this only matters once an operator flips one.)
    $planOnly = [bool]$WhatIf
    if (-not $planOnly -and @($DesiredContent.Keys).Count -eq 0) {
        Write-Host "  No desired content wired for '$RouteKey' yet — Engine runs PLAN-ONLY (preview). Real apply lands in this type's Stage-5C cutover." -ForegroundColor Yellow
        $planOnly = $true
    }

    $deployArgs = @{
        Context        = $scoped
        PlanId         = "deploy-$($ctx.Environment)-$RouteKey-$($script:DeployStamp)"
        GeneratedUtc   = $script:DeployGeneratedUtc
        ProjectRoot    = $ProjectRoot
        DesiredContent = $DesiredContent
    }
    if ($planOnly) { $deployArgs["WhatIf"] = $true }
    $result = Invoke-Compl8Deploy @deployArgs
    if ($result.render) { Write-Host $result.render }
    $result
}

# ── Reconcile / Migrate walk (Stage 5 Reconciliation R5; D6 — the TUI walks, the Engine decides) ──
# Operator-gated, opt-in (-UseEngine). Surfaces the assessment's name-collisions + orphans as a
# WALKABLE set (Get-Compl8ReconcileCandidates), each with its R3 removal blast-radius; collects a
# per-candidate resolution (claim/remove/leave/keep) interactively; runs the Engine reconcile verb
# (Invoke-Compl8Reconcile) and renders the resulting iteration walk (Get-Compl8ReconciliationReport).
# All intelligence lives in the Engine — this handler only prompts + prints, then writes the first
# (appliable) iteration's plan and hands it to Invoke-Compl8Apply behind an explicit confirmation.
function Invoke-Compl8ReconcileMenu {
    param([ref]$Connected)

    if (-not $UseEngine) {
        Write-Host "  Reconcile / Migrate is an Engine path — re-run with -UseEngine." -ForegroundColor Yellow
        return
    }
    $ctx = Get-Compl8DeployContext
    if (-not $ctx) {
        Write-Host "  Engine context unavailable (select a pinned target environment under -UseEngine)." -ForegroundColor Yellow
        return
    }

    # The recorded actual state (read-only; produced by scripts/record-engine-fixtures.ps1 -Connect).
    $invPath = Join-Path $ctx.WorkspacePath 'actual' 'inventory.json'
    if (-not (Test-Path -LiteralPath $invPath -PathType Leaf)) {
        Write-Host "  No recorded inventory at $invPath." -ForegroundColor Yellow
        Write-Host "  Record the tenant first (operator, connected): scripts/record-engine-fixtures.ps1 -Connect -TargetEnvironment $($ctx.Environment) -Prefix $($ctx.Prefix)" -ForegroundColor DarkYellow
        return
    }

    Write-Host "  Assessing '$($ctx.Environment)' (desired vs recorded actual)..." -ForegroundColor Cyan
    $assessment = Invoke-Compl8Assess -WorkspacePath $ctx.WorkspacePath -InventoryPath $invPath `
        -Workspace $ctx.Environment -GeneratedUtc $script:DeployGeneratedUtc -ConfigRoot $ConfigPath
    Write-Host (Get-Compl8AssessmentReport -Assessment $assessment)

    # Reference graph over the recorded actual objects — the substrate for blast-radius + cascade.
    $inv = Get-Content -LiteralPath $invPath -Raw | ConvertFrom-Json
    $graph = Get-DeploymentReferenceGraph `
        -Dictionaries @($inv.objects.dictionaries) `
        -SitPackages  @($inv.objects.sitPackages) `
        -DlpRules     @($inv.objects.dlpRules) `
        -DlpPolicies  @($inv.objects.dlpPolicies)

    $candidates = @(Get-Compl8ReconcileCandidates -Assessment $assessment -Graph $graph)
    if ($candidates.Count -eq 0) {
        Write-Host "  Nothing to reconcile — no name-collisions or orphans surfaced." -ForegroundColor Green
        return
    }

    Write-Host ""
    Write-Host "  --- Reconciliation walk: choose a resolution per item ---" -ForegroundColor Cyan
    $resolutions = [System.Collections.Generic.List[object]]::new()
    foreach ($cand in $candidates) {
        Write-Host ""
        Write-Host ("  [{0}] {1} '{2}'" -f $cand.kind, $cand.objectType, $cand.ref) -ForegroundColor White
        if ($cand.detail) { Write-Host ("      {0}" -f $cand.detail) -ForegroundColor Gray }
        if ($cand.blastRadius -and @($cand.blastRadius.referencingRules).Count -gt 0) {
            $blk = if ($cand.blastRadius.blocked) { ' [dereference required first]' } else { '' }
            Write-Host ("      Removal impact -> referencing rules: {0}{1}" -f (@($cand.blastRadius.referencingRules) -join ', '), $blk) -ForegroundColor DarkYellow
        }
        $opts = @($cand.allowedResolutions) -join '/'
        $pick = (Read-Host ("      Resolution [{0}] (Enter = skip)" -f $opts)).Trim().ToLower()
        if (-not $pick) { continue }
        if (@($cand.allowedResolutions) -notcontains $pick) {
            Write-Host "      '$pick' is not allowed here; skipping." -ForegroundColor Yellow
            continue
        }
        $resolutions.Add([pscustomobject]@{ objectType = $cand.objectType; ref = $cand.ref; resolution = $pick }) | Out-Null
    }

    if ($resolutions.Count -eq 0) {
        Write-Host "  No resolutions chosen — nothing to reconcile." -ForegroundColor Yellow
        return
    }

    $recon = Invoke-Compl8Reconcile -Assessment $assessment -Graph $graph -Resolutions @($resolutions) `
        -Workspace $ctx.Environment -PlanIdPrefix "reconcile-$($ctx.Environment)-$($script:DeployStamp)" `
        -GeneratedUtc $script:DeployGeneratedUtc
    Write-Host ""
    Write-Host (Get-Compl8ReconciliationReport -Reconciliation $recon)

    $first = @($recon.iterations | Sort-Object index)[0]
    if (-not $first) { Write-Host "  No iterations to apply." -ForegroundColor Yellow; return }

    # Persist iteration 1's plan so it is ready for apply via whichever path is appropriate.
    $planPath = Join-Path $ctx.WorkspacePath 'history' 'plans' ("$($first.plan.id).json")
    $planDir  = Split-Path -Parent $planPath
    if (-not (Test-Path -LiteralPath $planDir)) { New-Item -ItemType Directory -Path $planDir -Force | Out-Null }
    $first.plan | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $planPath -Encoding UTF8 -NoNewline
    Write-Host ""
    Write-Host "  Iteration 1 plan written: $planPath" -ForegroundColor Cyan
    Write-Host "  Only iteration 1 is appliable now; projected iterations must be re-walked after re-recording the inventory (APPLY CONTRACT)." -ForegroundColor DarkCyan

    # SAFE-APPLY SCOPE (codex R5): only a CLAIM-ONLY iteration 1 is applied directly here. Claims are
    # non-destructive (no snapshot step) and need no resolved desired content, so the canonical apply
    # runs with a minimal executor map. A plan that also creates/updates (needs DesiredContent) or
    # removes/dereferences (needs the snapshot-executor context) MUST be applied through the per-type
    # deploy path that threads that context — applying it here with an empty map would fail or under-apply.
    $steps = @($first.plan.steps)
    $claimOnly = ($steps.Count -gt 0) -and (@($steps | Where-Object { [string]$_.action -ne 'claim' }).Count -eq 0)
    if (-not $claimOnly) {
        Write-Host "  Iteration 1 carries create/update/remove/dereference steps needing desired-content + snapshot context." -ForegroundColor Yellow
        Write-Host "  Apply it through the per-type deploy path (which threads that context); this walk is preview + plan only." -ForegroundColor DarkYellow
        return
    }

    Write-Host "  Iteration 1 is CLAIM-ONLY (adopt ownership; non-destructive, content-free)." -ForegroundColor Cyan
    if ((Read-Host "  Type APPLY to adopt these objects now, anything else to preview-only").Trim() -cne 'APPLY') {
        Write-Host "  Preview only — no changes applied." -ForegroundColor Cyan
        return
    }
    if (-not (Require-Connection -Connected $Connected)) { return }
    Invoke-Compl8Apply -PlanPath $planPath -ProjectRoot $ProjectRoot -TargetEnvironment $ctx.Environment `
        -ExecutorMap (Get-Compl8ExecutorMap -StepContent @{} -Prefix $ctx.Prefix) | Out-Null
    Write-Host "  Claimed. The adopted objects now bucket as drift — re-record the inventory and reconcile/deploy them via the per-type path." -ForegroundColor Green
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
        Write-Host "    A. Update from TestPattern " -NoNewline -ForegroundColor Green
        Write-Host "[regenerates local files]" -ForegroundColor DarkGray
        Write-Host "       Pull the latest catalogue/bundle into local config + XML," -ForegroundColor DarkGray
        Write-Host "       then re-check. Review the git diff before deploying." -ForegroundColor DarkGray
        Write-Host "    B. Continue with current local content " -NoNewline -ForegroundColor Yellow
        Write-Host "[ignores drift]" -ForegroundColor DarkGray
        Write-Host "       Proceed using what's on disk now, accepting the difference." -ForegroundColor DarkGray
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

    Select-TargetEnvironment

    if (Test-Compl8PhaseRoutesToEngine 'label') {
        Write-Host ""
        Write-Host "  --- Deploy Labels (Engine) ---" -ForegroundColor Cyan
        $dryRun = Read-YesNo "Dry run (WhatIf preview)?" -Default $true
        Invoke-Compl8EnginePhase -RouteKey 'label' -PhaseLabel 'Labels' -WhatIf:$dryRun | Out-Null
        return
    }

    if (-not (Confirm-ConfigSkew)) { return }

    Write-Host ""
    Write-Host "  --- Deploy Labels ---" -ForegroundColor Cyan
    if (Read-YesNo "Check live TestPattern drift before deploying labels?" -Default $true) {
        if (-not (Invoke-TestPatternDriftDecision)) { return }
    }
    $dryRun   = Read-YesNo "Dry run (WhatIf)?" -Default $true
    $publish  = Read-YesNo "Publish labels after creation?"
    $noMark   = Read-YesNo "Skip visual markings?"

    if (-not (Confirm-DeploymentNaming)) { return }
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

    Select-TargetEnvironment

    if (Test-Compl8PhaseRoutesToEngine 'rulePackage') {
        Write-Host ""
        Write-Host "  --- Deploy Classifiers (Engine) ---" -ForegroundColor Cyan
        $dryRun = Read-YesNo "Dry run (WhatIf preview)?" -Default $true
        Invoke-Compl8EnginePhase -RouteKey 'rulePackage' -PhaseLabel 'Classifiers' -WhatIf:$dryRun | Out-Null
        return
    }

    if (-not (Confirm-ConfigSkew)) { return }

    Write-Host ""
    Write-Host "  --- Deploy Classifiers ---" -ForegroundColor Cyan
    Write-Host "    1. Guided deploy " -NoNewline -ForegroundColor White
    Write-Host "[writes to tenant]" -ForegroundColor Red
    Write-Host "       Compare -> backup -> prompt -> upload. Safest path when the" -ForegroundColor DarkGray
    Write-Host "       tenant may already have custom packages." -ForegroundColor DarkGray
    Write-Host "    2. Generate refit plan " -NoNewline -ForegroundColor Green
    Write-Host "[read-only]" -ForegroundColor DarkGray
    Write-Host "       Plan how your packages fit into EXISTING tenant packages." -ForegroundColor DarkGray
    Write-Host "       Writes a plan file; deploys nothing." -ForegroundColor DarkGray
    Write-Host "    3. Apply refit plan " -NoNewline -ForegroundColor Green
    Write-Host "[WhatIf preview]" -ForegroundColor DarkGray
    Write-Host "       Preview applying a plan from option 2. Makes no changes." -ForegroundColor DarkGray
    Write-Host "    4. Direct upload " -NoNewline -ForegroundColor Yellow
    Write-Host "[writes to tenant]" -ForegroundColor Red
    Write-Host "       GREENFIELD/empty tenants only -- no merge logic. Refuses" -ForegroundColor DarkGray
    Write-Host "       unless you confirm the tenant is empty." -ForegroundColor DarkGray
    Write-Host "    5. Validate local XML " -NoNewline -ForegroundColor White
    Write-Host "[offline]" -ForegroundColor DarkGray
    Write-Host "       Structural check of local XML. No tenant connection." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Select: " -NoNewline
    $operation = (Read-Host).Trim()

    Write-Host "  Tier [small/medium/large] (Enter = all tiers): " -NoNewline
    $tier = (Read-Host).Trim().ToLower()
    if ($operation -in @("1", "2", "3", "4")) {
        if (-not (Confirm-DeploymentNaming)) { return }
    }
    $commonArgs = @(Get-CommonDeploymentArgs)
    if ($operation -in @("1", "2", "3", "4") -and (Read-YesNo "Check live TestPattern drift before using classifier content?" -Default $true)) {
        if (-not (Invoke-TestPatternDriftDecision)) { return }
    }

    switch ($operation) {
        "1" {
            $params = @("-Action", "Interactive") + $commonArgs
            if ($tier -in @("small", "medium", "large")) { $params += @("-Tier", $tier) }
            Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList $params
            return
        }
        "2" {
            $params = @("-Action", "RefitPlan") + $commonArgs
            if ($tier -in @("small", "medium", "large")) { $params += @("-Tier", $tier) }
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
            if ($tier -in @("small", "medium", "large")) { $params += @("-Tier", $tier) }
            if ($dryRun)  { $params += "-WhatIf" }
            if ($skip)    { $params += "-SkipPreFlight" }
            Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList $params
            return
        }
        "5" {
            $params = @("-Action", "Validate")
            if ($tier -in @("small", "medium", "large")) { $params += @("-Tier", $tier) }
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

    Select-TargetEnvironment

    if (Test-Compl8PhaseRoutesToEngine 'dlpRule') {
        Write-Host ""
        Write-Host "  --- Deploy DLP Rules (Engine) ---" -ForegroundColor Cyan
        $dryRun = Read-YesNo "Dry run (WhatIf preview)?" -Default $true
        Invoke-Compl8EnginePhase -RouteKey 'dlpRule' -PhaseLabel 'DLPRules' -WhatIf:$dryRun | Out-Null
        return
    }

    if (-not (Confirm-ConfigSkew)) { return }

    Write-Host ""
    Write-Host "  --- Deploy DLP Rules ---" -ForegroundColor Cyan
    if (Read-YesNo "Check live TestPattern drift before deploying DLP rules?" -Default $true) {
        if (-not (Invoke-TestPatternDriftDecision)) { return }
    }
    $dryRun    = Read-YesNo "Dry run (WhatIf)?" -Default $true
    $skipVal   = Read-YesNo "Skip SIT validation?"
    $skipVerif = Read-YesNo "Skip post-deploy verification?"

    if (-not (Confirm-DeploymentNaming)) { return }
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
    Write-Host "    1. Generate change pack " -NoNewline -ForegroundColor Cyan
    Write-Host "[read-only]" -ForegroundColor DarkGray
    Write-Host "       Diff tenant vs local config; writes a CSV of the changes." -ForegroundColor DarkGray
    Write-Host "       No tenant changes -- review the CSV before applying." -ForegroundColor DarkGray
    Write-Host "    2. Apply change pack " -NoNewline -ForegroundColor Cyan
    Write-Host "[writes to tenant]" -ForegroundColor Red
    Write-Host "       Apply the edits from a change-pack CSV back to the tenant." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Select: " -NoNewline
    $subChoice = (Read-Host).Trim()

    if ($subChoice -in @("1", "2") -and (Read-YesNo "Check live TestPattern drift before running the change pack?" -Default $true)) {
        if (-not (Invoke-TestPatternDriftDecision)) { return }
    }

    # Pick the tenant config context so the change pack diffs/applies against the
    # same per-tenant config the deploy scripts use (not silently global).
    if ($subChoice -in @("1", "2")) { Select-TargetEnvironment }

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
            if ($script:TargetEnvironment) { $params += @("-TargetEnvironment", $script:TargetEnvironment) }

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
            if ($script:TargetEnvironment) { $params += @("-TargetEnvironment", $script:TargetEnvironment) }

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

function Invoke-GuidedClassifierRemoval {
    # Gated classifier removal per CLASSIFIER-REMOVAL-RUNBOOK.md. Thin driver over the gated
    # scripts; all hard gates (refit-plan, reference guard) live in Deploy-Classifiers.ps1.
    param(
        [ref]$Connected,
        [switch]$SnapshotAlreadyRun
    )
    if (-not (Require-Connection $Connected)) { return }

    Write-Host ""
    Write-Host "  === Guided Classifier Removal (gated) ===" -ForegroundColor Cyan
    Write-Host "  Snapshot -> plan -> clear references -> dry-run -> gated remove -> verify." -ForegroundColor DarkGray

    if (-not $script:TargetEnvironment) { Select-TargetEnvironment }
    $commonArgs = @(Get-CommonDeploymentArgs)

    # Step 0.5 - snapshot (skip when the caller already captured one this session)
    if (-not $SnapshotAlreadyRun) {
        if (Read-YesNo "Step 0.5: capture a read-only tenant snapshot first (STRONGLY recommended)?" -Default $true) {
            $snapArgs = @()
            if ($script:TargetEnvironment) { $snapArgs += @("-TargetEnvironment", $script:TargetEnvironment) }
            try {
                Invoke-ToolkitScript -ScriptName "Export-TenantSnapshot.ps1" -ArgumentList $snapArgs
            } catch {
                Write-Host "  Snapshot FAILED: $($_.Exception.Message)" -ForegroundColor Red
                if (-not (Read-YesNo "Continue the removal WITHOUT a verified snapshot?" -Default $false)) {
                    Write-Host "  Aborted." -ForegroundColor Yellow; return
                }
            }
        } else {
            Write-Host "  Proceeding WITHOUT a snapshot." -ForegroundColor Yellow
            if (-not (Read-YesNo "Delete with NO backup?" -Default $false)) {
                Write-Host "  Aborted." -ForegroundColor Yellow; return
            }
        }
    }

    # Step 0 - inventory
    Write-Host "`n  Step 0: deployed classifier packages" -ForegroundColor Cyan
    Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList (@("-Action", "List") + $commonArgs)

    Write-Host ""
    Write-Host "  Enter registry package key(s) to RETIRE, comma-separated (e.g. QGISCF-medium-08):" -ForegroundColor White
    Write-Host "  (Only packages in deploy-registry.json are removable here; unregistered tenant packages are not.)" -ForegroundColor DarkGray
    $pkgInput = (Read-Host "  Packages").Trim()
    if ([string]::IsNullOrWhiteSpace($pkgInput)) { Write-Host "  No packages entered; aborting." -ForegroundColor Yellow; return }
    $packageNames = @($pkgInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($packageNames.Count -eq 0) { Write-Host "  No valid package keys entered; aborting." -ForegroundColor Yellow; return }

    if (Read-YesNo "Show dependency impact across deployed packages?" -Default $true) {
        foreach ($pkg in $packageNames) {
            Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList (@("-Action", "Impact", "-ImpactMode", "Remove", "-PackageNames", $pkg) + $commonArgs)
        }
    }

    # Step 1 - retire plan
    Write-Host "`n  Step 1: generating retire plan..." -ForegroundColor Cyan
    Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList (@("-Action", "RefitPlan") + $commonArgs)
    $planPath = Read-RefitPlanPath
    if (-not $planPath -or -not (Test-Path -LiteralPath $planPath -PathType Leaf)) {
        Write-Host "  No valid refit plan; aborting removal." -ForegroundColor Red; return
    }
    Show-RefitPlanEvidence -PlanPath $planPath
    Write-Host "  Confirm each target package is classified RetireCandidate (or Reusable*Slot)" -ForegroundColor Yellow
    Write-Host "  in the plan above, and review any referencing DLP rules it lists." -ForegroundColor Yellow

    # Step 2 - clear references (pause + re-check loop)
    $override = $false
    if (Read-YesNo "Do any DLP rules still reference the classifiers being removed?" -Default $true) {
        while ($true) {
            Write-Host ""
            Write-Host "  Clear them first: drop the SIT(s) from config/classifiers.json and redeploy rules" -ForegroundColor Yellow
            Write-Host "  (menu [R]/[4] or Deploy-DLPRules), or remove the rules. Then return here." -ForegroundColor Yellow
            $ans = (Read-Host "  Press Enter to re-check once rules are updated (or type SKIP to override)").Trim()
            if ($ans.ToUpper() -eq 'SKIP') {
                Write-Host "  OVERRIDE will delete despite live references, leaving rules pointing at a deleted SIT." -ForegroundColor Red
                if ((Read-Host "  Type OVERRIDE to confirm, anything else to keep clearing").Trim() -ceq 'OVERRIDE') { $override = $true; break }
                continue
            }
            Write-Host "  Re-checking references..." -ForegroundColor Cyan
            foreach ($pkg in $packageNames) {
                Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList (@("-Action", "Impact", "-ImpactMode", "Remove", "-PackageNames", $pkg) + $commonArgs)
            }
            if (Read-YesNo "Did the impact check show ZERO referencing rules for your targets now?" -Default $false) { break }
        }
    }

    # Step 3 - dry-run (per package; Invoke-ToolkitScript binds one value per -Param)
    Write-Host "`n  Step 3: removal dry-run (WhatIf)..." -ForegroundColor Cyan
    foreach ($pkg in $packageNames) {
        Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList (@("-Action", "Remove", "-PackageNames", $pkg, "-WhatIf") + $commonArgs)
    }

    # Step 4 - gated removal
    Write-Host ""
    Write-Host "  Step 4: execute the gated removal of: $($packageNames -join ', ')" -ForegroundColor Cyan
    if ((Read-Host "  Type REMOVE (uppercase) to delete, anything else to abort").Trim() -cne 'REMOVE') {
        Write-Host "  Aborted. Nothing deleted." -ForegroundColor Yellow; return
    }
    foreach ($pkg in $packageNames) {
        $removeArgs = @("-Action", "Remove", "-PackageNames", $pkg, "-RefitPlanPath", $planPath, "-ApproveRefitPlan")
        if ($override) { $removeArgs += "-AllowBreakingClassifierReferences" }
        $removeArgs += $commonArgs
        Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList $removeArgs
    }

    # Step 5 - verify
    Write-Host "`n  Step 5: verify..." -ForegroundColor Cyan
    Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList (@("-Action", "List") + $commonArgs)
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

    # 0. Pre-destructive snapshot (rebuild-grade "old config" backup)
    $rolloutSnapshotRan = $false
    Write-Host ""
    Write-Host "  Phase 0: Tenant snapshot (read-only backup before any change)" -ForegroundColor Cyan
    if (Read-YesNo "Capture a tenant snapshot now (recommended before a replace)?" -Default $true) {
        $snapArgs = @()
        if ($script:TargetEnvironment) { $snapArgs += @("-TargetEnvironment", $script:TargetEnvironment) }
        try {
            Invoke-ToolkitScript -ScriptName "Export-TenantSnapshot.ps1" -ArgumentList $snapArgs
            $rolloutSnapshotRan = $true
        } catch {
            Write-Host "  Snapshot FAILED: $($_.Exception.Message)" -ForegroundColor Red
            if (-not (Read-YesNo "Continue the rollout WITHOUT a verified snapshot?" -Default $false)) {
                Write-Host "  Rollout aborted." -ForegroundColor Yellow; return
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

    # 1.5 Fit & coverage preview (read-only): will the new classifier set fit, and do rules cover it?
    Write-Host ""
    Write-Host "  Phase 1.5: Fit & coverage preview (read-only)" -ForegroundColor Cyan
    if (Read-YesNo "Preview classifier capacity/fit and DLP rule coverage before deploying?" -Default $true) {
        Write-Host "  -- Classifier capacity / fit (slots, package size, dictionary budget) --" -ForegroundColor DarkCyan
        Invoke-ToolkitScript -ScriptName "Deploy-Classifiers.ps1" -ArgumentList (@("-Action", "CapacityPlan") + $commonArgs)
        Write-Host "  -- DLP rule coverage (any SITs referenced by config but missing from tenant) --" -ForegroundColor DarkCyan
        Invoke-ToolkitScript -ScriptName "Deploy-DLPRules.ps1" -ArgumentList (@("-WhatIf") + $commonArgs)
        if (-not (Read-YesNo "Preview looks acceptable - continue the rollout?" -Default $true)) {
            Write-Host "  Rollout aborted after preview." -ForegroundColor Yellow
            return
        }
    }

    # 3. Cleanup (optional) — broad scoped reset OR surgical gated package removal
    Write-Host ""
    Write-Host "  Phase 3/6: Cleanup of prior toolkit-owned objects (optional)" -ForegroundColor Cyan
    Write-Host "    B. Broad scoped reset (Reset-DeploymentScope)" -ForegroundColor White
    Write-Host "    S. Surgical gated removal of specific classifier packages" -ForegroundColor White
    Write-Host "    N. No cleanup" -ForegroundColor Gray
    $cleanupChoice = (Read-Host "  Select [B/S/N]").Trim().ToUpper()
    switch ($cleanupChoice) {
        "B" {
            Write-Host "  Broad reset is destructive. Type the word CLEANUP (uppercase) to confirm: " -NoNewline -ForegroundColor Yellow
            if ((Read-Host).Trim() -ceq 'CLEANUP') {
                $cleanupArgs = @("-Action", "Execute", "-Force") + $commonArgs
                Invoke-ToolkitScript -ScriptName "Reset-DeploymentScope.ps1" -ArgumentList $cleanupArgs
            } else {
                Write-Host "  Cleanup skipped." -ForegroundColor Yellow
            }
        }
        "S" {
            Invoke-GuidedClassifierRemoval -Connected $Connected -SnapshotAlreadyRun:$rolloutSnapshotRan
        }
        default {
            Write-Host "  No cleanup." -ForegroundColor Gray
        }
    }

    # 4. Labels
    Write-Host ""
    Write-Host "  Phase 4/6: Labels" -ForegroundColor Cyan
    if (Test-Compl8PhaseRoutesToEngine 'label') {
        Invoke-Compl8EnginePhase -RouteKey 'label' -PhaseLabel 'Labels' -WhatIf | Out-Null
        if (Read-YesNo "WhatIf looked good — apply labels (Engine) for real?" -Default $false) {
            Invoke-Compl8EnginePhase -RouteKey 'label' -PhaseLabel 'Labels' | Out-Null
        }
    } elseif (Read-YesNo "Deploy labels (WhatIf preview first)?" -Default $true) {
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
    $classifiersApplied = $false
    if (Test-Compl8PhaseRoutesToEngine 'rulePackage') {
        Invoke-Compl8EnginePhase -RouteKey 'rulePackage' -PhaseLabel 'Classifiers' -WhatIf | Out-Null
        if (Read-YesNo "WhatIf looked good — apply classifiers (Engine) for real?" -Default $false) {
            Invoke-Compl8EnginePhase -RouteKey 'rulePackage' -PhaseLabel 'Classifiers' | Out-Null
            $classifiersApplied = $true
        }
    } else {
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
                $classifiersApplied = $true
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
                    $classifiersApplied = $true
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
    }

    # Propagation checkpoint: custom SITs take 4-24h to become visible to the DLP engine.
    if ($classifiersApplied) {
        Write-Host ""
        Write-Host "  Custom SITs were just uploaded. They take 4-24h to propagate before DLP rules" -ForegroundColor Yellow
        Write-Host "  that reference them will match. Deploying rules now may warn about not-yet-visible SITs." -ForegroundColor Yellow
        if (-not (Read-YesNo "Continue to DLP rules now (No = stop here and run rules in a later session)?" -Default $false)) {
            Write-Host "  Stopping before DLP rules. Re-run the wizard (or menu [7]) after propagation." -ForegroundColor Cyan
            return
        }
    }

    # 6. DLP rules
    Write-Host ""
    Write-Host "  Phase 6/6: DLP rules" -ForegroundColor Cyan
    if (Test-Compl8PhaseRoutesToEngine 'dlpRule') {
        Invoke-Compl8EnginePhase -RouteKey 'dlpRule' -PhaseLabel 'DLPRules' -WhatIf | Out-Null
        if (Read-YesNo "WhatIf looked good — apply DLP rules (Engine) for real?" -Default $false) {
            Invoke-Compl8EnginePhase -RouteKey 'dlpRule' -PhaseLabel 'DLPRules' | Out-Null
        }
    } elseif (Read-YesNo "Deploy DLP rules (WhatIf preview first)?" -Default $true) {
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

function Invoke-ConfigSkewReport {
    $env = $script:TargetEnvironment
    if (-not $env) {
        $env = Read-OptionalValue -Prompt "Environment key to check (e.g. demo)" -Current ''
    }
    if (-not $env) { Write-Host "  No environment selected." -ForegroundColor Yellow; return }
    Invoke-ToolkitScript -ScriptName "Test-ConfigSkew.ps1" -ArgumentList @("-Environment", $env, "-NoExit")
}

function Invoke-ConfigEdit {
    Write-Host ""
    Write-Host "  --- Edit Config (global / tenant) ---" -ForegroundColor Cyan
    Write-Host "    1. Set a value" -ForegroundColor White
    Write-Host "    2. Pull a global file into a tenant" -ForegroundColor White
    Write-Host "  Select: " -NoNewline
    $choice = (Read-Host).Trim()

    $scopedFiles = @('classifiers.json','policies.json','labels.json','tier-assignments.json','rule-overrides.json','tenant-sits.json','settings.json')

    if ($choice -eq '1') {
        Write-Host "  Config file [$($scopedFiles -join ', ')]: " -NoNewline
        $file = (Read-Host).Trim()
        if ($file -notin $scopedFiles) { Write-Host "  Not a scoped config file." -ForegroundColor Red; return }
        $keyPath = Read-OptionalValue -Prompt "Key path (dotted, e.g. namingPrefix or SENS_X.tier)" -Current ''
        if (-not $keyPath) { Write-Host "  No key path." -ForegroundColor Yellow; return }
        $rawVal = Read-OptionalValue -Prompt "New value (number/true/false/null/JSON/text)" -Current ''
        $value = ConvertTo-ConfigValue -Raw $rawVal

        Write-Host "  Apply to: (G)lobal or (T)enant? " -NoNewline
        $scope = (Read-Host).Trim().ToUpper()
        if ($scope -eq 'G') {
            $dir = Join-Path $ProjectRoot 'config'
            $written = Set-ConfigValue -ConfigDir $dir -File $file -Path $keyPath -Value $value
            Write-Host "  Wrote GLOBAL: $written" -ForegroundColor Green
        } elseif ($scope -eq 'T') {
            $env = Read-OptionalValue -Prompt "Tenant environment key" -Current $script:TargetEnvironment
            if (-not $env) { Write-Host "  No environment." -ForegroundColor Yellow; return }
            $tenantDir = Join-Path (Join-Path $ProjectRoot 'config/tenants') $env
            if (-not (Test-Path -LiteralPath $tenantDir -PathType Container)) {
                if (-not (Read-YesNo "Tenant '$env' has no config yet. Seed a full copy from global now?" -Default $true)) { return }
                Invoke-ToolkitScript -ScriptName "New-TenantConfig.ps1" -ArgumentList @("-Environment", $env)
            }
            $written = Set-ConfigValue -ConfigDir $tenantDir -File $file -Path $keyPath -Value $value
            Write-Host "  Wrote TENANT '$env': $written" -ForegroundColor Green
        } else {
            Write-Host "  Cancelled." -ForegroundColor Yellow
        }
        return
    }

    if ($choice -eq '2') {
        $env = Read-OptionalValue -Prompt "Tenant environment key" -Current $script:TargetEnvironment
        if (-not $env) { Write-Host "  No environment." -ForegroundColor Yellow; return }
        Write-Host "  Global file to pull [$($scopedFiles -join ', ')]: " -NoNewline
        $file = (Read-Host).Trim()
        if ($file -notin $scopedFiles) { Write-Host "  Not a scoped config file." -ForegroundColor Red; return }
        try {
            $written = Copy-GlobalConfigToTenant -ProjectRoot $ProjectRoot -Environment $env -File $file
            Write-Host "  Pulled global -> $written" -ForegroundColor Green
        } catch {
            Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        }
        return
    }

    Write-Host "  Invalid selection." -ForegroundColor Yellow
}

#endregion

#region Main Loop
# Check if we're already connected
$isConnected = Test-Connected

while ($true) {
    try { Clear-Host } catch { }
    Show-Menu -Connected $isConnected

    $menuKeys = if ($UseEngine) { "1-12, R, M, C, Q" } else { "1-12, R, C, Q" }
    $choice = Read-Choice "  Enter selection [$menuKeys]"

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
        "10" { Invoke-GuidedClassifierRemoval -Connected ([ref]$isConnected); Pause-AfterRun }
        "11" { Invoke-ValidateXML; Pause-AfterRun }
        "12" { Invoke-TestPatternDriftMenu; Pause-AfterRun }
        "S"  { Invoke-ConfigSkewReport; Pause-AfterRun }
        "E"  { Invoke-ConfigEdit; Pause-AfterRun }
        "R"  { Invoke-CustomerRolloutWizard ([ref]$isConnected); Pause-AfterRun }
        "M"  { Invoke-Compl8ReconcileMenu ([ref]$isConnected); Pause-AfterRun }
        "Q"  { Write-Host "  Bye." -ForegroundColor Gray; exit 0 }
        default { Write-Host "  Invalid choice." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }

}
#endregion
