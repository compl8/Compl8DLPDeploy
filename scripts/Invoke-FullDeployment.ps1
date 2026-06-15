#==============================================================================
# Invoke-FullDeployment.ps1
# Orchestrates DLP deployment in phases:
#   Phase 1:   Labels (immediate)
#   Phase 1.5: Keyword dictionaries (create-or-update, returns GUID map)
#   Phase 2:   SIT classifier packages (patches dictionary placeholders, uploads)
#   Phase 3:   DLP rules (requires SITs to be indexed — up to 24h after upload)
#
# Phases can be run independently or together. When run together, Phase 3
# checks whether custom SITs have propagated and warns if too recent.
#
# Usage:
#   pwsh -File scripts/Invoke-FullDeployment.ps1 -Tenant tenant.onmicrosoft.com -TargetEnvironment tenant-profile
#   pwsh -File scripts/Invoke-FullDeployment.ps1 -UPN admin@tenant.com -Phase Labels        # Labels only
#   pwsh -File scripts/Invoke-FullDeployment.ps1 -Tenant tenant.onmicrosoft.com -Phase Dictionaries
#   pwsh -File scripts/Invoke-FullDeployment.ps1 -Tenant tenant.onmicrosoft.com -Phase Classifiers -TargetEnvironment tenant-profile
#   pwsh -File scripts/Invoke-FullDeployment.ps1 -Tenant tenant.onmicrosoft.com -Phase DLPRules -TargetEnvironment tenant-profile
#   pwsh -File scripts/Invoke-FullDeployment.ps1 -Tenant tenant.onmicrosoft.com -Phase Cleanup -TargetEnvironment tenant-profile
#   pwsh -File scripts/Invoke-FullDeployment.ps1 -Tenant tenant.onmicrosoft.com -Phase Cleanup -SkipLabels  # Teardown, keep labels
#   pwsh -File scripts/Invoke-FullDeployment.ps1 -Tenant tenant.onmicrosoft.com -SkipLabels  # Nuke & redeploy, keep labels
#==============================================================================

param(
    [string]$UPN,
    [ValidateSet("All", "Labels", "Dictionaries", "Classifiers", "DLPRules", "Cleanup")]
    [string]$Phase = "All",
    [string]$PublishTo,
    [string]$Tenant,
    [string]$TargetEnvironment,
    [string]$Prefix,
    [switch]$Delegated,
    [string]$Scope = "universal,en-government,au",
    [string]$DeployDir = "xml/deploy",
    [switch]$SkipLabels,
    [switch]$Force,
    [switch]$AllowBreakingClassifierReferences,
    [switch]$Greenfield,
    [switch]$WhatIf,
    [switch]$RegisterFingerprint,
    [string]$FingerprintMode = 'warn',
    [string]$ExpectedTenantId,
    # Stage 5 (D1/D4/D6): opt-in to the Engine path. When set, the 7-field bundle is mapped into a
    # New-Compl8Context and each phase routes through Invoke-Compl8Deploy IF that object type's route
    # is ON in the context (tenant.json engineRoutes). Routes default ALL FALSE, so even with
    # -UseEngine every type still defers to the leaf path until an operator flips a route after its
    # nonprod shadow trial (5C). WITHOUT -UseEngine the orchestrator behaves byte-for-byte as today.
    [switch]$UseEngine,
    [string]$WorkspaceRoot
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent

Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

# This process is the orchestrator: it runs the drift / config-skew gates itself, so
# child leaf scripts (Deploy-Labels/Classifiers/DLPRules) invoked via & below must not
# re-trip Assert-OrchestrationGate. Same-process & inherits this env var.
$env:COMPL8_ORCHESTRATED = '1'

# ── Load Config ───────────────────────────────────────────────────────────────
# Scoped config (settings, namingPrefix) resolves per-tenant so the orchestrator's
# prefix/dictionary/cleanup decisions match the per-tenant child deploys. Non-scoped
# state (last-classifier-upload.json) is written to the global config dir directly.
$ConfigPath  = Get-EffectiveConfigDir -ProjectRoot $ProjectRoot -Environment $TargetEnvironment
$Defaults    = Get-ModuleDefaults
$settingsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
$Config      = Merge-GlobalConfig -Defaults $Defaults -GlobalJson $settingsJson
$Config      = Set-DeploymentConfigPrefix -Config $Config -Prefix $Prefix
if (-not (Assert-ConfigCustomised -Config $Config)) { return }

# PublishTo is required for Labels and All phases
if (($Phase -eq "All" -or $Phase -eq "Labels") -and -not $PublishTo) {
    Write-Error "-PublishTo is required for Labels and All phases (e.g. -PublishTo 'user@domain.com')"
    return
}
$cleanupPrefix = $Config.namingPrefix

# ── Connect ──────────────────────────────────────────────────────────────────
if (-not $UPN -and -not $Tenant) {
    Write-Error "Specify -Tenant, -UPN, or both so the SCC connection target is explicit."
    return
}

$connectTarget = if ($Tenant) { $Tenant } else { $UPN }
Write-Host "`n=== Connecting to $connectTarget ===" -ForegroundColor Cyan
$connectArgs = @{}
if ($UPN) { $connectArgs["UPN"] = $UPN }
if ($Tenant) { $connectArgs["Tenant"] = $Tenant }
if ($Delegated) { $connectArgs["Delegated"] = $true }
$connected = Connect-DLPSession @connectArgs
if (-not $connected) {
    Write-Error "Connection failed. Aborting."
    return
}
Write-Host "  Connected.`n" -ForegroundColor Green

# ── Tenant fingerprint guard ───────────────────────────────────────────────────
# Refuse to operate against a tenant that does not match the pinned fingerprint.
$fingerprint = Test-DeploymentTenantFingerprint -ProjectRoot $ProjectRoot -TargetEnvironment $TargetEnvironment -RegisterIfMissing:$RegisterFingerprint -RegisterMode $FingerprintMode -ExpectedTenantId $ExpectedTenantId
Write-Host "=== Tenant Fingerprint ===" -ForegroundColor Cyan
foreach ($m in @($fingerprint.messages)) {
    Write-Host "  $m" -ForegroundColor $(if ($fingerprint.passed) { "Green" } else { "Red" })
}
foreach ($mm in @($fingerprint.mismatches)) {
    Write-Host "  MISMATCH $($mm.field): expected '$($mm.expected)', actual '$($mm.actual)'" -ForegroundColor Red
}
if (-not $fingerprint.passed) { throw "Tenant fingerprint check failed. Aborting." }
Write-Host ""

# ── Engine context (Stage 5 D1/D4/D6) ──────────────────────────────────────────
# Under -UseEngine, resolve the 7-field bundle ONCE into a New-Compl8Context. The context's
# engineRoutes (from tenant.json; default ALL FALSE) drive per-phase routing below: a phase routes
# through the Engine verbs (Invoke-Compl8Deploy) only when its object type's route is ON; otherwise
# it runs the existing leaf script unchanged. Building the context (and importing Compl8.Engine) is
# gated on -UseEngine so the default path is byte-for-byte today's leaf orchestration.
$DeployContext = $null
if ($UseEngine) {
    Import-Module (Join-Path $ProjectRoot "modules" "Compl8.Engine") -Force
    $ctxArgs = @{ TargetEnvironment = $TargetEnvironment }
    if ($WorkspaceRoot) { $ctxArgs["WorkspaceRoot"] = $WorkspaceRoot }
    if ($Prefix)        { $ctxArgs["Prefix"] = $Prefix }
    if ($UPN)           { $ctxArgs["UPN"] = $UPN }
    if ($Delegated)     { $ctxArgs["Delegated"] = $true }
    $DeployContext = New-Compl8Context @ctxArgs

    # Deterministic-within-this-run stamps for the plan id / generatedUtc the Engine verbs require
    # (the orchestrator surface MAY call Get-Date; the determinism ban is only on the pure Engine
    # paths, which receive these stamps as injected values).
    $script:DeployStamp        = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
    $script:DeployGeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
}

# Routes a single phase's object type through the Engine. The context is SCOPED to just this route
# (others forced off) so Invoke-Compl8Deploy applies ONLY this phase's type and defers the rest —
# preserving the orchestrator's per-phase ordering + propagation messaging. The Engine's own
# propagation gate replaces the leaf propagation checkpoint for routed types. Per-type apply content
# is threaded by that type's Stage-5C cutover slice; -WhatIf (and the default routes-off state) make
# this a safe plan/preview until then.
function Invoke-Compl8EnginePhase {
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][ValidateSet('dictionary', 'label', 'rulePackage', 'dlpRule', 'autoLabel')][string]$RouteKey,
        [Parameter(Mandatory)][string]$PhaseLabel,
        [hashtable]$DesiredContent = @{}
    )
    $scopedRoutes = [pscustomobject]@{ dictionary = $false; label = $false; rulePackage = $false; dlpRule = $false; autoLabel = $false }
    $scopedRoutes.$RouteKey = $true
    $scoped = $Context.PSObject.Copy()
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
        Context      = $scoped
        PlanId       = "deploy-$($Context.Environment)-$RouteKey-$($script:DeployStamp)"
        GeneratedUtc = $script:DeployGeneratedUtc
        ProjectRoot  = $ProjectRoot
        DesiredContent = $DesiredContent
    }
    if ($planOnly) { $deployArgs["WhatIf"] = $true }
    $result = Invoke-Compl8Deploy @deployArgs
    if ($result.render) { Write-Host $result.render }
    $result
}

# True when the Engine should drive this phase's object type (opt-in + the type's route is ON).
function Test-Compl8PhaseRoutesToEngine {
    param([string]$RouteKey)
    if (-not $UseEngine -or -not $DeployContext) { return $false }
    $prop = $DeployContext.EngineRoutes.PSObject.Properties[$RouteKey]
    return ($prop -and [bool]$prop.Value)
}

# ── Cleanup ──────────────────────────────────────────────────────────────────
# Resolve exactly which live tenant objects each pattern matches, present the full
# list, then (after typed confirmation) delete ONLY those previewed objects.
if ($Phase -eq "All" -or $Phase -eq "Cleanup") {
    Write-Host "=== Cleanup: planning removal ===" -ForegroundColor Cyan
    if ($SkipLabels) { Write-Host "  (Labels and label policy will be preserved)" -ForegroundColor Gray }

    $objects = @{
        AutoLabelPolicy   = @(Get-AutoSensitivityLabelPolicy -ErrorAction SilentlyContinue)
        DlpPolicy         = @(Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)
        SitPackage        = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction SilentlyContinue)
        KeywordDictionary = @(Get-DlpKeywordDictionary -ErrorAction SilentlyContinue)
    }
    if (-not $SkipLabels) {
        $objects.LabelPolicy = @(Get-LabelPolicy -ErrorAction SilentlyContinue)
        $objects.Label       = @(Get-Label -ErrorAction SilentlyContinue)
    }

    $targets     = @(Resolve-CleanupTargets -Config $Config -Objects $objects -IncludeLabels:(-not $SkipLabels))
    $planSummary = Show-CleanupPlan -Targets $targets -Tenant $connectTarget

    if ($targets.Count -eq 0) {
        Write-Host "`n  Nothing to clean up." -ForegroundColor Green
    } elseif ($WhatIf) {
        Write-Host "`n  WhatIf: previewed $($targets.Count) object(s). No deletions performed." -ForegroundColor Yellow
    } else {
        $phrase = Get-CleanupConfirmationPhrase -Prefix $Config.namingPrefix -Tenant $connectTarget
        if ($Force) {
            Write-Host "`n  -Force supplied: skipping typed confirmation." -ForegroundColor Yellow
        } else {
            Write-Host ""
            $answer = Read-Host "Type '$phrase' to delete the $($targets.Count) object(s) listed above"
            if ($answer -ne $phrase) {
                Write-Host "  Cleanup aborted. Nothing was deleted." -ForegroundColor Yellow
                return
            }
        }
        $removal = Invoke-CleanupPlan -Targets $targets -AllowBreakingClassifierReferences:$AllowBreakingClassifierReferences
        Write-Host "`n  Removal results:" -ForegroundColor Green
        foreach ($k in $removal.Keys) { Write-Host "    ${k}: $($removal[$k]) deleted" -ForegroundColor Gray }
        Write-Host "  Waiting 2 minutes for Purview cleanup propagation..." -ForegroundColor Gray
        Write-Host "  Note: Labels may take hours/days to fully purge. SIT packages and rules take minutes." -ForegroundColor Gray
        Start-Sleep 120
    }
    Write-Host ""

    if ($Phase -eq "Cleanup") {
        Write-Host "=== Cleanup Complete ===" -ForegroundColor Green
        return
    }
}

# ── Phase 1: Labels ──────────────────────────────────────────────────────────
if (($Phase -eq "All" -or $Phase -eq "Labels") -and -not $SkipLabels) {
    Write-Host "=== Phase 1: Deploying Labels ===" -ForegroundColor Cyan
    if (Test-Compl8PhaseRoutesToEngine 'label') {
        Invoke-Compl8EnginePhase -Context $DeployContext -RouteKey 'label' -PhaseLabel 'Labels' | Out-Null
    } else {
        $labelArgs = @{ PublishTo = $PublishTo }
        if ($Prefix) { $labelArgs["Prefix"] = $Prefix }
        if ($WhatIf) { $labelArgs["WhatIf"] = $true }
        if ($TargetEnvironment) { $labelArgs["TargetEnvironment"] = $TargetEnvironment }
        & (Join-Path $PSScriptRoot "Deploy-Labels.ps1") @labelArgs
    }
    Write-Host ""
}

# ── Phase 1.5: Keyword Dictionaries ──────────────────────────────────────────
if ($Phase -eq "All" -or $Phase -eq "Dictionaries" -or $Phase -eq "Classifiers") {
    Write-Host "=== Phase 1.5: Keyword Dictionaries ===" -ForegroundColor Cyan

    if (Test-Compl8PhaseRoutesToEngine 'dictionary') {
        Invoke-Compl8EnginePhase -Context $DeployContext -RouteKey 'dictionary' -PhaseLabel 'Dictionaries' | Out-Null
    } else {
        $manifestUrl = "$($Config.dictionaryManifestUrl)?scope=$Scope"
        if ($WhatIf) {
            $guidMap = Sync-DlpKeywordDictionaries -ManifestUrl $manifestUrl -NamePrefix $Config.namingPrefix -WhatIf
        } else {
            $guidMap = Sync-DlpKeywordDictionaries -ManifestUrl $manifestUrl -NamePrefix $Config.namingPrefix
        }
    }
    Write-Host ""

    if ($Phase -eq "Dictionaries") { return }
}

# ── Phase 2: SIT Classifier Packages ─────────────────────────────────────────
if ($Phase -eq "All" -or $Phase -eq "Classifiers") {
    Write-Host "=== Phase 2: SIT Classifier Package Manager ===" -ForegroundColor Cyan

    if (Test-Compl8PhaseRoutesToEngine 'rulePackage') {
        Invoke-Compl8EnginePhase -Context $DeployContext -RouteKey 'rulePackage' -PhaseLabel 'Classifiers' | Out-Null
    } else {
    $deployPath = Join-Path $ProjectRoot $DeployDir
    $xmlFiles = Get-ChildItem -Path $deployPath -Filter "*.xml" | Sort-Object Name

    if ($xmlFiles.Count -eq 0) {
        Write-Warning "No XML files found in $deployPath"
    } else {
        Write-Host "  Found $($xmlFiles.Count) package(s). Delegating to Deploy-Classifiers safety workflow." -ForegroundColor Gray
        $classifierArgs = @{
            Action = "Upload"
            Scope  = $Scope
        }
        if ($WhatIf) { $classifierArgs["WhatIf"] = $true }
        if ($Tenant) { $classifierArgs["Tenant"] = $Tenant }
        if ($TargetEnvironment) { $classifierArgs["TargetEnvironment"] = $TargetEnvironment }
        if ($Prefix) { $classifierArgs["Prefix"] = $Prefix }
        if ($Delegated) { $classifierArgs["Delegated"] = $true }
        if ($Greenfield) { $classifierArgs["Greenfield"] = $true }
        & (Join-Path $PSScriptRoot "Deploy-Classifiers.ps1") @classifierArgs

        if ($Phase -eq "Classifiers" -or $Phase -eq "All") {
            Write-Host ""
            Write-Host "  NOTE: Custom SITs take 4-24 hours to propagate in Purview's DLP engine." -ForegroundColor Yellow
            Write-Host "  DLP rules referencing these SITs will fail until propagation completes." -ForegroundColor Yellow
            Write-Host "  Run Phase 3 (DLPRules) separately after propagation:" -ForegroundColor Yellow
            $ruleCommandTarget = if ($Tenant) { "-Tenant $Tenant" } else { "-UPN $UPN" }
            $ruleCommandProfile = if ($TargetEnvironment) { " -TargetEnvironment $TargetEnvironment" } else { "" }
            Write-Host "    .\scripts\Invoke-FullDeployment.ps1 $ruleCommandTarget -Phase DLPRules$ruleCommandProfile" -ForegroundColor Gray
            Write-Host ""

            # Record upload timestamp for propagation check
            $timestampFile = Join-Path $ProjectRoot "config" "last-classifier-upload.json"
            if (-not $WhatIf) {
                @{ timestamp = (Get-Date).ToUniversalTime().ToString("o"); packages = $xmlFiles.Count } | ConvertTo-Json | Out-File $timestampFile -Encoding utf8
            }
        }
    }
    }

    if ($Phase -eq "Classifiers") { return }
}

# ── Phase 3: DLP Rules ──────────────────────────────────────────────────────
if ($Phase -eq "All" -or $Phase -eq "DLPRules") {
    Write-Host "=== Phase 3: Deploying DLP Rules ===" -ForegroundColor Cyan

    if (Test-Compl8PhaseRoutesToEngine 'dlpRule') {
        Invoke-Compl8EnginePhase -Context $DeployContext -RouteKey 'dlpRule' -PhaseLabel 'DLPRules' | Out-Null
    } else {
    # Propagation check: warn if classifiers were uploaded recently
    $timestampFile = Join-Path $ProjectRoot "config" "last-classifier-upload.json"
    if (Test-Path $timestampFile) {
        $uploadInfo = Get-Content $timestampFile -Raw | ConvertFrom-Json
        # ConvertFrom-Json may auto-convert ISO timestamps to DateTime objects,
        # which lose timezone info and get culture-formatted on ToString().
        # Handle both string and DateTime inputs.
        $ts = $uploadInfo.timestamp
        if ($ts -is [datetime]) {
            $uploadTime = [DateTimeOffset]::new($ts, [TimeSpan]::Zero)
        } else {
            $uploadTime = [DateTimeOffset]::Parse($ts, [System.Globalization.CultureInfo]::InvariantCulture)
        }
        $hoursAgo = [math]::Round(((Get-Date).ToUniversalTime() - $uploadTime.UtcDateTime).TotalHours, 1)

        if ($hoursAgo -lt 1) {
            Write-Host ""
            Write-Host "  WARNING: Classifier packages were uploaded $hoursAgo hours ago." -ForegroundColor Red
            Write-Host "  Microsoft states custom SITs take 'up to one hour' to propagate," -ForegroundColor Red
            Write-Host "  but real-world experience shows 1-24+ hours depending on workload." -ForegroundColor Red
            Write-Host "  DLP rules referencing custom SITs will almost certainly fail." -ForegroundColor Red
            Write-Host "  Ref: https://learn.microsoft.com/en-us/purview/sit-create-a-custom-sensitive-information-type-in-scc-powershell" -ForegroundColor Gray
            Write-Host ""

            if (-not $Force) {
                $choice = Read-Host "  Continue anyway? (Y/N)"
                if (-not $choice) { $choice = "N" }  # Default to No in non-interactive
                if ($choice -ne "Y") {
                    Write-Host "  Skipping DLP rules. Re-run with -Phase DLPRules after propagation." -ForegroundColor Yellow
                    return
                }
            }
        } elseif ($hoursAgo -lt 4) {
            Write-Host "  Classifier packages uploaded $hoursAgo hours ago." -ForegroundColor Yellow
            Write-Host "  MS official SLA is 1 hour, but propagation may still be in progress." -ForegroundColor Yellow
            Write-Host "  Proceeding - some SITs may not have propagated yet." -ForegroundColor Yellow
        } else {
            Write-Host "  Classifier packages uploaded $hoursAgo hours ago - propagation likely complete." -ForegroundColor Green
        }
    }

    $ruleArgs = @{ SkipValidation = $true }
    if ($WhatIf) { $ruleArgs["WhatIf"] = $true }
    if ($Tenant) { $ruleArgs["Tenant"] = $Tenant }
    if ($TargetEnvironment) { $ruleArgs["TargetEnvironment"] = $TargetEnvironment }
    if ($Prefix) { $ruleArgs["Prefix"] = $Prefix }
    if ($Delegated) { $ruleArgs["Delegated"] = $true }
    & (Join-Path $PSScriptRoot "Deploy-DLPRules.ps1") @ruleArgs
    }
}

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host "`n=== Deployment Complete ===" -ForegroundColor Green
Write-Host "  Session left open (run Disconnect-ExchangeOnline to close).`n"
