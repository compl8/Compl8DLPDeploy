function Invoke-Compl8Deploy {
    <#
    .SYNOPSIS
        The holistic Engine deploy workflow: context -> assess -> plan -> render -> confirm ->
        apply, behind ONE verb, honouring the context's per-type EngineRoutes. (Stage 5 PHASE 5B,
        Task 5B-1; arch design §5/§6; decisions D1/D4/D6.)

    .DESCRIPTION
        Stage 4 built the three verbs (assess / plan / apply) and the production executor map.
        Stage 5B composes them into the single workflow the Surface (TUI + CLI) calls — so the
        Surface carries NO business logic, only render + confirm. The flow:

          1. ASSESS the whole workspace (Invoke-Compl8Assess) — the FULL, type-agnostic delta.
          2. BUILD the reference graph over the desired packages + actual rules (the same graph
             assess builds internally; New-Compl8Plan requires it for ordering/impact/dereference).
          3. ROUTE (D4/D6). Compute which object types are routed THROUGH THE ENGINE from
             Context.EngineRoutes (default ALL FALSE = leaf). Filter the assessment buckets to the
             routed object types and plan ONLY those (New-Compl8Plan) — so the routed plan contains
             only what the engine will apply this run; everything else is reported DEFERRED to the
             still-live leaf path and is never mutated here. (Old paths stay live until each type's
             nonprod shadow trial passes and an operator flips its route — Stage 5C, D5.)
          4. RENDER the full assessment + a routing/plan summary (Get-Compl8AssessmentReport plus
             the engine-routes call-out) for the operator.
          5. CONFIRM via the injected callback (the Surface's interactive gate). A callback that
             returns falsey DEFERS the apply (phase 'planned'); no callback => proceed.
          6. APPLY the routed plan (Invoke-Compl8Apply) with the production executor map
             (Get-Compl8ExecutorMap), the apply layer doing all gating / snapshot-before-destroy /
             checkpoint-resume. As a backstop, the executor map is route-wrapped: any step whose
             objectType is NOT routed (e.g. a planner-generated cross-type dereference) is DEFERRED
             (no-op) rather than mutated — the 'tenant' snapshot step is always allowed.

        -WhatIf is plan-only (assess + plan + render, NO apply). When NO type is routed the routed
        plan has zero steps and apply is skipped entirely ("assess + plan only").

        DETERMINISM: -PlanId and -GeneratedUtc are injected (Get-Date / Get-Random are BANNED). The
        snapshot timestamp is derived from -GeneratedUtc. -Now is the injected gate clock.

    .PARAMETER Context
        A New-Compl8Context object (Compl8.Tenant). The verb reads WorkspacePath, Environment,
        Prefix, ProvenanceRegistryPath and EngineRoutes from it.

    .PARAMETER InventoryPath
        Path to the actual/inventory.json. Defaults to <WorkspacePath>/actual/inventory.json.

    .PARAMETER Inventory
        An already-parsed inventory object (alternative to -InventoryPath).

    .PARAMETER PlanId
        Deterministic plan id (Get-Date banned) — the Surface stamps it.

    .PARAMETER GeneratedUtc
        Deterministic generated-at stamp written verbatim into the assessment + plan, and the source
        of the snapshot folder timestamp.

    .PARAMETER DesiredContent
        Hashtable keyed by 'objectType|objectRef' -> the resolved desired content that type's executor
        needs (e.g. 'dictionary|{{DICT_X}}' -> { placeholder; name; terms; ... }). This is the
        caller-knowable key (the plan step ids are not known until planning); the verb re-maps it to
        the stepId -> content map Get-Compl8ExecutorMap / Invoke-Compl8Apply consume after planning.

    .PARAMETER ExecutorMap
        Optional override for the production executor map. When omitted, Get-Compl8ExecutorMap builds
        it from the context + DesiredContent + inventory. Either way the map is route-wrapped before
        apply (un-routed types deferred).

    .PARAMETER ConfirmCallback
        Optional scriptblock invoked as `& $ConfirmCallback $Assessment $Plan $RenderText` before any
        apply; a falsey return DEFERS the apply. Omitted => proceed (the Surface owns confirmation).

    .PARAMETER ProjectRoot
        Repository root forwarded to apply's fingerprint gate. Defaults to the repo root.

    .PARAMETER DictionaryInventory
        Tenant keyword-dictionary inventory forwarded to the rule-package executor's dictionary-ref gate.

    .PARAMETER TenantSitInventory
        Tenant SIT inventory forwarded to the dlpRule / auto-label executors' SIT-validation gate.

    .PARAMETER ConfirmNameConflicts
        Forwarded to the dlpRule / auto-label executors' name-conflict pre-flight.

    .PARAMETER SleepAction
        Injectable sleep forwarded to the executor map (retry / verify paths). Defaults to Start-Sleep.

    .PARAMETER Now
        Injected gate clock ([datetime]) forwarded to apply. Defaults to [datetime]::UtcNow.

    .PARAMETER ConfirmExternalRefs
        Forwarded to apply (operator confirmation for externalRefs gates).

    .PARAMETER ContinueOnBlock
        Forwarded to apply (continue past a blocked step to independent steps).

    .PARAMETER WhatIf
        Plan-only: assess + plan + render, NO apply.

    .OUTPUTS
        A compl8.deploy-result/v1 object:
          { schemaVersion; workspace; environment; phase ('planned'|'applied'); confirmed;
            routedTypes; deferredTypes; assessment; plan; render; deferred[]; apply (or $null) }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [string]$InventoryPath,

        [pscustomobject]$Inventory,

        [Parameter(Mandatory)]
        [string]$PlanId,

        [string]$GeneratedUtc,

        [hashtable]$DesiredContent = @{},

        [hashtable]$ExecutorMap,

        [scriptblock]$ConfirmCallback,

        [string]$ProjectRoot,

        [object[]]$DictionaryInventory = @(),

        [object[]]$TenantSitInventory = @(),

        [switch]$ConfirmNameConflicts,

        [scriptblock]$SleepAction = { param($s) Start-Sleep -Seconds $s },

        [datetime]$Now = [datetime]::UtcNow,

        # The production propagation probe: resolves a propagation-gated rule by real tenant SIT
        # VISIBILITY (Get-DlpSensitiveInformationType) instead of the time-window fallback. Defaults to the
        # shared probe so connected deployments use the authoritative signal; a caller can inject a fake
        # (tests) or $null (force the time fallback). When the tenant cannot be queried the probe returns
        # $null and the gate falls back to its time window, so this is safe disconnected.
        [scriptblock]$PropagationProbe = (Get-Compl8SitVisibilityProbe),

        # The reference-existence pre-flight resolver: classifies each named identity a deploy references
        # (exists/missing/external/unverified) against the tenant. Defaults to the connected resolver; a
        # caller injects a fake (tests) or uses -SkipReferenceCheck to bypass. A MISSING internal identity
        # HALTS the deploy before apply (fix it first); external domains/emails + built-in tokens are exempt.
        [scriptblock]$ReferenceResolver = (Get-Compl8IdentityResolver),

        [switch]$SkipReferenceCheck,

        # Risk strategist: each routed change is risk-evaluated (Get-Compl8ChangeRisk). A change whose
        # blast radius reaches a NOT-OURS object — or whose cascade is too large — is HANDED BACK: the
        # deploy halts (phase='blocked-risk') and withholds it until explicitly approved via
        # -ApprovedRiskActions ('action|objectType|ref' keys) or -ApproveAllRiskHandBacks.
        # -SkipRiskCheck bypasses the strategist entirely.
        [string[]]$ApprovedRiskActions = @(),

        [switch]$ApproveAllRiskHandBacks,

        [switch]$SkipRiskCheck,

        [switch]$ConfirmExternalRefs,

        [switch]$ContinueOnBlock,

        [switch]$WhatIf
    )

    # ------------------------------------------------------------------ nested helpers (private)
    # Reference graph over DESIRED packages + ACTUAL rules — delegates to the shared public builder
    # (Get-Compl8ReferenceGraph) so the deploy, the reconcile walk and the risk strategist all reason over
    # the same graph. -IncludeActualSits registers actual (incl. retired) sit GUIDs for risk/blast-radius.
    function Get-Compl8DeployReferenceGraph {
        param([string]$ResolvedDir, [pscustomobject]$Inventory, [switch]$IncludeActualSits)
        Get-Compl8ReferenceGraph -ResolvedDir $ResolvedDir -Inventory $Inventory -IncludeActualSits:$IncludeActualSits
    }

    # Deterministic snapshot folder timestamp derived from -GeneratedUtc (Get-Date is BANNED).
    function ConvertTo-Compl8SnapshotTimestamp {
        param([string]$GeneratedUtc)
        if (-not [string]::IsNullOrWhiteSpace($GeneratedUtc)) {
            $dto = [datetimeoffset]::MinValue
            $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
            if ([datetimeoffset]::TryParse($GeneratedUtc, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dto)) {
                return $dto.UtcDateTime.ToString('yyyyMMdd_HHmmss')
            }
        }
        '00000000_000000'
    }

    # Operator-facing render: the full assessment report + an engine-routes / routed-plan call-out.
    function Get-Compl8DeployRender {
        param([pscustomobject]$Assessment, [pscustomobject]$Plan, [pscustomobject]$EngineRoutes, [string[]]$RoutedTypes, [string[]]$DeferredTypes)
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add((Get-Compl8AssessmentReport -Assessment $Assessment)) | Out-Null
        $lines.Add('') | Out-Null
        $routePairs = [System.Collections.Generic.List[string]]::new()
        if ($EngineRoutes) {
            foreach ($p in ($EngineRoutes.PSObject.Properties | Sort-Object Name)) {
                $routePairs.Add(("{0}={1}" -f $p.Name, $(if ([bool]$p.Value) { 'ON' } else { 'off' }))) | Out-Null
            }
        }
        $lines.Add("Engine routes: $((@($routePairs)) -join '  ')") | Out-Null
        $lines.Add("  routed through Engine: $(if (@($RoutedTypes).Count) { (@($RoutedTypes)) -join ', ' } else { '(none)' })") | Out-Null
        $lines.Add("  deferred to leaf:      $(if (@($DeferredTypes).Count) { (@($DeferredTypes)) -join ', ' } else { '(none)' })") | Out-Null
        $lines.Add('') | Out-Null
        $lines.Add("Routed plan '$($Plan.id)': $(@($Plan.steps).Count) step(s).") | Out-Null
        ($lines -join [Environment]::NewLine)
    }

    # ------------------------------------------------------------------ context + paths
    $workspacePath = [string]$Context.WorkspacePath
    if ([string]::IsNullOrWhiteSpace($workspacePath)) { throw "Invoke-Compl8Deploy: Context.WorkspacePath is required." }
    $environment = [string]$Context.Environment
    if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
        # This file lives at modules/Compl8.Engine/Public/ — repo root is three levels up.
        $ProjectRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    }
    $resolvedDir = Join-Path (Join-Path $workspacePath 'desired') 'resolved'

    # ------------------------------------------------------------------ inventory (object + path)
    if ($PSBoundParameters.ContainsKey('Inventory') -and $Inventory) {
        $inv = $Inventory
        $invPathForAssess = $null
    } else {
        $invPathForAssess = if ($InventoryPath) { $InventoryPath } else { Join-Path (Join-Path $workspacePath 'actual') 'inventory.json' }
        if (-not (Test-Path -LiteralPath $invPathForAssess -PathType Leaf)) {
            throw "Invoke-Compl8Deploy: inventory not found at '$invPathForAssess' (supply -Inventory / -InventoryPath)."
        }
        $inv = Get-Content -LiteralPath $invPathForAssess -Raw | ConvertFrom-Json
    }

    # ------------------------------------------------------------------ 1. ASSESS (full)
    $assessArgs = @{ WorkspacePath = $workspacePath; Workspace = $environment }
    if ($GeneratedUtc) { $assessArgs['GeneratedUtc'] = $GeneratedUtc }
    if ($invPathForAssess) { $assessArgs['InventoryPath'] = $invPathForAssess } else { $assessArgs['Inventory'] = $inv }
    $assessment = Invoke-Compl8Assess @assessArgs

    # ------------------------------------------------------------------ 2. reference graph
    # Built over the DESIRED packages (their XML carries the entity GUIDs) + the ACTUAL dlp rules
    # (their classifier-reference text names the GUIDs) — IDENTICALLY to Invoke-Compl8Assess, so the
    # planner's ordering / impact roll-up / dereference generation see the same graph assess did.
    $graph = Get-Compl8DeployReferenceGraph -ResolvedDir $resolvedDir -Inventory $inv

    # ------------------------------------------------------------------ 3. ROUTE (D4/D6)
    # objectType -> route key. A route ON admits its object type(s) to the engine path.
    $routeToTypes = [ordered]@{
        dictionary  = @('dictionary')
        label       = @('label', 'labelPolicy')
        rulePackage = @('rulePackage', 'sit')
        dlpRule     = @('dlpRule', 'dlpPolicy')
        autoLabel   = @('autoLabelPolicy')
    }
    $routedTypeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($routeKey in $routeToTypes.Keys) {
        $prop = if ($Context.EngineRoutes) { $Context.EngineRoutes.PSObject.Properties[$routeKey] } else { $null }
        if ($prop -and [bool]$prop.Value) {
            foreach ($t in $routeToTypes[$routeKey]) { $routedTypeSet.Add($t) | Out-Null }
        }
    }
    $routedTypes = @($routedTypeSet | Sort-Object)

    # Filter the assessment buckets to the routed object types -> the routed assessment the engine
    # plans + applies. (Clone via JSON round-trip so the original full assessment is untouched.)
    $routedAssessment = $assessment | ConvertTo-Json -Depth 12 | ConvertFrom-Json
    $newBuckets = [ordered]@{}
    foreach ($bucket in (Get-Compl8EngineSchemaEnums).Buckets) {
        $entries = @(@($routedAssessment.buckets.$bucket) | Where-Object { $_ -and $routedTypeSet.Contains([string]$_.objectType) })
        $newBuckets[$bucket] = @($entries)
    }
    $routedAssessment.buckets = [pscustomobject]$newBuckets

    # Deferred = full actionable items (every bucket except foreign — never-touch) whose objectType
    # is NOT routed this run; they remain the leaf path's job and are reported, never mutated.
    $deferred = [System.Collections.Generic.List[object]]::new()
    $deferredTypeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($bucket in (Get-Compl8EngineSchemaEnums).Buckets) {
        if ($bucket -eq 'foreign') { continue }
        foreach ($entry in @($assessment.buckets.$bucket)) {
            if ($entry -and -not $routedTypeSet.Contains([string]$entry.objectType)) {
                $deferred.Add([pscustomobject]@{ bucket = $bucket; objectType = [string]$entry.objectType; ref = [string]$entry.ref }) | Out-Null
                $deferredTypeSet.Add([string]$entry.objectType) | Out-Null
            }
        }
    }

    # ------------------------------------------------------------------ plan the routed delta
    $plan = New-Compl8Plan -Assessment $routedAssessment -Graph $graph -Inventory $inv `
        -Workspace $environment -Id $PlanId -GeneratedUtc $GeneratedUtc -WorkspacePath $workspacePath
    $planPath = Join-Path (Join-Path (Join-Path $workspacePath 'history') 'plans') "$PlanId.json"

    # ------------------------------------------------------------------ 4. RENDER
    $render = Get-Compl8DeployRender -Assessment $assessment -Plan $plan `
        -EngineRoutes $Context.EngineRoutes -RoutedTypes $routedTypes -DeferredTypes (@($deferredTypeSet | Sort-Object))

    $planned = {
        param([bool]$Confirmed)
        [pscustomobject]([ordered]@{
            schemaVersion = 'compl8.deploy-result/v1'
            workspace     = $environment
            environment   = $environment
            phase         = 'planned'
            confirmed     = $Confirmed
            routedTypes   = $routedTypes
            deferredTypes = @($deferredTypeSet | Sort-Object)
            assessment    = $assessment
            plan          = $plan
            render        = $render
            deferred      = @($deferred)
            apply         = $null
        })
    }

    # ------------------------------------------------------------------ 5. plan-only short-circuits
    if ($WhatIf) { return (& $planned $true) }

    $confirmed = $true
    if ($ConfirmCallback) { $confirmed = [bool](& $ConfirmCallback $assessment $plan $render) }
    if (-not $confirmed) { return (& $planned $false) }

    # Nothing routed (or no actionable routed delta) => assess + plan only, no apply.
    if (@($plan.steps).Count -eq 0) { return (& $planned $true) }

    # ------------------------------------------------------------------ 5b. REFERENCE-EXISTENCE pre-flight
    # A deploy must NOT mutate the tenant if it references a tenant identity that does not exist — an
    # incident-report / notify recipient, or (broad) a named group/user/site in a condition/scope —
    # EXCEPT external domains/emails and built-in Purview tokens. Collect the desired rules' identity
    # references, resolve them against the tenant (connected -ReferenceResolver), and HALT before apply
    # with the fix-list if any INTERNAL identity is missing. Disconnected/undetermined refs do not block
    # (the resolver fail-safes to 'unverified'); run connected to enforce.
    # SCOPE: only validate the references of DLP RULES actually being deployed this run (the routed
    # plan's dlpRule steps). A deploy that touches no DLP rule (e.g. dictionary-only, or dlpRule routing
    # off) must NOT be blocked by recipients of rules it isn't deploying (codex).
    $deployedRuleNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in @($plan.steps)) { if ([string]$s.objectType -eq 'dlpRule') { $deployedRuleNames.Add([string]$s.objectRef) | Out-Null } }
    if (-not $SkipReferenceCheck -and $deployedRuleNames.Count -gt 0) {
        # Use the SAME desired-rule source assess used (DR-4): the persisted dlp-rules.json first, else the
        # config fallback (workspace config dirs -> Resolve-DesiredDlpRules). Reading only dlp-rules.json
        # would silently skip the check for config-fallback workspaces and apply a missing-recipient rule
        # (codex). Either source yields rule records with .content (the recipient fields).
        $dlpRulesPath = Join-Path $workspacePath 'desired' 'resolved' 'dlp-rules.json'
        $desiredRules = @()
        if (Test-Path -LiteralPath $dlpRulesPath -PathType Leaf) {
            try { $desiredRules = @((Get-Content -LiteralPath $dlpRulesPath -Raw | ConvertFrom-Json).rules) } catch { $desiredRules = @() }
        } else {
            $cfgSource = $null
            foreach ($cand in @((Join-Path $workspacePath 'desired' 'config'), (Join-Path $workspacePath 'config'))) {
                if (Test-Path -LiteralPath $cand -PathType Container) { $cfgSource = $cand; break }
            }
            if ($cfgSource) { try { $desiredRules = @((Resolve-DesiredDlpRules -ConfigPath $cfgSource).Rules) } catch { $desiredRules = @() } }
        }
        $desiredRules = @($desiredRules | Where-Object { $deployedRuleNames.Contains([string]$_.ruleName) })
        $refCandidates = @(Get-Compl8ReferenceCandidates -DesiredRules $desiredRules)
        if ($refCandidates.Count -gt 0) {
            $readiness = Get-Compl8ReferenceReadiness -References $refCandidates -Resolver $ReferenceResolver
            if (-not $readiness.ready) {
                $missingList = (@($readiness.blocking | ForEach-Object { "$($_.value) [$($_.source)]" }) -join '; ')
                return [pscustomobject]([ordered]@{
                    schemaVersion      = 'compl8.deploy-result/v1'
                    workspace          = $environment
                    environment        = $environment
                    phase              = 'blocked-references'
                    confirmed          = $true
                    routedTypes        = $routedTypes
                    deferredTypes      = @($deferredTypeSet | Sort-Object)
                    assessment         = $assessment
                    plan               = $plan
                    render             = "REFERENCE CHECK FAILED — deploy blocked before apply. Missing tenant identities (fix these, then re-run): $missingList"
                    deferred           = @($deferred)
                    apply              = $null
                    referenceReadiness = $readiness
                })
            }
        }
    }

    # ------------------------------------------------------------------ 5c. RISK STRATEGIST pre-flight
    # Risk-evaluate each routed change and HAND BACK (block auto-apply) any whose blast radius reaches a
    # NOT-OURS object — or whose cascade is too large. Ownership comes from the inventory's `ours` flags;
    # the graph spans ours + foreign so foreign downstream consumers are visible. A handed-back change is
    # withheld until explicitly approved; this realises "never auto-apply a change that damages something
    # we do not manage". -SkipRiskCheck bypasses; -ApprovedRiskActions / -ApproveAllRiskHandBacks approve.
    if (-not $SkipRiskCheck) {
        $ownership = Get-Compl8OwnershipMap -Inventory $inv

        # sit steps carry the slug as objectRef, but the graph walk keys sits by entity GUID — resolve it
        # from the inventory and pass it as the change identity, or a SIT change reaching a foreign rule
        # would evaluate as no-impact and bypass the hand-back gate (codex).
        $sitGuidByName = @{}
        foreach ($s in @($inv.objects.sits)) { if ($s.name -and $s.identity) { $sitGuidByName[[string]$s.name] = [string]$s.identity } }

        # The risk graph additionally knows the ACTUAL (incl. retired) sit GUIDs, so a removal of a sit no
        # longer in the desired packages still surfaces the foreign rules that reference it (codex P1).
        $riskGraph = Get-Compl8DeployReferenceGraph -ResolvedDir $resolvedDir -Inventory $inv -IncludeActualSits

        $riskRecords = [System.Collections.Generic.List[object]]::new()
        foreach ($step in @($plan.steps)) {
            if ([string]$step.action -eq 'snapshot') { continue }
            $change = [pscustomobject]@{ objectType = [string]$step.objectType; action = [string]$step.action; ref = [string]$step.objectRef }
            if ([string]$step.objectType -eq 'sit' -and $sitGuidByName.ContainsKey([string]$step.objectRef)) {
                $change | Add-Member -NotePropertyName identity -NotePropertyValue $sitGuidByName[[string]$step.objectRef] -Force
            }
            $riskRecords.Add((Get-Compl8ChangeRisk -Change $change -Graph $riskGraph -OwnershipMap $ownership)) | Out-Null
        }
        $unapproved = @($riskRecords | Where-Object {
            $_.handBack -and -not ($ApproveAllRiskHandBacks -or ($ApprovedRiskActions -contains "$($_.action)|$($_.objectType)|$($_.ref)"))
        })
        if ($unapproved.Count -gt 0) {
            $riskLines = @($unapproved | ForEach-Object { "  [$($_.riskLevel)] $($_.rationale)" }) -join "`n"
            return [pscustomobject]([ordered]@{
                schemaVersion = 'compl8.deploy-result/v1'
                workspace     = $environment
                environment   = $environment
                phase         = 'blocked-risk'
                confirmed     = $true
                routedTypes   = $routedTypes
                deferredTypes = @($deferredTypeSet | Sort-Object)
                assessment    = $assessment
                plan          = $plan
                render        = "RISK CHECK — deploy blocked: $($unapproved.Count) change(s) reach not-ours objects or are too complex to auto-apply. Approve explicitly (-ApprovedRiskActions '<action>|<objectType>|<ref>' or -ApproveAllRiskHandBacks) to proceed:`n$riskLines"
                deferred      = @($deferred)
                apply         = $null
                risk          = @($riskRecords)
                handBack      = @($unapproved)
            })
        }
    }

    # ------------------------------------------------------------------ 6. APPLY the routed plan
    # Re-key the caller's 'objectType|objectRef' content to the plan step ids the executor map +
    # apply's reference-guard consume.
    $contentById = @{}
    foreach ($step in @($plan.steps)) {
        $key = "$([string]$step.objectType)|$([string]$step.objectRef)"
        if ($DesiredContent.ContainsKey($key)) { $contentById[[string]$step.id] = $DesiredContent[$key] }
    }

    # The executor map: injected override, else the production map bound to the context.
    if ($ExecutorMap) {
        $baseMap = $ExecutorMap
    } else {
        $snapTs = ConvertTo-Compl8SnapshotTimestamp -GeneratedUtc $GeneratedUtc
        $mapArgs = @{
            StepContent            = $contentById
            Prefix                 = [string]$Context.Prefix
            TargetEnvironment      = $environment
            DictionaryInventory    = $DictionaryInventory
            TenantSitInventory     = $TenantSitInventory
            ConfirmNameConflicts   = [bool]$ConfirmNameConflicts
            Inventory              = $inv
            Plan                   = $plan
            SleepAction            = $SleepAction
            SnapshotInventory      = $inv
            SnapshotWorkspacePath  = $workspacePath
            SnapshotTimestamp      = $snapTs
        }
        if ($Context.ProvenanceRegistryPath) { $mapArgs['ProvenanceRegistryPath'] = [string]$Context.ProvenanceRegistryPath }
        $baseMap = Get-Compl8ExecutorMap @mapArgs
    }

    # Route-wrap (backstop): defer any step whose objectType is not routed (e.g. a planner-generated
    # cross-type dereference). The 'tenant' snapshot step is infrastructure and always allowed.
    $deferExecutor = {
        param($Step)
        [pscustomobject]@{
            stepId     = [string]$Step.id
            action     = [string]$Step.action
            objectType = [string]$Step.objectType
            objectRef  = [string]$Step.objectRef
            status     = 'deferred'
            reason     = "objectType '$([string]$Step.objectType)' is not routed through the Engine (EngineRoutes off) — left to the leaf path."
        }
    }
    $map = @{}
    foreach ($type in $baseMap.Keys) {
        if ($type -eq 'tenant' -or $routedTypeSet.Contains([string]$type)) {
            $map[$type] = $baseMap[$type]
        } else {
            $map[$type] = $deferExecutor
        }
    }

    $applyArgs = @{
        PlanPath          = $planPath
        ProjectRoot       = $ProjectRoot
        TargetEnvironment = $environment
        ExecutorMap       = $map
        StepContent       = $contentById
        Now               = $Now
    }
    if ($ConfirmExternalRefs) { $applyArgs['ConfirmExternalRefs'] = $true }
    if ($ContinueOnBlock)     { $applyArgs['ContinueOnBlock'] = $true }
    if ($PropagationProbe)    { $applyArgs['PropagationProbe'] = $PropagationProbe }
    $applyResult = Invoke-Compl8Apply @applyArgs

    [pscustomobject]([ordered]@{
        schemaVersion = 'compl8.deploy-result/v1'
        workspace     = $environment
        environment   = $environment
        phase         = 'applied'
        confirmed     = $true
        routedTypes   = $routedTypes
        deferredTypes = @($deferredTypeSet | Sort-Object)
        assessment    = $assessment
        plan          = $plan
        render        = $render
        deferred      = @($deferred)
        apply         = $applyResult
    })
}
