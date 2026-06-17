function Invoke-Compl8Apply {
    <#
    .SYNOPSIS
        The ONLY tenant-mutating layer: applies a compl8.plan/v1 PLAN FILE, gated, in dependency
        order, with per-step checkpoint/resume. (PHASE 4C, Task 6; arch design §5; D3/D4/D5.)

    .DESCRIPTION
        Hard rule (§5): nothing mutates a tenant except apply, and apply accepts NOTHING except a
        PLAN FILE. An inline step list or plan object passed directly is REJECTED (throw). The flow
        is always: resolve -> assess -> plan -> render -> confirm -> apply, so the only way to
        mutate is to hand apply a path to a written, hash-bound plan.

        ORDER OF OPERATIONS (every gate is consulted BEFORE any mutation):
          1. PLAN-ONLY guard. -PlanPath is the sole accepted input; -Plan / -Steps (inline) throw.
          2. LOAD + VALIDATE the plan from disk (Test-PlanSchema). planId / workspace come from it.
          3. FRESHNESS. Re-verify the plan against the CURRENT inputs via Test-Compl8PlanCurrent
             (the live resolveManifest / inventory hashes are passed in -ResolveManifestHash /
             -InventoryHash, mockable). A stale plan is REFUSED with a clear error before anything.
          4. FINGERPRINT gate. Test-DeploymentTenantFingerprint (mockable) must pass before any
             mutation; a failing/blocking fingerprint refuses the apply.
          5. -WhatIf SHORT-CIRCUIT. With -WhatIf, apply reports the steps that WOULD run (in
             dependency order) and returns BEFORE any executor call and BEFORE any checkpoint write.
          6. DISPATCH each step IN DEPENDENCY ORDER to an executor resolved by step.objectType:
               * UNSATISFIED-DEPENDENCY skip (safety). Before anything else, if any id in this step's
                 direct dependsOn is in the UNSATISFIED set (a prerequisite that was blocked/failed and
                 produced no success checkpoint), this step is recorded 'skipped-dependency', added to
                 the unsatisfied set, and its executor is NOT called. Steps run in topological order so
                 the set propagates forward and the whole dependent subtree is skipped — a dependent
                 with no gate of its own can never mutate the tenant out of dependency order.
               * gate check (Test-Compl8Gate, injected clock -Now). A blocked step is recorded
                 'blocked' and apply stops (or, with -ContinueOnBlock, records the block, marks the
                 step unsatisfied, and continues to independent steps) — it resumes from checkpoint on
                 a later run.
               * DESTRUCTIVE backstop (D5). A `remove` of a `rulePackage` re-invokes the reference
                 guard (Test-DlpRulePackageRemovalReferenceGuard) at apply time with the step's REAL
                 resolved package content (-StepContent); a veto (Safe=false) blocks that step
                 (recorded 'blocked', marked unsatisfied, executor NOT called). The guard is SCOPED to
                 genuine rule-package removals: label/dictionary/policy removals and dlpRule
                 `dereference` steps do NOT trigger it (they carry no rule-package XML, so the guard's
                 parser would falsely veto them; a dereference is itself the de-referencing work,
                 handled by the dlpRule executor).
               * EXECUTOR. The resolved scriptblock/command runs the step's mutation.
               * CHECKPOINT. On success a per-step checkpoint lands at
                 history/applies/<planId>/<stepId>.json. Re-running the SAME plan path skips any
                 step that already has a checkpoint (kill-mid-plan / resume).
          7. RESULT. A history/applies/<planId>/result.json summarises every step exactly once.

        EXECUTOR INJECTION. The executor is INJECTABLE so this task's tests inject FAKE executors
        and the real per-type executors (Tasks 8-12) wire in later WITHOUT changing this framework:
          * -ExecutorMap @{ objectType = <scriptblock|command> } maps an objectType to its executor;
          * the default/production dispatcher resolves the map and FAILS CLOSED for an unknown
            objectType (throw "no executor registered for <type>"). Production wires the real
            executors by populating the map (a default map can be assembled by a future
            Get-Compl8ExecutorMap once Tasks 8-12 land); until then an unmapped type is a hard stop.
        Each executor receives the step object (-Step / first positional) and returns a result that
        is recorded verbatim in the checkpoint.

        DETERMINISM. The clock is INJECTED (-Now) so gate timing is reproducible; Get-Date is not
        used for gate decisions. Checkpoints carry the apply instant from -Now.

    .PARAMETER PlanPath
        Path to a written compl8.plan/v1 JSON file (the ONLY accepted input). Its parent workspace
        root (the dir two levels above history/plans/) is where history/applies/<planId>/ is written.

    .PARAMETER ResolveManifestHash
        The CURRENT resolve-manifest input hash, for the freshness re-check (Test-Compl8PlanCurrent).

    .PARAMETER InventoryHash
        The CURRENT inventory input hash, for the freshness re-check.

    .PARAMETER ProjectRoot
        Repository root, forwarded to the fingerprint gate (Test-DeploymentTenantFingerprint).

    .PARAMETER TargetEnvironment
        Optional environment key forwarded to the fingerprint gate.

    .PARAMETER ExecutorMap
        Hashtable objectType -> executor (scriptblock or command name). The dispatcher resolves each
        step's executor here; an unmapped objectType fails closed.

    .PARAMETER StepContent
        Optional hashtable stepId -> resolved content for that step (the same resolved content the
        production executor-map closure binds as the executor's -Content). The apply framework uses
        it for ONE thing: the D5 rule-package removal reference guard. For a `remove` of a
        `rulePackage`, the guard needs the REAL serialized rule-package XML (+ live DLP rules) to
        decide Safe — the framework only knows the step's objectRef (Identity/Name), which the
        guard's package parser would treat as an unparsed package (Safe=false, a false block). So the
        rule-package-removal guard is handed this step's content { Packages = @(<serialized package>);
        DlpRules = @(<rules>) } when present; absent content falls back to the objectRef identity. The
        guard runs ONLY for genuine rulePackage removals (see DISPATCH below) — never for label/dict/
        policy removals or dlpRule `dereference` steps, which carry no rule-package XML.

    .PARAMETER Now
        Injected current instant ([datetime]) for gate evaluation and checkpoint stamps. Defaults to
        [datetime]::UtcNow ONLY as a convenience for production callers; tests pin it. (Get-Date is
        not called; the default uses the .NET clock directly and is overridden in all tests.)

    .PARAMETER PropagationProbe
        Optional scriptblock that resolves classifier propagation by tenant VISIBILITY — the
        authoritative propagation signal (matching the leaf, which polls Get-DlpSensitiveInformationType
        until the uploaded SIT IDs appear). Invoked as & $PropagationProbe $sitIds for a propagation-gated
        step whose gate carries requiresSitIds; it returns $true (all visible -> the gate proceeds now),
        $false (still propagating -> the gate blocks now), or $null (undetermined -> the gate falls back to
        the time window). DEFAULT is unset: with no probe the propagation gate uses only the time-offset
        fallback (notBeforeOffsetHours from the dependency apply time) — i.e. behaviour is unchanged unless
        a caller opts in to live visibility. (Connected callers pass a Get-DlpSensitiveInformationType-based
        probe; tests inject a deterministic fake.)

    .PARAMETER ConfirmExternalRefs
        Operator confirmation forwarded to externalRefs gate evaluation.

    .PARAMETER ContinueOnBlock
        When a step is blocked by a gate or the destructive backstop, continue to subsequent
        INDEPENDENT steps instead of stopping at the first block. Blocked steps are recorded and
        resumed from checkpoint on a later run regardless.

        SAFETY (dependent-skip): a step that was blocked or failed and did NOT produce a success
        checkpoint is recorded in an UNSATISFIED set. Steps run in topological order, so before
        executing a step the framework checks its direct dependsOn: if ANY prerequisite is unsatisfied
        the step is itself recorded 'skipped-dependency' and added to the unsatisfied set WITHOUT
        calling its executor. Because the set propagates forward in dependency order, this transitively
        skips the whole dependent subtree — a dependent with no gate of its own can never mutate the
        tenant once a prerequisite was neither applied nor checkpointed. Without -ContinueOnBlock the
        run still STOPS at the first block/failure (so dependents are never reached anyway).

    .PARAMETER WhatIf
        Plan-without-apply: report the steps that WOULD run (dependency order) and return before any
        executor call or checkpoint write.

    .OUTPUTS
        With -WhatIf: { whatIf = $true; planId; wouldRun = @({ stepId; action; objectType; objectRef }) }.
        Otherwise the apply result object (also written to result.json):
        { schemaVersion='compl8.apply-result/v1'; planId; workspace; appliedUtc; steps = @({ stepId;
        action; objectType; objectRef; status; reason; result }) }.
    #>
    [CmdletBinding(DefaultParameterSetName = 'PlanPath')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'PlanPath')]
        [string]$PlanPath,

        # --- REJECTED inline inputs: present ONLY so passing them lands in a distinct parameter set
        #     we can refuse with a clear plan-only error (rather than a generic binding failure). ---
        [Parameter(Mandatory, ParameterSetName = 'RejectPlan')]
        [pscustomobject]$Plan,

        [Parameter(Mandatory, ParameterSetName = 'RejectSteps')]
        [object[]]$Steps,

        [string]$ResolveManifestHash,

        [string]$InventoryHash,

        [string]$ProjectRoot,

        [string]$TargetEnvironment,

        [hashtable]$ExecutorMap = @{},

        [hashtable]$StepContent = @{},

        [datetime]$Now = [datetime]::UtcNow,

        [scriptblock]$PropagationProbe,

        [switch]$ConfirmExternalRefs,

        [switch]$ContinueOnBlock,

        [switch]$WhatIf
    )

    # ------------------------------------------------------------------ nested helpers (private)
    # Deterministic topological order over the plan's steps (Kahn, ready set sorted by step id).
    # New-Compl8Plan already emits graph-derived order, but apply RE-DERIVES from dependsOn so the
    # traversal is robust to on-disk reordering and a resume always walks the same sequence. A
    # dependency cycle throws a clear error.
    function Get-ApplyStepOrder {
        param([pscustomobject]$ThePlan)
        $steps = @($ThePlan.steps)
        $byId = @{}
        foreach ($s in $steps) { $byId[[string]$s.id] = $s }

        $remaining = [System.Collections.Generic.List[object]]::new()
        foreach ($s in $steps) { $remaining.Add($s) | Out-Null }
        $placed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $ordered = [System.Collections.Generic.List[object]]::new()

        while ($remaining.Count -gt 0) {
            $ready = @($remaining | Where-Object {
                $met = $true
                foreach ($dep in @($_.dependsOn)) {
                    if ($byId.ContainsKey([string]$dep) -and -not $placed.Contains([string]$dep)) { $met = $false; break }
                }
                $met
            })
            if ($ready.Count -eq 0) {
                $stuck = (@($remaining | ForEach-Object { [string]$_.id }) | Sort-Object) -join ', '
                throw "Invoke-Compl8Apply: dependency cycle among plan steps ($stuck) — cannot order for apply."
            }
            $next = @($ready | Sort-Object @{ Expression = { [string]$_.id } })[0]
            $ordered.Add($next) | Out-Null
            $placed.Add([string]$next.id) | Out-Null
            $remaining.Remove($next) | Out-Null
        }
        @($ordered)
    }

    function New-ApplyResultObject {
        param([string]$ThePlanId, [string]$TheWorkspace, [string]$AppliedUtc, [object]$TheStepResults)
        [pscustomobject]@{
            schemaVersion = 'compl8.apply-result/v1'
            planId        = $ThePlanId
            workspace     = $TheWorkspace
            appliedUtc    = $AppliedUtc
            steps         = @($TheStepResults)
        }
    }

    function Write-ApplyResult {
        param([string]$TheAppliesDir, [pscustomobject]$TheResult)
        if (-not (Test-Path -LiteralPath $TheAppliesDir)) { New-Item -ItemType Directory -Path $TheAppliesDir -Force | Out-Null }
        $p = Join-Path $TheAppliesDir 'result.json'
        $tmp = "$p.$([guid]::NewGuid().ToString('n')).tmp"
        try {
            ($TheResult | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $tmp -Encoding UTF8 -NoNewline
            if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -Confirm:$false }
            Move-Item -LiteralPath $tmp -Destination $p
        } finally {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }

    # ------------------------------------------------------------------ 1. PLAN-ONLY guard (§5)
    if ($PSCmdlet.ParameterSetName -in 'RejectPlan', 'RejectSteps') {
        throw "Invoke-Compl8Apply accepts ONLY a plan FILE PATH (-PlanPath). An inline plan object / step list is refused: apply mutates nothing except a written, hash-bound plan file (arch design §5)."
    }

    if (-not (Test-Path -LiteralPath $PlanPath -PathType Leaf)) {
        throw "Invoke-Compl8Apply: plan file not found at '$PlanPath'."
    }

    # ------------------------------------------------------------------ 2. LOAD + VALIDATE plan
    try {
        $plan = Get-Content -LiteralPath $PlanPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Invoke-Compl8Apply: could not read/parse the plan at '$PlanPath': $($_.Exception.Message)"
    }
    $schemaCheck = Test-PlanSchema -Plan $plan
    if (-not $schemaCheck.Valid) {
        throw "Invoke-Compl8Apply: plan at '$PlanPath' is invalid: $((@($schemaCheck.Errors)) -join '; ')"
    }
    $planId    = [string]$plan.id
    $workspace = [string]$plan.workspace

    # Workspace root = the directory two levels above history/plans/<id>.json (…/history/plans/x.json
    # -> …). history/applies/<planId>/ is written under the same root, one-writer-per-domain (Engine
    # writes history/, D8).
    $plansDir      = Split-Path -Parent $PlanPath           # …/history/plans
    $historyDir    = Split-Path -Parent $plansDir           # …/history
    $workspaceRoot = Split-Path -Parent $historyDir         # … (workspace root)
    $appliesDir    = Join-Path (Join-Path (Join-Path $workspaceRoot 'history') 'applies') $planId

    # ------------------------------------------------------------------ ordered steps (dependency)
    $orderedSteps = Get-ApplyStepOrder -ThePlan $plan

    # ------------------------------------------------------------------ 3. FRESHNESS re-check
    # A stale plan is refused BEFORE the fingerprint gate and BEFORE any executor / checkpoint.
    $rmHash  = if ($PSBoundParameters.ContainsKey('ResolveManifestHash')) { $ResolveManifestHash } else { [string]$plan.inputs.resolveManifest }
    $invHash = if ($PSBoundParameters.ContainsKey('InventoryHash'))       { $InventoryHash }       else { [string]$plan.inputs.inventory }
    # Plain (boolean) freshness call — Test-Compl8PlanCurrent returns $true only when both input
    # hashes still match. (Called without -Detail so a test mock returning a bare bool is honoured.)
    $isCurrent = [bool](Test-Compl8PlanCurrent -Plan $plan -ResolveManifestHash $rmHash -InventoryHash $invHash)
    if (-not $isCurrent) {
        # Describe which input(s) drifted for the operator (local diff against the plan's recorded
        # inputs; no second call to the freshness function so a bare-bool mock can't perturb it).
        $stale = @()
        if ([string]$plan.inputs.resolveManifest -ne $rmHash)  { $stale += 'resolveManifest' }
        if ([string]$plan.inputs.inventory       -ne $invHash) { $stale += 'inventory' }
        $staleText = if ($stale.Count) { $stale -join ', ' } else { 'live inputs no longer match the plan' }
        throw "Invoke-Compl8Apply: plan '$planId' is STALE — input(s) drifted: $staleText. Regenerate the plan (resolve -> assess -> plan) before applying."
    }

    # ------------------------------------------------------------------ 4. FINGERPRINT gate
    $fpParams = @{ ProjectRoot = $ProjectRoot }
    if ($TargetEnvironment) { $fpParams['TargetEnvironment'] = $TargetEnvironment }
    $fingerprint = Test-DeploymentTenantFingerprint @fpParams
    if ($fingerprint -and $fingerprint.PSObject.Properties['passed'] -and -not $fingerprint.passed) {
        $fpMsg = if ($fingerprint.PSObject.Properties['messages']) { (@($fingerprint.messages)) -join '; ' } else { '' }
        throw "Invoke-Compl8Apply: tenant fingerprint gate FAILED for plan '$planId' — refusing to mutate the wrong tenant. $fpMsg"
    }

    # ------------------------------------------------------------------ 5. -WhatIf short-circuit
    # Report the would-run steps; NO executor call, NO checkpoint write.
    if ($WhatIf) {
        return [pscustomobject]@{
            whatIf   = $true
            planId   = $planId
            wouldRun = @($orderedSteps | ForEach-Object {
                [pscustomobject]@{ stepId = [string]$_.id; action = [string]$_.action; objectType = [string]$_.objectType; objectRef = [string]$_.objectRef }
            })
        }
    }

    # ------------------------------------------------------------------ checkpoint helpers
    if (-not (Test-Path -LiteralPath $appliesDir)) {
        New-Item -ItemType Directory -Path $appliesDir -Force | Out-Null
    }

    $applyStampUtc = $Now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    function Get-CheckpointPath {
        param([string]$StepId)
        Join-Path $appliesDir "$StepId.json"
    }
    function Test-StepCheckpointed {
        param([string]$StepId)
        Test-Path -LiteralPath (Get-CheckpointPath -StepId $StepId) -PathType Leaf
    }
    function Read-Checkpoint {
        param([string]$StepId)
        $p = Get-CheckpointPath -StepId $StepId
        if (Test-Path -LiteralPath $p -PathType Leaf) {
            return Get-Content -LiteralPath $p -Raw | ConvertFrom-Json
        }
        $null
    }
    function Write-Checkpoint {
        param([pscustomobject]$Checkpoint)
        $p = Get-CheckpointPath -StepId ([string]$Checkpoint.stepId)
        # Atomic: temp sibling then move, so a checkpoint file is never half-written.
        $tmp = "$p.$([guid]::NewGuid().ToString('n')).tmp"
        try {
            ($Checkpoint | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $tmp -Encoding UTF8 -NoNewline
            if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -Confirm:$false }
            Move-Item -LiteralPath $tmp -Destination $p
        } finally {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }

    # ------------------------------------------------------------------ executor dispatch (injected)
    # Resolve a step's executor by objectType from the injected map; fail CLOSED for an unmapped
    # type. The map values are scriptblocks or command names; both are invoked with the step bound.
    function Invoke-StepExecutor {
        param([pscustomobject]$Step)
        $type = [string]$Step.objectType
        if (-not $ExecutorMap.ContainsKey($type)) {
            throw "Invoke-Compl8Apply: no executor registered for '$type' (step '$($Step.id)'). The real per-type executors are wired in later tasks; an unmapped objectType is a hard stop (fail-closed)."
        }
        $executor = $ExecutorMap[$type]
        if ($executor -is [scriptblock]) {
            return & $executor $Step
        }
        return & $executor -Step $Step
    }

    # Resolve the apply instant of a step's already-checkpointed dependency (for propagation gates
    # whose notBefore is offset from the dependency apply time). The checkpoint is read back via
    # ConvertFrom-Json, which auto-converts the 'yyyy-MM-ddTHH:mm:ssZ' appliedUtc string into a
    # [datetime] (Kind=Unspecified/Local) — NOT the original 'Z' string. A culture-sensitive
    # [string] cast of that [datetime] + a locale-default TryParse then FAILS to round-trip on many
    # machines (e.g. it yields '06/13/2026 00:00:01', which InvariantCulture-less TryParse rejects),
    # silently dropping the dependency time and fail-closing the propagation gate forever. So accept
    # a [datetime]/[datetimeoffset] directly, and parse a string with InvariantCulture + AssumeUniversal.
    function ConvertTo-AppliedInstant {
        param($Value)
        if ($null -eq $Value) { return $null }
        if ($Value -is [datetime]) {
            $dt = [datetime]$Value
            if ($dt.Kind -eq [System.DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($dt, [System.DateTimeKind]::Utc) }
            return $dt.ToUniversalTime()
        }
        if ($Value -is [datetimeoffset]) { return ([datetimeoffset]$Value).UtcDateTime }
        $s = [string]$Value
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        $parsed = [datetimeoffset]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        if ([datetimeoffset]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
            return $parsed.UtcDateTime
        }
        $null
    }
    function Get-DependencyAppliedUtc {
        param([pscustomobject]$Step)
        $latest = $null
        foreach ($depId in @($Step.dependsOn)) {
            $cp = Read-Checkpoint -StepId ([string]$depId)
            if ($cp -and $cp.PSObject.Properties['appliedUtc'] -and $cp.appliedUtc) {
                $instant = ConvertTo-AppliedInstant -Value $cp.appliedUtc
                if ($null -ne $instant) {
                    if ($null -eq $latest -or $instant -gt $latest) { $latest = $instant }
                }
            }
        }
        if ($null -ne $latest) { return $latest.ToString('o') }
        $null
    }

    # ------------------------------------------------------------------ 6. DISPATCH in dep order
    $stepResults = [System.Collections.Generic.List[object]]::new()

    # UNSATISFIED set (SAFETY, P1): step ids that were blocked or failed and produced NO success
    # checkpoint. Steps are processed in topological order, so a step whose direct dependsOn names an
    # unsatisfied id is itself unsatisfied and is skipped WITHOUT running its executor — the set
    # propagates forward and the whole dependent subtree is skipped, never mutating the tenant out of
    # dependency order. A checkpointed/applied/already-done step is NOT in this set.
    $unsatisfied = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

    foreach ($step in $orderedSteps) {
        $stepId = [string]$step.id

        # ---- resume: a step with an existing checkpoint is SKIPPED -------------------------------
        if (Test-StepCheckpointed -StepId $stepId) {
            $cp = Read-Checkpoint -StepId $stepId
            $stepResults.Add([pscustomobject]@{
                stepId = $stepId; action = [string]$step.action; objectType = [string]$step.objectType
                objectRef = [string]$step.objectRef; status = 'skipped'
                reason = 'already checkpointed (resume)'; result = $cp.result
            }) | Out-Null
            continue
        }

        # ---- SAFETY (P1): skip a step whose prerequisite is UNSATISFIED --------------------------
        # If any DIRECT dependsOn id was blocked/failed without a success checkpoint, this step must
        # NOT run (its prerequisite was neither applied nor checkpointed). Record it skipped, add it
        # to the unsatisfied set so its own dependents are skipped too, and do NOT call the executor.
        $unmetDeps = @(@($step.dependsOn) | Where-Object { $unsatisfied.Contains([string]$_) } | ForEach-Object { [string]$_ })
        if ($unmetDeps.Count -gt 0) {
            $stepResults.Add([pscustomobject]@{
                stepId = $stepId; action = [string]$step.action; objectType = [string]$step.objectType
                objectRef = [string]$step.objectRef; status = 'skipped-dependency'
                reason = "prerequisite step(s) not satisfied (blocked/failed upstream): $($unmetDeps -join ', ') — refusing out-of-dependency-order mutation."
                result = $null
            }) | Out-Null
            $unsatisfied.Add($stepId) | Out-Null
            continue
        }

        # ---- gate check (Test-Compl8Gate, injected clock) ---------------------------------------
        $gateContext = @{}
        if ($null -ne $step.gate) {
            $gateType = [string]$step.gate.type
            if ($gateType -eq 'snapshotBeforeDestroy') {
                # The snapshotBeforeDestroy gate guards DESTRUCTIVE steps: they may proceed only once
                # the snapshot Step 0.5 has checkpointed. The snapshot step ITSELF carries the gate
                # in the generated plan (golden fixture) as the marker — but running the snapshot IS
                # taking the snapshot, so the gate is inherently satisfied for action='snapshot'
                # (otherwise it would deadlock — the snapshot could never run). For any other step,
                # the gate is satisfied once the snapshot step it depends on is checkpointed.
                $snapApplied = $false
                if ([string]$step.action -eq 'snapshot') {
                    $snapApplied = $true
                } else {
                    foreach ($depId in @($step.dependsOn)) {
                        $depStep = @($orderedSteps | Where-Object { [string]$_.id -eq [string]$depId })[0]
                        if ($depStep -and [string]$depStep.action -eq 'snapshot' -and (Test-StepCheckpointed -StepId ([string]$depId))) {
                            $snapApplied = $true; break
                        }
                    }
                }
                $gateContext['SnapshotApplied'] = $snapApplied
            }
            if ($gateType -eq 'propagation') {
                $depApplied = Get-DependencyAppliedUtc -Step $step
                if ($depApplied) { $gateContext['DependencyAppliedUtc'] = $depApplied }
                # PROPAGATION BY VISIBILITY (the authoritative signal — matches the leaf's
                # Get-DlpSensitiveInformationType poll). When a -PropagationProbe is supplied AND the gate
                # names the SIT ids the dependent rule reads from the changed package(s), probe the tenant:
                # the probe returns $true (all visible -> proceed), $false (still propagating -> block), or
                # $null (couldn't determine -> leave unknown so the gate falls back to the time window).
                # No probe (the default) => visibility unknown => time-offset fallback, unchanged behaviour.
                $reqIds = @()
                if ($step.gate.PSObject.Properties['requiresSitIds']) { $reqIds = @(@($step.gate.requiresSitIds) | Where-Object { $_ }) }
                if ($PropagationProbe -and $reqIds.Count -gt 0) {
                    $visible = $null
                    try { $visible = & $PropagationProbe $reqIds } catch { $visible = $null }
                    if ($null -ne $visible) { $gateContext['DependencyVisible'] = [bool]$visible }
                }
            }

            $gateResult = Test-Compl8Gate -Gate $step.gate -Now $Now -Context $gateContext -ConfirmExternalRefs:$ConfirmExternalRefs
            if (-not $gateResult.Passed) {
                $stepResults.Add([pscustomobject]@{
                    stepId = $stepId; action = [string]$step.action; objectType = [string]$step.objectType
                    objectRef = [string]$step.objectRef; status = 'blocked'
                    reason = "gate: $($gateResult.Reason)"; result = $null
                }) | Out-Null
                # Blocked, no success checkpoint => unsatisfied (dependents must be skipped, P1).
                $unsatisfied.Add($stepId) | Out-Null
                if ($ContinueOnBlock) { continue } else { break }
            }
        }

        # ---- destructive backstop (D5): rule-package REMOVAL reference guard ---------------------
        # SCOPED (P2): this guard parses serialized rule-package XML to find live DLP rules still
        # referencing the package's SITs. It is therefore meaningful ONLY for an actual rule-package
        # removal. Running it for label/dictionary/policy removals or a dlpRule `dereference` step
        # would hand its parser an object with no package XML, which it treats as an unparsed package
        # and vetoes (Safe=false) — falsely blocking unrelated destructive work. (A dereference is the
        # de-referencing work itself, performed by the dlpRule executor; non-rulePackage removals
        # carry no rule-package XML.) So gate ONLY genuine rule-package removals here.
        if ([string]$step.action -eq 'remove' -and [string]$step.objectType -eq 'rulePackage') {
            # Supply the guard REAL package data: the step's resolved content (the same content the
            # production executor-map closure binds as the executor's -Content) carries the serialized
            # rule-package XML + the live DLP rules the guard parses. Without it the guard can only see
            # the objectRef identity (which would parse as unsafe), so prefer -StepContent when present.
            $content = if ($StepContent.ContainsKey($stepId)) { $StepContent[$stepId] } else { $null }
            # Read a field from the resolved content whether it is a hashtable (the documented
            # -StepContent value shape: @{ Packages = ...; DlpRules = ... }) OR a PSObject. A bare
            # PSObject.Properties[...] lookup misses hashtable keys, which would drop DlpRules /
            # Packages and falsely veto a safe rule-package removal (codex 4C re-review P2).
            $readContentField = {
                param($Obj, [string]$Key)
                if ($null -eq $Obj) { return $null }
                if ($Obj -is [System.Collections.IDictionary]) {
                    if ($Obj.Contains($Key)) { return $Obj[$Key] } else { return $null }
                }
                $p = $Obj.PSObject.Properties[$Key]
                if ($p) { return $p.Value } else { return $null }
            }
            $contentPackages = & $readContentField $content 'Packages'
            $contentPayload  = & $readContentField $content 'payloadXml'
            $contentDlpRules = & $readContentField $content 'DlpRules'
            $guardArgs = @{ OperationName = "apply: remove rulePackage $($step.objectRef)" }
            if ($content -and $contentPackages) {
                $guardArgs['Packages'] = @($contentPackages)
            } elseif ($content -and $contentPayload) {
                # A package payload carried as a single resolved object — pass it through as the package.
                $guardArgs['Packages'] = @($content)
            } else {
                # Fallback: only the identity is known. Still genuinely guards a real rule-package
                # removal (defence-in-depth); the guard fails closed if it cannot parse the package.
                $guardArgs['Packages'] = @([pscustomobject]@{ Identity = [string]$step.objectRef; Name = [string]$step.objectRef })
            }
            if ($content -and $contentDlpRules) {
                $guardArgs['DlpRules'] = @($contentDlpRules)
            }
            $guard = Test-DlpRulePackageRemovalReferenceGuard @guardArgs
            $guardSafe = $true
            if ($guard -and $guard.PSObject.Properties['Safe']) { $guardSafe = [bool]$guard.Safe }
            if (-not $guardSafe) {
                $refCount = if ($guard.PSObject.Properties['ReferencingRuleCount']) { [int]$guard.ReferencingRuleCount } else { 0 }
                $stepResults.Add([pscustomobject]@{
                    stepId = $stepId; action = [string]$step.action; objectType = [string]$step.objectType
                    objectRef = [string]$step.objectRef; status = 'blocked'
                    reason = "reference guard veto: '$($step.objectRef)' is still referenced by $refCount live DLP rule(s) — refusing the destructive step (D5 backstop)."
                    result = $null
                }) | Out-Null
                # Blocked, no success checkpoint => unsatisfied (dependents must be skipped, P1).
                $unsatisfied.Add($stepId) | Out-Null
                if ($ContinueOnBlock) { continue } else { break }
            }
        }

        # ---- executor + checkpoint --------------------------------------------------------------
        $execResult = $null
        try {
            $execResult = Invoke-StepExecutor -Step $step
        } catch {
            # Executor failure: record it, write NO checkpoint (so a re-run RETRIES this step), and
            # rethrow so the operator sees the failure and the apply halts here.
            $stepResults.Add([pscustomobject]@{
                stepId = $stepId; action = [string]$step.action; objectType = [string]$step.objectType
                objectRef = [string]$step.objectRef; status = 'failed'
                reason = $_.Exception.Message; result = $null
            }) | Out-Null
            $partial = New-ApplyResultObject -ThePlanId $planId -TheWorkspace $workspace -AppliedUtc $applyStampUtc -TheStepResults $stepResults
            Write-ApplyResult -TheAppliesDir $appliesDir -TheResult $partial
            throw "Invoke-Compl8Apply: step '$stepId' ($([string]$step.action) $([string]$step.objectType) '$([string]$step.objectRef)') FAILED: $($_.Exception.Message). Steps before it are checkpointed; re-run the same plan to resume from here."
        }

        $checkpoint = [pscustomobject]@{
            schemaVersion = 'compl8.apply-checkpoint/v1'
            planId        = $planId
            stepId        = $stepId
            action        = [string]$step.action
            objectType    = [string]$step.objectType
            objectRef     = [string]$step.objectRef
            appliedUtc    = $applyStampUtc
            result        = $execResult
        }
        Write-Checkpoint -Checkpoint $checkpoint

        $stepResults.Add([pscustomobject]@{
            stepId = $stepId; action = [string]$step.action; objectType = [string]$step.objectType
            objectRef = [string]$step.objectRef; status = 'applied'
            reason = ''; result = $execResult
        }) | Out-Null
    }

    # ------------------------------------------------------------------ 7. result.json (every step)
    $result = New-ApplyResultObject -ThePlanId $planId -TheWorkspace $workspace -AppliedUtc $applyStampUtc -TheStepResults $stepResults
    Write-ApplyResult -TheAppliesDir $appliesDir -TheResult $result
    return $result
}
