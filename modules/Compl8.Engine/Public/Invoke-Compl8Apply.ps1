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
               * gate check (Test-Compl8Gate, injected clock -Now). A blocked step is recorded
                 'blocked' and apply stops (or, with -ContinueOnBlock, records the block and
                 continues to independent steps) — it resumes from checkpoint on a later run.
               * DESTRUCTIVE backstop (D5). A remove/dereference step re-invokes the reference
                 guard (Test-DlpRulePackageRemovalReferenceGuard) at apply time; a veto (Safe=false)
                 blocks that step (recorded 'blocked', executor NOT called).
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

    .PARAMETER Now
        Injected current instant ([datetime]) for gate evaluation and checkpoint stamps. Defaults to
        [datetime]::UtcNow ONLY as a convenience for production callers; tests pin it. (Get-Date is
        not called; the default uses the .NET clock directly and is overridden in all tests.)

    .PARAMETER ConfirmExternalRefs
        Operator confirmation forwarded to externalRefs gate evaluation.

    .PARAMETER ContinueOnBlock
        When a step is blocked by a gate or the destructive backstop, continue to subsequent
        independent steps instead of stopping at the first block. Blocked steps are recorded and
        resumed from checkpoint on a later run regardless.

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

        [datetime]$Now = [datetime]::UtcNow,

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
    # whose notBefore is offset from the dependency apply time).
    function Get-DependencyAppliedUtc {
        param([pscustomobject]$Step)
        $latest = $null
        foreach ($depId in @($Step.dependsOn)) {
            $cp = Read-Checkpoint -StepId ([string]$depId)
            if ($cp -and $cp.PSObject.Properties['appliedUtc'] -and $cp.appliedUtc) {
                $parsed = [datetimeoffset]::MinValue
                if ([datetimeoffset]::TryParse([string]$cp.appliedUtc, [ref]$parsed)) {
                    if ($null -eq $latest -or $parsed.UtcDateTime -gt $latest) { $latest = $parsed.UtcDateTime }
                }
            }
        }
        if ($null -ne $latest) { return $latest.ToString('o') }
        $null
    }

    # ------------------------------------------------------------------ 6. DISPATCH in dep order
    $stepResults = [System.Collections.Generic.List[object]]::new()

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
            }

            $gateResult = Test-Compl8Gate -Gate $step.gate -Now $Now -Context $gateContext -ConfirmExternalRefs:$ConfirmExternalRefs
            if (-not $gateResult.Passed) {
                $stepResults.Add([pscustomobject]@{
                    stepId = $stepId; action = [string]$step.action; objectType = [string]$step.objectType
                    objectRef = [string]$step.objectRef; status = 'blocked'
                    reason = "gate: $($gateResult.Reason)"; result = $null
                }) | Out-Null
                if ($ContinueOnBlock) { continue } else { break }
            }
        }

        # ---- destructive backstop (D5): re-invoke the reference guard before remove/dereference --
        if ([string]$step.action -in 'remove', 'dereference') {
            $guardPackages = @([pscustomobject]@{ Identity = [string]$step.objectRef; Name = [string]$step.objectRef })
            $guard = Test-DlpRulePackageRemovalReferenceGuard -Packages $guardPackages -OperationName "apply: $($step.action) $($step.objectRef)"
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
