function Get-Compl8ExecutorMap {
    <#
    .SYNOPSIS
        Assembles the PRODUCTION executor map (objectType -> closure) that Invoke-Compl8Apply
        dispatches plan steps through — binding the real per-type executors with their resolved
        -Content via closures. (PHASE 4D, Task 13; arch design §5/§6; decisions D1/D3.)

    .DESCRIPTION
        Invoke-Compl8Apply (Task 6) resolves each step's executor from -ExecutorMap by objectType
        and invokes a scriptblock executor as `& $executor $Step` (one positional). The real
        per-type executors (Tasks 8-12) take -Step PLUS the resolved -Content the step needs (the
        dictionary terms, the label definition, the rule-package payload XML, the rule condition,
        the auto-label classifier list). That content is NOT on the plan step — it is resolved
        from the desired/ pipeline and threaded in per-step.

        This function is the SINGLE place the whole map is assembled (the wiring the per-executor
        headers each document as the production map shape). Each map value is a CLOSURE that:
          1. resolves the step's content from -StepContent[$Step.id] (a stepId -> content map), and
          2. calls the matching Invoke-Compl8<Type>Executor with -Step + -Content + the shared
             apply-batch context (prefix, tenant inventories for the gates, an injectable sleep).
        The SCC cmdlets the executors call are the ONLY tenant mutations (D3); under test they are
        mocked -ModuleName Compl8.Engine. The map closures only CALL the module-exported executors,
        so a `Mock -ModuleName Compl8.Engine <SccCmdlet>` still resolves inside the executor body
        (the executor's own retry scriptblocks keep their module affinity — see each executor).

        OBJECT-TYPE COVERAGE (the apply enum objectType, see Get-Compl8EngineSchemaEnums):
          dictionary       -> Invoke-Compl8DictionaryExecutor
          rulePackage      -> Invoke-Compl8RulePackageExecutor
          label/labelPolicy-> Invoke-Compl8LabelExecutor
          dlpRule/dlpPolicy-> Invoke-Compl8DlpRuleExecutor   (also the planner-generated dereference)
          autoLabelPolicy  -> Invoke-Compl8AutoLabelExecutor
          tenant           -> the snapshotBeforeDestroy Step 0.5 executor (writes actual/ via the
                              Tenant reader Export-TenantActualSnapshot, D8), or the injected
                              -SnapshotExecutor for tests/operators that capture the snapshot
                              differently.

        The dereference dlpRule step carries no -Content (the removed SIT refs to strip are on the
        step's impact, read by the executor itself), so its closure passes -Content $null and the
        executor reads $Step.impact — exactly as Invoke-Compl8DlpRuleExecutor documents.

    .PARAMETER StepContent
        Hashtable stepId -> resolved content for that step. A step with no entry is invoked with
        -Content $null (valid for remove / dereference / snapshot, which need no resolved content).

    .PARAMETER Prefix
        Deployment naming prefix (e.g. 'QGISCF'), forwarded to every executor's provenance stamp.

    .PARAMETER TargetEnvironment
        Optional environment key forwarded to the executors' provenance stamps.

    .PARAMETER DictionaryInventory
        Tenant keyword-dictionary inventory (objects with a Guid), forwarded to the rule-package
        executor's dictionary-reference assertion gate.

    .PARAMETER TenantSitInventory
        Tenant SIT inventory (objects with Id + Name), forwarded to the dlpRule / auto-label
        executors' SIT-validation gate.

    .PARAMETER ConfirmNameConflicts
        Forwarded to the dlpRule / auto-label executors' name-conflict pre-flight (an active
        same-named object is refused without this).

    .PARAMETER Inventory
        The tenant inventory the map is assembled against (the same shape the assess/plan consumes:
        { objects = { sitPackages = [ { name; ours; ... } ] ... } }). Used to DERIVE the rule-package
        capacity gate's CurrentSlotsUsed = the count of OUR existing rule packages
        (objects.sitPackages where ours -eq $true), so a near-full tenant's gate sees TRUE headroom
        and refuses an over-cap create. Optional; when omitted (and -CurrentRulePackageSlotsUsed is not
        given) the gate falls back to 0 used (legacy behaviour).

    .PARAMETER Plan
        The plan being applied (compl8.plan/v1: { steps = [ { action; objectType; ... } ] }). Used to
        DERIVE the capacity gate's SlotsFreed = the count of rulePackage REMOVALS in THIS plan
        (steps where objectType -eq 'rulePackage' -and action -eq 'remove'), crediting freed slots so a
        create that reuses a removed package's slot is not falsely blocked. Optional; when omitted (and
        -RulePackageSlotsFreed is not given) the gate falls back to 0 freed.

    .PARAMETER CurrentRulePackageSlotsUsed
        Explicit override for the rule-package capacity gate's CurrentSlotsUsed. When supplied it wins
        over the -Inventory derivation; otherwise it is derived from -Inventory (or defaults to 0).

    .PARAMETER RulePackageSlotsFreed
        Explicit override for the rule-package capacity gate's SlotsFreed. When supplied it wins over
        the -Plan derivation; otherwise it is derived from -Plan (or defaults to 0).

    .PARAMETER SleepAction
        Injectable sleep forwarded to every executor's retry / remove / verify paths. Defaults to a
        real Start-Sleep; tests pass a no-op so retry/verify run instantly.

    .PARAMETER SnapshotExecutor
        Optional scriptblock for the `tenant` snapshotBeforeDestroy Step 0.5. It receives the plan
        step ($Step) positionally and returns the snapshot result recorded in the step checkpoint.
        When omitted, the default writes the supplied -SnapshotInventory into the workspace actual/
        tree via Export-TenantActualSnapshot at -SnapshotTimestamp.

    .PARAMETER SnapshotInventory
        The inventory object the default snapshot executor persists (the actual/ state captured
        before any destructive step). Required by the DEFAULT snapshot executor only.

    .PARAMETER SnapshotWorkspacePath
        The workspace root the default snapshot executor writes actual/snapshots/<ts>/ under.
        Required by the DEFAULT snapshot executor only.

    .PARAMETER SnapshotTimestamp
        The deterministic snapshot folder name for the default snapshot executor (Get-Date is
        banned). Required by the DEFAULT snapshot executor only.

    .OUTPUTS
        A hashtable objectType -> scriptblock, ready to pass to Invoke-Compl8Apply -ExecutorMap.

    .NOTES
        SHARED LABEL PARENT-GUID CACHE. The map creates ONE [hashtable] parent-guid cache and threads
        it (-ParentGuidCache) into EVERY label/labelPolicy closure. A label GROUP created by an earlier
        step seeds the cache (the executor writes its new Guid back under the group name), so a later
        SUBLABEL step in the SAME apply resolves the parent from the cache instead of falling to Get-Label
        — which would return 'parent-not-found' if Purview has not yet surfaced the just-created group.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$StepContent = @{},

        [string]$Prefix,

        [string]$TargetEnvironment,

        [object[]]$DictionaryInventory = @(),

        [object[]]$TenantSitInventory = @(),

        [switch]$ConfirmNameConflicts,

        [object]$Inventory,

        [object]$Plan,

        [int]$CurrentRulePackageSlotsUsed,

        [int]$RulePackageSlotsFreed,

        [scriptblock]$SleepAction = { param($s) Start-Sleep -Seconds $s },

        [scriptblock]$SnapshotExecutor,

        [object]$SnapshotInventory,

        [string]$SnapshotWorkspacePath,

        [string]$SnapshotTimestamp
    )

    # ---- RULE-PACKAGE SLOT ACCOUNTING (capacity-gate inputs for the rulePackage closure) ---------
    # The capacity gate refuses a create that would exceed MaxRulePackagesPerTenant. It needs the TRUE
    # batch accounting, NOT the executor defaults (0 used / 0 freed) — otherwise a near-full tenant
    # always looks to have room and an over-cap create slips through. Derive both from the data the
    # assembler already holds, with explicit overrides winning when supplied:
    #   CurrentSlotsUsed = count of OUR existing rule packages (objects.sitPackages where ours = $true),
    #   SlotsFreed       = count of rulePackage REMOVALS in THIS plan (steps action=remove type=rulePackage).
    $rulePackageSlotsUsed = if ($PSBoundParameters.ContainsKey('CurrentRulePackageSlotsUsed')) {
        $CurrentRulePackageSlotsUsed
    } elseif ($Inventory -and $Inventory.PSObject.Properties['objects'] -and $Inventory.objects `
              -and $Inventory.objects.PSObject.Properties['sitPackages']) {
        @(@($Inventory.objects.sitPackages) | Where-Object {
            $_ -and $_.PSObject.Properties['ours'] -and [bool]$_.ours
        }).Count
    } else { 0 }

    $rulePackageSlotsFreed = if ($PSBoundParameters.ContainsKey('RulePackageSlotsFreed')) {
        $RulePackageSlotsFreed
    } elseif ($Plan -and $Plan.PSObject.Properties['steps']) {
        @(@($Plan.steps) | Where-Object {
            $_ -and [string]$_.objectType -eq 'rulePackage' -and [string]$_.action -eq 'remove'
        }).Count
    } else { 0 }

    # The executor's gate is STATELESS per call (it only knows the CurrentSlotsUsed it is handed), so it
    # cannot see slots consumed by EARLIER creates in this same apply batch. The map closes that gap: it
    # keeps a running count of creates already realised this batch and adds it to the baseline used, so
    # the Nth create sees the slots the prior N-1 creates filled. A mutable [ref] survives across the
    # closure's repeated invocations (the closure captures the SAME box).
    $rulePackageCreatesDone = [ref]0

    # ---- SHARED LABEL PARENT-GUID CACHE ---------------------------------------------------------
    # ONE hashtable threaded into every label/labelPolicy closure (each .GetNewClosure() captures the
    # SAME reference): a group created by an earlier step seeds it for a later sublabel in this apply.
    $parentGuidCache = @{}

    # Resolve a step's bound content from the stepId -> content map (or $null when absent).
    $resolveContent = {
        param($Step)
        if ($StepContent -and $StepContent.ContainsKey([string]$Step.id)) { return $StepContent[[string]$Step.id] }
        $null
    }.GetNewClosure()

    # The snapshotBeforeDestroy Step 0.5 executor. A caller/operator may inject one; otherwise the
    # default persists the captured inventory into the workspace actual/ tree (the Tenant reader
    # owns actual/, D8) and returns its descriptor.
    $snapshotExec = if ($SnapshotExecutor) {
        $SnapshotExecutor
    } else {
        {
            param($Step)
            if (-not $SnapshotWorkspacePath -or -not $SnapshotTimestamp) {
                throw "Get-Compl8ExecutorMap snapshot executor: -SnapshotWorkspacePath and -SnapshotTimestamp are required for the default snapshot (or inject -SnapshotExecutor)."
            }
            $written = Export-TenantActualSnapshot -WorkspacePath $SnapshotWorkspacePath `
                -Timestamp $SnapshotTimestamp -Inventory $SnapshotInventory
            [pscustomobject]@{
                stepId     = [string]$Step.id
                action     = 'snapshot'
                objectType = 'tenant'
                objectRef  = [string]$Step.objectRef
                status     = 'snapshotted'
                snapshotDir = $written.SnapshotDir
                reason     = "tenant snapshot captured to $($written.SnapshotDir) before any destructive step (snapshotBeforeDestroy)."
            }
        }.GetNewClosure()
    }

    @{
        dictionary = {
            param($Step)
            Invoke-Compl8DictionaryExecutor -Step $Step -Content (& $resolveContent $Step) `
                -Prefix $Prefix -TargetEnvironment $TargetEnvironment -SleepAction $SleepAction
        }.GetNewClosure()

        rulePackage = {
            param($Step)
            # Add creates already realised this batch to the baseline used so the gate sees true
            # headroom shrink as the batch fills slots (the executor itself is stateless per call).
            $usedNow = $rulePackageSlotsUsed + $rulePackageCreatesDone.Value
            $result = Invoke-Compl8RulePackageExecutor -Step $Step -Content (& $resolveContent $Step) `
                -DictionaryInventory $DictionaryInventory -Prefix $Prefix -TargetEnvironment $TargetEnvironment `
                -CurrentSlotsUsed $usedNow -SlotsFreed $rulePackageSlotsFreed `
                -SleepAction $SleepAction
            # A realised create consumed a slot — charge the running batch count so the next create sees it.
            if ($result -and [string]$result.status -eq 'created') { $rulePackageCreatesDone.Value++ }
            $result
        }.GetNewClosure()

        # A `sit` step (create / repack-move / remove of a SIT entity) has NO standalone tenant
        # cmdlet: a SIT lives INSIDE a rule package, so its create/move/remove is REALIZED by the
        # rule-package executor re-uploading the owning package (the planner orders the sit step
        # against that package step). The sit step is therefore a tracking unit — its executor
        # records the SIT lifecycle as subsumed-by-package and performs no separate mutation (which
        # would be a second, conflicting write of the same package). The package upload (a
        # rulePackage step) is the real mutation; this keeps apply dispatching every step exactly
        # once without double-writing.
        sit = {
            param($Step)
            [pscustomobject]@{
                stepId     = [string]$Step.id
                action     = [string]$Step.action
                objectType = 'sit'
                objectRef  = [string]$Step.objectRef
                status     = 'subsumed-by-package'
                reason     = "SIT '$([string]$Step.objectRef)' ($([string]$Step.action)) is realized by its owning rule-package upload; no standalone SIT mutation."
            }
        }.GetNewClosure()

        label = {
            param($Step)
            Invoke-Compl8LabelExecutor -Step $Step -Content (& $resolveContent $Step) `
                -Prefix $Prefix -TargetEnvironment $TargetEnvironment -ParentGuidCache $parentGuidCache `
                -SleepAction $SleepAction
        }.GetNewClosure()

        labelPolicy = {
            param($Step)
            Invoke-Compl8LabelExecutor -Step $Step -Content (& $resolveContent $Step) `
                -Prefix $Prefix -TargetEnvironment $TargetEnvironment -ParentGuidCache $parentGuidCache `
                -SleepAction $SleepAction
        }.GetNewClosure()

        dlpRule = {
            param($Step)
            Invoke-Compl8DlpRuleExecutor -Step $Step -Content (& $resolveContent $Step) `
                -TenantSitInventory $TenantSitInventory -ConfirmNameConflicts:$ConfirmNameConflicts `
                -Prefix $Prefix -TargetEnvironment $TargetEnvironment -SleepAction $SleepAction
        }.GetNewClosure()

        dlpPolicy = {
            param($Step)
            Invoke-Compl8DlpRuleExecutor -Step $Step -Content (& $resolveContent $Step) `
                -TenantSitInventory $TenantSitInventory -ConfirmNameConflicts:$ConfirmNameConflicts `
                -Prefix $Prefix -TargetEnvironment $TargetEnvironment -SleepAction $SleepAction
        }.GetNewClosure()

        autoLabelPolicy = {
            param($Step)
            Invoke-Compl8AutoLabelExecutor -Step $Step -Content (& $resolveContent $Step) `
                -TenantSitInventory $TenantSitInventory -ConfirmNameConflicts:$ConfirmNameConflicts `
                -Prefix $Prefix -TargetEnvironment $TargetEnvironment -SleepAction $SleepAction
        }.GetNewClosure()

        tenant = $snapshotExec
    }
}
