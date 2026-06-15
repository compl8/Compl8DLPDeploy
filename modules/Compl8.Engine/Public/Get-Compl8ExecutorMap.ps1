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

    .PARAMETER ProvenanceRegistryPath
        Optional provenance registry path bound into EVERY stamping executor closure (dictionary, label,
        labelPolicy, dlpRule, dlpPolicy, autoLabelPolicy — the rulePackage / sit / tenant executors do NOT
        stamp provenance). This is the SEAM the production wiring uses to make a workspace apply write its
        provenance to the workspace's one-writer history file: pass Context.ProvenanceRegistryPath (from
        New-Compl8Context, = <ws>/history/applies/provenance.json) and each closure threads it to its
        executor's -ProvenanceRegistryPath -> Add-DeploymentProvenanceStamp -RegistryPath. When OMITTED the
        registry resolves via the existing precedence ($env:COMPL8_PROVENANCE_REGISTRY else the repo
        default) — so every existing caller and test is unaffected. (Stage 5 D8; codex 5A review.)

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
        The plan being applied (compl8.plan/v1: { steps = [ { action; objectType; ... } ] }). Retained for
        caller context/parity; it is NO LONGER used to pre-derive SlotsFreed. Freed slots are now counted
        from removals that ACTUALLY COMPLETE during this apply batch (the rulePackage remove path increments
        a shared running counter), so a create dispatched BEFORE its removals has run cannot be credited a
        slot that is not yet free. (A static count of all planned removals would wrongly credit such a create
        and let it slip past the cap — codex 4D re-review P2-A.)

    .PARAMETER CurrentRulePackageSlotsUsed
        Explicit override for the rule-package capacity gate's baseline CurrentSlotsUsed. When supplied it
        wins over the -Inventory derivation; otherwise it is derived from -Inventory (or defaults to 0). The
        map adds the slots consumed by EARLIER creates in this batch on top of this baseline per dispatch.

    .PARAMETER RulePackageSlotsFreed
        Optional STARTING credit for the running freed-slots counter (e.g. slots freed before this batch).
        The counter then ADVANCES as rulePackage removals actually complete in this apply. When omitted the
        starting credit is 0.

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

        [string]$SnapshotTimestamp,

        # Declared LAST so inserting it does not shift any existing positional slot (see .PARAMETER
        # ProvenanceRegistryPath above for the full contract). (Stage 5 D8; codex 5A re-review.)
        [string]$ProvenanceRegistryPath
    )

    # ---- RULE-PACKAGE SLOT ACCOUNTING (capacity-gate inputs for the rulePackage closure) ---------
    # The capacity gate refuses a create that would exceed MaxRulePackagesPerTenant. It needs the TRUE
    # batch accounting, NOT the executor defaults (0 used / 0 freed) — otherwise a near-full tenant
    # always looks to have room and an over-cap create slips through. The accounting must also CONVERGE
    # in DISPATCH ORDER: a create dispatched before its removals have run cannot borrow against slots that
    # are not yet free, and a create whose upload happened (even if post-upload verification then failed)
    # has ALREADY consumed its slot. So the map keeps the running batch state in two SHARED [ref] cells
    # that BOTH the create and remove paths of the (single) rulePackage closure mutate, and every create's
    # gate is computed from the state AT ITS DISPATCH POINT — not from a static count of all planned work.
    #
    #   baselineUsed = count of OUR existing rule packages (objects.sitPackages where ours = $true) — the
    #                  slots already taken before this batch ran. (-CurrentRulePackageSlotsUsed overrides.)
    $rulePackageSlotsUsed = if ($PSBoundParameters.ContainsKey('CurrentRulePackageSlotsUsed')) {
        $CurrentRulePackageSlotsUsed
    } elseif ($Inventory -and $Inventory.PSObject.Properties['objects'] -and $Inventory.objects `
              -and $Inventory.objects.PSObject.Properties['sitPackages']) {
        @(@($Inventory.objects.sitPackages) | Where-Object {
            $_ -and $_.PSObject.Properties['ours'] -and [bool]$_.ours
        }).Count
    } else { 0 }

    # SHARED running counters (mutable [ref] cells the rulePackage closure captures by reference, so they
    # survive across the closure's repeated invocations and BOTH the create and remove branches see the
    # same box):
    #   $rulePackageCreatesDone  — slots CONSUMED by this batch so far. A create consumes a slot the moment
    #                              its upload (New) happens, which is true for status 'created' AND
    #                              'verify-failed' (the upload succeeded; only the post-upload verification
    #                              timed out — the slot is taken either way). It must NOT advance on a
    #                              capacity-blocked / dict-ref-missing create (no upload happened).
    #   $rulePackageRemovesDone  — slots FREED by removals that have ACTUALLY COMPLETED this batch so far
    #                              (remove status 'deleted' — the package is gone). NOT a static count of
    #                              all planned removals: a removal that has not yet run frees nothing, so a
    #                              create dispatched before it must not be credited its slot. Seeded from
    #                              -RulePackageSlotsFreed when supplied (an explicit starting credit).
    # Each create then passes the executor:
    #   CurrentSlotsUsed = baselineUsed + $rulePackageCreatesDone.Value
    #   SlotsFreed       = $rulePackageRemovesDone.Value
    # The executor computes available = MaxPackages - CurrentSlotsUsed + SlotsFreed, so the NET headroom a
    # create sees = MaxPackages - (baselineUsed + consumedSoFar - removesCompletedSoFar) — exactly the true
    # batch state at this create's dispatch point.
    $rulePackageCreatesDone = [ref]0
    $rulePackageRemovesDone = [ref]([int]$(if ($PSBoundParameters.ContainsKey('RulePackageSlotsFreed')) { $RulePackageSlotsFreed } else { 0 }))

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
                -Prefix $Prefix -TargetEnvironment $TargetEnvironment `
                -ProvenanceRegistryPath $ProvenanceRegistryPath -SleepAction $SleepAction
        }.GetNewClosure()

        rulePackage = {
            param($Step)
            # The executor's gate is STATELESS per call, so the map threads the running batch state in at
            # THIS step's dispatch point: used = baseline + creates already consumed; freed = removals that
            # have ACTUALLY completed so far. (A create dispatched before its removals sees freed=0.)
            $usedNow  = $rulePackageSlotsUsed + $rulePackageCreatesDone.Value
            $freedNow = $rulePackageRemovesDone.Value
            $result = Invoke-Compl8RulePackageExecutor -Step $Step -Content (& $resolveContent $Step) `
                -DictionaryInventory $DictionaryInventory -Prefix $Prefix -TargetEnvironment $TargetEnvironment `
                -CurrentSlotsUsed $usedNow -SlotsFreed $freedNow `
                -SleepAction $SleepAction
            $status = if ($result) { [string]$result.status } else { '' }
            $stepAction = [string]$Step.action
            # A CREATE consumes a NEW slot the moment its upload happens — true for 'created' AND a
            # create that returns 'verify-failed' (the New upload succeeded; only post-upload verification
            # timed out). An UPDATE that returns 'verify-failed' reuses its EXISTING slot, so it must NOT
            # be charged as new consumption (would falsely capacity-block a later create). Hence the
            # verify-failed charge is gated on action='create'. 'created' is create-only by definition.
            if ($status -eq 'created' -or ($status -eq 'verify-failed' -and $stepAction -eq 'create')) {
                $rulePackageCreatesDone.Value++
            }
            # A remove FREES a slot only once the package is ACTUALLY gone. Remove-PurviewObject maps a
            # PendingDeletion to status='deleted' but preserves removeState='pending'; a pending package
            # may still count against the tenant cap, so do NOT credit it as freed (would let a later
            # create through against a slot that is not yet truly free). Credit only a completed delete.
            elseif ($status -eq 'deleted' -and [string]$result.removeState -ne 'pending') {
                $rulePackageRemovesDone.Value++
            }
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
                -ProvenanceRegistryPath $ProvenanceRegistryPath -SleepAction $SleepAction
        }.GetNewClosure()

        labelPolicy = {
            param($Step)
            Invoke-Compl8LabelExecutor -Step $Step -Content (& $resolveContent $Step) `
                -Prefix $Prefix -TargetEnvironment $TargetEnvironment -ParentGuidCache $parentGuidCache `
                -ProvenanceRegistryPath $ProvenanceRegistryPath -SleepAction $SleepAction
        }.GetNewClosure()

        dlpRule = {
            param($Step)
            # A `claim` step adopts an existing not-ours rule (re-stamp provenance); any other action
            # is the normal create/update/remove/dereference path (R2).
            if ([string]$Step.action -eq 'claim') {
                Invoke-Compl8ClaimExecutor -Step $Step -Prefix $Prefix -TargetEnvironment $TargetEnvironment `
                    -ProvenanceRegistryPath $ProvenanceRegistryPath -SleepAction $SleepAction
            } else {
                Invoke-Compl8DlpRuleExecutor -Step $Step -Content (& $resolveContent $Step) `
                    -TenantSitInventory $TenantSitInventory -ConfirmNameConflicts:$ConfirmNameConflicts `
                    -Prefix $Prefix -TargetEnvironment $TargetEnvironment `
                    -ProvenanceRegistryPath $ProvenanceRegistryPath -SleepAction $SleepAction
            }
        }.GetNewClosure()

        dlpPolicy = {
            param($Step)
            if ([string]$Step.action -eq 'claim') {
                Invoke-Compl8ClaimExecutor -Step $Step -Prefix $Prefix -TargetEnvironment $TargetEnvironment `
                    -ProvenanceRegistryPath $ProvenanceRegistryPath -SleepAction $SleepAction
            } else {
                Invoke-Compl8DlpRuleExecutor -Step $Step -Content (& $resolveContent $Step) `
                    -TenantSitInventory $TenantSitInventory -ConfirmNameConflicts:$ConfirmNameConflicts `
                    -Prefix $Prefix -TargetEnvironment $TargetEnvironment `
                    -ProvenanceRegistryPath $ProvenanceRegistryPath -SleepAction $SleepAction
            }
        }.GetNewClosure()

        autoLabelPolicy = {
            param($Step)
            Invoke-Compl8AutoLabelExecutor -Step $Step -Content (& $resolveContent $Step) `
                -TenantSitInventory $TenantSitInventory -ConfirmNameConflicts:$ConfirmNameConflicts `
                -Prefix $Prefix -TargetEnvironment $TargetEnvironment `
                -ProvenanceRegistryPath $ProvenanceRegistryPath -SleepAction $SleepAction
        }.GetNewClosure()

        tenant = $snapshotExec
    }
}
