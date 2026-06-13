function Invoke-Compl8LabelExecutor {
    <#
    .SYNOPSIS
        Apply executor for a SENSITIVITY-LABEL or LABEL-POLICY plan step (action create|update|remove;
        objectType label|labelPolicy). The FIRST executor copied from the Task-8 dictionary pilot that
        shadows against a leaf SCRIPT (Deploy-Labels.ps1) rather than a function — the shadow strategy
        it establishes is reused by Tasks 10-12. (PHASE 4C, Task 9; arch design §5/§6; decisions D1/D3.)

    .DESCRIPTION
        FRESH PORT (D1) of the label + label-policy mutation path from scripts/Deploy-Labels.ps1's inline
        loops into Compl8.Engine scope — the ONLY tenant-mutating layer (D3). The old Deploy-Labels.ps1
        stays live and UNMODIFIED; this executor reproduces its SCC cmdlet sequence and guards and is
        proven equivalent by a SHADOW DIFF against a GENUINE Deploy-Labels.ps1 run (Get-Compl8ShadowDiff
        Match -eq $true) before any cutover.

        ============================== TEMPLATE (copied from the dictionary pilot) ====================
        SIGNATURE / APPLY CONTRACT. Invoke-Compl8Apply dispatches a step to the executor as
        `& $executor -Step $step` (or `& $sb $step`), so the plan step is -Step (also positional 0). The
        RESOLVED CONTENT the step needs (display name / tooltip / markings for a label; scope + label
        list for a policy) is bound by the production executor-map closure as -Content — it is NOT on
        the step (the step only carries action/objectType/objectRef/dependsOn/impact/gate).

        PLANNED-OP / -WhatIf MODE. With -WhatIf the executor performs NO mutation and RETURNS a single
        normalised "planned operation" record in the Get-Compl8ShadowDiff op shape:
            { action; objectType; objectRef }
        This is the SHADOW-DIFF contract. The planned ACTION is derived from the desired-vs-existing
        state exactly as the old path decides it: a label/policy that already EXISTS plans an `update`,
        otherwise a `create` (a `remove` step always plans `remove`). Existing state under -WhatIf is
        supplied via -ExistingState (a name->object map) so planning is pure and matches the old path's
        Get-Label / Get-LabelPolicy lookups without a live tenant.

        RESULT / CHECKPOINT SHAPE (apply mode). The executor returns a result the apply checkpoint
        records verbatim:
            { stepId; action; objectType; objectRef; status; guid; reason; stampedComment;
              removeState?; parentId? }
        `status` ∈ created | updated | reused | deleted | type-mismatch | parent-not-found |
                   already-published | not-found | failed.

        PROVENANCE. On a create/update we stamp the label / policy Comment via
        Add-DeploymentProvenanceStamp (Compl8.Model) — the [[Compl8:<16hex>]] marker — so the object is
        discoverable as ours. The stamped string is returned as `stampedComment`.

        LABEL-SPECIFIC GUARDS (ported from Deploy-Labels.ps1):
          * PARENT RESOLUTION + CACHING. A sublabel (Content.parentGroup set) needs the parent group's
            Guid as -ParentId. We resolve it from -ParentGuidCache (keyed by parentGroup) first, else by
            Get-Label on the parent's prefixed name (Content.parentLabelName); the resolved Guid is
            written back into the cache. If the parent cannot be resolved the sublabel is SKIPPED
            (status 'parent-not-found', no New-Label) — matching the old path's
            "Parent group not found. Skipping sublabel" branch.
          * LEAF-vs-GROUP TYPE-MISMATCH. If the desired object is a GROUP but an existing label is a leaf
            (has a ContentType), or the desired is a top-level LEAF but the existing label is a group (no
            ContentType), the executor REFUSES to mutate (status 'type-mismatch', no New/Set) and the
            reason demands a manual delete — exactly the old path's "TYPE MISMATCH … Delete in Purview
            and re-run. Skipping" guard. (Sublabels are exempt from the leaf-as-group check, as in the
            old path: the `-not $label.parentGroup` condition.)

        LABEL-POLICY-SPECIFIC (ported from Deploy-Labels.ps1):
          * Invoke-WithRetry wraps New-/Set-LabelPolicy so transient Purview throttles back off + retry.
          * DUAL-PUBLISH RECOVERY. A Set-LabelPolicy that throws 'LabelAlreadyPublished' is treated as
            SUCCESS (status 'already-published', no rethrow) — the labels are already on the policy. Any
            OTHER error rethrows.

        REMOVE. Delegates to the ported Remove-PurviewObject state machine
        (deleted|pending|cooldown|not-found|failed), using Get-/Remove-Label or Get-/Remove-LabelPolicy
        per objectType. Both retry helpers have an injectable -SleepAction so tests never wait.

        NOTE on the retry scriptblock: it is passed to Invoke-WithRetry WITHOUT .GetNewClosure() so it
        keeps its module affinity (Compl8.Engine) and a `Mock -ModuleName Compl8.Engine` on
        New-/Set-LabelPolicy resolves inside it (a .GetNewClosure() would ESCAPE the module mock). Same
        as the dictionary pilot + the old Deploy-Labels.ps1.
        ============================================================================================

    .PARAMETER Step
        The label / label-policy plan step (compl8.plan/v1): { id; action; objectType; objectRef; ... }.
        action ∈ create|update|remove. objectType ∈ label|labelPolicy. Positional 0.

    .PARAMETER Content
        The resolved content for this step. For a label: { name; displayName; tooltip; priority; code;
        isGroup; parentGroup; parentLabelName; colour; headerText; footerText }. For a label policy:
        { name; scope; labels }. Required for create/update.

    .PARAMETER Prefix
        The deployment naming prefix (e.g. 'QGISCF'), forwarded to the provenance stamp.

    .PARAMETER TargetEnvironment
        Optional environment key forwarded to the provenance stamp.

    .PARAMETER ParentGuidCache
        A hashtable (parentGroup -> parent label Guid string) threaded across sublabel steps so a parent
        group is resolved at most once per apply, mirroring the old path's $parentGuids cache. Optional.

    .PARAMETER ExistingState
        A name -> existing-object map used ONLY in -WhatIf planning to decide create-vs-update without a
        live tenant (the planning analogue of the old path's Get-Label/Get-LabelPolicy existence probe).

    .PARAMETER NoMarking
        Suppress the visual content markings (header/footer), mirroring Deploy-Labels.ps1 -NoMarking.

    .PARAMETER SleepAction
        Injectable sleep forwarded to Invoke-WithRetry / Remove-PurviewObject. Defaults to a real
        Start-Sleep; tests pass a no-op so retry paths run instantly.

    .PARAMETER WhatIf
        Plan/report mode: perform NO mutation and return the normalised planned-operation record.

    .OUTPUTS
        -WhatIf: a planned-op record { action; objectType; objectRef }.
        Apply  : a step result { stepId; action; objectType; objectRef; status; guid; reason;
                 stampedComment; ... }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [pscustomobject]$Step,

        [pscustomobject]$Content,

        [string]$Prefix,

        [string]$TargetEnvironment,

        [hashtable]$ParentGuidCache,

        [hashtable]$ExistingState = @{},

        [switch]$NoMarking,

        [scriptblock]$SleepAction = { param($s) Start-Sleep -Seconds $s },

        [switch]$WhatIf
    )

    $action     = [string]$Step.action
    $objectRef  = [string]$Step.objectRef
    $objectType = if ($Step.PSObject.Properties['objectType'] -and $Step.objectType) { [string]$Step.objectType } else { 'label' }
    if ($objectType -ne 'label' -and $objectType -ne 'labelPolicy') {
        throw "Invoke-Compl8LabelExecutor: unsupported objectType '$objectType' for step '$($Step.id)' (expected label|labelPolicy)."
    }

    # --- planned-op helper: the normalised Get-Compl8ShadowDiff op shape ---------------------------
    function New-PlannedOp {
        param([string]$OpAction, [string]$OpRef)
        [pscustomobject]@{ action = $OpAction; objectType = $objectType; objectRef = $OpRef }
    }

    # --- step-result helper: the apply checkpoint result shape ------------------------------------
    function New-StepResult {
        param(
            [string]$Status,
            [string]$Guid = $null,
            [string]$Reason = '',
            [string]$StampedComment = $null,
            [string]$RemoveState = $null,
            [string]$ParentId = $null
        )
        $r = [ordered]@{
            stepId         = [string]$Step.id
            action         = $action
            objectType     = $objectType
            objectRef      = $objectRef
            status         = $Status
            guid           = $Guid
            reason         = $Reason
            stampedComment = $StampedComment
        }
        if ($PSBoundParameters.ContainsKey('RemoveState')) { $r['removeState'] = $RemoveState }
        if ($PSBoundParameters.ContainsKey('ParentId'))    { $r['parentId']    = $ParentId }
        [pscustomobject]$r
    }

    # --- remove-state -> step status mapping ------------------------------------------------------
    function ConvertTo-RemoveStatus {
        param([string]$RemoveState)
        switch ($RemoveState) {
            'deleted'   { 'deleted' }
            'pending'   { 'deleted' }    # already being removed — the desired end state is reached
            'not-found' { 'not-found' }
            default     { if ($RemoveState -like 'cooldown:*') { 'cooldown' } else { 'failed' } }
        }
    }

    # The scoped NAME the tenant cmdlets address. Prefer the resolved content's name; fall back to the
    # placeholder objectRef (e.g. a bare remove step with no content).
    $name = if ($Content -and $Content.PSObject.Properties['name'] -and $Content.name) { [string]$Content.name } else { $objectRef }

    # ============================================================ -WhatIf / plan mode (NO mutation)
    # Derive the planned ACTION from desired-vs-existing exactly as the old path decides it: an existing
    # object plans `update`, otherwise `create`; a `remove` step always plans `remove`.
    if ($WhatIf) {
        if ($action -eq 'remove') { return New-PlannedOp -OpAction 'remove' -OpRef $objectRef }
        $existsInState = $ExistingState -and $ExistingState.ContainsKey($name) -and $ExistingState[$name]
        $plannedAction = if ($existsInState) { 'update' } else { 'create' }
        return New-PlannedOp -OpAction $plannedAction -OpRef $objectRef
    }

    # ============================================================ POLICY path =====================
    if ($objectType -eq 'labelPolicy') {
        # ---- REMOVE policy ----------------------------------------------------------------------
        if ($action -eq 'remove') {
            $removeState = Remove-PurviewObject -Identity $name `
                -GetCommand 'Get-LabelPolicy' -RemoveCommand 'Remove-LabelPolicy' `
                -OperationName 'label policy' -SleepAction $SleepAction
            return New-StepResult -Status (ConvertTo-RemoveStatus $removeState) -RemoveState $removeState `
                -Reason "remove label policy '$name' -> $removeState"
        }

        if (-not $Content) {
            throw "Invoke-Compl8LabelExecutor: step '$($Step.id)' ($action $objectRef) requires -Content (resolved label policy) but none was supplied."
        }

        $scope            = if ($Content.PSObject.Properties['scope']) { [string]$Content.scope } else { '' }
        $publishableLabels = @(if ($Content.PSObject.Properties['labels']) { $Content.labels } else { @() })

        # Provenance-stamped policy Comment.
        $policyStampArgs = @{
            Text      = "$(if ($Prefix) { $Prefix } else { 'UNSCOPED' }) label policy - scope: $scope"
            Prefix    = if ($Prefix) { $Prefix } else { 'UNSCOPED' }
            Component = 'LabelPolicy'
            Metadata  = @{ Scope = $scope }
        }
        if ($TargetEnvironment) { $policyStampArgs['TargetEnvironment'] = $TargetEnvironment }
        $policyComment = Add-DeploymentProvenanceStamp @policyStampArgs

        # Existence probe.
        $existingPolicy = $null
        try { $existingPolicy = Get-LabelPolicy -Identity $name -ErrorAction Stop } catch { $existingPolicy = $null }

        $locationValue = if ($scope -eq 'All') { 'All' } else { $scope }

        if ($existingPolicy) {
            # ---- UPDATE policy: Set-LabelPolicy (AddLabels) with dual-publish recovery ------------
            $alreadyPublished = $false
            try {
                # Bare scriptblock (no .GetNewClosure()) — keeps the module mock resolvable inside retry.
                Invoke-WithRetry -OperationName "Set-LabelPolicy $name" -ScriptBlock {
                    Set-LabelPolicy -Identity $name -AddLabels $publishableLabels -Comment $policyComment -ErrorAction Stop
                } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
            } catch {
                if ($_.Exception.Message -match 'LabelAlreadyPublished') {
                    $alreadyPublished = $true   # labels already on the policy — treat as success (no rethrow)
                } else {
                    throw
                }
            }
            $guid = if ($existingPolicy.PSObject.Properties['Guid'] -and $existingPolicy.Guid) { $existingPolicy.Guid.ToString() } else { $null }
            $status = if ($alreadyPublished) { 'already-published' } else { 'updated' }
            return New-StepResult -Status $status -Guid $guid -StampedComment $policyComment `
                -Reason "label policy '$name' ($status, $($publishableLabels.Count) labels, scope: $scope)"
        }

        # ---- CREATE policy: New-LabelPolicy -------------------------------------------------------
        Invoke-WithRetry -OperationName "New-LabelPolicy $name" -ScriptBlock {
            New-LabelPolicy -Name $name -Labels $publishableLabels -ExchangeLocation $locationValue -Comment $policyComment -ErrorAction Stop
        } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
        return New-StepResult -Status 'created' -StampedComment $policyComment `
            -Reason "created label policy '$name' ($($publishableLabels.Count) labels, scope: $scope)"
    }

    # ============================================================ LABEL path ======================
    # ---- REMOVE -----------------------------------------------------------------------------------
    if ($action -eq 'remove') {
        $removeState = Remove-PurviewObject -Identity $name `
            -GetCommand 'Get-Label' -RemoveCommand 'Remove-Label' `
            -OperationName 'label' -SleepAction $SleepAction
        return New-StepResult -Status (ConvertTo-RemoveStatus $removeState) -RemoveState $removeState `
            -Reason "remove label '$name' -> $removeState"
    }

    if (-not $Content) {
        throw "Invoke-Compl8LabelExecutor: step '$($Step.id)' ($action $objectRef) requires -Content (resolved label definition) but none was supplied."
    }

    $isGroup     = [bool]$Content.isGroup
    $parentGroup = if ($Content.PSObject.Properties['parentGroup']) { [string]$Content.parentGroup } else { '' }

    # ---- existence probe + leaf-vs-group TYPE-MISMATCH guard --------------------------------------
    $existingLabel = $null
    try { $existingLabel = Get-Label -Identity $name -ErrorAction Stop } catch { $existingLabel = $null }

    if ($existingLabel) {
        $existingHasContentType = -not [string]::IsNullOrWhiteSpace([string]$existingLabel.ContentType)
        if ($isGroup -and $existingHasContentType) {
            return New-StepResult -Status 'type-mismatch' `
                -Reason "TYPE MISMATCH: '$name' exists as a leaf label but must be a label group. Delete in Purview and re-run (manual cleanup required)."
        }
        if (-not $isGroup -and -not $existingHasContentType -and -not $parentGroup) {
            return New-StepResult -Status 'type-mismatch' `
                -Reason "TYPE MISMATCH: '$name' exists as a label group but must be a leaf label. Delete in Purview and re-run (manual cleanup required)."
        }
    }

    # ---- parent resolution (sublabel) ------------------------------------------------------------
    $parentId = $null
    if ($parentGroup) {
        if ($ParentGuidCache -and $ParentGuidCache.ContainsKey($parentGroup) -and $ParentGuidCache[$parentGroup]) {
            $parentId = [string]$ParentGuidCache[$parentGroup]
        } else {
            $parentLabelName = if ($Content.PSObject.Properties['parentLabelName'] -and $Content.parentLabelName) { [string]$Content.parentLabelName } else { $parentGroup }
            $parentLabel = $null
            try { $parentLabel = Get-Label -Identity $parentLabelName -ErrorAction Stop } catch { $parentLabel = $null }
            if (-not $parentLabel -or -not $parentLabel.Guid) {
                return New-StepResult -Status 'parent-not-found' `
                    -Reason "Parent group '$parentLabelName' not found. Skipping sublabel '$name'."
            }
            $parentId = $parentLabel.Guid.ToString()
            if ($ParentGuidCache) { $ParentGuidCache[$parentGroup] = $parentId }
        }
    }

    # ---- provenance-stamped Comment --------------------------------------------------------------
    $priority = if ($Content.PSObject.Properties['priority']) { $Content.priority } else { 0 }
    $code     = if ($Content.PSObject.Properties['code']) { [string]$Content.code } else { '' }
    $stampArgs = @{
        Text      = "$(if ($Prefix) { $Prefix } else { 'UNSCOPED' }) label. Priority: $priority."
        Prefix    = if ($Prefix) { $Prefix } else { 'UNSCOPED' }
        Component = 'SensitivityLabel'
        Metadata  = @{ LabelCode = $code; LabelName = $name }
    }
    if ($TargetEnvironment) { $stampArgs['TargetEnvironment'] = $TargetEnvironment }
    $stampedComment = Add-DeploymentProvenanceStamp @stampArgs

    # ---- common label parameters -----------------------------------------------------------------
    $labelParams = @{
        DisplayName = if ($Content.PSObject.Properties['displayName']) { [string]$Content.displayName } else { $name }
        Tooltip     = if ($Content.PSObject.Properties['tooltip']) { [string]$Content.tooltip } else { '' }
        Comment     = $stampedComment
    }
    if (-not $NoMarking) {
        $colour = if ($Content.PSObject.Properties['colour']) { [string]$Content.colour } else { '' }
        if ($Content.PSObject.Properties['headerText'] -and $Content.headerText) {
            $labelParams['ApplyContentMarkingHeaderEnabled']   = $true
            $labelParams['ApplyContentMarkingHeaderText']      = [string]$Content.headerText
            $labelParams['ApplyContentMarkingHeaderFontSize']  = 10
            $labelParams['ApplyContentMarkingHeaderAlignment'] = 'Center'
            if ($colour) { $labelParams['ApplyContentMarkingHeaderFontColor'] = $colour }
        }
        if ($Content.PSObject.Properties['footerText'] -and $Content.footerText) {
            $labelParams['ApplyContentMarkingFooterEnabled']   = $true
            $labelParams['ApplyContentMarkingFooterText']      = [string]$Content.footerText
            $labelParams['ApplyContentMarkingFooterFontSize']  = 8
            $labelParams['ApplyContentMarkingFooterAlignment'] = 'Center'
            if ($colour) { $labelParams['ApplyContentMarkingFooterFontColor'] = $colour }
        }
    }
    $advancedSettings = @{}
    if ($Content.PSObject.Properties['colour'] -and $Content.colour) { $advancedSettings['color'] = [string]$Content.colour }

    # ---- UPDATE (existing label) -----------------------------------------------------------------
    if ($existingLabel) {
        $updateParams = @{ Identity = $name }
        foreach ($key in $labelParams.Keys) { $updateParams[$key] = $labelParams[$key] }
        if ($advancedSettings.Count -gt 0) { $updateParams['AdvancedSettings'] = $advancedSettings }
        # Bare scriptblock (no .GetNewClosure()) — keeps the module mock resolvable for Set-Label.
        Invoke-WithRetry -OperationName "Set-Label $name" -ScriptBlock {
            Set-Label @updateParams -ErrorAction Stop
        } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
        $guid = if ($existingLabel.Guid) { $existingLabel.Guid.ToString() } else { $null }
        return New-StepResult -Status 'updated' -Guid $guid -StampedComment $stampedComment -ParentId $parentId `
            -Reason "updated label '$name'"
    }

    # ---- CREATE (new label) ----------------------------------------------------------------------
    $createParams = @{ Name = $name }
    foreach ($key in $labelParams.Keys) { $createParams[$key] = $labelParams[$key] }
    if ($isGroup) { $createParams['IsLabelGroup'] = $true } else { $createParams['ContentType'] = 'File, Email' }
    if ($parentId) { $createParams['ParentId'] = $parentId }
    if ($advancedSettings.Count -gt 0) { $createParams['AdvancedSettings'] = $advancedSettings }
    # Bare scriptblock (no .GetNewClosure()) — keeps the module mock resolvable for New-Label.
    $newLabel = Invoke-WithRetry -OperationName "New-Label $name" -ScriptBlock {
        New-Label @createParams -ErrorAction Stop
    } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction
    $guid = if ($newLabel -and $newLabel.Guid) { $newLabel.Guid.ToString() } else { $null }
    # Cache our own Guid under our name (the old path records $parentGuids[$labelName]) so a later
    # sublabel that names this label as its parent can resolve without a re-query.
    if ($ParentGuidCache -and $guid) { $ParentGuidCache[$name] = $guid }
    return New-StepResult -Status 'created' -Guid $guid -StampedComment $stampedComment -ParentId $parentId `
        -Reason "created label '$name'"
}
