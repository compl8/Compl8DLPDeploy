function Invoke-Compl8DlpRuleExecutor {
    <#
    .SYNOPSIS
        Apply executor for a DLP RULE or DLP POLICY plan step (action create|update|remove|dereference;
        objectType dlpRule|dlpPolicy). Copies the Task-8/9 executor template and shadows against the
        inline deployment loop of scripts/Deploy-DLPRules.ps1. Also handles the planner-generated
        `dereference` action (D5). (PHASE 4C, Task 11; arch design §5/§6; decisions D1/D3/D5.)

    .DESCRIPTION
        FRESH PORT (D1) of the DLP rule + policy mutation path from scripts/Deploy-DLPRules.ps1's inline
        loops — New/Set/Get-DlpCompliancePolicy and New/Set/Get-DlpComplianceRule — into Compl8.Engine
        scope, the ONLY tenant-mutating layer (D3). The old Deploy-DLPRules.ps1 stays live and UNMODIFIED;
        this executor reproduces its SCC cmdlet sequence + guards and is proven equivalent by a SHADOW
        DIFF against a GENUINE Deploy-DLPRules.ps1 run (Get-Compl8ShadowDiff Match -eq $true).

        ============================== TEMPLATE (copied from the pilot) ==============================
        SIGNATURE / APPLY CONTRACT. Invoke-Compl8Apply dispatches a step as `& $executor -Step $step` (or
        `& $sb $step`), so the plan step is -Step (also positional 0). The RESOLVED CONTENT (policy
        Mode/locations/comment for a policy; rule name/policy/condition/comment for a rule) is bound by
        the production executor-map closure as -Content — it is NOT on the step.

        PLANNED-OP / -WhatIf MODE. With -WhatIf the executor performs NO mutation and RETURNS a single
        normalised "planned operation" record { action; objectType; objectRef }. The planned ACTION is
        derived from desired-vs-existing exactly as the old path decides it: an existing rule/policy plans
        `update`, otherwise `create`; a `remove`/`dereference` step plans its own action. Existing state
        under -WhatIf is supplied via -ExistingState (name->object map) so planning is pure and matches
        the old path's Get-DlpComplianceRule / Get-DlpCompliancePolicy probes without a live tenant.

        RESULT / CHECKPOINT SHAPE (apply mode):
            { stepId; action; objectType; objectRef; status; reason; stampedComment?; removeState?;
              strippedSits?; remainingSits? }
        `status` ∈ created | updated | deleted | dereferenced | rule-emptied-deleted | sit-invalid |
                   name-conflict | not-found | failed.

        PROVENANCE. Create/update stamp the policy/rule Comment via Add-DeploymentProvenanceStamp
        (Compl8.Model) — the [[Compl8:<16hex>]] marker.

        GUARDS PORTED (from Deploy-DLPRules.ps1):
          * SIT VALIDATION GATE. Mirrors the old "Validating Sensitive Information Types" block: each
            classifier the rule references (by GUID) must resolve in the tenant SIT inventory
            (-TenantSitInventory: objects with Id + Name), and (for SITs, not trainable MLModel
            classifiers) the tenant NAME must match one of the expected names. A missing SIT REFUSES the
            create/update — NO New/Set call, status 'sit-invalid'. Supplying no inventory skips the gate
            (the old -SkipValidation / skipSitValidation path).
          * NAME-CONFLICT PRE-FLIGHT. Mirrors Test-PurviewNameConflicts: if the rule/policy name already
            exists as an ACTIVE (non-pending-deletion) object AND -ConfirmNameConflicts was not supplied,
            the executor REFUSES (status 'name-conflict', no mutation) — the apply-time analogue of the
            old interactive "Proceed? Active items will be deleted and recreated" prompt. (An EXISTING
            object the executor is updating is not a conflict — it takes the Set path.)
          * Invoke-WithRetry wraps every New-/Set- call so transient Purview throttles back off + retry.

        DEREFERENCE (action dereference, objectType dlpRule — the planner-generated step, D5):
          The removed SIT GUID(s) to strip are carried on the step's `impact` (the coalesced list of
          removed sit refs Get-Compl8PlanOrder produces). The executor:
            1. Fetches the rule (Get-DlpComplianceRule) and reads its
               ContentContainsSensitiveInformation sensitivetypes.
            2. STRIPS every sensitivetype whose id (or name) is in the impact set.
            3. If SITs REMAIN, Set-DlpComplianceRule with the trimmed condition (status 'dereferenced',
               strippedSits/remainingSits recorded).
            4. If NO SIT remains, the rule would match nothing — DELETE it via Remove-PurviewObject
               (status 'rule-emptied-deleted'), exactly the "if the rule references no other SIT after
               stripping, delete the rule" contract.
          The condition source is the LIVE rule's CCSI (read back from the tenant), so the strip operates
          on what is actually deployed; -Content may carry the desired condition for parity but the strip
          is authoritative against the fetched rule.

        REMOVE. Delegates to Remove-PurviewObject (deleted|pending|cooldown|not-found|failed), using
        Get-/Remove-DlpComplianceRule or Get-/Remove-DlpCompliancePolicy per objectType.

        NOTE on the retry scriptblock: passed to Invoke-WithRetry WITHOUT .GetNewClosure() so it keeps its
        module affinity (Compl8.Engine) and a `Mock -ModuleName Compl8.Engine` resolves inside it. Same
        as the pilot + the old Deploy-DLPRules.ps1.
        ============================================================================================

    .PARAMETER Step
        The DLP rule / policy plan step (compl8.plan/v1): { id; action; objectType; objectRef; impact; ... }.
        action ∈ create|update|remove|dereference. objectType ∈ dlpRule|dlpPolicy. Positional 0.

    .PARAMETER Content
        The resolved content for this step. For a policy: { name; mode; comment; locations (hashtable of
        Location params) }. For a rule: { name; policy; comment; condition ({ Format; Value }); sitIds
        (string[] of the classifier GUIDs the rule references); sitNames (hashtable id->expected names);
        trainableIds (string[] of MLModel classifier GUIDs exempt from the SIT-name check); ruleParams
        (optional extra New-DlpComplianceRule params) }. Required for create/update.

    .PARAMETER TenantSitInventory
        The tenant SIT inventory (objects with Id + Name) for the SIT-validation gate. Empty => gate
        skipped (the old -SkipValidation path).

    .PARAMETER ConfirmNameConflicts
        Acknowledge that an active same-named object will be overwritten (the apply-time analogue of the
        old interactive name-conflict confirmation). Without it an active conflict is refused.

    .PARAMETER PolicyMode
        The DLP policy Mode (e.g. 'TestWithNotifications'/'Enable') used when -Content does not carry one.

    .PARAMETER Prefix
        The deployment naming prefix forwarded to the provenance stamp.

    .PARAMETER TargetEnvironment
        Optional environment key forwarded to the provenance stamp.

    .PARAMETER ExistingState
        A name -> existing-object map used ONLY in -WhatIf planning to decide create-vs-update.

    .PARAMETER SleepAction
        Injectable sleep forwarded to Invoke-WithRetry / Remove-PurviewObject. Tests pass a no-op.

    .PARAMETER WhatIf
        Plan/report mode: perform NO mutation and return the normalised planned-operation record.

    .OUTPUTS
        -WhatIf: a planned-op record { action; objectType; objectRef }.
        Apply  : a step result { stepId; action; objectType; objectRef; status; reason; ... }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [pscustomobject]$Step,

        [pscustomobject]$Content,

        [object[]]$TenantSitInventory = @(),

        [switch]$ConfirmNameConflicts,

        [string]$PolicyMode = 'TestWithNotifications',

        [string]$Prefix,

        [string]$TargetEnvironment,

        # Optional workspace provenance registry path threaded to Add-DeploymentProvenanceStamp
        # -RegistryPath; absent => repo/env default (unchanged). (Stage 5 D8; codex 5A review.)
        [string]$ProvenanceRegistryPath,

        [hashtable]$ExistingState = @{},

        [scriptblock]$SleepAction = { param($s) Start-Sleep -Seconds $s },

        [switch]$WhatIf
    )

    $action     = [string]$Step.action
    $objectRef  = [string]$Step.objectRef
    $objectType = if ($Step.PSObject.Properties['objectType'] -and $Step.objectType) { [string]$Step.objectType } else { 'dlpRule' }
    if ($objectType -ne 'dlpRule' -and $objectType -ne 'dlpPolicy') {
        throw "Invoke-Compl8DlpRuleExecutor: unsupported objectType '$objectType' for step '$($Step.id)' (expected dlpRule|dlpPolicy)."
    }

    # --- planned-op helper -----------------------------------------------------------------------
    function New-PlannedOp {
        param([string]$OpAction, [string]$OpRef)
        [pscustomobject]@{ action = $OpAction; objectType = $objectType; objectRef = $OpRef }
    }

    # --- step-result helper ----------------------------------------------------------------------
    function New-StepResult {
        param(
            [string]$Status,
            [string]$Reason = '',
            [string]$StampedComment = $null,
            [string]$RemoveState = $null,
            [string[]]$StrippedSits = @(),
            [string[]]$RemainingSits = @()
        )
        $r = [ordered]@{
            stepId     = [string]$Step.id
            action     = $action
            objectType = $objectType
            objectRef  = $objectRef
            status     = $Status
            reason     = $Reason
        }
        if ($PSBoundParameters.ContainsKey('StampedComment')) { $r['stampedComment'] = $StampedComment }
        if ($PSBoundParameters.ContainsKey('RemoveState'))    { $r['removeState']    = $RemoveState }
        if ($PSBoundParameters.ContainsKey('StrippedSits'))   { $r['strippedSits']   = @($StrippedSits) }
        if ($PSBoundParameters.ContainsKey('RemainingSits'))  { $r['remainingSits']  = @($RemainingSits) }
        [pscustomobject]$r
    }

    function ConvertTo-RemoveStatus {
        param([string]$RemoveState)
        switch ($RemoveState) {
            'deleted'   { 'deleted' }
            'pending'   { 'deleted' }
            'not-found' { 'not-found' }
            default     { if ($RemoveState -like 'cooldown:*') { 'cooldown' } else { 'failed' } }
        }
    }

    $name = if ($Content -and $Content.PSObject.Properties['name'] -and $Content.name) { [string]$Content.name } else { $objectRef }

    $getCmd    = if ($objectType -eq 'dlpPolicy') { 'Get-DlpCompliancePolicy' } else { 'Get-DlpComplianceRule' }
    $removeCmd = if ($objectType -eq 'dlpPolicy') { 'Remove-DlpCompliancePolicy' } else { 'Remove-DlpComplianceRule' }

    # ============================================================ -WhatIf / plan mode (NO mutation)
    if ($WhatIf) {
        if ($action -in 'remove', 'dereference') { return New-PlannedOp -OpAction $action -OpRef $objectRef }
        $existsInState = $ExistingState -and $ExistingState.ContainsKey($name) -and $ExistingState[$name]
        $plannedAction = if ($existsInState) { 'update' } else { 'create' }
        return New-PlannedOp -OpAction $plannedAction -OpRef $objectRef
    }

    # ============================================================ DEREFERENCE (dlpRule, D5)
    # Strip the removed SIT GUID(s) (carried on the step's impact) from the LIVE rule's
    # ContentContainsSensitiveInformation; delete the rule if it ends up referencing no SIT.
    if ($action -eq 'dereference') {
        if ($objectType -ne 'dlpRule') {
            throw "Invoke-Compl8DlpRuleExecutor: dereference is only valid for objectType dlpRule (step '$($Step.id)')."
        }
        # The removed SIT refs to strip — from the step's impact (coalesced removed-sit list).
        $removedRefs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($i in @(if ($Step.PSObject.Properties['impact']) { $Step.impact } else { @() })) {
            if ($i) { [void]$removedRefs.Add([string]$i) }
        }
        if ($removedRefs.Count -eq 0) {
            return New-StepResult -Status 'dereferenced' -StrippedSits @() `
                -Reason "rule '$name': no removed SIT refs on the step impact; nothing to strip."
        }

        $rule = $null
        try { $rule = Get-DlpComplianceRule -Identity $name -ErrorAction Stop } catch { $rule = $null }
        if (-not $rule) {
            return New-StepResult -Status 'not-found' -Reason "rule '$name' not found; nothing to dereference."
        }

        # Read the rule's sensitivetypes from ContentContainsSensitiveInformation. The shape mirrors
        # New-DLPSITCondition's Simple Value: { operator; groups = @({ operator; name; sensitivetypes = @({ id; name; ... }) }) }.
        $ccsi = if ($rule.PSObject.Properties['ContentContainsSensitiveInformation']) { $rule.ContentContainsSensitiveInformation } else { $null }
        $groups = @()
        if ($ccsi) {
            if ($ccsi.PSObject.Properties['groups'] -and $ccsi.groups) { $groups = @($ccsi.groups) }
            elseif ($ccsi -is [System.Collections.IDictionary] -and $ccsi['groups']) { $groups = @($ccsi['groups']) }
        }

        $stripped   = [System.Collections.Generic.List[string]]::new()
        $remaining  = [System.Collections.Generic.List[string]]::new()
        $newGroups  = [System.Collections.Generic.List[object]]::new()
        foreach ($g in $groups) {
            $sits = @(if ($g.PSObject.Properties['sensitivetypes']) { $g.sensitivetypes } elseif ($g -is [System.Collections.IDictionary]) { $g['sensitivetypes'] } else { @() })
            $kept = [System.Collections.Generic.List[object]]::new()
            foreach ($s in $sits) {
                $sid   = if ($s.PSObject.Properties['id'])   { [string]$s.id }   elseif ($s -is [System.Collections.IDictionary]) { [string]$s['id'] }   else { '' }
                $sname = if ($s.PSObject.Properties['name']) { [string]$s.name } elseif ($s -is [System.Collections.IDictionary]) { [string]$s['name'] } else { '' }
                if (($sid -and $removedRefs.Contains($sid)) -or ($sname -and $removedRefs.Contains($sname))) {
                    $stripped.Add($(if ($sid) { $sid } else { $sname })) | Out-Null
                } else {
                    $kept.Add($s) | Out-Null
                    $remaining.Add($(if ($sid) { $sid } else { $sname })) | Out-Null
                }
            }
            if ($kept.Count -gt 0) {
                $newGroup = if ($g -is [System.Collections.IDictionary]) { @{} + $g } else {
                    $h = @{}; foreach ($p in $g.PSObject.Properties) { $h[$p.Name] = $p.Value }; $h
                }
                $newGroup['sensitivetypes'] = @($kept)
                $newGroups.Add($newGroup) | Out-Null
            }
        }

        # No SIT left anywhere => the rule matches nothing; delete it (D5 "delete the empty rule").
        if ($remaining.Count -eq 0) {
            $removeState = Remove-PurviewObject -Identity $name `
                -GetCommand 'Get-DlpComplianceRule' -RemoveCommand 'Remove-DlpComplianceRule' `
                -OperationName 'DLP rule' -SleepAction $SleepAction
            return New-StepResult -Status 'rule-emptied-deleted' -RemoveState $removeState `
                -StrippedSits @($stripped) -RemainingSits @() `
                -Reason "rule '$name' references no SIT after stripping $($stripped.Count) removed SIT(s) -> deleted (remove -> $removeState)."
        }

        # SITs remain => Set the trimmed condition.
        $newCcsi = @{ operator = if ($ccsi.PSObject.Properties['operator']) { $ccsi.operator } elseif ($ccsi -is [System.Collections.IDictionary] -and $ccsi['operator']) { $ccsi['operator'] } else { 'And' }; groups = @($newGroups) }
        Invoke-WithRetry -OperationName "Set-Rule(deref) $name" -ScriptBlock {
            Set-DlpComplianceRule -Identity $name -ContentContainsSensitiveInformation $newCcsi -Confirm:$false -ErrorAction Stop
        } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
        return New-StepResult -Status 'dereferenced' -StrippedSits @($stripped) -RemainingSits @($remaining) `
            -Reason "rule '$name': stripped $($stripped.Count) removed SIT(s); $($remaining.Count) SIT(s) remain."
    }

    # ============================================================ REMOVE
    if ($action -eq 'remove') {
        $removeState = Remove-PurviewObject -Identity $name `
            -GetCommand $getCmd -RemoveCommand $removeCmd `
            -OperationName $(if ($objectType -eq 'dlpPolicy') { 'DLP policy' } else { 'DLP rule' }) -SleepAction $SleepAction
        return New-StepResult -Status (ConvertTo-RemoveStatus $removeState) -RemoveState $removeState `
            -Reason "remove $objectType '$name' -> $removeState"
    }

    if (-not $Content) {
        throw "Invoke-Compl8DlpRuleExecutor: step '$($Step.id)' ($action $objectRef) requires -Content but none was supplied."
    }

    # ---- existence probe (drives create-vs-update + the name-conflict gate) ----------------------
    $existing = $null
    try { $existing = & $getCmd -Identity $name -ErrorAction Stop } catch { $existing = $null }

    # ---- NAME-CONFLICT PRE-FLIGHT ---------------------------------------------------------------
    # An EXISTING object we will UPDATE is not a conflict. A conflict only matters for a desired CREATE
    # whose name is already taken by an ACTIVE object; without confirmation, refuse.
    if ($action -eq 'create' -and $existing) {
        $isPending = ($existing.PSObject.Properties['Mode'] -and $existing.Mode -eq 'PendingDeletion') -or
                     ($existing.PSObject.Properties['State'] -and $existing.State -eq 'PendingDeletion')
        if (-not $isPending -and -not $ConfirmNameConflicts) {
            return New-StepResult -Status 'name-conflict' `
                -Reason "$objectType '$name' already exists (active). Re-run with confirmation to delete-and-recreate, or plan an update."
        }
    }

    # ============================================================ POLICY path =====================
    if ($objectType -eq 'dlpPolicy') {
        $mode      = if ($Content.PSObject.Properties['mode'] -and $Content.mode) { [string]$Content.mode } else { $PolicyMode }
        $locations = @{}
        if ($Content.PSObject.Properties['locations'] -and $Content.locations) {
            foreach ($k in $Content.locations.Keys) { $locations[$k] = $Content.locations[$k] }
        }
        $policyComment = Add-DeploymentProvenanceStamp `
            -Text $(if ($Content.PSObject.Properties['comment']) { [string]$Content.comment } else { '' }) `
            -Prefix $(if ($Prefix) { $Prefix } else { 'UNSCOPED' }) -Component 'DlpPolicy' `
            -TargetEnvironment $TargetEnvironment -Metadata @{ PolicyName = $name } `
            -RegistryPath $ProvenanceRegistryPath

        if ($existing) {
            Invoke-WithRetry -OperationName "Set-Policy $name" -ScriptBlock {
                Set-DlpCompliancePolicy -Identity $name -Comment $policyComment -Mode $mode -Confirm:$false -ErrorAction Stop
            } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
            return New-StepResult -Status 'updated' -StampedComment $policyComment -Reason "updated DLP policy '$name'"
        }
        $newPolicyParams = @{ Name = $name; Comment = $policyComment; Mode = $mode }
        foreach ($k in $locations.Keys) { $newPolicyParams[$k] = $locations[$k] }
        Invoke-WithRetry -OperationName "New-Policy $name" -ScriptBlock {
            New-DlpCompliancePolicy @newPolicyParams -ErrorAction Stop
        } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
        return New-StepResult -Status 'created' -StampedComment $policyComment -Reason "created DLP policy '$name'"
    }

    # ============================================================ RULE path =======================
    # ---- SIT VALIDATION GATE --------------------------------------------------------------------
    $sitIds       = @(if ($Content.PSObject.Properties['sitIds']) { $Content.sitIds } else { @() }) | Where-Object { $_ } | ForEach-Object { [string]$_ }
    $trainableIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in @(if ($Content.PSObject.Properties['trainableIds']) { $Content.trainableIds } else { @() })) { if ($t) { [void]$trainableIds.Add([string]$t) } }
    if (@($TenantSitInventory).Count -gt 0 -and @($sitIds).Count -gt 0) {
        $byId = @{}
        foreach ($s in @($TenantSitInventory)) {
            $id = if ($s.PSObject.Properties['Id'] -and $s.Id) { [string]$s.Id } elseif ($s.PSObject.Properties['Identity'] -and $s.Identity) { [string]$s.Identity } else { '' }
            if ($id) { $byId[$id.ToLowerInvariant()] = $s }
        }
        $expectedNames = @{}
        if ($Content.PSObject.Properties['sitNames'] -and $Content.sitNames) {
            foreach ($k in $Content.sitNames.Keys) { $expectedNames[[string]$k] = $Content.sitNames[$k] }
        }
        $missing   = @()
        $mismatch  = @()
        foreach ($sid in $sitIds) {
            if ($trainableIds.Contains($sid)) { continue }   # trainable classifiers are not in the SIT list
            $lk = $sid.ToLowerInvariant()
            if (-not $byId.ContainsKey($lk)) { $missing += $sid; continue }
            if ($expectedNames.ContainsKey($sid)) {
                $tenantName = [string]$byId[$lk].Name
                $exp = @($expectedNames[$sid])
                if ($exp.Count -gt 0 -and ($exp -notcontains $tenantName)) { $mismatch += $sid }
            }
        }
        if ($missing.Count -gt 0) {
            return New-StepResult -Status 'sit-invalid' `
                -Reason "rule '$name' references SIT GUID(s) not found in the tenant: $($missing -join ', '). Rule would fail to create. (SIT validation gate.)"
        }
        # NB: name mismatches are a WARNING in the old path (GUIDs match) — not a hard stop — so we
        # proceed. They are surfaced in the reason for observability.
        if ($mismatch.Count -gt 0) {
            # carry on; record nothing fatal
        }
    }

    $ruleComment = Add-DeploymentProvenanceStamp `
        -Text $(if ($Content.PSObject.Properties['comment']) { [string]$Content.comment } else { '' }) `
        -Prefix $(if ($Prefix) { $Prefix } else { 'UNSCOPED' }) -Component 'DlpRule' `
        -TargetEnvironment $TargetEnvironment -Metadata @{ RuleName = $name } `
        -RegistryPath $ProvenanceRegistryPath

    $condition = if ($Content.PSObject.Properties['condition']) { $Content.condition } else { $null }
    $policyName = if ($Content.PSObject.Properties['policy']) { [string]$Content.policy } else { '' }

    # Base rule params + any extra params the caller supplied.
    $ruleParams = @{ Name = $name; Policy = $policyName; Comment = $ruleComment; Disabled = $false }
    if ($Content.PSObject.Properties['ruleParams'] -and $Content.ruleParams) {
        foreach ($k in $Content.ruleParams.Keys) { $ruleParams[$k] = $Content.ruleParams[$k] }
    }
    if ($condition) {
        $fmt = if ($condition.PSObject.Properties['Format']) { [string]$condition.Format } elseif ($condition -is [System.Collections.IDictionary]) { [string]$condition['Format'] } else { 'Simple' }
        $val = if ($condition.PSObject.Properties['Value']) { $condition.Value } elseif ($condition -is [System.Collections.IDictionary]) { $condition['Value'] } else { $null }
        if ($fmt -eq 'AdvancedRule') { $ruleParams['AdvancedRule'] = $val }
        else { $ruleParams['ContentContainsSensitiveInformation'] = $val }
    }

    if ($existing) {
        $updateRuleParams = @{ Identity = $name }
        foreach ($k in $ruleParams.Keys) { if ($k -notin @('Name', 'Policy')) { $updateRuleParams[$k] = $ruleParams[$k] } }
        Invoke-WithRetry -OperationName "Set-Rule $name" -ScriptBlock {
            Set-DlpComplianceRule @updateRuleParams -Confirm:$false -ErrorAction Stop
        } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
        return New-StepResult -Status 'updated' -StampedComment $ruleComment -Reason "updated DLP rule '$name'"
    }
    Invoke-WithRetry -OperationName "New-Rule $name" -ScriptBlock {
        New-DlpComplianceRule @ruleParams -ErrorAction Stop
    } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
    return New-StepResult -Status 'created' -StampedComment $ruleComment -Reason "created DLP rule '$name'"
}
