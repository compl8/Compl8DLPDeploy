function Invoke-Compl8AutoLabelExecutor {
    <#
    .SYNOPSIS
        Apply executor for an AUTO-LABELING POLICY or RULE plan step (action create|update|remove;
        objectType autoLabelPolicy|autoLabelRule). Copies the Task-8/9 executor template and shadows
        against the inline deployment loop of scripts/Deploy-AutoLabeling.ps1. Ports the 125-classifier-
        per-rule CHUNKING faithfully. (PHASE 4C, Task 12; arch design §5/§6; decisions D1/D3.)

    .DESCRIPTION
        FRESH PORT (D1) of the auto-labeling policy + rule mutation path from
        scripts/Deploy-AutoLabeling.ps1's inline loops — New/Set/Get-AutoSensitivityLabelPolicy and
        New/Set/Get-AutoSensitivityLabelRule — into Compl8.Engine scope, the ONLY tenant-mutating layer
        (D3). The old Deploy-AutoLabeling.ps1 stays live and UNMODIFIED; this executor reproduces its SCC
        cmdlet sequence + guards and is proven equivalent by a SHADOW DIFF against a GENUINE
        Deploy-AutoLabeling.ps1 run (Get-Compl8ShadowDiff Match -eq $true).

        ============================== TEMPLATE (copied from the pilot) ==============================
        SIGNATURE / APPLY CONTRACT. Invoke-Compl8Apply dispatches a step as `& $executor -Step $step`
        (or `& $sb $step`), so the plan step is -Step (also positional 0). The RESOLVED CONTENT (policy
        label/mode/locations/comment; rule policy/workload/classifier-list/scope/comment) is bound by the
        production executor-map closure as -Content — it is NOT on the step.

        PLANNED-OP / -WhatIf MODE. With -WhatIf the executor performs NO mutation and RETURNS the
        normalised "planned operation" record(s) { action; objectType; objectRef }. The planned ACTION is
        derived from desired-vs-existing exactly as the old path decides it: an existing policy/rule plans
        `update`, otherwise `create`; a `remove` plans `remove`. Existing state under -WhatIf is supplied
        via -ExistingState (name->object map). CHUNKING APPLIES IN -WhatIf TOO: a rule step whose
        classifier list exceeds the per-rule cap emits ONE planned op PER CHUNK (with the chunk-letter
        rule names), exactly as the old path plans one rule per chunk.

        RESULT / CHECKPOINT SHAPE (apply mode):
            { stepId; action; objectType; objectRef; status; reason; stampedComment?; removeState?;
              chunks? }   (for a chunked rule step: chunks = @( per-chunk { ruleName; status } ))
        `status` ∈ created | updated | deleted | sit-invalid | name-conflict | not-found | failed |
                   chunked (a multi-chunk rule step whose chunks each created/updated).

        125-CLASSIFIER CHUNKING (Split-ClassifierChunks parity — the distinctive auto-label guard):
          A single auto-labeling RULE may reference at most AutoLabelMaxSitsPerRule classifiers
          (Get-DeploymentLimits.AutoLabelMaxSitsPerRule = 125 — the CONSUMPTION limit, distinct from the
          50-SIT AUTHORING cap on rule packages). When a rule step's classifier list exceeds the cap, the
          executor SPLITS it into chunks of <= cap and creates ONE rule per chunk, appending a chunk
          letter (a, b, c, ...) to the rule name. The split is EVEN (not cap + remainder): chunkCount =
          ceil(total / cap), chunkSize = ceil(total / chunkCount) — byte-for-byte the old
          Split-ClassifierChunks algorithm (e.g. 126 -> 2 chunks of 63; 130 -> 2 of 65). A split needing
          > 26 chunks throws (a-z rule-name suffix limit), as the old path does.

        PROVENANCE. Create/update stamp the policy/rule Comment via Add-DeploymentProvenanceStamp.

        SIMULATION MODE. New/Set-AutoSensitivityLabelPolicy is created with Mode =
        'TestWithoutNotifications' (the old path's simulation default). Starting the simulation
        (Set-AutoSensitivityLabelPolicy -StartSimulation $true) is a SEPARATE post-deploy / -StartSimulation
        operation in the old script, NOT part of the per-object mutation — so it is out of the executor's
        per-step scope (a dedicated simulation step/operation, like the old -StartSimulation switch).

        GUARDS PORTED (from Deploy-AutoLabeling.ps1):
          * SIT VALIDATION GATE. Same as the DLP-rule executor: each non-trainable classifier GUID the
            rule references must resolve in -TenantSitInventory; a missing SIT REFUSES the rule create/
            update (status 'sit-invalid', no New/Set). Empty inventory => gate skipped (-SkipValidation).
          * NAME-CONFLICT PRE-FLIGHT. A desired CREATE whose name is an ACTIVE existing object is refused
            unless -ConfirmNameConflicts (the apply-time analogue of Test-PurviewNameConflicts' prompt).
          * Invoke-WithRetry wraps every New-/Set- call.

        REMOVE. Delegates to Remove-PurviewObject (deleted|pending|cooldown|not-found|failed), using
        Get-/Remove-AutoSensitivityLabelRule or Get-/Remove-AutoSensitivityLabelPolicy per objectType.

        NOTE on the retry scriptblock: passed to Invoke-WithRetry WITHOUT .GetNewClosure() so it keeps its
        module affinity (Compl8.Engine) and a `Mock -ModuleName Compl8.Engine` resolves inside it. Same
        as the pilot + the old Deploy-AutoLabeling.ps1.
        ============================================================================================

    .PARAMETER Step
        The auto-label policy / rule plan step (compl8.plan/v1): { id; action; objectType; objectRef; ... }.
        action ∈ create|update|remove. objectType ∈ autoLabelPolicy|autoLabelRule. Positional 0.

    .PARAMETER Content
        The resolved content for this step. For a policy: { name; label (ApplySensitivityLabel); mode;
        comment; locations (hashtable) }. For a rule: { name (the BASE rule name, chunk letter appended
        per-chunk); policy; workload; comment; classifiers (the full classifier list — each { Id; Name;
        ClassifierType?; minCount?; maxCount?; confidencelevel? }); scopeParam; scopeValue }. Required for
        create/update.

    .PARAMETER TenantSitInventory
        Tenant SIT inventory (objects with Id + Name) for the SIT-validation gate. Empty => gate skipped.

    .PARAMETER ConfirmNameConflicts
        Acknowledge overwriting an active same-named object (apply-time name-conflict confirmation).

    .PARAMETER MaxSitsPerRule
        The per-rule classifier cap for chunking. Defaults to Get-DeploymentLimits.AutoLabelMaxSitsPerRule
        (125). Exposed for testing the split math.

    .PARAMETER Prefix
        The deployment naming prefix forwarded to the provenance stamp.

    .PARAMETER TargetEnvironment
        Optional environment key forwarded to the provenance stamp.

    .PARAMETER ExistingState
        A name -> existing-object map used ONLY in -WhatIf planning to decide create-vs-update.

    .PARAMETER SleepAction
        Injectable sleep forwarded to Invoke-WithRetry / Remove-PurviewObject. Tests pass a no-op.

    .PARAMETER WhatIf
        Plan/report mode: perform NO mutation and return the normalised planned-operation record(s).

    .OUTPUTS
        -WhatIf: planned-op record(s) { action; objectType; objectRef } (one per chunk for a chunked rule).
        Apply  : a step result { stepId; action; objectType; objectRef; status; reason; ... }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [pscustomobject]$Step,

        [pscustomobject]$Content,

        [object[]]$TenantSitInventory = @(),

        [switch]$ConfirmNameConflicts,

        [int]$MaxSitsPerRule = 0,

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
    $objectType = if ($Step.PSObject.Properties['objectType'] -and $Step.objectType) { [string]$Step.objectType } else { 'autoLabelRule' }
    if ($objectType -ne 'autoLabelPolicy' -and $objectType -ne 'autoLabelRule') {
        throw "Invoke-Compl8AutoLabelExecutor: unsupported objectType '$objectType' for step '$($Step.id)' (expected autoLabelPolicy|autoLabelRule)."
    }
    if ($MaxSitsPerRule -le 0) {
        $MaxSitsPerRule = [int](Get-DeploymentLimits).AutoLabelMaxSitsPerRule
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
            [object[]]$Chunks = $null
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
        if ($PSBoundParameters.ContainsKey('Chunks'))         { $r['chunks']         = @($Chunks) }
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

    # --- 125-classifier chunking (Split-ClassifierChunks parity — even split, not cap+remainder) ---
    function Split-Compl8ClassifierChunks {
        # Returns a List[object] whose elements are chunk arrays. A List (not a bare array) is used so a
        # SINGLE-chunk result does not get flattened back to its inner items by a caller's @() wrap.
        param([object[]]$ClassifierList, [int]$MaxPerRule)
        $out = [System.Collections.Generic.List[object]]::new()
        $total = @($ClassifierList).Count
        if ($total -eq 0) {
            $out.Add(@()) | Out-Null
        } elseif ($total -le $MaxPerRule) {
            $out.Add(@($ClassifierList)) | Out-Null
        } else {
            $chunkCount = [int][math]::Ceiling($total / $MaxPerRule)
            if ($chunkCount -gt 26) {
                throw "Cannot split $total classifiers into chunks of $MaxPerRule — would need $chunkCount chunks but maximum is 26 (a-z). Reduce classifier count or increase MaxSitsPerRule."
            }
            $chunkSize = [int][math]::Ceiling($total / $chunkCount)
            for ($i = 0; $i -lt $total; $i += $chunkSize) {
                $end = [math]::Min($i + $chunkSize, $total)
                $out.Add(@($ClassifierList[$i..($end - 1)])) | Out-Null
            }
        }
        # -NoEnumerate so the returned List is ONE object (a single-chunk result must not be flattened
        # back into its inner classifier items by the caller).
        Write-Output -NoEnumerate $out
    }
    function Get-Compl8ChunkLetter {
        param([int]$ChunkIndex)   # 1-based
        if ($ChunkIndex -lt 1 -or $ChunkIndex -gt 26) {
            throw "Chunk index $ChunkIndex is out of range (1-26) — rule names only support a-z suffixes."
        }
        [char]([int][char]'a' + $ChunkIndex - 1)
    }
    # Builds the chunked rule names for a base rule name. The base name carries no chunk letter; when
    # split, the letter is inserted after the R-number token (the old "R{ruleNumber}{chunkLetter}"
    # convention), here approximated by appending the letter to the base name's R-segment. To stay
    # name-format-agnostic, the chunk letter is inserted immediately after the first "-R<digits>" run if
    # present, else appended; both reproduce the old path's distinct per-chunk names.
    function Get-Compl8ChunkRuleName {
        param([string]$BaseName, [int]$ChunkIndex, [int]$ChunkTotal)
        if ($ChunkTotal -le 1) { return $BaseName }
        $letter = Get-Compl8ChunkLetter -ChunkIndex $ChunkIndex
        if ($BaseName -match '(-R\d+)(?=-|$)') {
            return ($BaseName -replace '(-R\d+)(?=-|$)', ('${1}' + $letter))
        }
        return "$BaseName$letter"
    }

    # Builds the ContentContainsSensitiveInformation Simple value for a classifier chunk (mirrors
    # New-DLPSITCondition's Simple format).
    function New-Compl8SitCondition {
        param([object[]]$ClassifierChunk)
        $sensitivetypes = @()
        foreach ($sit in @($ClassifierChunk)) {
            $sensitivetypes += @{
                name            = if ($sit.PSObject.Properties['Name']) { $sit.Name } elseif ($sit -is [System.Collections.IDictionary]) { $sit['Name'] } else { '' }
                id              = if ($sit.PSObject.Properties['Id'])   { $sit.Id }   elseif ($sit -is [System.Collections.IDictionary]) { $sit['Id'] }   else { '' }
                mincount        = [int]$(if ($sit.PSObject.Properties['minCount']) { $sit.minCount } elseif ($sit -is [System.Collections.IDictionary] -and $sit['minCount']) { $sit['minCount'] } else { 1 })
                maxcount        = [int]$(if ($sit.PSObject.Properties['maxCount']) { $sit.maxCount } elseif ($sit -is [System.Collections.IDictionary] -and $sit['maxCount']) { $sit['maxCount'] } else { -1 })
                confidencelevel = if ($sit.PSObject.Properties['confidencelevel']) { $sit.confidencelevel } elseif ($sit -is [System.Collections.IDictionary] -and $sit['confidencelevel']) { $sit['confidencelevel'] } else { 'Medium' }
            }
        }
        @{ operator = 'And'; groups = @(@{ operator = 'Or'; name = 'Default'; sensitivetypes = $sensitivetypes }) }
    }

    $name = if ($Content -and $Content.PSObject.Properties['name'] -and $Content.name) { [string]$Content.name } else { $objectRef }

    $getCmd    = if ($objectType -eq 'autoLabelPolicy') { 'Get-AutoSensitivityLabelPolicy' } else { 'Get-AutoSensitivityLabelRule' }
    $removeCmd = if ($objectType -eq 'autoLabelPolicy') { 'Remove-AutoSensitivityLabelPolicy' } else { 'Remove-AutoSensitivityLabelRule' }

    # ============================================================ -WhatIf / plan mode (NO mutation)
    if ($WhatIf) {
        if ($action -eq 'remove') { return New-PlannedOp -OpAction 'remove' -OpRef $objectRef }
        # Chunking applies to planning too: a rule whose classifier list exceeds the cap plans one op
        # per chunk (chunk-letter names), exactly as the old path plans one rule per chunk.
        if ($objectType -eq 'autoLabelRule' -and $Content -and $Content.PSObject.Properties['classifiers']) {
            $chunks = Split-Compl8ClassifierChunks -ClassifierList @($Content.classifiers) -MaxPerRule $MaxSitsPerRule
            $chunkTotal = $chunks.Count
            if ($chunkTotal -gt 1) {
                $ops = for ($i = 0; $i -lt $chunkTotal; $i++) {
                    $ruleName = Get-Compl8ChunkRuleName -BaseName $name -ChunkIndex ($i + 1) -ChunkTotal $chunkTotal
                    $exists = $ExistingState -and $ExistingState.ContainsKey($ruleName) -and $ExistingState[$ruleName]
                    $chunkAction = if ($exists) { 'update' } else { 'create' }
                    New-PlannedOp -OpAction $chunkAction -OpRef $ruleName
                }
                return $ops
            }
        }
        $existsInState = $ExistingState -and $ExistingState.ContainsKey($name) -and $ExistingState[$name]
        $plannedAction = if ($existsInState) { 'update' } else { 'create' }
        return New-PlannedOp -OpAction $plannedAction -OpRef $name
    }

    # ============================================================ REMOVE
    if ($action -eq 'remove') {
        $removeState = Remove-PurviewObject -Identity $name `
            -GetCommand $getCmd -RemoveCommand $removeCmd `
            -OperationName $(if ($objectType -eq 'autoLabelPolicy') { 'AL policy' } else { 'AL rule' }) -SleepAction $SleepAction
        return New-StepResult -Status (ConvertTo-RemoveStatus $removeState) -RemoveState $removeState `
            -Reason "remove $objectType '$name' -> $removeState"
    }

    if (-not $Content) {
        throw "Invoke-Compl8AutoLabelExecutor: step '$($Step.id)' ($action $objectRef) requires -Content but none was supplied."
    }

    # ============================================================ POLICY path =====================
    if ($objectType -eq 'autoLabelPolicy') {
        $label     = if ($Content.PSObject.Properties['label']) { [string]$Content.label } else { '' }
        $mode      = if ($Content.PSObject.Properties['mode'] -and $Content.mode) { [string]$Content.mode } else { 'TestWithoutNotifications' }
        $locations = @{}
        if ($Content.PSObject.Properties['locations'] -and $Content.locations) {
            foreach ($k in $Content.locations.Keys) { $locations[$k] = $Content.locations[$k] }
        }
        $policyComment = Add-DeploymentProvenanceStamp `
            -Text $(if ($Content.PSObject.Properties['comment']) { [string]$Content.comment } else { '' }) `
            -Prefix $(if ($Prefix) { $Prefix } else { 'UNSCOPED' }) -Component 'AutoLabelPolicy' `
            -TargetEnvironment $TargetEnvironment -Metadata @{ PolicyName = $name } `
            -RegistryPath $ProvenanceRegistryPath

        $existing = $null
        try { $existing = Get-AutoSensitivityLabelPolicy -Identity $name -ErrorAction Stop } catch { $existing = $null }

        if ($action -eq 'create' -and $existing) {
            $isPending = ($existing.PSObject.Properties['Mode'] -and $existing.Mode -eq 'PendingDeletion')
            if (-not $isPending -and -not $ConfirmNameConflicts) {
                return New-StepResult -Status 'name-conflict' -Reason "AL policy '$name' already exists (active)."
            }
        }

        if ($existing) {
            Invoke-WithRetry -OperationName "Set-ALPolicy $name" -ScriptBlock {
                Set-AutoSensitivityLabelPolicy -Identity $name -ApplySensitivityLabel $label -Comment $policyComment -Mode $mode -Confirm:$false -ErrorAction Stop
            } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
            return New-StepResult -Status 'updated' -StampedComment $policyComment -Reason "updated AL policy '$name'"
        }
        $newPolicyParams = @{ Name = $name; ApplySensitivityLabel = $label; Comment = $policyComment; Mode = $mode }
        foreach ($k in $locations.Keys) { $newPolicyParams[$k] = $locations[$k] }
        Invoke-WithRetry -OperationName "New-ALPolicy $name" -ScriptBlock {
            New-AutoSensitivityLabelPolicy @newPolicyParams -ErrorAction Stop
        } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
        return New-StepResult -Status 'created' -StampedComment $policyComment -Reason "created AL policy '$name' (mode: $mode)"
    }

    # ============================================================ RULE path (with 125-chunking) ===
    $classifiers = @(if ($Content.PSObject.Properties['classifiers']) { $Content.classifiers } else { @() })
    $policyName  = if ($Content.PSObject.Properties['policy']) { [string]$Content.policy } else { '' }
    $workload    = if ($Content.PSObject.Properties['workload']) { [string]$Content.workload } else { '' }
    $scopeParam  = if ($Content.PSObject.Properties['scopeParam']) { [string]$Content.scopeParam } else { '' }
    $scopeValue  = if ($Content.PSObject.Properties['scopeValue']) { [string]$Content.scopeValue } else { '' }

    # ---- SIT VALIDATION GATE (over the WHOLE classifier set, before any chunk is created) ---------
    if (@($TenantSitInventory).Count -gt 0 -and @($classifiers).Count -gt 0) {
        $byId = @{}
        foreach ($s in @($TenantSitInventory)) {
            $id = if ($s.PSObject.Properties['Id'] -and $s.Id) { [string]$s.Id } elseif ($s.PSObject.Properties['Identity'] -and $s.Identity) { [string]$s.Identity } else { '' }
            if ($id) { $byId[$id.ToLowerInvariant()] = $s }
        }
        $missing = @()
        foreach ($c in $classifiers) {
            $ct = if ($c.PSObject.Properties['ClassifierType']) { [string]$c.ClassifierType } elseif ($c -is [System.Collections.IDictionary] -and $c['ClassifierType']) { [string]$c['ClassifierType'] } else { '' }
            if ($ct -eq 'MLModel') { continue }   # trainable classifiers are not in the SIT list
            $cid = if ($c.PSObject.Properties['Id']) { [string]$c.Id } elseif ($c -is [System.Collections.IDictionary]) { [string]$c['Id'] } else { '' }
            if (-not $cid) { continue }
            if (-not $byId.ContainsKey($cid.ToLowerInvariant())) { $missing += $cid }
        }
        if ($missing.Count -gt 0) {
            return New-StepResult -Status 'sit-invalid' `
                -Reason "AL rule '$name' references SIT GUID(s) not found in the tenant: $($missing -join ', '). (SIT validation gate.)"
        }
    }

    # ---- CHUNK the classifier list and create/update one rule per chunk ---------------------------
    $chunks = Split-Compl8ClassifierChunks -ClassifierList @($classifiers) -MaxPerRule $MaxSitsPerRule
    $chunkTotal = $chunks.Count
    $chunkResults = [System.Collections.Generic.List[object]]::new()

    for ($i = 0; $i -lt $chunkTotal; $i++) {
        $chunk    = @($chunks[$i])
        $ruleName = Get-Compl8ChunkRuleName -BaseName $name -ChunkIndex ($i + 1) -ChunkTotal $chunkTotal
        $chunkNote = if ($chunkTotal -gt 1) { " [chunk $($i + 1)/$chunkTotal]" } else { '' }

        $ruleComment = Add-DeploymentProvenanceStamp `
            -Text $(if ($Content.PSObject.Properties['comment']) { "$([string]$Content.comment)$chunkNote" } else { $chunkNote }) `
            -Prefix $(if ($Prefix) { $Prefix } else { 'UNSCOPED' }) -Component 'AutoLabelRule' `
            -TargetEnvironment $TargetEnvironment -Metadata @{ RuleName = $ruleName; Chunk = ($i + 1) } `
            -RegistryPath $ProvenanceRegistryPath

        $condition = New-Compl8SitCondition -ClassifierChunk $chunk
        $ruleParams = @{
            Name                                = $ruleName
            Policy                              = $policyName
            Workload                            = $workload
            Comment                             = $ruleComment
            ContentContainsSensitiveInformation = $condition
            ReportSeverityLevel                 = 'Low'
            Disabled                            = $false
        }
        if ($scopeParam) { $ruleParams[$scopeParam] = $scopeValue }

        $existingRule = $null
        try { $existingRule = Get-AutoSensitivityLabelRule -Identity $ruleName -ErrorAction Stop } catch { $existingRule = $null }

        if ($action -eq 'create' -and $existingRule) {
            $isPending = ($existingRule.PSObject.Properties['Mode'] -and $existingRule.Mode -eq 'PendingDeletion')
            if (-not $isPending -and -not $ConfirmNameConflicts) {
                $chunkResults.Add([pscustomobject]@{ ruleName = $ruleName; status = 'name-conflict' }) | Out-Null
                continue
            }
        }

        if ($existingRule) {
            $updateRuleParams = @{ Identity = $ruleName }
            foreach ($k in $ruleParams.Keys) { if ($k -notin @('Name', 'Policy')) { $updateRuleParams[$k] = $ruleParams[$k] } }
            Invoke-WithRetry -OperationName "Set-ALRule $ruleName" -ScriptBlock {
                Set-AutoSensitivityLabelRule @updateRuleParams -Confirm:$false -ErrorAction Stop
            } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
            $chunkResults.Add([pscustomobject]@{ ruleName = $ruleName; status = 'updated' }) | Out-Null
        } else {
            Invoke-WithRetry -OperationName "New-ALRule $ruleName" -ScriptBlock {
                $null = New-AutoSensitivityLabelRule @ruleParams -ErrorAction Stop
            } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
            $chunkResults.Add([pscustomobject]@{ ruleName = $ruleName; status = 'created' }) | Out-Null
        }
    }

    # Single-chunk rule: report the simple status. Multi-chunk: report 'chunked' with per-chunk detail.
    if ($chunkTotal -le 1) {
        $only = @($chunkResults)[0]
        return New-StepResult -Status $only.status -Chunks @($chunkResults) `
            -Reason "$($only.status) AL rule '$($only.ruleName)' ($(@($classifiers).Count) classifiers)"
    }
    return New-StepResult -Status 'chunked' -Chunks @($chunkResults) `
        -Reason "AL rule '$name' split into $chunkTotal chunk(s) (<= $MaxSitsPerRule classifiers each) for $(@($classifiers).Count) classifiers."
}
