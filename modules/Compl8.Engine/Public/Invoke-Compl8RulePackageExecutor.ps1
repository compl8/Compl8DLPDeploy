function Invoke-Compl8RulePackageExecutor {
    <#
    .SYNOPSIS
        Apply executor for a SIT RULE-PACKAGE plan step (action create|update|remove; objectType
        rulePackage). Copies the Task-8 dictionary pilot + Task-9 label template and shadows against
        the rule-package upload/removal path of scripts/Deploy-Classifiers.ps1.
        (PHASE 4C, Task 10; arch design §5/§6; decisions D1/D3/D5.)

    .DESCRIPTION
        FRESH PORT (D1) of the rule-package mutation path from scripts/Deploy-Classifiers.ps1 —
        Invoke-RulePackageUploadCommand / Invoke-ClassifierUploadPlan (create/update) and
        Invoke-ClassifierPackageRemoval (remove) — into Compl8.Engine scope, the ONLY tenant-mutating
        layer (D3). The old Deploy-Classifiers.ps1 stays live and UNMODIFIED; this executor reproduces
        its SCC cmdlet sequence + the operational guards that belong at apply time and is proven
        equivalent by a SHADOW DIFF against a GENUINE Deploy-Classifiers.ps1 upload run
        (Get-Compl8ShadowDiff Match -eq $true) before any cutover.

        ============================== TEMPLATE (copied from the pilot) ==============================
        SIGNATURE / APPLY CONTRACT. Invoke-Compl8Apply dispatches a step to the executor as
        `& $executor -Step $step` (or `& $sb $step`), so the plan step is -Step (also positional 0). The
        RESOLVED CONTENT the step needs (the package name + the resolved, dictionary-GUID-substituted
        rule-package XML payload + the local SIT ids the package declares) is bound by the production
        executor-map closure as -Content — it is NOT on the step.

        PLANNED-OP / -WhatIf MODE. With -WhatIf the executor performs NO mutation and RETURNS a single
        normalised "planned operation" record in the Get-Compl8ShadowDiff op shape:
            { action; objectType; objectRef }
        This is the SHADOW-DIFF contract. The planned ACTION is derived from desired-vs-existing exactly
        as the old path decides it: a package that already EXISTS in the tenant plans an `update` (the
        old "Replace" action), otherwise a `create` (the old "New" action); a `remove` step always plans
        `remove`. Existing state under -WhatIf is supplied via -ExistingState (a name->object map) so
        planning is pure and matches the old path's Get-DlpSensitiveInformationTypeRulePackage lookup
        without a live tenant. (The genuine shadow run records its ops against an EMPTY tenant, so every
        package plans a `create` there.)

        RESULT / CHECKPOINT SHAPE (apply mode). The executor returns a result the apply checkpoint
        records verbatim:
            { stepId; action; objectType; objectRef; status; reason; verified?; removeState?; dictErrors? }
        `status` ∈ created | updated | deleted | dict-ref-missing | capacity-blocked | verify-failed |
                   not-found | failed.

        OPERATIONAL GUARDS PORTED (the ones that are the executor's job — see SUBSUMED note):
          * CAPACITY GATE. Mirrors Test-UploadCapacityGate: a create that would exceed the 10 custom
            rule-package slots (CurrentSlotsUsed + new creates - SlotsFreed > 10) is REFUSED — NO New
            call, status 'capacity-blocked'. CurrentSlotsUsed / SlotsFreed are supplied by the caller
            (-CurrentSlotsUsed/-SlotsFreed) since slot accounting is an apply-batch concern; an update
            consumes no new slot. (Old path: Test-UploadCapacityGate BLOCKED branch.)
          * DICTIONARY-REFERENCE ASSERTION. Mirrors Assert-RulePackageUploadDictionaryReferences /
            Assert-PackageDictionaryReferencesExist: before a create/update the resolved XML's dictionary
            GUID references (Get-DictionaryGuidReferences, Compl8.Model) must ALL be present in the tenant
            dictionary inventory (-DictionaryInventory, a list of objects with a Guid). A missing GUID
            REFUSES the upload — NO New/Set call, status 'dict-ref-missing' — exactly the old "references
            dictionary GUID(s) not present in the tenant ... Upload aborted" guard (the silent-failure
            case: never upload a classifier pointing at a non-existent dictionary).
          * POST-UPLOAD VERIFICATION POLL. Mirrors Test-UploadedSensitiveInformationTypes: after a
            create/update, poll Get-DlpSensitiveInformationType until every local SIT id the package
            declares (Content.localSitIds) is visible, or the timeout elapses. The wait is INJECTABLE via
            -SleepAction so tests never wait on the wall clock. A timeout sets status 'verify-failed'
            (the upload happened; verification did not confirm visibility) — mirroring the old throw
            "Post-upload SIT verification failed".

        SUBSUMED GUARDS (deliberately NOT duplicated in this executor — flagged per D5/D4/plan-freshness):
          * REMOVAL REFERENCE GUARD. Test-DlpRulePackageRemovalReferenceGuard is the APPLY-FRAMEWORK
            backstop: Invoke-Compl8Apply (Task 6) RE-CHECKS it before any remove/dereference step (D5).
            The planner also GENERATES the dereference steps that strip the SITs from referencing rules
            BEFORE this removal. So the executor does NOT re-run the reference guard — that would double
            the gate, not strengthen it.
          * SNAPSHOT-BEFORE-DESTROY. The old Backup-DeployedPackage per-package backup is SUBSUMED by the
            generated snapshotBeforeDestroy plan Step 0.5 (D4) — a tenant snapshot the apply cannot skip.
            DECISION: per-package backup is therefore NOT the executor's job; the plan-level snapshot
            covers it and avoids a second, narrower backup the apply framework cannot gate.
          * REFIT-PLAN FRESHNESS / DIRECT-UPLOAD REFIT GATE. Expressed as PLAN freshness
            (Test-Compl8PlanCurrent) — a stale plan is rejected before any executor runs. Not the
            executor's concern.

        RETRY. Create/update go through Invoke-WithRetry (Task 7) so transient Purview throttles back off
        + retry; remove goes through Remove-PurviewObject (Task 7) for its
        deleted|pending|cooldown|not-found|failed state machine. Both have an injectable -SleepAction.

        NOTE on the retry scriptblock: passed to Invoke-WithRetry WITHOUT .GetNewClosure() so it keeps its
        module affinity (Compl8.Engine) and a `Mock -ModuleName Compl8.Engine` on
        New-/Set-DlpSensitiveInformationTypeRulePackage resolves inside it. Same as the pilot + the old
        Deploy-Classifiers.ps1.
        ============================================================================================

    .PARAMETER Step
        The rule-package plan step (compl8.plan/v1): { id; action; objectType='rulePackage'; objectRef; ... }.
        action ∈ create|update|remove. Positional 0.

    .PARAMETER Content
        The resolved content for this step. For create/update: { name; payloadXml (the resolved,
        dictionary-GUID-substituted rule-package XML); fileData? (pre-encoded UTF-16LE bytes, optional);
        localSitIds (string[] of the SIT ids the package declares, for post-upload verification) }. For a
        remove: { name; identity (the deployed package Identity passed to Remove) }. Required for all actions.

    .PARAMETER DictionaryInventory
        The tenant keyword-dictionary inventory (objects carrying a Guid) used by the dictionary-reference
        assertion. Defaults to empty (a package that references no dictionary GUID passes trivially).

    .PARAMETER CurrentSlotsUsed
        Custom rule-package slots currently consumed in the tenant (capacity-gate input). Default 0.

    .PARAMETER SlotsFreed
        Slots freed by removals earlier in this apply batch, credited to the capacity gate. Default 0.

    .PARAMETER MaxPackageSlots
        The tenant custom rule-package slot cap. Default 10 (the Purview limit the old path hard-codes).

    .PARAMETER VerifyTimeoutSeconds
        Post-upload verification poll budget. Default 120 (matches the old path).

    .PARAMETER VerifyIntervalSeconds
        Post-upload verification poll interval. Default 10 (matches the old path).

    .PARAMETER Prefix
        The deployment naming prefix (e.g. 'QGISCF'). Reserved for parity with the other executors.

    .PARAMETER TargetEnvironment
        Optional environment key. Reserved for parity with the other executors.

    .PARAMETER ExistingState
        A name -> existing-object map used ONLY in -WhatIf planning to decide create-vs-update without a
        live tenant (the planning analogue of the old path's Get-DlpSensitiveInformationTypeRulePackage probe).

    .PARAMETER SleepAction
        Injectable sleep forwarded to Invoke-WithRetry / Remove-PurviewObject AND the post-upload verify
        poll. Defaults to a real Start-Sleep; tests pass a no-op so retry/verify run instantly.

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

        [object[]]$DictionaryInventory = @(),

        [int]$CurrentSlotsUsed = 0,

        [int]$SlotsFreed = 0,

        [int]$MaxPackageSlots = 10,

        [int]$VerifyTimeoutSeconds = 120,

        [int]$VerifyIntervalSeconds = 10,

        [string]$Prefix,

        [string]$TargetEnvironment,

        [hashtable]$ExistingState = @{},

        [scriptblock]$SleepAction = { param($s) Start-Sleep -Seconds $s },

        [switch]$WhatIf
    )

    $action    = [string]$Step.action
    $objectRef = [string]$Step.objectRef

    # --- planned-op helper: the normalised Get-Compl8ShadowDiff op shape ---------------------------
    function New-PlannedOp {
        param([string]$OpAction, [string]$OpRef)
        [pscustomobject]@{ action = $OpAction; objectType = 'rulePackage'; objectRef = $OpRef }
    }

    # --- step-result helper: the apply checkpoint result shape ------------------------------------
    function New-StepResult {
        param(
            [string]$Status,
            [string]$Reason = '',
            [nullable[bool]]$Verified = $null,
            [string]$RemoveState = $null,
            [string[]]$DictErrors = @()
        )
        $r = [ordered]@{
            stepId     = [string]$Step.id
            action     = $action
            objectType = 'rulePackage'
            objectRef  = $objectRef
            status     = $Status
            reason     = $Reason
        }
        if ($PSBoundParameters.ContainsKey('Verified'))    { $r['verified']    = $Verified }
        if ($PSBoundParameters.ContainsKey('RemoveState')) { $r['removeState'] = $RemoveState }
        if ($PSBoundParameters.ContainsKey('DictErrors'))  { $r['dictErrors']  = @($DictErrors) }
        [pscustomobject]$r
    }

    # The scoped package NAME the tenant addresses. Prefer the resolved content's name; fall back to
    # the placeholder objectRef (e.g. a bare remove step with no content).
    $name = if ($Content -and $Content.PSObject.Properties['name'] -and $Content.name) { [string]$Content.name } else { $objectRef }

    # ============================================================ -WhatIf / plan mode (NO mutation)
    # Derive the planned ACTION from desired-vs-existing exactly as the old path decides it: an existing
    # package plans `update` (old "Replace"), otherwise `create` (old "New"); a `remove` always `remove`.
    if ($WhatIf) {
        if ($action -eq 'remove') { return New-PlannedOp -OpAction 'remove' -OpRef $objectRef }
        $existsInState = $ExistingState -and $ExistingState.ContainsKey($name) -and $ExistingState[$name]
        $plannedAction = if ($existsInState) { 'update' } else { 'create' }
        return New-PlannedOp -OpAction $plannedAction -OpRef $objectRef
    }

    # ============================================================ REMOVE
    # Delegate to the ported Remove-PurviewObject state machine. The apply framework already re-checked
    # the removal reference guard (D5 backstop) before dispatching this step, so the executor focuses on
    # the SCC delete itself. Remove addresses the deployed Identity when supplied, else the name.
    if ($action -eq 'remove') {
        $identity = if ($Content -and $Content.PSObject.Properties['identity'] -and $Content.identity) { [string]$Content.identity } else { $name }
        $removeState = Remove-PurviewObject -Identity $identity `
            -GetCommand 'Get-DlpSensitiveInformationTypeRulePackage' `
            -RemoveCommand 'Remove-DlpSensitiveInformationTypeRulePackage' `
            -OperationName 'SIT rule package' -SleepAction $SleepAction
        $status = switch ($removeState) {
            'deleted'   { 'deleted' }
            'pending'   { 'deleted' }   # already being removed — desired end state reached
            'not-found' { 'not-found' }
            default     { if ($removeState -like 'cooldown:*') { 'cooldown' } else { 'failed' } }
        }
        return New-StepResult -Status $status -RemoveState $removeState -Reason "remove rule package '$name' -> $removeState"
    }

    # ---- create / update need resolved content --------------------------------------------------
    if (-not $Content) {
        throw "Invoke-Compl8RulePackageExecutor: step '$($Step.id)' ($action $objectRef) requires -Content (resolved package payload) but none was supplied."
    }

    $payloadXml = if ($Content.PSObject.Properties['payloadXml']) { [string]$Content.payloadXml } else { '' }
    if ([string]::IsNullOrWhiteSpace($payloadXml) -and -not ($Content.PSObject.Properties['fileData'] -and $Content.fileData)) {
        throw "Invoke-Compl8RulePackageExecutor: step '$($Step.id)' ($action $objectRef) requires -Content.payloadXml (the resolved rule-package XML) or -Content.fileData."
    }

    # ============================================================ CAPACITY GATE (create only)
    # An update reuses an existing slot; only a create consumes a new one. Mirror the old gate's BLOCKED
    # branch: refuse if the create would not fit the available slots.
    if ($action -eq 'create') {
        $slotsAvailable = [math]::Max(0, $MaxPackageSlots - $CurrentSlotsUsed + [math]::Max(0, $SlotsFreed))
        if ($slotsAvailable -lt 1) {
            return New-StepResult -Status 'capacity-blocked' `
                -Reason "capacity: creating rule package '$name' needs 1 slot but only $slotsAvailable of $MaxPackageSlots are available (used $CurrentSlotsUsed, freed $SlotsFreed). Remove an existing package or consolidate bundles."
        }
    }

    # ============================================================ DICTIONARY-REFERENCE ASSERTION
    # Never upload a classifier that points at a dictionary GUID absent from the tenant (the silent-
    # failure case). Mirror Assert-PackageDictionaryReferencesExist.
    if ($payloadXml) {
        $referenced = @(Get-DictionaryGuidReferences -PackageXmlText $payloadXml)
        if ($referenced.Count -gt 0) {
            $present = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($d in @($DictionaryInventory)) {
                if ($d -and $d.PSObject.Properties['Guid'] -and $d.Guid) { [void]$present.Add([string]$d.Guid) }
            }
            $missing = @($referenced | Where-Object { -not $present.Contains($_) })
            if ($missing.Count -gt 0) {
                return New-StepResult -Status 'dict-ref-missing' -DictErrors @($missing) `
                    -Reason "package '$name' references dictionary GUID(s) not present in the tenant: $($missing -join ', '). Dictionary sync may have failed. Upload aborted."
            }
        }
    }

    # ---- the Purview-safe payload bytes (UTF-16LE + BOM), reusing pre-encoded bytes if supplied ---
    $fileData = if ($Content.PSObject.Properties['fileData'] -and $Content.fileData) {
        [byte[]]$Content.fileData
    } else {
        $encoding = [System.Text.UnicodeEncoding]::new($false, $true)
        $normalized = $payloadXml.TrimStart([char]0xFEFF)
        $body = $encoding.GetBytes($normalized)
        $preamble = $encoding.GetPreamble()
        $bytes = New-Object byte[] ($preamble.Length + $body.Length)
        [System.Array]::Copy($preamble, 0, $bytes, 0, $preamble.Length)
        [System.Array]::Copy($body, 0, $bytes, $preamble.Length, $body.Length)
        $bytes
    }

    # ============================================================ CREATE / UPDATE (Invoke-WithRetry)
    # Bare scriptblock (no .GetNewClosure()) — keeps the module mock resolvable inside retry.
    if ($action -eq 'create') {
        Invoke-WithRetry -OperationName "New-RulePackage $name" -ScriptBlock {
            New-DlpSensitiveInformationTypeRulePackage -FileData $fileData -Confirm:$false -ErrorAction Stop
        } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
        $createStatus = 'created'
    } elseif ($action -eq 'update') {
        Invoke-WithRetry -OperationName "Set-RulePackage $name" -ScriptBlock {
            Set-DlpSensitiveInformationTypeRulePackage -FileData $fileData -Confirm:$false -ErrorAction Stop
        } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
        $createStatus = 'updated'
    } else {
        throw "Invoke-Compl8RulePackageExecutor: unsupported action '$action' for step '$($Step.id)' (expected create|update|remove)."
    }

    # ============================================================ POST-UPLOAD VERIFICATION POLL
    # Confirm every local SIT id the package declares is visible in Get-DlpSensitiveInformationType,
    # polling with the injectable sleep. Mirror Test-UploadedSensitiveInformationTypes.
    $localSitIds = @(if ($Content.PSObject.Properties['localSitIds']) { $Content.localSitIds } else { @() }) |
        Where-Object { $_ } | ForEach-Object { [string]$_ }
    $verified = $null
    if (@($localSitIds).Count -gt 0) {
        $expected = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($id in $localSitIds) { [void]$expected.Add($id) }
        $attempts = [math]::Max(1, [int][math]::Ceiling($VerifyTimeoutSeconds / [math]::Max(1, $VerifyIntervalSeconds)))
        $verified = $false
        for ($attempt = 1; $attempt -le $attempts; $attempt++) {
            $present = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            try {
                foreach ($sit in @(Get-DlpSensitiveInformationType -ErrorAction Stop)) {
                    if ($sit.PSObject.Properties['Identity'] -and $sit.Identity) { [void]$present.Add([string]$sit.Identity) }
                    if ($sit.PSObject.Properties['Id'] -and $sit.Id)             { [void]$present.Add([string]$sit.Id) }
                }
            } catch { }
            $missing = @($expected | Where-Object { -not $present.Contains($_) })
            if ($missing.Count -eq 0) { $verified = $true; break }
            if ($attempt -lt $attempts) { & $SleepAction $VerifyIntervalSeconds }
        }
        if (-not $verified) {
            return New-StepResult -Status 'verify-failed' -Verified $false `
                -Reason "rule package '$name' $createStatus, but post-upload SIT verification did not confirm visibility of all declared local SIT id(s) within ${VerifyTimeoutSeconds}s."
        }
    }

    return New-StepResult -Status $createStatus -Verified $verified `
        -Reason "$createStatus rule package '$name'$(if ($null -ne $verified -and $verified) { ' (post-upload SIT verification passed)' } else { '' })"
}
