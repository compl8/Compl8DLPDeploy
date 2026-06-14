function Invoke-Compl8DictionaryExecutor {
    <#
    .SYNOPSIS
        Apply executor for a KEYWORD-DICTIONARY plan step (action create|update|remove). The PILOT
        executor — it establishes the TEMPLATE Tasks 9-12 copy for the remaining object types.
        (PHASE 4C, Task 8; arch design §5/§6; decisions D1/D3.)

    .DESCRIPTION
        FRESH PORT (D1) of the dictionary mutation path from DLP-Deploy.psm1's
        Sync-DlpKeywordDictionaries into Compl8.Engine scope — the ONLY tenant-mutating layer (D3).
        The old Sync stays live and UNMODIFIED; this executor reproduces its SCC cmdlet sequence and
        guards and is proven equivalent by a SHADOW DIFF against Sync-DlpKeywordDictionaries -WhatIf
        (Get-Compl8ShadowDiff.Match -eq $true) before any cutover.

        ============================== THE EXECUTOR TEMPLATE (Tasks 9-12 copy this) ==================
        SIGNATURE / APPLY CONTRACT. Invoke-Compl8Apply (Task 6) dispatches each step to an executor it
        resolves from -ExecutorMap by objectType. The dispatcher invokes a COMMAND-name executor as
        `& $cmd -Step $step` and a SCRIPTBLOCK executor as `& $sb $step` (one positional). So every
        executor MUST accept the plan step as -Step (also positional 0). The RESOLVED CONTENT the step
        needs (terms/description/byte-budget for a dictionary) is NOT on the step (the step only carries
        action/objectType/objectRef/dependsOn/impact/gate). Production wires it via a closure in the
        executor map, e.g.
            $map = @{ dictionary = { param($Step) Invoke-Compl8DictionaryExecutor -Step $Step `
                        -Content ($resolved.Dictionaries | ? placeholder -eq $Step.objectRef) `
                        -Prefix $prefix }.GetNewClosure() }
        so the executor receives -Content already bound. -Content is therefore an executor parameter,
        not a step field. (Tasks 9-12 follow the same shape: -Step + the resolved content slice.)

        PLANNED-OP / -WhatIf MODE. With -WhatIf the executor performs NO mutation and RETURNS a single
        normalised "planned operation" record in the Get-Compl8ShadowDiff op shape:
            { action; objectType; objectRef }   (+ optional descriptive fields)
        This is the SHADOW-DIFF contract — the op list Tasks 9-12 reuse and the list apply -WhatIf and
        Get-Compl8ShadowDiff compare. For dictionaries the planned op is always a `create` of the
        dictionary keyed by its placeholder objectRef, exactly mirroring the old -WhatIf path (which,
        with an empty tenant inventory under -WhatIf, reports every manifest dictionary as a planned
        create with a dummy GUID — it cannot see existing dictionaries in -WhatIf, so neither do we).

        RESULT / CHECKPOINT SHAPE (apply mode). The executor returns a result object the apply
        checkpoint records verbatim:
            { stepId; action; objectType; objectRef; status; guid; reason;
              stampedDescription; removeState?; budgetErrors? }
        `status` ∈ created | updated | reused | deleted | over-budget | not-found | failed. The apply
        framework records this under result.<...> and re-running a checkpointed step skips it (Task 6).

        PROVENANCE. On a create/update we stamp the dictionary Description via
        Add-DeploymentProvenanceStamp (Compl8.Model) — the [[Compl8:<16hex>]] marker — so the object is
        discoverable as ours. The stamped string is returned as `stampedDescription`.

        BUDGET GATE. Before a create/update we run Test-ContentDictionaryBudget (Compl8.Content) on the
        dictionary's termsBytes. Mirroring the old path's PRE-CREATE budget guard (Sync line ~2006:
        "would exceed the tenant hard cap … Skipping"), a hard-cap breach REFUSES the mutation: NO New/Set
        call, status='over-budget', budgetErrors populated. (The old path keeps the existing/skips and
        lets the upload guard flag dependent classifiers; we likewise do not create/modify.)

        IDEMPOTENCY. A `create` where the dictionary already exists REUSES it (status='reused', returns
        the existing GUID, NO New call, NO duplicate) — mirroring Sync's already-exists recovery
        (Sync line ~2024: on an "already exists" error it re-fetches by name and reuses the GUID). We
        check existence UP FRONT (Get-DlpKeywordDictionary) rather than catching the create error, which
        is the same outcome with one fewer failed API call.

        RETRY. Create/update go through Invoke-WithRetry (Task 7) so transient Purview throttles are
        retried with backoff; remove goes through Remove-PurviewObject (Task 7) for its
        deleted|pending|cooldown|not-found|failed state machine. Both have an injectable sleep so tests
        never wait on the wall clock.
        ============================================================================================

    .PARAMETER Step
        The dictionary plan step (compl8.plan/v1): { id; action; objectType='dictionary'; objectRef;
        dependsOn; impact; gate }. action ∈ create|update|remove. Positional 0 so the apply dispatcher's
        `& $executor $step` binds it.

    .PARAMETER Content
        The resolved dictionary content for this step's objectRef: an object carrying placeholder, name
        (prefix-scoped), description, terms (string[]) and termsBytes (the budget input). Bound by the
        production executor-map closure; required for create/update (the remove path needs only the name).

    .PARAMETER Prefix
        The deployment naming prefix (e.g. 'QGISCF'), forwarded to the provenance stamp as its Prefix.

    .PARAMETER TargetEnvironment
        Optional environment key forwarded to the provenance stamp.

    .PARAMETER SleepAction
        Injectable sleep forwarded to Invoke-WithRetry / Remove-PurviewObject. Defaults to a real
        Start-Sleep; tests pass a no-op so retry paths run instantly.

    .PARAMETER WhatIf
        Plan/report mode: perform NO mutation and return the normalised planned-operation record
        (Get-Compl8ShadowDiff op shape) for shadow comparison.

    .OUTPUTS
        -WhatIf: a planned-op record { action; objectType; objectRef }.
        Apply  : a step result { stepId; action; objectType; objectRef; status; guid; reason;
                 stampedDescription; ... } recorded verbatim by the apply checkpoint.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [pscustomobject]$Step,

        [pscustomobject]$Content,

        [string]$Prefix,

        [string]$TargetEnvironment,

        # Optional provenance registry path (the workspace's history/applies/provenance.json). When
        # supplied it is threaded to Add-DeploymentProvenanceStamp -RegistryPath so this apply's
        # provenance entry is written to the WORKSPACE registry rather than the repo/env default.
        # Absent => unchanged behaviour. (Stage 5 D8; codex 5A review.)
        [string]$ProvenanceRegistryPath,

        [scriptblock]$SleepAction = { param($s) Start-Sleep -Seconds $s },

        [switch]$WhatIf
    )

    $action    = [string]$Step.action
    $objectRef = [string]$Step.objectRef

    # --- planned-op helper: the normalised Get-Compl8ShadowDiff op shape ---------------------------
    function New-PlannedOp {
        param([string]$OpAction, [string]$OpRef)
        [pscustomobject]@{ action = $OpAction; objectType = 'dictionary'; objectRef = $OpRef }
    }

    # --- step-result helper: the apply checkpoint result shape ------------------------------------
    function New-StepResult {
        param(
            [string]$Status,
            [string]$Guid = $null,
            [string]$Reason = '',
            [string]$StampedDescription = $null,
            [string]$RemoveState = $null,
            [string[]]$BudgetErrors = @()
        )
        $r = [ordered]@{
            stepId             = [string]$Step.id
            action             = $action
            objectType         = 'dictionary'
            objectRef          = $objectRef
            status             = $Status
            guid               = $Guid
            reason             = $Reason
            stampedDescription = $StampedDescription
        }
        if ($PSBoundParameters.ContainsKey('RemoveState')) { $r['removeState'] = $RemoveState }
        if ($PSBoundParameters.ContainsKey('BudgetErrors')) { $r['budgetErrors'] = @($BudgetErrors) }
        [pscustomobject]$r
    }

    # ============================================================ -WhatIf / plan mode (NO mutation)
    # Emit the normalised planned op. For dictionaries every step plans a `create` of the dictionary
    # keyed by its placeholder objectRef — matching the old Sync -WhatIf path exactly (empty inventory
    # under -WhatIf => every dictionary reported as a planned create with a dummy GUID).
    if ($WhatIf) {
        return New-PlannedOp -OpAction 'create' -OpRef $objectRef
    }

    # The scoped dictionary NAME the tenant cmdlets address. Prefer the resolved content's name; fall
    # back to the placeholder objectRef if content was not supplied (e.g. a bare remove step).
    $name = if ($Content -and $Content.PSObject.Properties['name'] -and $Content.name) { [string]$Content.name } else { $objectRef }

    # ============================================================ REMOVE
    # Delegate to the ported Remove-PurviewObject state machine (deleted|pending|cooldown|not-found|failed).
    if ($action -eq 'remove') {
        $removeState = Remove-PurviewObject -Identity $name `
            -GetCommand 'Get-DlpKeywordDictionary' -RemoveCommand 'Remove-DlpKeywordDictionary' `
            -OperationName 'keyword dictionary' -SleepAction $SleepAction
        $status = switch ($removeState) {
            'deleted'   { 'deleted' }
            'pending'   { 'deleted' }   # already being removed — the desired end state is reached
            'not-found' { 'not-found' }
            default     { if ($removeState -like 'cooldown:*') { 'cooldown' } else { 'failed' } }
        }
        return New-StepResult -Status $status -RemoveState $removeState -Reason "remove '$name' -> $removeState"
    }

    # ---- create / update need resolved content --------------------------------------------------
    if (-not $Content) {
        throw "Invoke-Compl8DictionaryExecutor: step '$($Step.id)' ($action $objectRef) requires -Content (resolved dictionary terms/description) but none was supplied."
    }

    # ============================================================ BUDGET GATE (pre-mutation)
    # Mirror the old path's pre-create budget guard: a hard-cap breach REFUSES the create/update — no
    # New/Set call — and the dependent classifiers are left to the upload guard (we don't create/modify).
    $budget = Test-ContentDictionaryBudget -Dictionaries @($Content)
    if (@($budget.Errors).Count -gt 0) {
        return New-StepResult -Status 'over-budget' -Reason ("budget: " + (@($budget.Errors) -join '; ')) -BudgetErrors @($budget.Errors)
    }

    # ============================================================ existence probe (idempotency)
    # Up-front existence check drives idempotent reuse on create and locates the GUID for update.
    $existing = $null
    try {
        $found = @(Get-DlpKeywordDictionary -Identity $name -ErrorAction Stop)
        $existing = $found | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if (-not $existing -and $found.Count -gt 0) { $existing = $found | Select-Object -First 1 }
    } catch {
        # A "not found" get error means it simply does not exist yet; any other error is left to the
        # mutation call below to surface. Treat both as "no existing" for the decision.
        $existing = $null
    }

    # The provenance-stamped description (create/update both stamp it).
    $metadata = @{ Placeholder = $objectRef }
    $stampArgs = @{
        Text      = if ($Content.PSObject.Properties['description']) { [string]$Content.description } else { '' }
        Prefix    = if ($Prefix) { $Prefix } else { 'UNSCOPED' }
        Component = 'KeywordDictionary'
        Metadata  = $metadata
    }
    if ($TargetEnvironment) { $stampArgs['TargetEnvironment'] = $TargetEnvironment }
    if ($ProvenanceRegistryPath) { $stampArgs['RegistryPath'] = $ProvenanceRegistryPath }
    $stampedDescription = Add-DeploymentProvenanceStamp @stampArgs

    # The Purview-safe term bytes (UTF-16LE + BOM via a temp file, matching the old path's $toBytes).
    function ConvertTo-DictionaryFileData {
        param([string[]]$Terms)
        $tf = [System.IO.Path]::GetTempFileName()
        try {
            $Terms | Set-Content -Path $tf -Encoding Unicode
            [System.IO.File]::ReadAllBytes($tf)
        } finally {
            Remove-Item $tf -ErrorAction SilentlyContinue
        }
    }
    $terms    = @($Content.terms)
    $fileData = ConvertTo-DictionaryFileData -Terms $terms

    # ============================================================ CREATE (idempotent)
    if ($action -eq 'create') {
        if ($existing) {
            # IDEMPOTENT REUSE — mirror Sync's already-exists recovery: reuse the existing GUID, do not
            # create a duplicate, do not modify.
            $guid = if ($existing.PSObject.Properties['Identity']) { [string]$existing.Identity } else { $null }
            return New-StepResult -Status 'reused' -Guid $guid -StampedDescription $stampedDescription `
                -Reason "dictionary '$name' already exists; reused (idempotent), no duplicate created"
        }
        # NOTE: the scriptblock is passed WITHOUT .GetNewClosure(). It retains BOTH its defining
        # variable scope ($name/$stampedDescription/$fileData) AND its module affinity (Compl8.Engine),
        # so a `Mock -ModuleName Compl8.Engine New-DlpKeywordDictionary` resolves inside it. A
        # .GetNewClosure() would rebind it to a module-less clone and ESCAPE the module mock. (Same as
        # the old Sync path, which passes a bare scriptblock.)
        $result = Invoke-WithRetry -OperationName "New-Dictionary $name" -ScriptBlock {
            New-DlpKeywordDictionary -Name $name -Description $stampedDescription -FileData $fileData -Confirm:$false -ErrorAction Stop
        } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction
        $guid = if ($result -and $result.PSObject.Properties['Identity']) { [string]$result.Identity } else { $null }
        return New-StepResult -Status 'created' -Guid $guid -StampedDescription $stampedDescription `
            -Reason "created dictionary '$name' ($($terms.Count) terms)"
    }

    # ============================================================ UPDATE
    if ($action -eq 'update') {
        $guid = if ($existing -and $existing.PSObject.Properties['Identity']) { [string]$existing.Identity } else { $null }
        # Bare scriptblock (no .GetNewClosure()) — see the create path note: keeps the module mock
        # resolvable for Set-DlpKeywordDictionary.
        Invoke-WithRetry -OperationName "Set-Dictionary $name" -ScriptBlock {
            Set-DlpKeywordDictionary -Identity $name -Description $stampedDescription -FileData $fileData -Confirm:$false -ErrorAction Stop
        } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null
        return New-StepResult -Status 'updated' -Guid $guid -StampedDescription $stampedDescription `
            -Reason "updated dictionary '$name' ($($terms.Count) terms)"
    }

    throw "Invoke-Compl8DictionaryExecutor: unsupported action '$action' for step '$($Step.id)' (expected create|update|remove)."
}
