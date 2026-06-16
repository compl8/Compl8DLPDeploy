function Invoke-Compl8Reconcile {
    <#
    .SYNOPSIS
        The ITERATIVE reconciliation verb (Reconciliation R4; spec §5 / plan D5): turns a one-shot
        assessment + an operator RESOLUTION SET into an ordered, multi-iteration reconciliation that
        converges a real migration (e.g. the compl8.dev old-deployment squatting desired names) instead
        of silently no-op'ing on it.

    .DESCRIPTION
        PURE and DETERMINISTIC (no tenant call, no I/O; Get-Date / Get-Random are BANNED — the plan ids
        and clock are injected). It models the spec §5 loop:

            assess -> present conflicts + blast-radius -> apply chosen resolutions
                   -> re-assess (PROJECTED) -> re-plan -> repeat -> converge

        WHY PROJECTION (not live re-fetch): apply is the only tenant-mutating layer, and a reconcile
        run must be reproducible from an explicit resolution INPUT SET (not interactive mid-apply). So
        between iterations the assessment is advanced DETERMINISTICALLY from the chosen resolutions —
        the same delta a live re-assess would observe after those resolutions apply. The real apply
        (Invoke-Compl8Apply on each emitted plan) still re-checks freshness + fingerprint live.

        TWO KINDS OF WORK, ordered per D5 ("claims now; removals/updates queued"):

          * CLAIMS go FIRST (R2; non-destructive). A name-collision conflict — a desired object whose
            name is held by a NOT-OURS (foreign) actual — silently never deploys (the engine neither
            overwrites a foreign object nor creates a duplicate). The operator resolution `claim` ADOPTS
            it by re-stamping provenance (Comment), content untouched. Claiming flips foreign -> ours;
            the PROJECTED re-assess then buckets it as `drift`, so the next (reconcile) iteration updates
            its content via the ordinary path. Claims are emitted as a claim-only plan in their own
            iteration so they land before any destructive teardown.

          * The RECONCILE iteration then builds the bucketed change-set via New-Compl8Plan over the
            resolution-FILTERED assessment — so it inherits ALL safety machinery unchanged (D7):
            graph-derived dependency order, the R3 backward removal cascade (dereference steps for every
            referencing rule), the snapshotBeforeDestroy Step 0.5, and propagation / externalRefs gates.
            For each removal it also emits a Get-Compl8RemovalImpact BLAST-RADIUS preview so a destructive
            choice is informed, not blind.

        RESOLUTION SET. -Resolutions is a list of { objectType; ref; resolution }. Supported resolutions
        by source bucket / conflict:
          * name-collision (foreign object squatting a desired name): `claim` (adopt -> drift -> update)
            or `leave` (accept the blockage). A foreign object is NEVER removed directly
            (opacity-as-safety, spec §8) — to retire one, claim it first, then remove in a later run.
          * orphan (ours, unexpected): `remove` (-> backward cascade), `claim` (adopt -> drift -> update),
            or `leave`/`keep` (no action).
          * create / update-in-place / repack-move / remove / drift (the desired delta): acted by default;
            `leave` drops the entry from this run.
        A resolution is matched to an object by the composite key "objectType|ref". A name-collision's
        objectType is recovered from its foreign bucket entry (the conflict record carries only the name).
        Only dlpRule / dlpPolicy are claimable (Get-Compl8EngineSchemaEnums ClaimableObjectTypes); a
        `claim` of any other type is reported in unclaimable[] and the conflict stays unresolved.

        TERMINATION + STATUS. The loop runs until no claim is pending AND the bucketed reconcile produces
        no steps (bounded by -MaxIterations as a backstop). status='converged' when no name-collision is
        left unresolved; otherwise status='blocked' and unresolvedConflicts[] lists the still-colliding
        desired objects (deliberately left, or with no/unclaimable resolution). A deliberate `leave` on a
        drift/orphan is NOT a blockage — only an unresolved name-collision is.

    .PARAMETER Assessment
        A compl8.assessment/v1 object (Invoke-Compl8Assess / New-AssessmentObject shape) — the starting
        state. Its buckets + upgradeConflicts + impact[] drive the loop; inputs.* hashes flow to plans.

    .PARAMETER Graph
        A Get-DeploymentReferenceGraph result. Passed to New-Compl8Plan (ordering/cascade) and to
        Get-Compl8RemovalImpact (blast radius). Should be the COMPLETE graph (R1).

    .PARAMETER Inventory
        Optional parsed inventory — forwarded to New-Compl8Plan for package -> contained-sit impact roll-up.

    .PARAMETER Resolutions
        The operator's resolution set: objects with .objectType, .ref, .resolution (claim|remove|update|
        leave|keep). Absent = act by default for desired-delta buckets; a name-collision with no
        resolution stays unresolved (blocked).

    .PARAMETER Workspace
        Logical workspace name written to the reconciliation + each plan.

    .PARAMETER PlanIdPrefix
        Deterministic plan-id stem; each iteration's plan id is "<PlanIdPrefix>-i<n>" (Get-Date/Get-Random
        banned, so the caller stamps it for reproducibility).

    .PARAMETER GeneratedUtc
        Stamp written verbatim to the reconciliation and every emitted plan (Get-Date is NOT called).

    .PARAMETER MaxIterations
        Backstop cap on the loop (default 12). A correct projection converges in 2–3 iterations; the cap
        guards against a non-converging resolution set rather than being a normal exit.

    .OUTPUTS
        A compl8.reconciliation/v1 object:
        { schemaVersion; workspace; generatedUtc; status; iterationCount; iterations = @({ index; phase;
          actions = @({objectType; ref; resolution}); plan = <compl8.plan/v1>; blastRadius = @(<R3 records>);
          remainingConflicts = @(<projected name-collisions>) }); iterationCapHit; unresolvedConflicts;
          pendingWork; unreconciled; unclaimable }. status is 'converged' ONLY when unresolvedConflicts,
        unreconciled AND pendingWork are all empty — otherwise 'blocked'. pendingWork lists actionable
        entries the loop never planned (e.g. -MaxIterations truncated it; iterationCapHit flags that
        case). unreconciled lists entries the planner could not turn into a step (e.g. non-dlpRule drift).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Assessment,
        [Parameter(Mandatory)][pscustomobject]$Graph,
        [pscustomobject]$Inventory,
        [object[]]$Resolutions = @(),
        [Parameter(Mandatory)][string]$Workspace,
        [Parameter(Mandatory)][string]$PlanIdPrefix,
        [string]$GeneratedUtc,
        [int]$MaxIterations = 12
    )

    $bucketNames = (Get-Compl8EngineSchemaEnums).Buckets
    $claimable   = (Get-Compl8EngineSchemaEnums).ClaimableObjectTypes

    # ------------------------------------------------------------------ resolution lookup (type|ref)
    $resByKey = @{}
    foreach ($r in @($Resolutions)) {
        if (-not $r) { continue }
        $k = "$([string]$r.objectType)|$([string]$r.ref)"
        if (-not $resByKey.ContainsKey($k)) { $resByKey[$k] = ([string]$r.resolution).ToLowerInvariant() }
    }
    function Get-Res { param([string]$Type, [string]$Ref)
        $k = "$Type|$Ref"
        if ($resByKey.ContainsKey($k)) { return $resByKey[$k] }
        $null
    }

    # ------------------------------------------------------------------ mutable working state
    # Buckets copied into editable lists; conflicts into an editable list. Each iteration rebuilds a
    # fresh assessment object from this state (so New-Compl8Plan sees the PROJECTED buckets).
    $bk = @{}
    foreach ($name in $bucketNames) {
        $bk[$name] = [System.Collections.Generic.List[object]]::new()
        foreach ($e in @($Assessment.buckets.$name)) { if ($e) { $bk[$name].Add($e) | Out-Null } }
    }
    $conflicts = [System.Collections.Generic.List[object]]::new()
    foreach ($c in @($Assessment.upgradeConflicts)) { if ($c) { $conflicts.Add($c) | Out-Null } }
    $impactList = @($Assessment.impact)
    $rmHash  = [string]$Assessment.inputs.resolveManifest
    $invHash = [string]$Assessment.inputs.inventory

    $claimedKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $unclaimable = [System.Collections.Generic.List[object]]::new()
    # Entries reconcile WANTED to act on but the planner produced NO step for (codex R4 P1): e.g.
    # non-dlpRule `drift` (dlpPolicy/sit/dictionary/autoLabelPolicy), which Get-Compl8PlanOrder does
    # not yet turn into an update step. These must be SURFACED — never silently cleared — or the run
    # would report `converged` while the tenant object is unchanged (false convergence).
    $unreconciled = [System.Collections.Generic.List[object]]::new()
    function Add-Unreconciled { param([string]$Bucket, [string]$Type, [string]$Ref)
        $key = "$Type|$Ref"
        if (-not @($unreconciled | Where-Object { "$([string]$_.objectType)|$([string]$_.ref)" -eq $key })) {
            $unreconciled.Add([pscustomobject]@{
                objectType = $Type; ref = $Ref; bucket = $Bucket
                reason = "no plan step produced — the current planner cannot reconcile this state (e.g. non-dlpRule drift); surfaced rather than falsely reported reconciled"
            }) | Out-Null
        }
    }

    function Remove-BucketEntry { param([string]$Bucket, [string]$Type, [string]$Ref)
        $keep = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $bk[$Bucket]) {
            if (-not ([string]$e.objectType -eq $Type -and [string]$e.ref -eq $Ref)) { $keep.Add($e) | Out-Null }
        }
        $bk[$Bucket] = $keep
    }
    # A name-collision's objectType is not a field on the conflict record — assess encodes it in the
    # detail text ("desired <type> '<name>' is blocked …"). Recover it so collision handling can be
    # type-scoped (two foreign objects of DIFFERENT types can share a name => two distinct collisions).
    function Get-ConflictType { param($Conflict)
        $m = [regex]::Match([string]$Conflict.detail, "^desired\s+(?<t>[A-Za-z]+)\s+'")
        if ($m.Success) { return $m.Groups['t'].Value }
        $null
    }
    # Mutate the $conflicts List IN PLACE (never reassign the variable — a child scope reassignment would
    # not propagate to the parent function scope; removing items from the shared list object does). SCOPED
    # to (type, ref): claiming a dlpRule 'Foo' must NOT clear a dlpPolicy 'Foo' collision (codex R4 P2) —
    # else the unclaimed one vanishes from unresolvedConflicts and the run can falsely report converged. A
    # conflict whose type can't be parsed falls back to slug-only match (assess always writes the detail).
    function Remove-Collision { param([string]$Type, [string]$Ref)
        $toRemove = @($conflicts | Where-Object {
            [string]$_.kind -eq 'name-collision' -and [string]$_.slug -eq $Ref -and
            (($null -eq (Get-ConflictType $_)) -or ((Get-ConflictType $_) -eq $Type))
        })
        foreach ($x in $toRemove) { $conflicts.Remove($x) | Out-Null }
    }
    # Does a name-collision exist for THIS (type, ref)? Keyed by (parsed conflict type, slug) — same
    # matching as Remove-Collision (codex R4 P2) — so a foreign dlpRule 'Foo' is NOT treated as colliding
    # just because a dlpPolicy 'Foo' collides. A collision means a DESIRED counterpart exists, which is
    # the precondition for projecting a claim into drift (then updating it).
    function Test-IsCollision { param([string]$Type, [string]$Ref)
        foreach ($c in $conflicts) {
            if ([string]$c.kind -ne 'name-collision' -or [string]$c.slug -ne $Ref) { continue }
            $ct = Get-ConflictType $c
            if ($null -eq $ct -or $ct -eq $Type) { return $true }
        }
        $false
    }

    # Claim candidates: FOREIGN entries only (codex R4 P2). Claiming ADOPTS a NOT-ours object by
    # re-stamping provenance — an orphan is ALREADY ours, so claim is a no-op for it (handled below as
    # unclaimable). `isCollision` = this foreign object squats a DESIRED name (a name-collision), so a
    # desired counterpart exists and claiming it can be reconciled by the update path (project -> drift).
    # A foreign object NOT squatting a desired name, claimed, is adopted only (no desired content to
    # update toward — projecting it to drift would emit an update step the executor can't fulfil).
    function Get-PendingClaims {
        $pending = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $bk['foreign']) {
            $cand = [pscustomobject]@{ objectType = [string]$e.objectType; ref = [string]$e.ref; bucket = 'foreign'; isCollision = (Test-IsCollision -Type ([string]$e.objectType) -Ref ([string]$e.ref)) }
            $key = "$($cand.objectType)|$($cand.ref)"
            if ($claimedKeys.Contains($key)) { continue }
            if ((Get-Res -Type $cand.objectType -Ref $cand.ref) -ne 'claim') { continue }
            $pending.Add($cand) | Out-Null
        }
        @($pending | Sort-Object @{ Expression = { $_.objectType } }, @{ Expression = { $_.ref } })
    }

    # An orphan resolved 'claim' is a no-op (it is already ours) — surface it so it is not silently
    # ignored. It is left in the orphan bucket; a 'remove'/'keep' resolution is the meaningful choice.
    foreach ($e in @($bk['orphan'])) {
        if ((Get-Res -Type ([string]$e.objectType) -Ref ([string]$e.ref)) -eq 'claim') {
            $unclaimable.Add([pscustomobject]@{ objectType = [string]$e.objectType; ref = [string]$e.ref; reason = 'orphan is already ours — claim adopts a foreign object; use remove or keep' }) | Out-Null
        }
    }

    # ------------------------------------------------------------------ the loop
    $iterations = [System.Collections.Generic.List[object]]::new()
    $iterIndex = 0

    while ($iterIndex -lt $MaxIterations) {
        $pendingClaims = @(Get-PendingClaims)

        if ($pendingClaims.Count -gt 0) {
            # -------- CLAIM iteration (D5: claims first) ------------------------------------------
            $iterIndex++
            $plan = New-PlanObject -Workspace $Workspace -Id "$PlanIdPrefix-i$iterIndex" -GeneratedUtc $GeneratedUtc `
                -ResolveManifestHash $rmHash -InventoryHash $invHash -AssessmentHash ''
            $actions = [System.Collections.Generic.List[object]]::new()
            $n = 0
            foreach ($cand in $pendingClaims) {
                $key = "$($cand.objectType)|$($cand.ref)"
                if ($claimable -notcontains $cand.objectType) {
                    # A claim resolution on a non-claimable type cannot be honoured — record it and leave
                    # the conflict unresolved (the operator must pick remove/leave, or claim a claimable).
                    $unclaimable.Add([pscustomobject]@{ objectType = $cand.objectType; ref = $cand.ref; reason = "objectType '$($cand.objectType)' is not claimable (only $($claimable -join ', '))" }) | Out-Null
                    $claimedKeys.Add($key) | Out-Null   # don't reconsider it as a pending claim
                    continue
                }
                $n++
                $plan = Add-PlanStep -Plan $plan -Id ('c{0:D2}' -f $n) -Action 'claim' `
                    -ObjectType $cand.objectType -ObjectRef $cand.ref -DependsOn @() -Impact @() -Gate $null
                $actions.Add([pscustomobject]@{ objectType = $cand.objectType; ref = $cand.ref; resolution = 'claim' }) | Out-Null
                # PROJECT: the claimed foreign object is now ours; the collision clears. Project it to
                # `drift` for the next (update) pass ONLY when a DESIRED counterpart exists (it squatted a
                # desired name). A foreign object with no desired counterpart is adopted ONLY — projecting
                # it to drift would queue an update with no resolved content to apply (codex R4 P2).
                $claimedKeys.Add($key) | Out-Null
                Remove-BucketEntry -Bucket $cand.bucket -Type $cand.objectType -Ref $cand.ref
                Remove-Collision -Type $cand.objectType -Ref $cand.ref
                if ($cand.isCollision) {
                    $bk['drift'].Add([pscustomobject]@{ objectType = $cand.objectType; ref = $cand.ref; reason = 'claimed — re-stamped ours; content reconciled by the update path' }) | Out-Null
                }
            }

            if ($n -eq 0) {
                # Every pending claim was unclaimable — no claim step emitted; do not record an empty
                # iteration, and fall through to the reconcile phase / termination.
                continue
            }

            $check = Test-PlanSchema -Plan $plan
            if (-not $check.Valid) { throw "Invoke-Compl8Reconcile: claim plan invalid: $((@($check.Errors)) -join '; ')" }

            $iterations.Add([pscustomobject]@{
                index              = $iterIndex
                phase              = 'claim'
                actions            = @($actions)
                plan               = $plan
                blastRadius        = @()
                remainingConflicts = @($conflicts | Where-Object { [string]$_.kind -eq 'name-collision' })
            }) | Out-Null
            continue
        }

        # -------- RECONCILE iteration (bucketed change-set) ---------------------------------------
        # Apply resolutions to produce the ACTIONABLE assessment: orphan->remove when chosen, drop
        # 'leave'/'keep' and foreign, pass the desired delta through. Then plan it (gates + cascade).
        $actionable = @{}
        foreach ($name in $bucketNames) { $actionable[$name] = [System.Collections.Generic.List[object]]::new() }

        $actedEntries = [System.Collections.Generic.List[object]]::new()   # (bucket,type,ref) to clear on success

        foreach ($bn in 'create', 'update-in-place', 'repack-move', 'remove', 'drift') {
            foreach ($e in $bk[$bn]) {
                $res = Get-Res -Type ([string]$e.objectType) -Ref ([string]$e.ref)
                if ($res -in 'leave', 'keep') { continue }
                $actionable[$bn].Add($e) | Out-Null
                $actedEntries.Add([pscustomobject]@{ bucket = $bn; objectType = [string]$e.objectType; ref = [string]$e.ref }) | Out-Null
            }
        }
        foreach ($e in $bk['orphan']) {
            if ((Get-Res -Type ([string]$e.objectType) -Ref ([string]$e.ref)) -ne 'remove') { continue }
            # FORWARD the original entry's properties (only override the reason) — Get-Compl8PlanOrder
            # reads identity/entityId off a removed sit to resolve it in the graph and generate the
            # dereference cascade + blast radius. Dropping those fields would strip the safety cascade
            # for a still-referenced classifier (codex R4 P2).
            $rec = [ordered]@{}
            foreach ($p in $e.PSObject.Properties) { $rec[$p.Name] = $p.Value }
            $rec['reason'] = 'orphan — operator-chosen removal'
            $actionable['remove'].Add([pscustomobject]$rec) | Out-Null
            $actedEntries.Add([pscustomobject]@{ bucket = 'orphan'; objectType = [string]$e.objectType; ref = [string]$e.ref }) | Out-Null
        }

        $hasWork = ($actionable.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum -gt 0
        if (-not $hasWork) { break }   # nothing actionable and no pending claims => terminal

        # Plan against a CANDIDATE index; only commit the increment once we know the plan made progress.
        $candidateIndex = $iterIndex + 1
        $iterAssessment = New-AssessmentObject -Workspace $Workspace -GeneratedUtc $GeneratedUtc -ResolveManifestHash $rmHash -InventoryHash $invHash
        $out = [ordered]@{}
        foreach ($name in $bucketNames) { $out[$name] = @($actionable[$name]) }
        $iterAssessment.buckets = [pscustomobject]$out
        $iterAssessment.impact  = @($impactList)
        $iterAssessment.upgradeConflicts = @($conflicts)

        $plan = New-Compl8Plan -Assessment $iterAssessment -Graph $Graph -Inventory $Inventory `
            -Workspace $Workspace -Id "$PlanIdPrefix-i$candidateIndex" -GeneratedUtc $GeneratedUtc

        # Which acted entries ACTUALLY became a plan step? The planner is SELECTIVE (e.g. it turns only
        # dlpRule drift into an update step), so map each non-generated step back to its (type|ref).
        # Generated dereference + the snapshot 0.5 are NOT object steps — exclude them.
        $plannedActionByKey = @{}
        foreach ($s in @($plan.steps)) {
            if ([string]$s.action -in 'snapshot', 'dereference') { continue }
            $plannedActionByKey["$([string]$s.objectType)|$([string]$s.objectRef)"] = [string]$s.action
        }
        $stepBacked  = @($actedEntries | Where-Object { $plannedActionByKey.ContainsKey("$($_.objectType)|$($_.ref)") })
        $unplannable = @($actedEntries | Where-Object { -not $plannedActionByKey.ContainsKey("$($_.objectType)|$($_.ref)") })

        if (@($stepBacked).Count -eq 0) {
            # No actionable entry produced a plan step — the loop can make no further progress. Surface
            # them as unreconciled (NOT converged) and stop WITHOUT recording an empty iteration. Clear
            # them from the working buckets so the terminal scan doesn't double-count (codex R4 P1).
            foreach ($e in $actedEntries) { Add-Unreconciled -Bucket $e.bucket -Type $e.objectType -Ref $e.ref; Remove-BucketEntry -Bucket $e.bucket -Type $e.objectType -Ref $e.ref }
            break
        }

        $iterIndex = $candidateIndex

        # Blast-radius preview for each removal in this plan (R3).
        $removeTargets = @($plan.steps | Where-Object { [string]$_.action -eq 'remove' } |
            ForEach-Object { [pscustomobject]@{ objectType = [string]$_.objectType; ref = [string]$_.objectRef } })
        $blast = if ($removeTargets.Count -gt 0) { @(Get-Compl8RemovalImpact -Graph $Graph -Target $removeTargets) } else { @() }

        # Actions reflect what the plan WILL do (the planned step action per object), not the raw request.
        $actions = @($stepBacked | ForEach-Object {
            [pscustomobject]@{ objectType = $_.objectType; ref = $_.ref; resolution = $plannedActionByKey["$($_.objectType)|$($_.ref)"] }
        })

        $iterations.Add([pscustomobject]@{
            index              = $iterIndex
            phase              = 'reconcile'
            actions            = $actions
            plan               = $plan
            blastRadius        = $blast
            remainingConflicts = @($conflicts | Where-Object { [string]$_.kind -eq 'name-collision' })
        }) | Out-Null

        # PROJECT: a step-backed entry is now reconciled — clear it. An entry we wanted to act on but the
        # planner emitted NO step for is UNPLANNABLE: surface it (unreconciled) and clear it too, so it is
        # neither silently dropped (false convergence) nor re-tried forever.
        foreach ($e in $stepBacked)  { Remove-BucketEntry -Bucket $e.bucket -Type $e.objectType -Ref $e.ref }
        foreach ($e in $unplannable) { Add-Unreconciled -Bucket $e.bucket -Type $e.objectType -Ref $e.ref; Remove-BucketEntry -Bucket $e.bucket -Type $e.objectType -Ref $e.ref }
    }

    # ------------------------------------------------------------------ remaining actionable work
    # Whatever is STILL actionable after the loop — a claim the cap never reached, or claimed->drift work
    # left unplanned when -MaxIterations truncated the loop mid-reconcile (codex R4 P2). 'leave'/'keep'
    # entries are deliberate skips, NOT pending. This is what stops a CAPPED run reporting false success.
    $pending = [System.Collections.Generic.List[object]]::new()
    foreach ($cand in @(Get-PendingClaims)) { $pending.Add([pscustomobject]@{ objectType = $cand.objectType; ref = $cand.ref; bucket = 'foreign'; wouldBe = 'claim' }) | Out-Null }
    foreach ($bn in 'create', 'update-in-place', 'repack-move', 'remove', 'drift') {
        foreach ($e in $bk[$bn]) {
            if ((Get-Res -Type ([string]$e.objectType) -Ref ([string]$e.ref)) -in 'leave', 'keep') { continue }
            $pending.Add([pscustomobject]@{ objectType = [string]$e.objectType; ref = [string]$e.ref; bucket = $bn; wouldBe = $bn }) | Out-Null
        }
    }
    foreach ($e in $bk['orphan']) {
        if ((Get-Res -Type ([string]$e.objectType) -Ref ([string]$e.ref)) -eq 'remove') {
            $pending.Add([pscustomobject]@{ objectType = [string]$e.objectType; ref = [string]$e.ref; bucket = 'orphan'; wouldBe = 'remove' }) | Out-Null
        }
    }
    $iterationCapHit = ($iterIndex -ge $MaxIterations) -and ($pending.Count -gt 0)

    # ------------------------------------------------------------------ terminal status
    # Converged ONLY when nothing is left: no unresolved name-collision, nothing unreconciled (a planner
    # gap), AND no actionable work still pending (the cap-truncation guard). Any of these makes the run
    # `blocked` so the operator is never told "done" while work remains.
    $unresolved = @($conflicts | Where-Object { [string]$_.kind -eq 'name-collision' })
    $status = if (@($unresolved).Count -eq 0 -and @($unreconciled).Count -eq 0 -and $pending.Count -eq 0) { 'converged' } else { 'blocked' }

    [pscustomobject]@{
        schemaVersion       = 'compl8.reconciliation/v1'
        workspace           = $Workspace
        generatedUtc        = $GeneratedUtc
        status              = $status
        iterationCount      = $iterations.Count
        iterationCapHit     = $iterationCapHit
        iterations          = @($iterations)
        unresolvedConflicts = @($unresolved)
        pendingWork         = @($pending)
        unreconciled        = @($unreconciled)
        unclaimable         = @($unclaimable)
    }
}
