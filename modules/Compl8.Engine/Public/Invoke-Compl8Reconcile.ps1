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
          remainingConflicts = @(<projected name-collisions>) }); unresolvedConflicts; unclaimable }.
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

    function Remove-BucketEntry { param([string]$Bucket, [string]$Type, [string]$Ref)
        $keep = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $bk[$Bucket]) {
            if (-not ([string]$e.objectType -eq $Type -and [string]$e.ref -eq $Ref)) { $keep.Add($e) | Out-Null }
        }
        $bk[$Bucket] = $keep
    }
    # Mutate the $conflicts List IN PLACE (never reassign the variable — a child scope reassignment
    # would not propagate to the parent function scope; removing items from the shared list object does).
    function Remove-Collision { param([string]$Ref)
        $toRemove = @($conflicts | Where-Object { [string]$_.kind -eq 'name-collision' -and [string]$_.slug -eq $Ref })
        foreach ($x in $toRemove) { $conflicts.Remove($x) | Out-Null }
    }

    # Name-collision claimable candidates: foreign entries whose name matches a name-collision conflict.
    function Get-PendingClaims {
        $pending = [System.Collections.Generic.List[object]]::new()
        # Sources: name-collision conflicts (matched to their foreign entry for the objectType), and any
        # foreign/orphan entry explicitly resolved 'claim'. Dedup by composite key; claims-only here.
        $candidates = [System.Collections.Generic.List[object]]::new()
        $collisionRefs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($c in $conflicts) { if ([string]$c.kind -eq 'name-collision') { $collisionRefs.Add([string]$c.slug) | Out-Null } }
        foreach ($bn in 'foreign', 'orphan') {
            foreach ($e in $bk[$bn]) {
                $candidates.Add([pscustomobject]@{ objectType = [string]$e.objectType; ref = [string]$e.ref; bucket = $bn; isCollision = ($bn -eq 'foreign' -and $collisionRefs.Contains([string]$e.ref)) }) | Out-Null
            }
        }
        foreach ($cand in $candidates) {
            $key = "$($cand.objectType)|$($cand.ref)"
            if ($claimedKeys.Contains($key)) { continue }
            if ((Get-Res -Type $cand.objectType -Ref $cand.ref) -ne 'claim') { continue }
            $pending.Add($cand) | Out-Null
        }
        @($pending | Sort-Object @{ Expression = { $_.objectType } }, @{ Expression = { $_.ref } })
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
                # PROJECT: foreign/orphan -> ours; the collision clears; it becomes drift for the next pass.
                $claimedKeys.Add($key) | Out-Null
                Remove-BucketEntry -Bucket $cand.bucket -Type $cand.objectType -Ref $cand.ref
                Remove-Collision -Ref $cand.ref
                $bk['drift'].Add([pscustomobject]@{ objectType = $cand.objectType; ref = $cand.ref; reason = 'claimed — re-stamped ours; content reconciled by the update path' }) | Out-Null
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
            $actionable['remove'].Add([pscustomobject]@{ objectType = [string]$e.objectType; ref = [string]$e.ref; reason = 'orphan — operator-chosen removal' }) | Out-Null
            $actedEntries.Add([pscustomobject]@{ bucket = 'orphan'; objectType = [string]$e.objectType; ref = [string]$e.ref }) | Out-Null
        }

        $hasWork = ($actionable.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum -gt 0
        if (-not $hasWork) { break }   # nothing actionable and no pending claims => terminal

        $iterIndex++
        $iterAssessment = New-AssessmentObject -Workspace $Workspace -GeneratedUtc $GeneratedUtc -ResolveManifestHash $rmHash -InventoryHash $invHash
        $out = [ordered]@{}
        foreach ($name in $bucketNames) { $out[$name] = @($actionable[$name]) }
        $iterAssessment.buckets = [pscustomobject]$out
        $iterAssessment.impact  = @($impactList)
        $iterAssessment.upgradeConflicts = @($conflicts)

        $plan = New-Compl8Plan -Assessment $iterAssessment -Graph $Graph -Inventory $Inventory `
            -Workspace $Workspace -Id "$PlanIdPrefix-i$iterIndex" -GeneratedUtc $GeneratedUtc

        # Blast-radius preview for each removal in this plan (R3).
        $removeTargets = @($plan.steps | Where-Object { [string]$_.action -eq 'remove' } |
            ForEach-Object { [pscustomobject]@{ objectType = [string]$_.objectType; ref = [string]$_.objectRef } })
        $blast = if ($removeTargets.Count -gt 0) { @(Get-Compl8RemovalImpact -Graph $Graph -Target $removeTargets) } else { @() }

        $actions = @($actedEntries | ForEach-Object {
            [pscustomobject]@{ objectType = $_.objectType; ref = $_.ref; resolution = (Get-Res -Type $_.objectType -Ref $_.ref) }
        })

        $iterations.Add([pscustomobject]@{
            index              = $iterIndex
            phase              = 'reconcile'
            actions            = $actions
            plan               = $plan
            blastRadius        = $blast
            remainingConflicts = @($conflicts | Where-Object { [string]$_.kind -eq 'name-collision' })
        }) | Out-Null

        # PROJECT: every acted entry is now reconciled — clear it so the loop terminates.
        foreach ($a in $actedEntries) { Remove-BucketEntry -Bucket $a.bucket -Type $a.objectType -Ref $a.ref }
        # A reconcile pass consumes all currently-actionable work; without new claims the next pass is empty.
    }

    # ------------------------------------------------------------------ terminal status
    $unresolved = @($conflicts | Where-Object { [string]$_.kind -eq 'name-collision' })
    $status = if (@($unresolved).Count -eq 0) { 'converged' } else { 'blocked' }

    [pscustomobject]@{
        schemaVersion       = 'compl8.reconciliation/v1'
        workspace           = $Workspace
        generatedUtc        = $GeneratedUtc
        status              = $status
        iterationCount      = $iterations.Count
        iterations          = @($iterations)
        unresolvedConflicts = @($unresolved)
        unclaimable         = @($unclaimable)
    }
}
