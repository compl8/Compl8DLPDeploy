function Get-Compl8PlanOrder {
    <#
    .SYNOPSIS
        Pure graph-derived ordering of plan steps + de-reference step generation (PHASE 4B,
        Task 4). Turns an assessment + reference graph into an ORDERED list of compl8.plan/v1
        steps.

    .DESCRIPTION
        A PURE transform — no I/O, no tenant call (arch design §5; D3/D7). Given an assessment
        (the Invoke-Compl8Assess output) and a reference graph (Get-DeploymentReferenceGraph),
        it returns the steps in dependency order:

          * Creates / updates / repack-moves walk the dependency graph FORWARD:
              dictionaries -> rule packages (and their sits) -> labels -> label policies ->
              DLP rules / DLP policies / auto-label policies.
            A step depends on the steps that produce the objects it references (its package, its
            feeding dictionary, the package a referencing rule reads), so a fresh object never
            lands before what it needs.

          * Removals walk the graph BACKWARD: a thing is torn down only after everything that
            depends on it. Of two remove steps, the dependant is removed first.

          * For a `remove` of a classifier / SIT that is STILL referenced by live DLP rules,
            it GENERATES one `dereference` step per referencing rule, ordered BEFORE the
            removal (D5 — the reference guard's veto becomes generated de-reference work). The
            referencing rules are derived from the GRAPH's sitReferencedByRule edges (the same
            shape the guard's References output carries) and/or the assessment's impact[] — NOT
            by calling the tenant-reading guard. The guard remains the apply-time backstop.

          * A `propagation` gate ({ type='propagation'; notBeforeOffsetHours=4 }) is attached to
            a rule / auto-label step ONLY when that step depends on a rule package that is
            CREATED / UPDATED in THIS SAME plan (a freshly-changed SIT needs propagation time
            before rules that read it are safe). A rule depending on an UNCHANGED package gets
            no propagation gate.

          * A dependency CYCLE throws a clear error (the topological sort cannot order it).

        DETERMINISM (Get-Date / Get-Random are banned here): step ids are derived from a
        deterministic, stable sort of the work items (object type tier, then ref) — `s01`,
        `s02`, … in final emission order. Same inputs => identical ordered step list.

    .PARAMETER Assessment
        A compl8.assessment/v1 object (New-AssessmentObject shape). Only the actionable buckets
        (create / update-in-place / repack-move / remove) and impact[] drive ordering; orphan /
        foreign / drift-of-non-rule objects are not turned into steps here (foreign is never
        touched; orphan is human-review; a drift dlpRule IS re-applied so it carries a step).

    .PARAMETER Graph
        A Get-DeploymentReferenceGraph result (Nodes / Edges / Summary). Edges consulted:
        packageContainsSit, dictionaryFeedsSit, sitReferencedByRule, ruleBelongsToPolicy,
        policyTargetsLabel.

    .OUTPUTS
        An ordered array of plan-step objects ({ id; action; objectType; objectRef; dependsOn;
        impact; gate }) as produced by Add-PlanStep — ready to drop into a New-PlanObject plan.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Assessment,

        [Parameter(Mandatory)]
        [pscustomobject]$Graph
    )

    # ------------------------------------------------------------------ object-type ordering tier
    # Forward create/update order. Lower tier = built first. Removals invert this via the
    # backward edge walk + dependsOn (a dependant is removed before its dependency).
    $typeTier = @{
        'dictionary'      = 1
        'rulePackage'     = 2
        'sit'             = 2
        'label'           = 3
        'labelPolicy'     = 4
        'dlpRule'         = 5
        'dlpPolicy'       = 5
        'autoLabelPolicy' = 5
        'tenant'          = 0
    }

    # ------------------------------------------------------------------ graph indexes
    $nodesById = @{}
    foreach ($node in @($Graph.Nodes)) { if ($node.Id) { $nodesById[[string]$node.Id] = $node } }

    # sit entity guid -> owning rule-package node name (packageContainsSit: pkg -> sit).
    $packageNameBySitGuid = @{}
    foreach ($edge in @($Graph.Edges | Where-Object { $_.Type -eq 'packageContainsSit' })) {
        if (-not ([string]$edge.To).StartsWith('sit:', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $sitGuid = ([string]$edge.To).Substring(4).ToLowerInvariant()
        $pkgNode = $nodesById[[string]$edge.From]
        $pkgName = if ($pkgNode -and $pkgNode.Name) { [string]$pkgNode.Name }
                   elseif (([string]$edge.From).StartsWith('sitPackage:', [System.StringComparison]::OrdinalIgnoreCase)) { ([string]$edge.From).Substring(11) }
                   else { [string]$edge.From }
        $packageNameBySitGuid[$sitGuid] = $pkgName
    }

    # sit entity guid -> @(referencing rule names) (sitReferencedByRule: sit -> rule).
    $rulesBySitGuid = @{}
    foreach ($edge in @($Graph.Edges | Where-Object { $_.Type -eq 'sitReferencedByRule' })) {
        if (-not ([string]$edge.From).StartsWith('sit:', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $sitGuid = ([string]$edge.From).Substring(4).ToLowerInvariant()
        $ruleNode = $nodesById[[string]$edge.To]
        $ruleName = if ($ruleNode -and $ruleNode.Name) { [string]$ruleNode.Name }
                    elseif (([string]$edge.To).StartsWith('dlpRule:', [System.StringComparison]::OrdinalIgnoreCase)) { ([string]$edge.To).Substring(8) }
                    else { [string]$edge.To }
        if (-not $rulesBySitGuid.ContainsKey($sitGuid)) { $rulesBySitGuid[$sitGuid] = [System.Collections.Generic.List[string]]::new() }
        if (-not $rulesBySitGuid[$sitGuid].Contains($ruleName)) { $rulesBySitGuid[$sitGuid].Add($ruleName) }
    }

    # rule name -> the rule-package name(s) it reads (rule depends on those packages' steps).
    $packagesByRuleName = @{}
    foreach ($sitGuid in $rulesBySitGuid.Keys) {
        $pkgName = if ($packageNameBySitGuid.ContainsKey($sitGuid)) { $packageNameBySitGuid[$sitGuid] } else { $null }
        if (-not $pkgName) { continue }
        foreach ($ruleName in $rulesBySitGuid[$sitGuid]) {
            if (-not $packagesByRuleName.ContainsKey($ruleName)) { $packagesByRuleName[$ruleName] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }
            $packagesByRuleName[$ruleName].Add($pkgName) | Out-Null
        }
    }

    # dictionary placeholder/guid -> sit guids it feeds, and the inverse package names.
    $packagesByDictionary = @{}
    foreach ($edge in @($Graph.Edges | Where-Object { $_.Type -eq 'dictionaryFeedsSit' })) {
        if (-not ([string]$edge.To).StartsWith('sit:', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $sitGuid = ([string]$edge.To).Substring(4).ToLowerInvariant()
        $dictNode = $nodesById[[string]$edge.From]
        $dictKey = if ($dictNode -and $dictNode.Identity) { [string]$dictNode.Identity }
                   elseif (([string]$edge.From).StartsWith('dictionary:', [System.StringComparison]::OrdinalIgnoreCase)) { ([string]$edge.From).Substring(11) }
                   else { [string]$edge.From }
        $pkgName = if ($packageNameBySitGuid.ContainsKey($sitGuid)) { $packageNameBySitGuid[$sitGuid] } else { $null }
        if ($pkgName) {
            if (-not $packagesByDictionary.ContainsKey($pkgName)) { $packagesByDictionary[$pkgName] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }
            $packagesByDictionary[$pkgName].Add($dictKey) | Out-Null
        }
    }

    # ------------------------------------------------------------------ collect actionable work
    # One work item per actionable assessment entry, plus the generated dereference items.
    # Each item: Action / ObjectType / Ref / Tier / Direction (forward|backward) / Key (graph
    # node id when resolvable) / DependsRefs (object refs it must follow, resolved to step ids
    # after numbering) / Gate.
    $items = [System.Collections.Generic.List[object]]::new()
    $createdPackages = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    function Add-WorkItem {
        param(
            [string]$Action, [string]$ObjectType, [string]$Ref, [string]$Direction = 'forward',
            [string[]]$DependsRefs = @(), [object[]]$Impact = @(), [pscustomobject]$Gate = $null
        )
        $items.Add([pscustomobject]@{
            Action      = $Action
            ObjectType  = $ObjectType
            Ref         = $Ref
            Tier        = [int]$typeTier[$ObjectType]
            Direction   = $Direction
            DependsRefs = @($DependsRefs)
            Impact      = @($Impact)
            Gate        = $Gate
        }) | Out-Null
    }

    # Map an assessment bucket name to a plan action.
    $bucketAction = @{
        'create'          = 'create'
        'update-in-place' = 'update'
        'repack-move'     = 'repack-move'
        'remove'          = 'remove'
    }

    # First pass: record which rule packages are created/updated this plan (propagation source).
    foreach ($bucketName in 'create', 'update-in-place', 'repack-move') {
        foreach ($entry in @($Assessment.buckets.$bucketName)) {
            if ($entry.objectType -eq 'rulePackage') { $createdPackages.Add([string]$entry.ref) | Out-Null }
        }
    }

    # impact[] indexed by objectRef (for de-reference fallback when the graph lacks edges).
    $impactByRef = @{}
    foreach ($im in @($Assessment.impact)) {
        if ($im.objectRef) { $impactByRef[[string]$im.objectRef] = @($im.affects) }
    }

    # ---- forward work (create / update-in-place / repack-move) -------------------------------
    foreach ($bucketName in 'create', 'update-in-place', 'repack-move') {
        foreach ($entry in @($Assessment.buckets.$bucketName)) {
            $action = $bucketAction[$bucketName]
            $type   = [string]$entry.objectType
            $ref    = [string]$entry.ref
            $deps   = [System.Collections.Generic.List[string]]::new()
            $gate   = $null
            $impact = @()

            switch ($type) {
                'rulePackage' {
                    # A package depends on the dictionaries it references that are also being created.
                    if ($packagesByDictionary.ContainsKey($ref)) {
                        foreach ($d in @($packagesByDictionary[$ref] | Sort-Object)) { $deps.Add($d) | Out-Null }
                    }
                }
                'dlpRule' {
                    # A rule depends on the package(s) it reads. A propagation gate is added only
                    # when one of those packages is created/updated in THIS plan.
                    if ($packagesByRuleName.ContainsKey($ref)) {
                        $changedDep = $false
                        foreach ($p in @($packagesByRuleName[$ref] | Sort-Object)) {
                            $deps.Add($p) | Out-Null
                            if ($createdPackages.Contains($p)) { $changedDep = $true }
                        }
                        if ($changedDep) {
                            $gate = [pscustomobject]@{ type = 'propagation'; notBeforeOffsetHours = 4 }
                        }
                    }
                    if ($impactByRef.ContainsKey($ref)) { $impact = @($impactByRef[$ref]) }
                }
                'autoLabelPolicy' {
                    if ($packagesByRuleName.ContainsKey($ref)) {
                        $changedDep = $false
                        foreach ($p in @($packagesByRuleName[$ref] | Sort-Object)) {
                            $deps.Add($p) | Out-Null
                            if ($createdPackages.Contains($p)) { $changedDep = $true }
                        }
                        if ($changedDep) {
                            $gate = [pscustomobject]@{ type = 'propagation'; notBeforeOffsetHours = 4 }
                        }
                    }
                }
            }
            Add-WorkItem -Action $action -ObjectType $type -Ref $ref -Direction 'forward' `
                -DependsRefs @($deps) -Impact $impact -Gate $gate
        }
    }

    # A `drift` dlpRule is re-applied (ours, changed out-of-band) — it carries a rule step too,
    # with the same dependency / propagation treatment as a forward rule.
    foreach ($entry in @($Assessment.buckets.drift)) {
        if ([string]$entry.objectType -ne 'dlpRule') { continue }
        $ref  = [string]$entry.ref
        $deps = [System.Collections.Generic.List[string]]::new()
        $gate = $null
        $impact = @()
        if ($packagesByRuleName.ContainsKey($ref)) {
            $changedDep = $false
            foreach ($p in @($packagesByRuleName[$ref] | Sort-Object)) {
                $deps.Add($p) | Out-Null
                if ($createdPackages.Contains($p)) { $changedDep = $true }
            }
            if ($changedDep) { $gate = [pscustomobject]@{ type = 'propagation'; notBeforeOffsetHours = 4 } }
        }
        if ($impactByRef.ContainsKey($ref)) { $impact = @($impactByRef[$ref]) }
        Add-WorkItem -Action 'update' -ObjectType 'dlpRule' -Ref $ref -Direction 'forward' `
            -DependsRefs @($deps) -Impact $impact -Gate $gate
    }

    # ---- removal work (backward) + generated dereference steps (D5) --------------------------
    # For each remove of a sit/rulePackage still referenced by live rules, generate a
    # dereference step per referencing rule; the remove depends on those dereference steps.
    foreach ($entry in @($Assessment.buckets.remove)) {
        $type = [string]$entry.objectType
        $ref  = [string]$entry.ref
        $removeDeps = [System.Collections.Generic.List[string]]::new()

        # Resolve the referencing rules for this removal, graph-first then impact[] fallback.
        $referencingRules = [System.Collections.Generic.List[string]]::new()
        $guid = if ($entry.PSObject.Properties['identity'] -and $entry.identity) { ([string]$entry.identity).ToLowerInvariant() }
                elseif ($entry.PSObject.Properties['entityId'] -and $entry.entityId) { ([string]$entry.entityId).ToLowerInvariant() }
                else { $null }
        if ($guid -and $rulesBySitGuid.ContainsKey($guid)) {
            foreach ($rn in @($rulesBySitGuid[$guid] | Sort-Object)) { if (-not $referencingRules.Contains($rn)) { $referencingRules.Add($rn) } }
        }
        if ($referencingRules.Count -eq 0 -and $impactByRef.ContainsKey($ref)) {
            # impact affects are formatted 'dlp-rule: <name>' — strip the prefix to the rule name.
            foreach ($aff in @($impactByRef[$ref] | Sort-Object)) {
                $rn = ([string]$aff) -replace '^\s*dlp-rule:\s*', ''
                if ($rn -and -not $referencingRules.Contains($rn)) { $referencingRules.Add($rn) }
            }
        }

        foreach ($rn in @($referencingRules)) {
            # The dereference step must precede the remove; the remove depends on it.
            Add-WorkItem -Action 'dereference' -ObjectType 'dlpRule' -Ref $rn -Direction 'backward' -DependsRefs @()
            $removeDeps.Add("dereference:$rn") | Out-Null
        }

        Add-WorkItem -Action 'remove' -ObjectType $type -Ref $ref -Direction 'backward' -DependsRefs @($removeDeps)
    }

    if ($items.Count -eq 0) { return @() }

    # ------------------------------------------------------------------ assign deterministic keys
    # Each item gets a stable key for dependency wiring. Forward items key by 'type:ref'; the
    # generated dereference items key by 'dereference:ref' (so a remove can name them, and so a
    # dereference is distinct from a forward rule step on the same rule).
    foreach ($it in $items) {
        $key = if ($it.Action -eq 'dereference') { "dereference:$($it.Ref)" } else { "$($it.ObjectType):$($it.Ref)" }
        $it | Add-Member -NotePropertyName Key -NotePropertyValue $key -Force
    }
    $itemByKey = @{}
    foreach ($it in $items) { if (-not $itemByKey.ContainsKey($it.Key)) { $itemByKey[$it.Key] = $it } }

    # ------------------------------------------------------------------ build dependency edges
    # Resolve each item's DependsRefs (object refs / dereference keys) to concrete item keys that
    # actually exist as steps in THIS plan. A forward dependency on a ref means "follow that
    # step if it is in the plan"; a missing ref (unchanged dependency) yields no edge.
    # predecessors[key] = set of keys that must come BEFORE key.
    $predecessors = @{}
    foreach ($it in $items) { $predecessors[$it.Key] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal) }

    foreach ($it in $items) {
        foreach ($depRef in @($it.DependsRefs)) {
            if ([string]::IsNullOrWhiteSpace($depRef)) { continue }
            # A dereference dependency is named explicitly ('dereference:<rule>').
            if (([string]$depRef).StartsWith('dereference:', [System.StringComparison]::Ordinal)) {
                if ($itemByKey.ContainsKey($depRef)) { $predecessors[$it.Key].Add($depRef) | Out-Null }
                continue
            }
            # Otherwise the dep is an object ref; it may resolve to any object-type key present.
            $candidate = @($items | Where-Object { $_.Action -ne 'dereference' -and $_.Ref -eq $depRef })
            foreach ($c in $candidate) {
                if ($c.Key -ne $it.Key) { $predecessors[$it.Key].Add($c.Key) | Out-Null }
            }
        }
    }

    # ------------------------------------------------------------------ topological sort
    # Deterministic Kahn's algorithm: among the ready items, always pick the one with the
    # smallest (Tier, Ref) — forward items by ascending tier, then ref; removals/dereferences are
    # pulled in once their dependants are placed. This yields the dictionaries->packages->rules
    # forward order and the dependant-before-dependency removal order, byte-stably.
    $remaining = [System.Collections.Generic.List[object]]::new()
    foreach ($it in $items) { $remaining.Add($it) | Out-Null }
    $placed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $ordered = [System.Collections.Generic.List[object]]::new()

    while ($remaining.Count -gt 0) {
        # Ready = all predecessors already placed.
        $ready = @($remaining | Where-Object {
            $allMet = $true
            foreach ($p in $predecessors[$_.Key]) { if (-not $placed.Contains($p)) { $allMet = $false; break } }
            $allMet
        })
        if ($ready.Count -eq 0) {
            $stuck = (@($remaining | ForEach-Object { $_.Key }) | Sort-Object) -join ', '
            throw "Get-Compl8PlanOrder: dependency cycle detected among plan steps ($stuck) — cannot produce a topological order."
        }
        $next = @($ready | Sort-Object @{ Expression = { $_.Tier } }, @{ Expression = { $_.Action } }, @{ Expression = { $_.Ref } })[0]
        $ordered.Add($next) | Out-Null
        $placed.Add($next.Key) | Out-Null
        $remaining.Remove($next) | Out-Null
    }

    # ------------------------------------------------------------------ number + build steps
    $keyToId = @{}
    for ($i = 0; $i -lt $ordered.Count; $i++) {
        $keyToId[$ordered[$i].Key] = ('s{0:D2}' -f ($i + 1))
    }

    $plan = New-PlanObject -Workspace ([string]$Assessment.workspace) -Id 'plan-order'
    foreach ($it in $ordered) {
        $depIds = @(@($predecessors[$it.Key]) | ForEach-Object { $keyToId[$_] } | Where-Object { $_ } | Sort-Object)
        $plan = Add-PlanStep -Plan $plan -Id $keyToId[$it.Key] -Action $it.Action `
            -ObjectType $it.ObjectType -ObjectRef $it.Ref -DependsOn $depIds `
            -Impact @($it.Impact) -Gate $it.Gate
    }

    return @($plan.steps)
}
