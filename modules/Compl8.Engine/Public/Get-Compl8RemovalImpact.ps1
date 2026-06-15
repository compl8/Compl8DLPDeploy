function Get-Compl8RemovalImpact {
    <#
    .SYNOPSIS
        Computes the BLAST RADIUS of removing one or more objects, by walking the reference graph
        backward (Reconciliation R3; spec §5 "removals walk the graph backward, the reference guard
        evolves from a veto into a planner"). The operator-facing preview the reconcile loop shows
        BEFORE committing a removal — so a destructive choice is informed, not blind.

    .DESCRIPTION
        Pure (no tenant calls, no I/O): given a completed Get-DeploymentReferenceGraph (R1 feeds it all
        five families, so the full dict -> sit -> rule -> policy -> label chain is present) and a set of
        removal candidates, it reports, per candidate, everything downstream that the removal touches:

          * containedSits      — for a rulePackage: the SITs it contains (packageContainsSit).
                                  for a dictionary: the SITs it feeds (dictionaryFeedsSit).
                                  for a sit: itself.
          * referencingRules   — live DLP rules that reference any in-scope SIT (sitReferencedByRule);
                                  for a dlpRule candidate: the rule itself.
          * affectedPolicies   — DLP policies those rules belong to (ruleBelongsToPolicy); for a
                                  dlpPolicy candidate: the policy itself.
          * dereferencesNeeded — the referencing rules that must be DE-REFERENCED (SIT stripped) before
                                  the removal is safe (the same set Get-Compl8PlanOrder orders ahead of
                                  the removal; here surfaced as a preview).
          * blocked            — TRUE when referencingRules is non-empty and the candidate is a
                                  sit/rulePackage/dictionary (the reference guard would veto a raw
                                  removal — the cascade/dereference must run first).

        Target resolution: rulePackage / dlpRule / dlpPolicy / dictionary candidates match a graph node
        by Name (or Identity); `sit` candidates match by Identity (the entity GUID — sits have no name in
        the graph). An unresolved candidate is returned with resolved=$false and empty sets.

    .PARAMETER Graph
        A Get-DeploymentReferenceGraph result (Nodes / Edges). Should be the COMPLETE graph (R1).

    .PARAMETER Target
        One or more removal candidates: objects with .objectType (sit|rulePackage|dlpRule|dlpPolicy|
        dictionary) and .ref (the object name; for sit, the entity GUID).

    .OUTPUTS
        One record per target: { objectType; ref; resolved; containedSits; referencingRules;
        affectedPolicies; dereferencesNeeded; blocked; summary }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Graph,
        [Parameter(Mandatory)][object[]]$Target
    )

    $nodesById = @{}
    foreach ($n in @($Graph.Nodes)) { if ($n.Id) { $nodesById[[string]$n.Id] = $n } }

    function Get-NodeName { param($NodeId, [string]$Prefix)
        $node = $nodesById[[string]$NodeId]
        if ($node -and $node.Name) { return [string]$node.Name }
        if (([string]$NodeId).StartsWith("$Prefix`:", [System.StringComparison]::OrdinalIgnoreCase)) { return ([string]$NodeId).Substring($Prefix.Length + 1) }
        [string]$NodeId
    }

    # Resolve a removal candidate to its canonical graph node Id, matching by Name OR Identity
    # (codex R3 P2: edges/indexes are keyed by node Id — `dictionary:<identity>` etc. — so a caller
    # using the documented Identity form, e.g. a dictionary GUID, must still hit the cascade. We
    # resolve ref -> node Id once, then key the whole backward walk by that canonical Id).
    function Resolve-TargetNodeId { param([string]$Type, [string]$Ref)
        $engineType = switch ($Type) {
            'rulePackage' { 'SitPackage' }
            'dictionary'  { 'KeywordDictionary' }
            'dlpRule'     { 'DlpRule' }
            'dlpPolicy'   { 'DlpPolicy' }
            'sit'         { 'SensitiveInformationType' }
            default       { $null }
        }
        if (-not $engineType) { return $null }
        $refLower = $Ref.ToLowerInvariant()
        foreach ($n in $nodesById.Values) {
            if ([string]$n.Type -ne $engineType) { continue }
            if ([string]$n.Name -eq $Ref -or [string]$n.Identity -eq $Ref -or ([string]$n.Identity).ToLowerInvariant() -eq $refLower) {
                return [string]$n.Id
            }
        }
        $null
    }

    # ---- backward edge indexes, keyed by canonical node Id (mirror Get-Compl8PlanOrder) ------------
    $sitGuidsByContainerId = @{}  # container (package OR dictionary) node Id -> [sit guid]
    foreach ($e in @($Graph.Edges | Where-Object { $_.Type -eq 'packageContainsSit' -or $_.Type -eq 'dictionaryFeedsSit' })) {
        if (-not ([string]$e.To).StartsWith('sit:', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $sitGuid     = ([string]$e.To).Substring(4).ToLowerInvariant()
        $containerId = [string]$e.From
        if (-not $sitGuidsByContainerId.ContainsKey($containerId)) { $sitGuidsByContainerId[$containerId] = [System.Collections.Generic.List[string]]::new() }
        if (-not $sitGuidsByContainerId[$containerId].Contains($sitGuid)) { $sitGuidsByContainerId[$containerId].Add($sitGuid) }
    }
    $ruleIdsBySitGuid = @{}       # sit guid -> [rule node Id]
    foreach ($e in @($Graph.Edges | Where-Object { $_.Type -eq 'sitReferencedByRule' })) {
        if (-not ([string]$e.From).StartsWith('sit:', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $sitGuid = ([string]$e.From).Substring(4).ToLowerInvariant()
        $ruleId  = [string]$e.To
        if (-not $ruleIdsBySitGuid.ContainsKey($sitGuid)) { $ruleIdsBySitGuid[$sitGuid] = [System.Collections.Generic.List[string]]::new() }
        if (-not $ruleIdsBySitGuid[$sitGuid].Contains($ruleId)) { $ruleIdsBySitGuid[$sitGuid].Add($ruleId) }
    }
    $policyIdsByRuleId = @{}      # rule node Id -> [policy node Id]
    foreach ($e in @($Graph.Edges | Where-Object { $_.Type -eq 'ruleBelongsToPolicy' })) {
        $ruleId   = [string]$e.From
        $policyId = [string]$e.To
        if (-not $policyIdsByRuleId.ContainsKey($ruleId)) { $policyIdsByRuleId[$ruleId] = [System.Collections.Generic.List[string]]::new() }
        if (-not $policyIdsByRuleId[$ruleId].Contains($policyId)) { $policyIdsByRuleId[$ruleId].Add($policyId) }
    }

    foreach ($t in @($Target)) {
        $type = [string]$t.objectType
        $ref  = [string]$t.ref
        $targetId = Resolve-TargetNodeId -Type $type -Ref $ref

        # The in-scope SITs whose removal the candidate implies (cascade keyed by canonical node Id).
        $sits = switch ($type) {
            'sit'         { @($ref.ToLowerInvariant()) }
            'rulePackage' { if ($targetId -and $sitGuidsByContainerId.ContainsKey($targetId)) { @($sitGuidsByContainerId[$targetId]) } else { @() } }
            'dictionary'  { if ($targetId -and $sitGuidsByContainerId.ContainsKey($targetId)) { @($sitGuidsByContainerId[$targetId]) } else { @() } }
            default       { @() }
        }
        $sits = @($sits | Sort-Object -Unique)

        # Referencing rules, collected as node Ids then projected to names for the operator-facing output.
        $ruleIds = [System.Collections.Generic.List[string]]::new()
        foreach ($g in $sits) { if ($ruleIdsBySitGuid.ContainsKey($g)) { foreach ($r in $ruleIdsBySitGuid[$g]) { if (-not $ruleIds.Contains($r)) { $ruleIds.Add($r) } } } }
        if ($type -eq 'dlpRule' -and $targetId -and -not $ruleIds.Contains($targetId)) { $ruleIds.Add($targetId) }
        $ruleNames = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($r in $ruleIds) { $ruleNames.Add((Get-NodeName -NodeId $r -Prefix 'dlpRule')) | Out-Null }
        $ruleList = @($ruleNames)

        $policyNames = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($r in $ruleIds) { if ($policyIdsByRuleId.ContainsKey($r)) { foreach ($p in $policyIdsByRuleId[$r]) { $policyNames.Add((Get-NodeName -NodeId $p -Prefix 'dlpPolicy')) | Out-Null } } }
        if ($type -eq 'dlpPolicy') { $policyNames.Add((Get-NodeName -NodeId ($targetId ? $targetId : "dlpPolicy:$ref") -Prefix 'dlpPolicy')) | Out-Null }
        $policyList = @($policyNames)

        # Dereferences are needed when removing a sit/package/dictionary still referenced by live rules.
        $derefTypes = @('sit', 'rulePackage', 'dictionary')
        $dereferences = if ($derefTypes -contains $type) { $ruleList } else { @() }

        [pscustomobject]@{
            objectType         = $type
            ref                = $ref
            resolved           = [bool]$targetId
            containedSits      = $sits
            referencingRules   = $ruleList
            affectedPolicies   = $policyList
            dereferencesNeeded = @($dereferences)
            blocked            = (($derefTypes -contains $type) -and $ruleList.Count -gt 0)
            summary            = "removing $type '$ref' -> $($sits.Count) sit(s), $($ruleList.Count) referencing rule(s), $($policyList.Count) affected policy(ies); $(@($dereferences).Count) dereference(s) required first."
        }
    }
}
