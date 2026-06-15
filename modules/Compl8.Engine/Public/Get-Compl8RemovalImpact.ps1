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

    # ---- backward edge indexes (mirror Get-Compl8PlanOrder) ----------------------------------------
    $sitsByPackageName = @{}      # package name      -> [sit guid]
    foreach ($e in @($Graph.Edges | Where-Object { $_.Type -eq 'packageContainsSit' })) {
        if (-not ([string]$e.To).StartsWith('sit:', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $sitGuid = ([string]$e.To).Substring(4).ToLowerInvariant()
        $pkgName = Get-NodeName -NodeId $e.From -Prefix 'sitPackage'
        if (-not $sitsByPackageName.ContainsKey($pkgName)) { $sitsByPackageName[$pkgName] = [System.Collections.Generic.List[string]]::new() }
        if (-not $sitsByPackageName[$pkgName].Contains($sitGuid)) { $sitsByPackageName[$pkgName].Add($sitGuid) }
    }
    $sitsByDictKey = @{}          # dictionary identity/key -> [sit guid]
    foreach ($e in @($Graph.Edges | Where-Object { $_.Type -eq 'dictionaryFeedsSit' })) {
        if (-not ([string]$e.To).StartsWith('sit:', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $sitGuid = ([string]$e.To).Substring(4).ToLowerInvariant()
        $dictKey = Get-NodeName -NodeId $e.From -Prefix 'dictionary'
        if (-not $sitsByDictKey.ContainsKey($dictKey)) { $sitsByDictKey[$dictKey] = [System.Collections.Generic.List[string]]::new() }
        if (-not $sitsByDictKey[$dictKey].Contains($sitGuid)) { $sitsByDictKey[$dictKey].Add($sitGuid) }
    }
    $rulesBySitGuid = @{}         # sit guid -> [rule name]
    foreach ($e in @($Graph.Edges | Where-Object { $_.Type -eq 'sitReferencedByRule' })) {
        if (-not ([string]$e.From).StartsWith('sit:', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $sitGuid = ([string]$e.From).Substring(4).ToLowerInvariant()
        $ruleName = Get-NodeName -NodeId $e.To -Prefix 'dlpRule'
        if (-not $rulesBySitGuid.ContainsKey($sitGuid)) { $rulesBySitGuid[$sitGuid] = [System.Collections.Generic.List[string]]::new() }
        if (-not $rulesBySitGuid[$sitGuid].Contains($ruleName)) { $rulesBySitGuid[$sitGuid].Add($ruleName) }
    }
    $policiesByRuleName = @{}     # rule name -> [policy name]
    foreach ($e in @($Graph.Edges | Where-Object { $_.Type -eq 'ruleBelongsToPolicy' })) {
        $ruleName   = Get-NodeName -NodeId $e.From -Prefix 'dlpRule'
        $policyName = Get-NodeName -NodeId $e.To   -Prefix 'dlpPolicy'
        if (-not $policiesByRuleName.ContainsKey($ruleName)) { $policiesByRuleName[$ruleName] = [System.Collections.Generic.List[string]]::new() }
        if (-not $policiesByRuleName[$ruleName].Contains($policyName)) { $policiesByRuleName[$ruleName].Add($policyName) }
    }

    foreach ($t in @($Target)) {
        $type = [string]$t.objectType
        $ref  = [string]$t.ref

        # The in-scope SITs whose removal the candidate implies.
        $sits = switch ($type) {
            'sit'         { @($ref.ToLowerInvariant()) }
            'rulePackage' { if ($sitsByPackageName.ContainsKey($ref)) { @($sitsByPackageName[$ref]) } else { @() } }
            'dictionary'  { if ($sitsByDictKey.ContainsKey($ref))     { @($sitsByDictKey[$ref]) }     else { @() } }
            default       { @() }
        }
        $sits = @($sits | Sort-Object -Unique)

        $rules = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($g in $sits) { if ($rulesBySitGuid.ContainsKey($g)) { foreach ($r in $rulesBySitGuid[$g]) { $rules.Add($r) | Out-Null } } }
        if ($type -eq 'dlpRule') { $rules.Add($ref) | Out-Null }
        $ruleList = @($rules)

        $policies = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($r in $ruleList) { if ($policiesByRuleName.ContainsKey($r)) { foreach ($p in $policiesByRuleName[$r]) { $policies.Add($p) | Out-Null } } }
        if ($type -eq 'dlpPolicy') { $policies.Add($ref) | Out-Null }

        # Dereferences are needed when removing a sit/package/dictionary still referenced by live rules.
        $derefTypes = @('sit', 'rulePackage', 'dictionary')
        $dereferences = if ($derefTypes -contains $type) { $ruleList } else { @() }
        # A node we couldn't locate (and which contributed no sits/rules) is unresolved.
        $resolved = $nodesById.Values | Where-Object {
            (($type -eq 'rulePackage' -and $_.Type -eq 'SitPackage') -or
             ($type -eq 'dictionary'  -and $_.Type -eq 'KeywordDictionary') -or
             ($type -eq 'dlpRule'     -and $_.Type -eq 'DlpRule') -or
             ($type -eq 'dlpPolicy'   -and $_.Type -eq 'DlpPolicy') -or
             ($type -eq 'sit'         -and $_.Type -eq 'SensitiveInformationType')) -and
            ([string]$_.Name -eq $ref -or [string]$_.Identity -eq $ref -or [string]$_.Identity -eq $ref.ToLowerInvariant())
        } | Select-Object -First 1

        [pscustomobject]@{
            objectType         = $type
            ref                = $ref
            resolved           = [bool]$resolved
            containedSits      = $sits
            referencingRules   = $ruleList
            affectedPolicies   = @($policies)
            dereferencesNeeded = @($dereferences)
            blocked            = (($derefTypes -contains $type) -and $ruleList.Count -gt 0)
            summary            = "removing $type '$ref' -> $($sits.Count) sit(s), $($ruleList.Count) referencing rule(s), $(@($policies).Count) affected policy(ies); $(@($dereferences).Count) dereference(s) required first."
        }
    }
}
