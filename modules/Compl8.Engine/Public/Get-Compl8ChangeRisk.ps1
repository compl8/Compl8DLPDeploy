function Get-Compl8ChangeRisk {
    <#
    .SYNOPSIS
        The strategist: evaluate the RISK and follow-on of a proposed change, describing its effect on
        INTERNAL (ours) and EXTERNAL (not-ours) rules and classifiers, and recommend proceed / review /
        hand-back. Pure (no I/O).

    .DESCRIPTION
        Extends opacity-as-safety from "never TOUCH a foreign object" to "never AUTO-APPLY a change whose
        blast radius REACHES a foreign object". Given a change, the reference graph, and an ownership map,
        it walks the DOWNSTREAM blast radius (reusing R3 Get-Compl8RemovalImpact — the dependent rules and,
        for a dictionary, the SITs it feeds), splits the affected objects into internal/external by
        ownership, scores risk, and decides whether the engine may auto-apply it or must HAND IT BACK for a
        human decision.

        WHAT IS "EXTERNAL IMPACT": foreign objects DOWNSTREAM of the change (e.g. a not-ours DLP rule that
        references the classifier you are removing/updating) — NOT the action's own target. So an
        operator-chosen `claim` of a foreign object is not self-blocking; only collateral damage to other
        not-ours objects is.

        OWNERSHIP (conservative): the -OwnershipMap maps an object identifier (rule name, or sit entity
        GUID) to whether it is ours. An affected object that is ABSENT from the map is treated as FOREIGN —
        the engine never auto-applies a change against something it cannot confirm is ours.

        HAND-BACK POLICY (operator-set): an action is handed back (recommendation='hand-back',
        handBack=$true — the deploy must withhold it and seek explicit approval) when EITHER it has any
        external (not-ours) impact, OR its total affected cascade exceeds -CascadeThreshold ("too complex
        to auto-apply"). Otherwise an internal destructive change is 'review' (proceed with the normal
        snapshot/gate machinery) and an impact-free change is 'proceed'.

        RISK LEVEL: critical = destructive AND reaches foreign; high = reaches foreign (non-destructive) or
        too-complex cascade; medium = internal destructive cascade; low = internal-only non-destructive /
        no blast radius. REVERSIBLE is $false only for a destructive change that reaches foreign (we cannot
        restore damage to objects we do not manage); internal destructive changes are reversible via the
        snapshot path.

    .PARAMETER Change
        The proposed change: { objectType; action (create|update|remove|repack-move|dereference|claim);
        ref; identity (optional — a sit's entity GUID) }.

    .PARAMETER Graph
        A Get-DeploymentReferenceGraph result spanning ours AND foreign objects (the inventory's full rule
        set), so foreign downstream consumers are visible.

    .PARAMETER OwnershipMap
        Hashtable: object identifier (rule name / sit entity GUID, case-insensitive) -> [bool] ours.
        Built by the caller from the inventory's `ours` flags. Absent entries => foreign (conservative).

    .PARAMETER CascadeThreshold
        Maximum affected-object count an internal-only change may have and still auto-apply; above it the
        change is handed back as too complex (default 25).

    .OUTPUTS
        [pscustomobject] { objectType; action; ref; riskLevel; reversible; recommendation; handBack;
        internalImpact = @({objectType; ref; effect}); externalImpact = @({...}); followOn = @(string);
        rationale }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Change,
        [Parameter(Mandatory)][pscustomobject]$Graph,
        [hashtable]$OwnershipMap = @{},
        [int]$CascadeThreshold = 25
    )

    $objectType  = [string]$Change.objectType
    $action      = [string]$Change.action
    $ref         = [string]$Change.ref
    $destructive = $action -in 'remove', 'dereference'

    function Test-Ours { param([string]$Key)
        if ([string]::IsNullOrWhiteSpace($Key)) { return $false }
        if ($OwnershipMap.ContainsKey($Key)) { return [bool]$OwnershipMap[$Key] }
        $lower = $Key.ToLowerInvariant()
        if ($OwnershipMap.ContainsKey($lower)) { return [bool]$OwnershipMap[$lower] }
        return $false   # unknown ownership => foreign (never auto-apply against the unconfirmed)
    }

    # Only a DAMAGING change to a CLASSIFIER (sit / rule package / dictionary) ripples into the rules that
    # read it — that is where a change can reach a foreign consumer. A create/claim is ADDITIVE (it harms
    # no existing consumer), and a rule/policy change affects only its own policy (name-collisions, missing
    # references and removal cascades for rules are handled by other gates). Those carry no downstream
    # blast-radius hand-back: low / proceed.
    $classifier = $objectType -in 'sit', 'rulePackage', 'dictionary'
    if (-not ($classifier -and $destructive) -and -not ($classifier -and $action -in 'update', 'repack-move')) {
        return [pscustomobject]@{
            objectType = $objectType; action = $action; ref = $ref
            riskLevel = 'low'; reversible = $true; recommendation = 'proceed'; handBack = $false
            internalImpact = @(); externalImpact = @(); followOn = @()
            rationale = "$action $objectType '$ref': additive or self-contained — no downstream blast radius (other gates cover name-collisions / missing references)."
        }
    }

    # Downstream blast radius via R3. For a sit target use its entity GUID; everything else by ref.
    $impactRef = if ($objectType -eq 'sit' -and $Change.PSObject.Properties['identity'] -and $Change.identity) { [string]$Change.identity } else { $ref }
    $impact = @(Get-Compl8RemovalImpact -Graph $Graph -Target @([pscustomobject]@{ objectType = $objectType; ref = $impactRef }))[0]

    $internal = [System.Collections.Generic.List[object]]::new()
    $external = [System.Collections.Generic.List[object]]::new()

    $ruleEffect = if ($destructive) { 'detection lost — the classifier it references is being removed/dereferenced' }
                  else { 'detection changes — the classifier it references is being updated' }
    foreach ($rn in @($impact.referencingRules)) {
        if ([string]$rn -eq $ref) { continue }   # the target itself is not "downstream impact"
        $rec = [pscustomobject]@{ objectType = 'dlpRule'; ref = [string]$rn; effect = $ruleEffect }
        if (Test-Ours -Key ([string]$rn)) { $internal.Add($rec) | Out-Null } else { $external.Add($rec) | Out-Null }
    }
    # A dictionary change also affects the SITs (classifiers) it feeds.
    if ($objectType -eq 'dictionary') {
        $sitEffect = if ($destructive) { 'loses a keyword dictionary it depends on' } else { 'a keyword dictionary it depends on is changing' }
        foreach ($g in @($impact.containedSits)) {
            $rec = [pscustomobject]@{ objectType = 'sit'; ref = [string]$g; effect = $sitEffect }
            if (Test-Ours -Key ([string]$g)) { $internal.Add($rec) | Out-Null } else { $external.Add($rec) | Out-Null }
        }
    }

    $affectedCount = $internal.Count + $external.Count
    $hasExternal   = $external.Count -gt 0
    $tooComplex    = $affectedCount -gt $CascadeThreshold
    # A DICTIONARY is a shared object whose FULL consumer set (the sits it feeds) cannot be reliably
    # enumerated from recorded tenant state — the inventory records no dictionary->sit edges for sits no
    # longer in the desired packages (only their entity GUIDs). So the engine cannot PROVE a dictionary
    # remove/update does not reach a foreign consumer; it conservatively hands every one back for review
    # (codex). The visible (current-sit) impact is still reported for transparency.
    $dictUnverifiable = ($objectType -eq 'dictionary')
    $handBack      = $hasExternal -or $tooComplex -or $dictUnverifiable

    $riskLevel =
        if ($hasExternal -and $destructive) { 'critical' }
        elseif ($hasExternal)               { 'high' }
        elseif ($tooComplex)                { 'high' }
        elseif ($dictUnverifiable)          { 'high' }
        elseif ($destructive -and $internal.Count -gt 0) { 'medium' }
        else { 'low' }

    $recommendation = if ($handBack) { 'hand-back' } elseif ($riskLevel -in 'medium', 'high') { 'review' } else { 'proceed' }
    # Irreversible only when we would destructively damage something not-ours (no snapshot of ours can
    # restore a foreign object); internal destructive changes are reversible via snapshot-before-destroy.
    $reversible = -not ($destructive -and $hasExternal)

    # follow-on consequences (ordered, human-readable).
    $followOn = [System.Collections.Generic.List[string]]::new()
    foreach ($e in @($external)) { $followOn.Add(("EXTERNAL {0} '{1}': {2}" -f $e.objectType, $e.ref, $e.effect)) | Out-Null }
    foreach ($e in @($internal)) { $followOn.Add(("internal {0} '{1}': {2}" -f $e.objectType, $e.ref, $e.effect)) | Out-Null }
    if ($destructive -and @($impact.dereferencesNeeded).Count -gt 0) {
        $followOn.Add(("dereference first: {0}" -f (@($impact.dereferencesNeeded) -join ', '))) | Out-Null
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add("$action $objectType '$ref':") | Out-Null
    if ($hasExternal) {
        $parts.Add(("reaches {0} EXTERNAL (not-ours) object(s) [{1}] we do not manage — auto-apply withheld; hand back for human approval." -f $external.Count, (@($external | ForEach-Object { $_.ref }) -join ', '))) | Out-Null
    }
    if ($internal.Count -gt 0) { $parts.Add(("affects {0} internal (ours) object(s)." -f $internal.Count)) | Out-Null }
    if ($tooComplex) { $parts.Add(("cascade of {0} affected objects exceeds the auto-apply threshold ({1}) — too complex/large to auto-apply; hand back." -f $affectedCount, $CascadeThreshold)) | Out-Null }
    if ($dictUnverifiable) { $parts.Add("a dictionary's full consumer set (the sits it feeds) cannot be enumerated from recorded tenant state, so foreign reach cannot be ruled out — hand back for review.") | Out-Null }
    if (-not $hasExternal -and -not $dictUnverifiable -and $affectedCount -eq 0) { $parts.Add('no downstream blast radius.') | Out-Null }

    [pscustomobject]@{
        objectType     = $objectType
        action         = $action
        ref            = $ref
        riskLevel      = $riskLevel
        reversible     = $reversible
        recommendation = $recommendation
        handBack       = $handBack
        internalImpact = @($internal)
        externalImpact = @($external)
        followOn       = @($followOn)
        rationale      = ($parts -join ' ')
    }
}
