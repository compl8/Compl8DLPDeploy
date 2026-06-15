function Compare-Compl8Plan {
    <#
    .SYNOPSIS
        Pure diff of two compl8.plan/v1 objects: added / removed / changed steps (PHASE 4B,
        Task 5).

    .DESCRIPTION
        A PURE transform (no I/O). Diffs the reference plan against the difference plan,
        matching steps by their IDENTITY = (action, objectRef) — the same (objectRef+action)
        key the plan diff is specified against (a step's id is positional and not stable
        across regenerations, so it is NOT the match key). It returns:

          Added    — steps present in the difference plan but not the reference plan.
          Removed  — steps present in the reference plan but not the difference plan.
          Changed  — steps present in BOTH (same action+objectRef) whose gate, dependsOn or
                     impact differ. A re-numbered dependsOn (different step ids for the same
                     logical dependency) is normalised away by comparing the DEPENDED-UPON
                     steps' identities, not their raw ids, so only a real wiring change shows.

        Each returned element is the difference-plan step (for Changed/Added) or the
        reference-plan step (for Removed), so the caller can render the new shape.

    .PARAMETER ReferencePlan
        The baseline plan (the "before").

    .PARAMETER DifferencePlan
        The plan to compare against the baseline (the "after").

    .OUTPUTS
        { Added = [object[]]; Removed = [object[]]; Changed = [object[]] }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$ReferencePlan,

        [Parameter(Mandatory)]
        [pscustomobject]$DifferencePlan
    )

    # A stable identity for a step: action|objectRef.
    function Get-StepKey { param($Step) "$($Step.action)|$($Step.objectRef)" }

    # Map a plan's step ids -> their identities, so dependsOn can be compared by identity (not
    # by positional id, which is not stable across regenerations).
    function Get-IdToKeyMap {
        param($Plan)
        $map = @{}
        foreach ($s in @($Plan.steps)) { if ($s.id) { $map[[string]$s.id] = (Get-StepKey -Step $s) } }
        $map
    }

    # Normalise a step's dependsOn to the SORTED set of depended-upon identities within its plan.
    function Get-DependsKeys {
        param($Step, [hashtable]$IdToKey)
        $keys = foreach ($dep in @($Step.dependsOn)) {
            if ($IdToKey.ContainsKey([string]$dep)) { $IdToKey[[string]$dep] } else { [string]$dep }
        }
        @($keys | Sort-Object) -join '||'
    }

    # Canonical gate signature (type + any ordered properties) for stable comparison.
    function Get-GateSignature {
        param($Gate)
        if ($null -eq $Gate) { return '' }
        ($Gate | ConvertTo-Json -Depth 6 -Compress)
    }

    # Canonical impact signature (sorted) for stable comparison.
    function Get-ImpactSignature {
        param($Step)
        (@($Step.impact | ForEach-Object { [string]$_ } | Sort-Object) -join '||')
    }

    $refIdToKey  = Get-IdToKeyMap -Plan $ReferencePlan
    $diffIdToKey = Get-IdToKeyMap -Plan $DifferencePlan

    $refByKey = @{}
    foreach ($s in @($ReferencePlan.steps)) { $refByKey[(Get-StepKey -Step $s)] = $s }
    $diffByKey = @{}
    foreach ($s in @($DifferencePlan.steps)) { $diffByKey[(Get-StepKey -Step $s)] = $s }

    $added   = [System.Collections.Generic.List[object]]::new()
    $removed = [System.Collections.Generic.List[object]]::new()
    $changed = [System.Collections.Generic.List[object]]::new()

    # Added / Changed: walk the difference plan.
    foreach ($s in @($DifferencePlan.steps)) {
        $key = Get-StepKey -Step $s
        if (-not $refByKey.ContainsKey($key)) {
            $added.Add($s) | Out-Null
            continue
        }
        $refStep = $refByKey[$key]
        $gateDiff    = (Get-GateSignature -Gate $refStep.gate) -ne (Get-GateSignature -Gate $s.gate)
        $dependsDiff = (Get-DependsKeys -Step $refStep -IdToKey $refIdToKey) -ne (Get-DependsKeys -Step $s -IdToKey $diffIdToKey)
        $impactDiff  = (Get-ImpactSignature -Step $refStep) -ne (Get-ImpactSignature -Step $s)
        if ($gateDiff -or $dependsDiff -or $impactDiff) { $changed.Add($s) | Out-Null }
    }

    # Removed: steps in the reference plan absent from the difference plan.
    foreach ($s in @($ReferencePlan.steps)) {
        $key = Get-StepKey -Step $s
        if (-not $diffByKey.ContainsKey($key)) { $removed.Add($s) | Out-Null }
    }

    [pscustomobject]@{
        Added   = @($added)
        Removed = @($removed)
        Changed = @($changed)
    }
}
