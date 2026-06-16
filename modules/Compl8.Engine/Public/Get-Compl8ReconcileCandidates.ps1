function Get-Compl8ReconcileCandidates {
    <#
    .SYNOPSIS
        Derives the WALKABLE reconciliation set from an assessment (Reconciliation R5; Stage-5 D6 — the
        TUI walks, the Engine decides what is walkable). Returns the ordered list of resolvable items the
        operator steps through, each carrying its allowed resolutions and (for a destructive candidate)
        the R3 removal blast-radius preview.

    .DESCRIPTION
        Pure (no I/O). It enumerates the two operator-resolvable situations an assessment surfaces:

          * NAME-COLLISIONS (upgradeConflicts kind='name-collision') — a desired object whose name is held
            by a foreign object. Resolvable by `claim` (adopt it, then the update path reconciles it) or
            `leave` (accept the blockage). The objectType is recovered from the conflict detail text
            ("desired <type> '<name>' …"). A foreign object is never removed directly (opacity-as-safety),
            so `remove` is NOT offered here — claim first, then remove in a later run.
          * ORPHANS (the `orphan` bucket — ours, unexpected) — resolvable by `remove` (with the R3 backward
            cascade), `keep` (leave it for review), or `claim` (a no-op: an orphan is already ours, so the
            reconcile verb records it unclaimable — offered only for completeness). Each orphan carries its
            Get-Compl8RemovalImpact blast-radius so the operator sees the cascade BEFORE choosing remove.

        The TUI prompts the operator WITHIN each item's allowedResolutions and feeds the chosen
        { objectType; ref; resolution } set to Invoke-Compl8Reconcile. All reconciliation intelligence
        (ordering, claims-first, cascade, convergence) stays in the Engine; the Surface only renders + asks.

    .PARAMETER Assessment
        A compl8.assessment/v1 object (Invoke-Compl8Assess output).

    .PARAMETER Graph
        A Get-DeploymentReferenceGraph result, used to compute each orphan's removal blast-radius (R3).

    .PARAMETER Inventory
        Optional parsed inventory (the same actual/inventory.json assess consumed). Used ONLY to recover a
        sit's entity GUID by name: an assessment's orphan/remove sit bucket entry carries no identity, but
        Get-Compl8RemovalImpact keys a `sit` target by its entity GUID — so without this an orphaned SIT's
        blast-radius would resolve EMPTY and the operator would lose the dereference warning before
        choosing `remove`. Absent, sit candidates fall back to the (name) ref and may not resolve.

    .OUTPUTS
        Zero or more candidate records (deterministically ordered by kind then objectType then ref):
        { kind ('name-collision'|'orphan'); objectType; ref; detail; allowedResolutions = @(...);
          blastRadius = <Get-Compl8RemovalImpact record or $null> }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Assessment,
        [Parameter(Mandatory)][pscustomobject]$Graph,
        [pscustomobject]$Inventory
    )

    $candidates = [System.Collections.Generic.List[object]]::new()

    # sit display name -> entity GUID (from inventory), so an orphan sit (whose bucket entry carries no
    # identity) still resolves its GUID-keyed removal blast-radius (codex R5).
    $sitGuidByName = @{}
    if ($Inventory -and $Inventory.objects -and $Inventory.objects.sits) {
        foreach ($s in @($Inventory.objects.sits)) {
            if ($s.name -and $s.identity) { $sitGuidByName[[string]$s.name] = ([string]$s.identity).ToLowerInvariant() }
        }
    }

    # --- name-collisions -> claim / leave ---------------------------------------------------------
    foreach ($c in @($Assessment.upgradeConflicts)) {
        if ([string]$c.kind -ne 'name-collision') { continue }
        # Recover the objectType from the detail ("desired <type> '<name>' …"); fall back to '' if absent.
        $m = [regex]::Match([string]$c.detail, "^desired\s+(?<t>[A-Za-z]+)\s+'")
        $type = if ($m.Success) { $m.Groups['t'].Value } else { '' }
        $candidates.Add([pscustomobject]@{
            kind               = 'name-collision'
            objectType         = $type
            ref                = [string]$c.slug
            detail             = [string]$c.detail
            allowedResolutions = @('claim', 'leave')
            blastRadius        = $null
        }) | Out-Null
    }

    # --- orphans -> remove / keep / claim, each with a blast-radius preview ------------------------
    foreach ($e in @($Assessment.buckets.orphan)) {
        $type = [string]$e.objectType
        $ref  = [string]$e.ref
        # Blast-radius target: a sit is keyed by its entity GUID (identity), everything else by ref. The
        # orphan bucket entry rarely carries the GUID, so fall back to the inventory name->GUID map.
        $impactRef = if ($type -eq 'sit' -and $e.PSObject.Properties['identity'] -and $e.identity) { [string]$e.identity }
                     elseif ($type -eq 'sit' -and $e.PSObject.Properties['entityId'] -and $e.entityId) { [string]$e.entityId }
                     elseif ($type -eq 'sit' -and $sitGuidByName.ContainsKey($ref)) { $sitGuidByName[$ref] }
                     else { $ref }
        $impact = $null
        try { $impact = @(Get-Compl8RemovalImpact -Graph $Graph -Target @([pscustomobject]@{ objectType = $type; ref = $impactRef }))[0] } catch { $impact = $null }
        $candidates.Add([pscustomobject]@{
            kind               = 'orphan'
            objectType         = $type
            ref                = $ref
            detail             = if ($e.PSObject.Properties['reason']) { [string]$e.reason } else { 'ours, unexpected' }
            allowedResolutions = @('remove', 'keep', 'claim')
            blastRadius        = $impact
        }) | Out-Null
    }

    @($candidates | Sort-Object @{ Expression = { $_.kind } }, @{ Expression = { $_.objectType } }, @{ Expression = { $_.ref } })
}
