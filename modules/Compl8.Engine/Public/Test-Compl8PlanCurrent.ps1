function Test-Compl8PlanCurrent {
    <#
    .SYNOPSIS
        Content-hash freshness check for a compl8.plan/v1: is the plan still valid for the
        live desired/actual inputs? (PHASE 4B, Task 5.)

    .DESCRIPTION
        Generalises the refit "<= 24h" staleness rule from AGE to CONTENT HASH (arch design
        §5 — "a plan is stale if resolveManifest or inventory no longer matches"). A plan is
        a pure function of its inputs, so a hash mismatch means it must be regenerated, never
        patched.

        Compares the plan's recorded inputs.resolveManifest / inputs.inventory hashes against
        the CURRENT input hashes. Returns $true only when BOTH match. With -Detail it returns
        { Current; Stale } where Stale names which input(s) drifted ('resolveManifest' and/or
        'inventory'), mirroring Test-ResolveManifestCurrent in Compl8.Content.

        Pure: no I/O. The caller supplies the current hashes (recomputed from the live
        resolve manifest + inventory, e.g. via the assessment's inputs), so this function
        never reads the tenant or the workspace.

    .PARAMETER Plan
        A compl8.plan/v1 object (its inputs.resolveManifest / inputs.inventory are the baseline).

    .PARAMETER ResolveManifestHash
        The CURRENT resolve-manifest input hash (e.g. 'sha256:...').

    .PARAMETER InventoryHash
        The CURRENT inventory input hash (e.g. 'sha256:...').

    .PARAMETER Detail
        Return { Current; Stale } instead of a bare boolean; Stale lists the drifted inputs.

    .OUTPUTS
        [bool] (default) or { Current = [bool]; Stale = [string[]] } with -Detail.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan,

        [Parameter(Mandatory)]
        [string]$ResolveManifestHash,

        [Parameter(Mandatory)]
        [string]$InventoryHash,

        [switch]$Detail
    )

    $stale = @()
    $planResolve   = [string]$Plan.inputs.resolveManifest
    $planInventory = [string]$Plan.inputs.inventory

    if ($planResolve -ne $ResolveManifestHash) { $stale += 'resolveManifest' }
    if ($planInventory -ne $InventoryHash)     { $stale += 'inventory' }

    if ($Detail) {
        return [pscustomobject]@{ Current = ($stale.Count -eq 0); Stale = @($stale) }
    }
    $stale.Count -eq 0
}
