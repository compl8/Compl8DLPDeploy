function Get-RulePackageAssignment {
    <#
    .SYNOPSIS
        Deterministic, churn-minimising assignment of desired items to rule packages.
    .DESCRIPTION
        Pure decision function (no I/O, no tenant calls) implementing the repack contract of
        the 2026-06-10 architecture design §4: same inputs → identical bins; between repacks
        items stay in their current package unless limits force movement.

        Algorithm:
          1. Prior assignments are sticky — a slug keeps its package while it fits.
          2. A package pushed over a limit by release growth evicts its NEWEST slugs
             (last in item order) until it fits; evicted slugs re-enter placement.
          3. Unplaced slugs fill existing packages in ascending ordinal order, then open
             new packages named <Prefix>-<Tier>-NN.
          4. Items beyond MaxRulePackagesPerTenant are returned in Dropped — never thrown
             (mirrors the iterative-fit drop behaviour of the legacy refit planner).

        Sizes are projections (wrapper overhead + fragment bytes); the composed package is
        re-validated against the hard limits at resolve time. Adoption of an existing tenant
        layout = pass the slug→package mapping as -Prior on the first resolve (the deploy
        registry alone cannot express membership, so the caller derives the mapping from
        deployed XML + release entityIds).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Items,

        [hashtable]$Prior,

        [Parameter(Mandatory)]
        [string]$Prefix,

        [Parameter(Mandatory)]
        [string]$Tier,

        [int]$WrapperOverheadBytes = 600
    )

    $limits = Get-DeploymentLimits
    $maxEntities = $limits.MaxSitsPerRulePackage
    $maxBytes = $limits.PreferredRulePackageBytes
    $maxPackages = $limits.MaxRulePackagesPerTenant
    $maxPackages = $maxPackages - $limits.ReservedManualPackages   # reserve slot(s) for manual additions

    # Package order: parse '-NN[a]' ordinal suffix; unparseable names sort last by name.
    function Get-PackageSortKey {
        param([string]$Name)
        if ($Name -match '-(\d+)([a-z]?)$') {
            '{0:d6}{1}' -f [int]$Matches[1], $(if ($Matches[2]) { $Matches[2] } else { ' ' })
        } else {
            "zzzzzz$Name"
        }
    }

    $groups = @{}    # name → List[item]
    $itemIndex = @{} # slug → original position (stable eviction/placement order)
    for ($i = 0; $i -lt $Items.Count; $i++) { $itemIndex[$Items[$i].Slug] = $i }

    # Pass 1 — sticky priors.
    $unplaced = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Items) {
        $priorName = if ($Prior) { $Prior[$item.Slug] } else { $null }
        if ($priorName) {
            if (-not $groups.ContainsKey($priorName)) {
                $groups[$priorName] = [System.Collections.Generic.List[object]]::new()
            }
            $groups[$priorName].Add($item)
        } else {
            $unplaced.Add($item)
        }
    }

    # Pass 2 — overflow eviction: newest (highest original index) leave first.
    $evicted = [System.Collections.Generic.List[object]]::new()
    foreach ($name in ($groups.Keys | Sort-Object { Get-PackageSortKey $_ })) {
        $group = $groups[$name]
        while ($group.Count -gt 0) {
            $projected = $WrapperOverheadBytes + (($group | Measure-Object SizeBytes -Sum).Sum)
            if ($group.Count -le $maxEntities -and $projected -le $maxBytes) { break }
            $newest = $group | Sort-Object { $itemIndex[$_.Slug] } | Select-Object -Last 1
            $group.Remove($newest) | Out-Null
            $evicted.Add($newest)
        }
    }
    foreach ($item in ($evicted | Sort-Object { $itemIndex[$_.Slug] })) { $unplaced.Add($item) }

    # Pass 2b — reservation cap: if prior groups already fill or exceed $maxPackages, evict
    # entire excess packages (highest ordinal first) so at most $maxPackages groups remain
    # before Pass 3 opens any new packages.
    $nonEmptyNames = @($groups.Keys | Where-Object { $groups[$_].Count -gt 0 } | Sort-Object { Get-PackageSortKey $_ } -Descending)
    while ($nonEmptyNames.Count -gt $maxPackages) {
        $excessName = $nonEmptyNames[0]
        foreach ($item in $groups[$excessName]) { $unplaced.Add($item) }
        $groups.Remove($excessName)
        $nonEmptyNames = @($groups.Keys | Where-Object { $groups[$_].Count -gt 0 } | Sort-Object { Get-PackageSortKey $_ } -Descending)
    }

    # Pass 3 — placement: fill ascending-ordinal headroom, then open new packages.
    $dropped = [System.Collections.Generic.List[object]]::new()
    # FFD: largest items claim space first; ties broken by original order for determinism.
    foreach ($item in ($unplaced | Sort-Object @{ Expression = { [int]$_.SizeBytes }; Descending = $true }, @{ Expression = { $itemIndex[$_.Slug] } })) {
        $placed = $false
        foreach ($name in ($groups.Keys | Sort-Object { Get-PackageSortKey $_ })) {
            $group = $groups[$name]
            $projected = $WrapperOverheadBytes + (($group | Measure-Object SizeBytes -Sum).Sum) + $item.SizeBytes
            if ($group.Count + 1 -le $maxEntities -and $projected -le $maxBytes) {
                $group.Add($item)
                $placed = $true
                break
            }
        }
        if ($placed) { continue }

        if ($groups.Count + 1 -gt $maxPackages) {
            $dropped.Add([pscustomobject]@{
                Slug   = $item.Slug
                Reason = "No headroom in any of the $maxPackages allowed rule packages."
            })
            continue
        }
        if ($WrapperOverheadBytes + $item.SizeBytes -gt $maxBytes) {
            $dropped.Add([pscustomobject]@{
                Slug   = $item.Slug
                Reason = "Item alone exceeds the $maxBytes-byte package budget."
            })
            continue
        }
        $maxOrdinal = 0
        foreach ($name in $groups.Keys) {
            if ($name -match '-(\d+)[a-z]?$' -and [int]$Matches[1] -gt $maxOrdinal) {
                $maxOrdinal = [int]$Matches[1]
            }
        }
        $newName = '{0}-{1}-{2:d2}' -f $Prefix, $Tier, ($maxOrdinal + 1)
        $groups[$newName] = [System.Collections.Generic.List[object]]::new()
        $groups[$newName].Add($item)
    }

    # Deterministic output: packages in ordinal order, slugs in item order.
    $packages = @()
    $assignments = [ordered]@{}
    foreach ($name in ($groups.Keys | Sort-Object { Get-PackageSortKey $_ })) {
        $group = @($groups[$name] | Sort-Object { $itemIndex[$_.Slug] })
        if ($group.Count -eq 0) { continue }
        $packages += [pscustomobject]@{
            Name           = $name
            Slugs          = @($group | ForEach-Object Slug)
            EntityCount    = $group.Count
            ProjectedBytes = $WrapperOverheadBytes + (($group | Measure-Object SizeBytes -Sum).Sum)
        }
        foreach ($member in $group) { $assignments[$member.Slug] = $name }
    }

    [pscustomobject]@{
        Assignments = $assignments
        Packages    = $packages
        Dropped     = $dropped.ToArray()
        Warnings    = @()
    }
}
