function Get-Compl8OwnershipMap {
    <#
    .SYNOPSIS
        Builds the ownership lookup (object identifier -> [bool] ours) from an inventory, for the risk
        strategist (Get-Compl8ChangeRisk) and any caller that must classify affected objects internal vs
        external. Pure (no I/O).

    .DESCRIPTION
        Maps every actual object's identifier to its `ours` flag: dlp rules + policies + sit packages +
        dictionaries by NAME, and sits BOTH by entity GUID (lowercased — how the graph keys them) and by
        name. An identifier absent from the map is treated as foreign by the strategist (conservative), so
        a complete inventory map is what lets a change reaching a not-ours object be recognised.

    .PARAMETER Inventory
        A parsed compl8.inventory/v1 object (its objects.* lists carry `ours`).

    .OUTPUTS
        [hashtable] identifier (case-insensitive) -> [bool] ours.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Inventory
    )

    $map = @{}
    if (-not $Inventory.objects) { return $map }
    foreach ($r in @($Inventory.objects.dlpRules))     { if ($r.name) { $map[[string]$r.name] = [bool]$r.ours } }
    foreach ($p in @($Inventory.objects.dlpPolicies))  { if ($p.name) { $map[[string]$p.name] = [bool]$p.ours } }
    foreach ($s in @($Inventory.objects.sits)) {
        if ($s.identity) { $map[([string]$s.identity).ToLowerInvariant()] = [bool]$s.ours }
        if ($s.name)     { $map[[string]$s.name] = [bool]$s.ours }
    }
    foreach ($pk in @($Inventory.objects.sitPackages)) { if ($pk.name) { $map[[string]$pk.name] = [bool]$pk.ours } }
    foreach ($d in @($Inventory.objects.dictionaries)) { if ($d.name) { $map[[string]$d.name] = [bool]$d.ours } }
    $map
}
