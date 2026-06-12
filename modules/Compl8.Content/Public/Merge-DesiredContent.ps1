function Merge-DesiredContent {
    <#
    .SYNOPSIS
        Deterministic merge of release + overlay into the desired item set.
    .DESCRIPTION
        Pure transform (no I/O): identity is the slug; conflicts are explicit, never
        silently resolved (arch design §4). Release upgrades that touch overridden,
        disabled, or removed items surface as upgrade conflicts:
          override-base-changed — release sourceHash drifted from override.baseSourceHash;
                                  the override is STILL applied (to old-behaviour intent)
                                  and the item is flagged StaleOverride.
          disabled-item-changed — release changed while the item is disabled (only
                                  detectable when the disable recorded a baseSourceHash).
          orphaned-override / orphaned-disable — the targeted slug left the release.
        Output order is deterministic: release items in release order, then adds in
        overlay order.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Release,

        [Parameter(Mandatory)]
        [pscustomobject]$Overlay
    )

    $overrideMap = @{}
    foreach ($override in @($Overlay.Override)) { $overrideMap[$override.Slug] = $override }
    $disableMap = @{}
    foreach ($disable in @($Overlay.Disable)) { $disableMap[$disable.Slug] = $disable }

    $items = [System.Collections.Generic.List[object]]::new()
    $conflicts = [System.Collections.Generic.List[object]]::new()

    foreach ($slug in $Release.Items.Keys) {
        $releaseItem = $Release.Items[$slug]

        if ($disableMap.Contains($slug)) {
            $disable = $disableMap[$slug]
            if ($disable.BaseSourceHash -and $disable.BaseSourceHash -ne $releaseItem.SourceHash) {
                $conflicts.Add([pscustomobject]@{
                    Slug   = $slug
                    Kind   = 'disabled-item-changed'
                    Detail = "Release item changed (sourceHash $($releaseItem.SourceHash)) while disabled against $($disable.BaseSourceHash); review before re-enabling."
                })
            }
            continue
        }

        $patches = @{}
        $stale = $false
        if ($overrideMap.Contains($slug)) {
            $override = $overrideMap[$slug]
            if ($override.BaseSourceHash -ne $releaseItem.SourceHash) {
                $stale = $true
                $conflicts.Add([pscustomobject]@{
                    Slug   = $slug
                    Kind   = 'override-base-changed'
                    Detail = "Override was authored against $($override.BaseSourceHash) but the release item is now $($releaseItem.SourceHash); override still applied, review and re-base."
                })
            }
            $patches = $override.Set
        }

        $items.Add([pscustomobject]@{
            Slug           = $slug
            Source         = 'release'
            EntityId       = $releaseItem.EntityId
            Name           = $releaseItem.Name
            DictionaryRefs = @($releaseItem.DictionaryRefs)
            SourceHash     = $releaseItem.SourceHash
            Sections       = $releaseItem.Sections
            AttrPatches    = $patches
            StaleOverride  = $stale
        })
    }

    foreach ($override in @($Overlay.Override)) {
        if (-not $Release.Items.Contains($override.Slug)) {
            $conflicts.Add([pscustomobject]@{
                Slug   = $override.Slug
                Kind   = 'orphaned-override'
                Detail = 'Override targets a slug no longer present in the release.'
            })
        }
    }
    foreach ($disable in @($Overlay.Disable)) {
        if (-not $Release.Items.Contains($disable.Slug)) {
            $conflicts.Add([pscustomobject]@{
                Slug   = $disable.Slug
                Kind   = 'orphaned-disable'
                Detail = 'Disable targets a slug no longer present in the release.'
            })
        }
    }

    foreach ($add in @($Overlay.Add)) {
        $items.Add([pscustomobject]@{
            Slug           = $add.Slug
            Source         = 'custom'
            EntityId       = $null   # bound by the ledger at resolve time
            Name           = $add.Definition.name
            DictionaryRefs = @()
            SourceHash     = $null
            Sections       = $null   # rendered by ConvertTo-CustomSitFragment at resolve time
            Definition     = $add.Definition
            AttrPatches    = @{}
            StaleOverride  = $false
        })
    }

    [pscustomobject]@{
        Items     = $items.ToArray()
        Conflicts = $conflicts.ToArray()
    }
}
