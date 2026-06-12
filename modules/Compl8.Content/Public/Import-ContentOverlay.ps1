function Import-ContentOverlay {
    <#
    .SYNOPSIS
        Loads and validates an operator overlay (add / override / disable).
    .DESCRIPTION
        Format: compl8.overlay/v1 per docs/superpowers/specs/2026-06-13-content-formats.md.
        A missing overlay.json is a valid empty overlay (no customisations is the common
        case). Validation is strict because overlay errors otherwise surface as confusing
        merge/resolve failures: custom namespace enforced, override keys whitelisted,
        targets must exist in the release.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [pscustomobject]$Release
    )

    $whitelist = @('patternsProximity', 'recommendedConfidence', 'confidenceLevel')
    $releaseSlugs = @($Release.Items.Keys)

    $empty = [pscustomobject]@{ Path = $Path; Add = @(); Override = @(); Disable = @() }
    $overlayPath = Join-Path $Path 'overlay.json'
    if (-not (Test-Path -LiteralPath $overlayPath -PathType Leaf)) {
        return $empty
    }
    $overlay = Get-Content -LiteralPath $overlayPath -Raw | ConvertFrom-Json
    if ($overlay.schemaVersion -ne 'compl8.overlay/v1') {
        throw "Unsupported overlay schemaVersion '$($overlay.schemaVersion)' (expected compl8.overlay/v1)."
    }

    $adds = @()
    foreach ($add in @($overlay.add)) {
        if (-not $add) { continue }
        if ($add.slug -notmatch '^custom-[a-z0-9-]+$') {
            throw "Overlay add slug '$($add.slug)' must use the custom- namespace (^custom-[a-z0-9-]+$)."
        }
        if ($releaseSlugs -contains $add.slug) {
            throw "Overlay add slug '$($add.slug)' collides with a release slug."
        }
        $defPath = Join-Path $Path $add.definition
        if (-not $add.definition -or -not (Test-Path -LiteralPath $defPath -PathType Leaf)) {
            throw "Overlay add '$($add.slug)': definition file '$($add.definition)' not found."
        }
        $definition = Get-Content -LiteralPath $defPath -Raw | ConvertFrom-Json
        if ($definition.slug -ne $add.slug) {
            throw "Overlay add '$($add.slug)': definition file declares slug '$($definition.slug)'."
        }
        $adds += [pscustomobject]@{ Slug = $add.slug; Definition = $definition }
    }

    $overrides = @()
    foreach ($override in @($overlay.override)) {
        if (-not $override) { continue }
        if ($releaseSlugs -notcontains $override.slug) {
            throw "Overlay override targets '$($override.slug)', which is not in the release."
        }
        if (-not $override.baseSourceHash) {
            throw "Overlay override '$($override.slug)' is missing baseSourceHash (needed for upgrade-conflict detection)."
        }
        $set = @{}
        foreach ($prop in $override.set.PSObject.Properties) {
            if ($whitelist -notcontains $prop.Name) {
                throw "Overlay override '$($override.slug)': field '$($prop.Name)' is not in the overridable-field whitelist ($($whitelist -join ', '))."
            }
            if ($prop.Value -isnot [int64] -and $prop.Value -isnot [int32]) {
                throw "Overlay override '$($override.slug)': field '$($prop.Name)' must be an integer."
            }
            $set[$prop.Name] = [int]$prop.Value
        }
        if ($set.Count -eq 0) {
            throw "Overlay override '$($override.slug)' sets no fields."
        }
        $overrides += [pscustomobject]@{
            Slug           = $override.slug
            BaseSourceHash = $override.baseSourceHash
            Set            = $set
        }
    }

    $disables = @()
    foreach ($disable in @($overlay.disable)) {
        if (-not $disable) { continue }
        if ($releaseSlugs -notcontains $disable.slug) {
            throw "Overlay disable targets '$($disable.slug)', which is not in the release."
        }
        $disables += [pscustomobject]@{ Slug = $disable.slug; Reason = $disable.reason }
    }

    [pscustomobject]@{
        Path     = $Path
        Add      = $adds
        Override = $overrides
        Disable  = $disables
    }
}
