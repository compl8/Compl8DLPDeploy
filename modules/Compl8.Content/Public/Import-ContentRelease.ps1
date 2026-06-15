function Import-ContentRelease {
    <#
    .SYNOPSIS
        Loads and validates a curated content release directory.
    .DESCRIPTION
        Reads release.json, every referenced fragment and definition, and the dictionaries
        manifest. Pure file reads — no tenant calls. Formats per
        docs/superpowers/specs/2026-06-13-content-formats.md (compl8.release/v1).
        Throws on any structural violation; a release is sealed, so a partial read is
        always corruption, never a state to continue from.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $manifestPath = Join-Path $Path 'release.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Not a content release: missing release.json under '$Path'."
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

    if ($manifest.schemaVersion -ne 'compl8.release/v1') {
        throw "Unsupported release schemaVersion '$($manifest.schemaVersion)' (expected compl8.release/v1)."
    }
    foreach ($required in 'version', 'generatedUtc', 'tier', 'contentHash') {
        if (-not $manifest.$required) {
            throw "release.json is missing required field '$required'."
        }
    }
    if (-not $manifest.items) {
        throw 'release.json has no items.'
    }

    # Dictionaries manifest (optional file; required if any item references a dictionary).
    $dictionaries = @()
    $dictManifestPath = Join-Path $Path 'dictionaries' 'manifest.json'
    if (Test-Path -LiteralPath $dictManifestPath -PathType Leaf) {
        $dictManifest = Get-Content -LiteralPath $dictManifestPath -Raw | ConvertFrom-Json
        if ($dictManifest.schemaVersion -ne 'compl8.dictionaries/v1') {
            throw "Unsupported dictionaries schemaVersion '$($dictManifest.schemaVersion)'."
        }
        $dictionaries = @($dictManifest.dictionaries)
    }
    $knownPlaceholders = @($dictionaries | ForEach-Object placeholder)

    $items = [ordered]@{}
    foreach ($item in $manifest.items) {
        if (-not $item.slug -or $item.slug -notmatch '^[a-z0-9-]+$') {
            throw "Invalid release item slug '$($item.slug)'."
        }
        if ($item.slug -like 'custom-*') {
            throw "Release item slug '$($item.slug)' uses the operator-reserved custom- namespace."
        }
        if ($items.Contains($item.slug)) {
            throw "Duplicate release item slug '$($item.slug)'."
        }

        $fragmentPath = Join-Path $Path $item.fragment
        if (-not $item.fragment -or -not (Test-Path -LiteralPath $fragmentPath -PathType Leaf)) {
            throw "Release item '$($item.slug)': fragment file '$($item.fragment)' not found."
        }
        $fragment = Get-Content -LiteralPath $fragmentPath -Raw | ConvertFrom-Json
        if ($fragment.schemaVersion -ne 'compl8.fragment/v1') {
            throw "Release item '$($item.slug)': unsupported fragment schemaVersion '$($fragment.schemaVersion)'."
        }
        if ($fragment.entityId -ne $item.entityId) {
            throw "Release item '$($item.slug)': entityId mismatch between release.json ('$($item.entityId)') and fragment ('$($fragment.entityId)') — release is corrupt."
        }
        if (-not $fragment.sections.entity) {
            throw "Release item '$($item.slug)': fragment has no entity section."
        }
        if (-not $fragment.sections.resources -or @($fragment.sections.resources).Count -lt 1) {
            throw "Release item '$($item.slug)': fragment has no resources section."
        }

        $definitionPath = Join-Path $Path $item.definition
        if (-not $item.definition -or -not (Test-Path -LiteralPath $definitionPath -PathType Leaf)) {
            throw "Release item '$($item.slug)': definition file '$($item.definition)' not found."
        }
        $definition = Get-Content -LiteralPath $definitionPath -Raw | ConvertFrom-Json

        foreach ($ref in @($item.dictionaryRefs)) {
            if ($ref -and $knownPlaceholders -notcontains $ref) {
                throw "Release item '$($item.slug)': dictionaryRef '$ref' is not in dictionaries/manifest.json."
            }
        }

        $items[$item.slug] = [pscustomobject]@{
            Slug           = $item.slug
            Type           = $item.type
            Name           = $item.name
            EntityId       = $item.entityId
            DictionaryRefs = @($item.dictionaryRefs)
            SourceHash     = $item.sourceHash
            Sections       = [pscustomobject]@{
                Entity     = $fragment.sections.entity
                Regexes    = @($fragment.sections.regexes)
                Keywords   = @($fragment.sections.keywords)
                Filters    = @($fragment.sections.filters)
                Validators = @($fragment.sections.validators)
                Resources  = @($fragment.sections.resources)
            }
            Definition     = $definition
        }
    }

    [pscustomobject]@{
        Path         = $Path
        Version      = $manifest.version
        Tier         = $manifest.tier
        GeneratedUtc = $manifest.generatedUtc
        ContentHash  = $manifest.contentHash
        Items        = $items
        Dictionaries = $dictionaries
    }
}
