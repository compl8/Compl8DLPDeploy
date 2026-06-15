function Test-ResolveManifestCurrent {
    <#
    .SYNOPSIS
        Staleness check: is desired/resolved current for (release, overlay, ledger)?
    .DESCRIPTION
        Recomputes the three input hashes and compares them to the resolve manifest.
        Returns $true only when every hash (and the release version) matches. Use -Detail
        for which input drifted. desired/resolved is a pure function of its inputs, so a
        hash mismatch means it must be regenerated, never patched.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WorkspacePath,

        [switch]$Detail
    )

    $manifestPath = Join-Path $WorkspacePath 'desired' 'resolved' 'resolve-manifest.json'
    $stale = @()
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        $stale += 'no resolve manifest (never resolved)'
        if ($Detail) { return [pscustomobject]@{ Current = $false; Stale = $stale } }
        return $false
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

    $current = Get-ContentInputHash `
        -ReleasePath (Join-Path $WorkspacePath 'desired' 'release') `
        -OverlayPath (Join-Path $WorkspacePath 'desired' 'overlay') `
        -LedgerPath (Join-Path $WorkspacePath 'entity-ledger.json')

    if ($manifest.inputs.releaseVersion -ne $current.ReleaseVersion) { $stale += 'releaseVersion' }
    if ($manifest.inputs.releaseHash -ne $current.ReleaseHash) { $stale += 'release' }
    if ($manifest.inputs.overlayHash -ne $current.OverlayHash) { $stale += 'overlay' }
    if ($manifest.inputs.ledgerHash -ne $current.LedgerHash) { $stale += 'ledger' }

    if ($Detail) {
        return [pscustomobject]@{ Current = ($stale.Count -eq 0); Stale = $stale }
    }
    $stale.Count -eq 0
}
