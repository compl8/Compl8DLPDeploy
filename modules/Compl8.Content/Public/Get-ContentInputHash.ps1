function Get-ContentInputHash {
    <#
    .SYNOPSIS
        Computes the resolve-manifest input hashes for (release, overlay, ledger).
    .DESCRIPTION
        Single source of the hash definitions used by Resolve-DesiredContent (writing) and
        Test-ResolveManifestCurrent (checking), per the formats spec:
          releaseHash = release.json contentHash, verbatim;
          overlayHash = SHA256 over UTF-8 of sorted '<relativePath>:<fileSha256hex>' lines
                        (forward slashes, LF-joined); no overlay files ⇒ hash of empty string;
          ledgerHash  = SHA256 of the ledger file bytes (empty string if absent).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ReleasePath,

        [Parameter(Mandatory)]
        [string]$OverlayPath,

        [Parameter(Mandatory)]
        [string]$LedgerPath
    )

    $releaseManifestPath = Join-Path $ReleasePath 'release.json'
    if (-not (Test-Path -LiteralPath $releaseManifestPath -PathType Leaf)) {
        throw "Not a content release: missing release.json under '$ReleasePath'."
    }
    $releaseManifest = Get-Content -LiteralPath $releaseManifestPath -Raw | ConvertFrom-Json

    function Get-Utf8Sha256Hex {
        param([string]$Text)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
            -join ($hash | ForEach-Object { $_.ToString('x2') })
        } finally {
            $sha.Dispose()
        }
    }

    $overlayLines = @()
    if (Test-Path -LiteralPath $OverlayPath -PathType Container) {
        $overlayRoot = (Get-Item -LiteralPath $OverlayPath).FullName
        $overlayLines = Get-ChildItem -LiteralPath $overlayRoot -Recurse -File | ForEach-Object {
            $relative = $_.FullName.Substring($overlayRoot.Length).TrimStart('\', '/').Replace('\', '/')
            $fileHash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            "${relative}:${fileHash}"
        } | Sort-Object
    }
    $overlayHash = Get-Utf8Sha256Hex -Text ($overlayLines -join "`n")

    $ledgerHash = if (Test-Path -LiteralPath $LedgerPath -PathType Leaf) {
        (Get-FileHash -LiteralPath $LedgerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    } else {
        Get-Utf8Sha256Hex -Text ''
    }

    [pscustomobject]@{
        ReleaseVersion = $releaseManifest.version
        ReleaseHash    = $releaseManifest.contentHash
        OverlayHash    = "sha256:$overlayHash"
        LedgerHash     = "sha256:$ledgerHash"
    }
}
