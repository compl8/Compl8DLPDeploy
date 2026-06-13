function New-AssessmentObject {
    <#
    .SYNOPSIS
        Constructs an empty compl8.assessment/v1 object.
    .DESCRIPTION
        Pure transform (no I/O): builds the read-only assessment shape Assess fills —
        seven buckets (create / update-in-place / repack-move / remove / orphan /
        foreign / drift), each tenant object landing in exactly one (enforced by
        Test-AssessmentSchema). Bucket names are single-sourced from
        Get-Compl8EngineSchemaEnums so callers never duplicate the literals.
        Format per docs/superpowers/specs/2026-06-13-engine-lifecycle.md.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Workspace,

        [string]$GeneratedUtc,

        [string]$ResolveManifestHash,

        [string]$InventoryHash
    )

    $buckets = [ordered]@{}
    foreach ($name in (Get-Compl8EngineSchemaEnums).Buckets) {
        $buckets[$name] = @()
    }

    [pscustomobject]@{
        schemaVersion    = 'compl8.assessment/v1'
        workspace        = $Workspace
        generatedUtc     = $GeneratedUtc
        inputs           = [pscustomobject]@{
            resolveManifest = $ResolveManifestHash
            inventory       = $InventoryHash
        }
        buckets          = [pscustomobject]$buckets
        upgradeConflicts = @()
        impact           = @()
    }
}
