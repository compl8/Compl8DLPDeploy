function New-PlanObject {
    <#
    .SYNOPSIS
        Constructs an empty compl8.plan/v1 object.
    .DESCRIPTION
        Pure transform (no I/O): builds the ordered, gated change-set shell that
        Add-PlanStep fills and Test-PlanSchema validates. Steps are added via
        Add-PlanStep so id-uniqueness and defaults stay in one place. Plan validity
        is by hash: it is stale once the recorded resolveManifest / inventory /
        assessment hashes no longer match the live inputs. Format per
        docs/superpowers/specs/2026-06-13-engine-lifecycle.md.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Workspace,

        [Parameter(Mandatory)]
        [string]$Id,

        [string]$GeneratedUtc,

        [string]$ResolveManifestHash,

        [string]$InventoryHash,

        [string]$AssessmentHash
    )

    [pscustomobject]@{
        schemaVersion = 'compl8.plan/v1'
        id            = $Id
        workspace     = $Workspace
        generatedUtc  = $GeneratedUtc
        inputs        = [pscustomobject]@{
            resolveManifest = $ResolveManifestHash
            inventory       = $InventoryHash
            assessment      = $AssessmentHash
        }
        steps         = @()
        ordering      = 'graph-derived'
        warnings      = @()
    }
}
