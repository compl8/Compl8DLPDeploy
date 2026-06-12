function Get-EntityLedger {
    <#
    .SYNOPSIS
        Reads and validates the entity ledger (slug → entity-GUID pins).
    .DESCRIPTION
        The ledger is one of the two precious per-workspace files (arch design §3): it pins
        each content slug to the entity GUID it was first bound under so repacks never dangle
        live DLP rules. Format: compl8.entity-ledger/v1.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Entity ledger not found at '$Path'. Seed it with Initialize-EntityLedger."
    }
    $ledger = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($ledger.schemaVersion -ne 'compl8.entity-ledger/v1') {
        throw "Unsupported entity-ledger schemaVersion '$($ledger.schemaVersion)' (expected compl8.entity-ledger/v1)."
    }

    [pscustomobject]@{
        Path    = $Path
        Entries = @($ledger.entries)
    }
}
