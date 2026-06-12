function Initialize-EntityLedger {
    <#
    .SYNOPSIS
        Seeds the entity ledger from a release; idempotent, never re-mints.
    .DESCRIPTION
        Adds an active entry for every release item missing from the ledger, binding the
        fragment's entityId. Existing entries are NEVER touched — an adopted or previously
        minted binding survives re-seeding (the ledger is precious; bindings only change by
        explicit operator action). With -InventoryPath (a JSON array with Id fields, the
        config/tenant-sits.json shape), entries whose GUID is absent from the inventory are
        still seeded but reported as warnings — binding is desired-side; presence in the
        tenant is informational here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Release,

        [Parameter(Mandatory)]
        [string]$Path,

        [string]$InventoryPath
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        foreach ($entry in (Get-EntityLedger -Path $Path).Entries) { $entries.Add($entry) }
    }
    $known = @{}
    foreach ($entry in $entries) { $known[$entry.slug] = $entry }

    $inventoryIds = $null
    if ($InventoryPath) {
        $inventoryIds = @((Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json) |
            ForEach-Object Id)
    }

    foreach ($slug in $Release.Items.Keys) {
        $item = $Release.Items[$slug]
        if ($known.Contains($slug)) { continue }
        $entries.Add([pscustomobject]@{
            slug       = $slug
            entityId   = $item.EntityId
            state      = 'active'
            source     = 'release'
            firstBound = (Get-Date).ToString('yyyy-MM-dd')
        })
        if ($null -ne $inventoryIds -and $inventoryIds -notcontains $item.EntityId) {
            Write-Warning "Ledger seed: '$slug' ($($item.EntityId)) is not present in the provided inventory."
        }
    }

    $payload = [pscustomobject]@{
        schemaVersion = 'compl8.entity-ledger/v1'
        entries       = $entries.ToArray()
    }
    # Atomic write: the ledger is precious — never leave a torn file.
    $tmp = "$Path.tmp"
    $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmp
    Move-Item -LiteralPath $tmp -Destination $Path -Force

    Get-EntityLedger -Path $Path
}
