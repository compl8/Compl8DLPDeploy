function Export-TenantActualSnapshot {
    <#
    .SYNOPSIS
        Writes a tenant inventory into the workspace actual/snapshots/<Timestamp>/ layout.
    .DESCRIPTION
        Thin, deterministic wiring of an already-read inventory (from Get-TenantInventory) into
        the workspace `actual/` tree (D8): actual/snapshots/<Timestamp>/inventory.json. The
        Timestamp is supplied by the caller — Get-Date is deliberately NOT called here so the
        write path is a pure function of its inputs and tests are reproducible.

        One-writer-per-domain (D8): the Tenant layer owns actual/; the Engine owns history/.

    .PARAMETER WorkspacePath
        The resolved workspace-environment root (e.g. the output of
        Get-Compl8WorkspacePath -Environment nonprod). actual/snapshots/<Timestamp>/ hangs off it.
    .PARAMETER Timestamp
        Snapshot folder name (e.g. '20260613_120000'). Mandatory and caller-supplied so the
        function is deterministic. Get-Date is banned in this path.
    .PARAMETER Inventory
        The compl8.inventory/v1 object to persist (from Get-TenantInventory).
    .OUTPUTS
        An object describing what was written: SnapshotDir, InventoryPath, Timestamp.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WorkspacePath,

        [Parameter(Mandatory)]
        [string]$Timestamp,

        [Parameter(Mandatory)]
        [object]$Inventory
    )

    if ([string]::IsNullOrWhiteSpace($Timestamp)) {
        throw "Export-TenantActualSnapshot requires a non-empty -Timestamp (Get-Date is banned in this deterministic path)."
    }

    $snapshotDir = Join-Path (Join-Path (Join-Path $WorkspacePath 'actual') 'snapshots') $Timestamp
    if (-not (Test-Path -LiteralPath $snapshotDir)) {
        New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null
    }

    $inventoryPath = Join-Path $snapshotDir 'inventory.json'
    $Inventory | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $inventoryPath -Encoding UTF8

    [pscustomobject][ordered]@{
        SnapshotDir   = $snapshotDir
        InventoryPath = $inventoryPath
        Timestamp     = $Timestamp
    }
}
