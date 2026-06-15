function Update-EntityLedger {
    <#
    .SYNOPSIS
        Mints custom-SIT bindings and flips entry state; entries are never deleted.
    .DESCRIPTION
        -Add <custom-slug>     mints a GUID for an operator-added SIT (idempotent: re-adding
                               returns the existing binding; re-adding a disabled slug
                               re-enables it with the SAME GUID — the re-enable invariant).
        -Disable <slug>        flips state to 'disabled' but RETAINS the entry/GUID.
        -Enable <slug>         flips state back to 'active'.
        -BindPackage <name>    mints (or returns) the RulePack GUID pinned to a package
                               name — package ids are precious for the same reason entity
                               ids are: regenerating desired/resolved must reproduce them.
        Returns the affected entry.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Add')]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'Add')]
        [string]$Add,

        [Parameter(Mandatory, ParameterSetName = 'Disable')]
        [string]$Disable,

        [Parameter(Mandatory, ParameterSetName = 'Enable')]
        [string]$Enable,

        [Parameter(Mandatory, ParameterSetName = 'BindPackage')]
        [string]$BindPackage
    )

    $ledger = Get-EntityLedger -Path $Path
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $ledger.Entries) { $entries.Add($entry) }
    $packages = [System.Collections.Generic.List[object]]::new()
    foreach ($package in $ledger.Packages) { $packages.Add($package) }

    $result = $null
    switch ($PSCmdlet.ParameterSetName) {
        'Add' {
            if ($Add -notmatch '^custom-[a-z0-9-]+$') {
                throw "Ledger -Add slug '$Add' must use the custom- namespace (^custom-[a-z0-9-]+$)."
            }
            $existing = $entries | Where-Object slug -EQ $Add
            if ($existing) {
                if ($existing.state -ne 'active') { $existing.state = 'active' }
                $result = $existing
            } else {
                $result = [pscustomobject]@{
                    slug       = $Add
                    entityId   = [guid]::NewGuid().ToString()
                    state      = 'active'
                    source     = 'custom'
                    firstBound = (Get-Date).ToString('yyyy-MM-dd')
                }
                $entries.Add($result)
            }
        }
        'Disable' {
            $existing = $entries | Where-Object slug -EQ $Disable
            if (-not $existing) { throw "Ledger has no entry for slug '$Disable'." }
            $existing.state = 'disabled'
            $result = $existing
        }
        'Enable' {
            $existing = $entries | Where-Object slug -EQ $Enable
            if (-not $existing) { throw "Ledger has no entry for slug '$Enable'." }
            $existing.state = 'active'
            $result = $existing
        }
        'BindPackage' {
            $existing = $packages | Where-Object name -EQ $BindPackage
            if ($existing) {
                $result = $existing
            } else {
                $result = [pscustomobject]@{
                    name       = $BindPackage
                    rulePackId = [guid]::NewGuid().ToString()
                }
                $packages.Add($result)
            }
        }
    }

    $payload = [pscustomobject]@{
        schemaVersion = 'compl8.entity-ledger/v1'
        entries       = $entries.ToArray()
        packages      = $packages.ToArray()
    }
    # Atomic write: the ledger is precious — never leave a torn file.
    $tmp = "$Path.tmp"
    $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmp
    Move-Item -LiteralPath $tmp -Destination $Path -Force

    $result
}
