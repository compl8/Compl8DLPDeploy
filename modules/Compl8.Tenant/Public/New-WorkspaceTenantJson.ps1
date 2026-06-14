function New-WorkspaceTenantJson {
    <#
    .SYNOPSIS
        Maps a legacy tenant-fingerprints.json env entry + naming prefix into the compl8.tenant/v1
        tenant.json document that New-Compl8Context / Get-Compl8TenantPin read.
    .DESCRIPTION
        Stage 5 / Task 5A-2 helper. Pure transform — no file IO, no live tenant call, no Get-Date.
        Convert-ToWorkspace writes the returned object to <ws>/tenant.json; New-Compl8Context resolves
        it back. Deliberately the INVERSE of Get-Compl8TenantPin's fingerprint-fallback branch, so a
        round-trip (fingerprints → tenant.json → context) reproduces the same tenant pin.

        compl8.tenant/v1 shape:
          {
            "schemaVersion": "compl8.tenant/v1",
            "environment":   "<env>",
            "identity":   { "tenantId": "<guid>", "prefix": "<namingPrefix>" },
            "fingerprint":{ "mode": "warn" | "block" },
            "settings":   { ...free-form deployment settings... }
          }
    .PARAMETER Environment
        The environment key (e.g. nonprod) this tenant.json is for.
    .PARAMETER FingerprintEntry
        The environments.<env> object from config/tenant-fingerprints.json
        ({ mode; tenantId; name? }). mode defaults to 'warn' when absent.
    .PARAMETER Prefix
        The naming prefix (settings.json namingPrefix) — the identity prefix the deployment uses.
    .PARAMETER Settings
        Optional free-form settings object carried under .settings (e.g. namingSuffix). $null => {}.
    .OUTPUTS
        A pscustomobject in the compl8.tenant/v1 shape (ready to ConvertTo-Json).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Environment,

        [Parameter(Mandatory)]
        [pscustomobject]$FingerprintEntry,

        [string]$Prefix,

        [pscustomobject]$Settings
    )

    $tenantId = if ($FingerprintEntry.PSObject.Properties['tenantId'] -and $FingerprintEntry.tenantId) {
        [string]$FingerprintEntry.tenantId
    } else { $null }

    $mode = if ($FingerprintEntry.PSObject.Properties['mode'] -and $FingerprintEntry.mode) {
        ([string]$FingerprintEntry.mode).ToLowerInvariant()
    } else { 'warn' }

    $identity = [ordered]@{
        tenantId = $tenantId
        prefix   = if ([string]::IsNullOrWhiteSpace($Prefix)) { $null } else { $Prefix }
    }
    # Carry the friendly tenant name when the fingerprint entry has one (informational).
    if ($FingerprintEntry.PSObject.Properties['name'] -and $FingerprintEntry.name) {
        $identity['name'] = [string]$FingerprintEntry.name
    }

    $settingsObj = if ($Settings) { $Settings } else { [pscustomobject]@{} }

    [pscustomobject]([ordered]@{
        schemaVersion = 'compl8.tenant/v1'
        environment   = $Environment
        identity      = [pscustomobject]$identity
        fingerprint   = [pscustomobject]([ordered]@{ mode = $mode })
        settings      = $settingsObj
    })
}
