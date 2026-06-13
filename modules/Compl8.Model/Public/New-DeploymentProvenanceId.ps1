function New-DeploymentProvenanceId {
    <#
    .SYNOPSIS
        Deterministic 16-char hex id derived from the canonical provenance fields.
        Identical inputs always yield the same id, so re-deploys are idempotent.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Fields)

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $Fields.GetEnumerator()) {
        if ($null -eq $entry.Value -or [string]::IsNullOrWhiteSpace($entry.Value.ToString())) { continue }
        $parts.Add(("{0}={1}" -f $entry.Key, $entry.Value.ToString())) | Out-Null
    }
    $canonical = ($parts -join ';')

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canonical))
    } finally {
        $sha.Dispose()
    }
    $hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    return $hex.Substring(0, 16)
}
