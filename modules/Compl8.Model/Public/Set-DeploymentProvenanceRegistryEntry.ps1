function Set-DeploymentProvenanceRegistryEntry {
    <#
    .SYNOPSIS
        Inserts or overwrites a single registry entry, creating the file/folder as needed.
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Entry,
        [string]$RegistryPath
    )

    $path = Resolve-DeploymentProvenanceRegistryPath -RegistryPath $RegistryPath
    $registry = Read-DeploymentProvenanceRegistry -RegistryPath $path
    $registry.entries[$Id] = $Entry

    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    ($registry | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $path -Encoding UTF8
}
