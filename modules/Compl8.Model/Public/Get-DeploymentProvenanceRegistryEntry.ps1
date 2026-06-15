function Get-DeploymentProvenanceRegistryEntry {
    <#
    .SYNOPSIS
        Returns the registry entry for a provenance id, or $null if absent.
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [string]$RegistryPath
    )

    $registry = Read-DeploymentProvenanceRegistry -RegistryPath $RegistryPath
    if ($registry.entries.Contains($Id)) { return $registry.entries[$Id] }
    return $null
}
