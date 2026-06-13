function Resolve-DeploymentProvenanceRegistryPath {
    <#
    .SYNOPSIS
        Resolves the provenance registry file path: explicit override > env var > repo default.
    .NOTES
        Private to Compl8.Model. Behaviourally identical to the DLP-Deploy.psm1 definition of
        the same name, but the repo-default branch is computed relative to the repository root
        (the grandparent of the modules/ directory) rather than via $PSScriptRoot of the calling
        file, so the default resolves to <repo>/reports/provenance-registry.json regardless of
        whether the provenance functions run inside Compl8.Model (this file lives in
        modules/Compl8.Model/Private) or are dot-sourced into DLP-Deploy via the facade. This
        keeps the default registry path identical to the original modules/-level helper.
    #>
    param([string]$RegistryPath)

    if (-not [string]::IsNullOrWhiteSpace($RegistryPath)) { return $RegistryPath }
    if (-not [string]::IsNullOrWhiteSpace($env:COMPL8_PROVENANCE_REGISTRY)) { return $env:COMPL8_PROVENANCE_REGISTRY }
    # $PSScriptRoot here is <repo>/modules/Compl8.Model/Private; walk up to <repo>.
    $repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    return Join-Path (Join-Path $repoRoot "reports") "provenance-registry.json"
}
