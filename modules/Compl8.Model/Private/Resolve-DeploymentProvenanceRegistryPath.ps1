function Resolve-DeploymentProvenanceRegistryPath {
    <#
    .SYNOPSIS
        Resolves the provenance registry file path: workspace history > explicit override > env var
        > repo default.
    .DESCRIPTION
        Stage-5 re-point (D8): when -WorkspacePath is supplied the registry is the workspace's
        one-writer history file <WorkspacePath>/history/applies/provenance.json — the Engine owns
        history/, and Convert-ToWorkspace copies the legacy reports/provenance-registry.json in.
        The workspace path takes precedence over EVERYTHING (explicit -RegistryPath, the env var,
        and the repo default), so a workspace-scoped caller is always self-contained.

        Without -WorkspacePath the precedence is UNCHANGED from before the re-point:
        explicit -RegistryPath > $env:COMPL8_PROVENANCE_REGISTRY > <repo>/reports/provenance-registry.json
        — so every existing caller (and the existing provenance tests, which pass no workspace)
        behaves identically.
    .NOTES
        Private to Compl8.Model. The repo-default branch is computed relative to the repository root
        (the grandparent of the modules/ directory) rather than via $PSScriptRoot of the calling
        file, so the default resolves to <repo>/reports/provenance-registry.json regardless of
        whether the provenance functions run inside Compl8.Model (this file lives in
        modules/Compl8.Model/Private) or are dot-sourced into DLP-Deploy via the facade.
    #>
    param(
        [string]$RegistryPath,
        [string]$WorkspacePath
    )

    if (-not [string]::IsNullOrWhiteSpace($WorkspacePath)) {
        return Join-Path (Join-Path (Join-Path $WorkspacePath "history") "applies") "provenance.json"
    }
    if (-not [string]::IsNullOrWhiteSpace($RegistryPath)) { return $RegistryPath }
    if (-not [string]::IsNullOrWhiteSpace($env:COMPL8_PROVENANCE_REGISTRY)) { return $env:COMPL8_PROVENANCE_REGISTRY }
    # $PSScriptRoot here is <repo>/modules/Compl8.Model/Private; walk up to <repo>.
    $repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    return Join-Path (Join-Path $repoRoot "reports") "provenance-registry.json"
}
