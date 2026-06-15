function New-DeploymentProvenanceStamp {
    <#
    .SYNOPSIS
        Creates a short opaque ownership marker ([[Compl8:<16hex>]]) for Purview Comment/Description
        fields, recording the full field set in the local provenance registry.
    #>
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Component,
        [string]$DeploymentId,
        [string]$TargetEnvironment,
        [hashtable]$Metadata = @{},

        # Optional explicit provenance registry path; forwarded to Set-DeploymentProvenanceRegistryEntry
        # so the entry lands at THIS registry (e.g. a workspace's history/applies/provenance.json). When
        # absent the registry resolves via the existing precedence (env var else repo default) — UNCHANGED
        # for every current caller. (Stage 5 D8 re-point; codex 5A review.)
        [string]$RegistryPath
    )

    if ([string]::IsNullOrWhiteSpace($DeploymentId)) {
        $DeploymentId = if ($env:COMPL8_DEPLOYMENT_ID) { $env:COMPL8_DEPLOYMENT_ID } else { Get-Date -Format "yyyyMMdd" }
    }

    $fields = [ordered]@{
        prefix       = $Prefix
        component    = $Component
        deploymentId = $DeploymentId
    }
    if (-not [string]::IsNullOrWhiteSpace($TargetEnvironment)) {
        $fields.environment = $TargetEnvironment
    }
    foreach ($key in @($Metadata.Keys | Sort-Object)) {
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        $safeKey = ($key.ToString() -replace '[^A-Za-z0-9_]', '')
        if ([string]::IsNullOrWhiteSpace($safeKey) -or $fields.Contains($safeKey)) { continue }
        $fields[$safeKey] = $Metadata[$key]
    }

    $id = New-DeploymentProvenanceId -Fields $fields

    $entry = [ordered]@{
        toolkit      = "Compl8DLPDeploy"
        version      = 1
        prefix       = $Prefix
        component    = $Component
        deploymentId = $fields.deploymentId
        environment  = if ($fields.Contains('environment')) { $fields.environment } else { $null }
        fields       = $fields
    }
    $setArgs = @{ Id = $id; Entry = $entry }
    if (-not [string]::IsNullOrWhiteSpace($RegistryPath)) { $setArgs['RegistryPath'] = $RegistryPath }
    Set-DeploymentProvenanceRegistryEntry @setArgs

    return "[[Compl8:$id]]"
}
