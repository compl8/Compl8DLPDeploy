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
        [hashtable]$Metadata = @{}
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
    Set-DeploymentProvenanceRegistryEntry -Id $id -Entry $entry

    return "[[Compl8:$id]]"
}
