function Get-DeploymentProvenanceStamp {
    <#
    .SYNOPSIS
        Reads a Compl8DLPDeploy provenance marker from text. Recognises both the short opaque
        form ([[Compl8:<16hex>]], resolved via the registry) and the legacy long form
        ([[Compl8DLPDeploy:provenance:v1;...]], parsed inline).
    #>
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    # Short opaque form — full fields live in the local registry.
    $shortMatch = [regex]::Match($Text, '\[\[Compl8:(?<id>[0-9a-f]{16})\]\]')
    if ($shortMatch.Success) {
        $id = $shortMatch.Groups["id"].Value
        $entry = Get-DeploymentProvenanceRegistryEntry -Id $id
        if ($null -eq $entry) {
            return [pscustomobject]@{
                Found             = $true
                Resolved          = $false
                Toolkit           = "Compl8DLPDeploy"
                Version           = $null
                Id                = $id
                Prefix            = $null
                Component         = $null
                DeploymentId      = $null
                TargetEnvironment = $null
                Fields            = $null
                Raw               = $shortMatch.Value
            }
        }
        return [pscustomobject]@{
            Found             = $true
            Resolved          = $true
            Toolkit           = if ($entry.toolkit) { $entry.toolkit } else { "Compl8DLPDeploy" }
            Version           = if ($entry.version) { [int]$entry.version } else { 1 }
            Id                = $id
            Prefix            = $entry.prefix
            Component         = $entry.component
            DeploymentId      = $entry.deploymentId
            TargetEnvironment = $entry.environment
            Fields            = $entry.fields
            Raw               = $shortMatch.Value
        }
    }

    # Legacy long form — self-contained, no registry needed.
    $pattern = '\[\[Compl8DLPDeploy:provenance:v(?<version>\d+)(?<fields>(?:;[A-Za-z][A-Za-z0-9_]*=[^\]\r\n;]*)*)\]\]'
    $match = [regex]::Match($Text, $pattern)
    if (-not $match.Success) { return $null }

    $fields = [ordered]@{}
    foreach ($fieldMatch in [regex]::Matches($match.Groups["fields"].Value, ';(?<key>[A-Za-z][A-Za-z0-9_]*)=(?<value>[^\]\r\n;]*)')) {
        $fields[$fieldMatch.Groups["key"].Value] = ConvertFrom-DeploymentProvenanceFieldValue -Value $fieldMatch.Groups["value"].Value
    }

    return [pscustomobject]@{
        Found             = $true
        Resolved          = $true
        Toolkit           = "Compl8DLPDeploy"
        Version           = [int]$match.Groups["version"].Value
        Id                = $null
        Prefix            = $fields["prefix"]
        Component         = $fields["component"]
        DeploymentId      = $fields["deploymentId"]
        TargetEnvironment = $fields["environment"]
        Fields            = [pscustomobject]$fields
        Raw               = $match.Value
    }
}
