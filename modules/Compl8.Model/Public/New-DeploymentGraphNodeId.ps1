function New-DeploymentGraphNodeId {
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Value
    )

    $cleanValue = $Value.Trim()
    if ($cleanValue -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        $cleanValue = $cleanValue.ToLowerInvariant()
    }
    return ("{0}:{1}" -f $Prefix, $cleanValue)
}
