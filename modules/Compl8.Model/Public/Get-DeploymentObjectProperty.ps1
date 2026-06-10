function Get-DeploymentObjectProperty {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string[]]$Names
    )

    foreach ($name in $Names) {
        $prop = $InputObject.PSObject.Properties[$name]
        if ($prop -and -not [string]::IsNullOrWhiteSpace($prop.Value)) {
            return $prop.Value.ToString()
        }
    }
    return $null
}
