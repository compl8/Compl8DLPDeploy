function ConvertTo-DeploymentNameTemplates {
    param([object]$Templates)

    $result = @{}
    if (-not $Templates) { return $result }

    if ($Templates -is [hashtable]) {
        foreach ($key in $Templates.Keys) {
            $result[$key] = $Templates[$key]
        }
        return $result
    }

    foreach ($prop in $Templates.PSObject.Properties) {
        $result[$prop.Name] = $prop.Value
    }
    return $result
}
