function Remove-DeploymentNamePrefix {
    param(
        [string]$Name,
        [string]$Prefix
    )

    if ([string]::IsNullOrWhiteSpace($Name) -or [string]::IsNullOrWhiteSpace($Prefix)) {
        return $Name
    }

    $marker = "$Prefix-"
    if ($Name.StartsWith($marker, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Name.Substring($marker.Length)
    }
    return $Name
}
