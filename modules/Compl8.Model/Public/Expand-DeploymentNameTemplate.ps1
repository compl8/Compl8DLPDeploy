function Expand-DeploymentNameTemplate {
    param(
        [Parameter(Mandatory)][string]$Template,
        [Parameter(Mandatory)][hashtable]$Tokens
    )

    $expanded = $Template
    foreach ($key in @($Tokens.Keys | Sort-Object { $_.Length } -Descending)) {
        $value = if ($null -eq $Tokens[$key]) { "" } else { $Tokens[$key].ToString() }
        $expanded = $expanded.Replace("{$key}", $value)
    }

    # Drop any {placeholder} that no caller supplied so we never leak literal tokens into Purview names.
    $expanded = $expanded -replace '\{[^{}]+\}', ''

    return (($expanded -replace '-{2,}', '-').Trim('-').Trim())
}
