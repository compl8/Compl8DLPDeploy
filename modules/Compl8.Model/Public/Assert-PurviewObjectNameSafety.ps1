function Assert-PurviewObjectNameSafety {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Names,
        [string]$ObjectType = "Purview object",
        [int]$MaxLength = 128
    )

    $failures = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @($Names)) {
        $result = Test-PurviewObjectNameSafety -Name $name -ObjectType $ObjectType -MaxLength $MaxLength
        if (-not $result.IsSafe) {
            $displayName = if ($null -eq $result.Name) { "<null>" } else { "'$($result.Name)'" }
            $failures.Add("$ObjectType $displayName`: $($result.Reasons -join ' ')")
        }
    }

    if ($failures.Count -gt 0) {
        throw "Unsafe Purview object name(s) blocked before tenant submission:`n  - $($failures -join "`n  - ")"
    }

    return $true
}
