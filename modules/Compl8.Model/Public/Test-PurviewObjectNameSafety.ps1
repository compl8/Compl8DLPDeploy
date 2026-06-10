function Test-PurviewObjectNameSafety {
    <#
    .SYNOPSIS
        Validates a generated Purview object identity against the deployment-safe
        naming policy.

    .DESCRIPTION
        Purview and Security & Compliance cmdlets can accept names that later
        become hard to query or remove. This guard intentionally uses a stricter
        deployment policy than a permissive service-side parser: ASCII letters,
        digits, underscore, dot, and hyphen only.
    #>
    param(
        [AllowNull()][AllowEmptyString()][string]$Name,
        [string]$ObjectType = "Purview object",
        [int]$MaxLength = 128
    )

    $reasons = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Name) {
        $reasons.Add("Name is null.")
    } elseif ([string]::IsNullOrWhiteSpace($Name)) {
        $reasons.Add("Name is empty or whitespace.")
    } else {
        if ($Name -ne $Name.Trim()) {
            $reasons.Add("Name has leading or trailing whitespace.")
        }
        if ($Name.Length -gt $MaxLength) {
            $reasons.Add("Name length $($Name.Length) exceeds max $MaxLength.")
        }
        if ($Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') {
            $unsafeChars = @(Get-PurviewUnsafeNameCharacterSummary -Name $Name)
            if ($unsafeChars.Count -gt 0) {
                $reasons.Add("Name contains unsupported character(s): $($unsafeChars -join ', ').")
            }
            $reasons.Add("Name must match ^[A-Za-z0-9][A-Za-z0-9_.-]*$.")
        }
    }

    return [PSCustomObject]@{
        IsSafe         = ($reasons.Count -eq 0)
        Name           = $Name
        ObjectType     = $ObjectType
        MaxLength      = $MaxLength
        AllowedPattern = '^[A-Za-z0-9][A-Za-z0-9_.-]*$'
        Reasons        = @($reasons)
    }
}
