function Get-DlpRulePolicyNames {
    param([Parameter(Mandatory)][object]$Rule)

    $names = New-Object System.Collections.Generic.List[string]
    if ($Rule.ParentPolicyName) {
        $names.Add($Rule.ParentPolicyName.ToString()) | Out-Null
    }
    foreach ($policy in @($Rule.Policy)) {
        if ($policy) {
            $names.Add($policy.ToString()) | Out-Null
        }
    }

    return @($names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
}
