function Get-DlpRuleClassifierReferenceText {
    param([Parameter(Mandatory)][object]$Rule)

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($propertyName in @(
        "ContentContainsSensitiveInformation",
        "ExceptIfContentContainsSensitiveInformation",
        "AdvancedRule",
        "Conditions",
        "Exceptions"
    )) {
        $property = $Rule.PSObject.Properties[$propertyName]
        if (-not $property -or $null -eq $property.Value) { continue }
        try {
            $parts.Add(($property.Value | ConvertTo-Json -Depth 20 -Compress)) | Out-Null
        } catch {
            $parts.Add($property.Value.ToString()) | Out-Null
        }
    }

    return ($parts -join "`n")
}
