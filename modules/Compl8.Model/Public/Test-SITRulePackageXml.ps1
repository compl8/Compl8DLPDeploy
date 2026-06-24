function Test-SITRulePackageXml {
    <#
    .SYNOPSIS
        Validates a SIT rule package XML file for Purview compliance.
    .OUTPUTS
        PSCustomObject with Valid (bool), Errors (string[]), Warnings (string[]), FileSize (int)
    #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [int]$MaxFileSizeBytes = (Get-DeploymentLimits).MaxRulePackageBytes
    )

    $result = [PSCustomObject]@{
        Valid    = $true
        Errors   = [System.Collections.Generic.List[string]]::new()
        Warnings = [System.Collections.Generic.List[string]]::new()
        FileSize = 0
    }

    if (-not (Test-Path $FilePath)) {
        $result.Valid = $false
        $result.Errors.Add("File not found: $FilePath")
        return $result
    }

    # Empty-file guard: check on-disk length before reading content.
    if ((Get-Item $FilePath).Length -eq 0) {
        $result.Valid = $false
        $result.Errors.Add("File is empty")
        return $result
    }

    # Read content once for both XML parsing and size measurement.
    $content = $null
    $xml = $null
    try {
        $content = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::UTF8)
        $xml = [xml]$content
    } catch {
        try {
            $content = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::Unicode)
            $xml = [xml]$content
        } catch {
            $result.Valid = $false
            $result.Errors.Add("XML parse error: $($_.Exception.Message)")
            return $result
        }
    }

    # Measure UTF-16 size: Purview's real package-size unit (matches the packer's Utf16SizeBytes).
    $result.FileSize = [System.Text.Encoding]::Unicode.GetByteCount($content)

    if ($result.FileSize -gt $MaxFileSizeBytes) {
        $result.Valid = $false
        $result.Errors.Add("File exceeds 150KB UTF-16 limit: $([math]::Round($result.FileSize / 1KB, 1))KB (UTF-16)")
    }

    # Validate structure
    if ($xml.DocumentElement.LocalName -ne "RulePackage") {
        $result.Valid = $false
        $result.Errors.Add("Root element is '$($xml.DocumentElement.LocalName)', expected 'RulePackage'")
    }

    $rulePack = $xml.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq "RulePack" }
    if (-not $rulePack) {
        $result.Valid = $false
        $result.Errors.Add("Missing <RulePack> element")
    }

    $rules = $xml.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq "Rules" }
    if (-not $rules) {
        $result.Valid = $false
        $result.Errors.Add("Missing <Rules> element")
    } else {
        $entities = $rules.ChildNodes | Where-Object { $_.LocalName -eq "Entity" }
        $entityCount = @($entities).Count
        if ($entityCount -eq 0) {
            $result.Warnings.Add("No <Entity> elements found inside <Rules>")
        } elseif ($entityCount -gt 50) {
            $result.Valid = $false
            $result.Errors.Add("Contains $entityCount entities (max 50 per package)")
        }

        $localizedInRules = $rules.ChildNodes | Where-Object { $_.LocalName -eq "LocalizedStrings" }
        if (-not $localizedInRules) {
            $result.Warnings.Add("No <LocalizedStrings> found directly inside <Rules>")
        }

        foreach ($entity in @($entities)) {
            $badLocalized = $entity.ChildNodes | Where-Object { $_.LocalName -eq "LocalizedStrings" }
            if ($badLocalized) {
                $result.Valid = $false
                $result.Errors.Add("Entity '$($entity.GetAttribute('id'))' has <LocalizedStrings> inside it (must be in <Rules>)")
            }
        }
    }

    return $result
}
