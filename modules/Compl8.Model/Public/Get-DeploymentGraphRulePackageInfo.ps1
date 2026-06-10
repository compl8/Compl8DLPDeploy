function Get-DeploymentGraphRulePackageInfo {
    param([Parameter(Mandatory)][object]$Package)

    $identity = Get-DeploymentGraphObjectValue -InputObject $Package -Names @("Identity", "Id", "Guid")
    $name = Get-DeploymentGraphObjectValue -InputObject $Package -Names @("Name", "DisplayName")
    $publisher = Get-DeploymentGraphObjectValue -InputObject $Package -Names @("Publisher")
    $rawText = Convert-DlpSerializedRulePackageToText -Raw $Package.SerializedClassificationRuleCollection

    $result = [pscustomobject]@{
        Identity   = $identity
        Name       = $name
        Publisher  = $publisher
        RulePackId = $null
        Parsed     = $false
        ParseError  = $null
        Xml        = $null
        RawText    = $rawText
    }

    if (-not $rawText) {
        $result.ParseError = "SerializedClassificationRuleCollection was empty."
        return $result
    }

    try {
        [xml]$xml = $rawText
        $result.Xml = $xml
        $result.Parsed = $true
        $rulePack = $xml.RulePackage.RulePack
        if ($rulePack -and $rulePack.id) {
            $result.RulePackId = $rulePack.id.ToString()
        }
        if ($rulePack -and $rulePack.Details -and $rulePack.Details.LocalizedDetails) {
            $localized = $rulePack.Details.LocalizedDetails | Select-Object -First 1
            if ($localized -and $localized.Name) {
                $result.Name = $localized.Name.ToString()
            }
        }
    } catch {
        $result.ParseError = $_.Exception.Message
    }

    return $result
}
