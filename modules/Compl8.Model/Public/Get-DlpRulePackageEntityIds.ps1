function Get-DlpRulePackageEntityIds {
    param([Parameter(Mandatory)][object[]]$Packages)

    $results = @()
    foreach ($pkg in @($Packages)) {
        $entityIds = @()
        $rulePackId = $null
        $packageName = $null
        $parsed = $false
        $parseError = $null
        $rawText = Convert-DlpSerializedRulePackageToText -Raw $pkg.SerializedClassificationRuleCollection
        if ($rawText) {
            try {
                [xml]$xml = $rawText
                $parsed = $true
                $rulePack = $xml.RulePackage.RulePack
                if ($rulePack -and $rulePack.id) {
                    $rulePackId = $rulePack.id.ToString()
                }
                if ($rulePack -and $rulePack.Details -and $rulePack.Details.LocalizedDetails) {
                    $packageName = ($rulePack.Details.LocalizedDetails | Select-Object -First 1).Name
                }
                $rules = $xml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq "Rules" } | Select-Object -First 1
                if ($rules) {
                    $entityIds = @($rules.ChildNodes |
                        Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -eq "Entity" } |
                        ForEach-Object { $_.GetAttribute("id") } |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                        Sort-Object -Unique)
                }
            } catch {
                $parseError = $_.Exception.Message
                Write-Warning "Could not parse classifier package XML for '$($pkg.Identity)': $parseError"
            }
        } else {
            $parseError = "SerializedClassificationRuleCollection was empty."
        }

        $results += [pscustomobject]@{
            Identity   = if ($pkg.Identity) { $pkg.Identity.ToString() } else { $null }
            Name       = if ($packageName) { $packageName } elseif ($pkg.Name) { $pkg.Name.ToString() } else { $null }
            Publisher  = if ($pkg.Publisher) { $pkg.Publisher.ToString() } else { $null }
            RulePackId = $rulePackId
            EntityIds  = @($entityIds)
            Parsed     = [bool]$parsed
            ParseError  = $parseError
            Package    = $pkg
        }
    }

    return $results
}
