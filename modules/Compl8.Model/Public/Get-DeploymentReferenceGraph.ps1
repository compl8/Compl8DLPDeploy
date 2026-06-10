function Get-DeploymentReferenceGraph {
    <#
    .SYNOPSIS
        Builds a dependency graph across Purview deployment objects.
    .DESCRIPTION
        Produces stable node and edge records for the roadmap substrate:
        keyword dictionary -> sensitive information type -> DLP rule -> DLP policy -> label.
        The function is intentionally pure: callers pass already-fetched tenant/config
        objects so destructive guards can reuse the same parser without introducing new
        tenant calls in tests or plan-generation paths.
    #>
    param(
        [object[]]$Dictionaries = @(),
        [object[]]$SitPackages = @(),
        [object[]]$DlpRules = @(),
        [object[]]$DlpPolicies = @(),
        [object[]]$Labels = @()
    )

    $nodes = New-Object System.Collections.Generic.List[object]
    $edges = New-Object System.Collections.Generic.List[object]
    $nodesById = @{}
    $edgesByKey = @{}
    $knownSitIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $labelIdByCode = @{}
    $unparsedPackageCount = 0

    function Add-GraphNode {
        param(
            [Parameter(Mandatory)][string]$Id,
            [Parameter(Mandatory)][string]$Type,
            [string]$Name,
            [string]$Identity,
            [string]$Source,
            [hashtable]$Properties = @{}
        )

        if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
        if (-not $nodesById.ContainsKey($Id)) {
            $node = [pscustomobject]@{
                Id         = $Id
                Type       = $Type
                Name       = $Name
                Identity   = $Identity
                Source     = $Source
                Properties = [pscustomobject]$Properties
            }
            $nodesById[$Id] = $node
            $nodes.Add($node) | Out-Null
        } else {
            $node = $nodesById[$Id]
            if ([string]::IsNullOrWhiteSpace($node.Name) -and -not [string]::IsNullOrWhiteSpace($Name)) {
                $node.Name = $Name
            }
            if ([string]::IsNullOrWhiteSpace($node.Identity) -and -not [string]::IsNullOrWhiteSpace($Identity)) {
                $node.Identity = $Identity
            }
        }
        return $Id
    }

    function Add-GraphEdge {
        param(
            [Parameter(Mandatory)][string]$From,
            [Parameter(Mandatory)][string]$To,
            [Parameter(Mandatory)][string]$Type,
            [string]$Source,
            [hashtable]$Properties = @{}
        )

        if ([string]::IsNullOrWhiteSpace($From) -or [string]::IsNullOrWhiteSpace($To)) { return }
        $key = "{0}|{1}|{2}" -f $From, $To, $Type
        if ($edgesByKey.ContainsKey($key)) { return }
        $edge = [pscustomobject]@{
            From       = $From
            To         = $To
            Type       = $Type
            Source     = $Source
            Properties = [pscustomobject]$Properties
        }
        $edgesByKey[$key] = $true
        $edges.Add($edge) | Out-Null
    }

    foreach ($dictionary in @($Dictionaries)) {
        if (-not $dictionary) { continue }
        $identity = Get-DeploymentGraphObjectValue -InputObject $dictionary -Names @("Identity", "Guid", "Id")
        $name = Get-DeploymentGraphObjectValue -InputObject $dictionary -Names @("Name", "DisplayName")
        $nodeValue = if ($identity) { $identity } elseif ($name) { $name } else { $null }
        if (-not $nodeValue) { continue }
        $nodeId = New-DeploymentGraphNodeId -Prefix "dictionary" -Value $nodeValue
        Add-GraphNode -Id $nodeId -Type "KeywordDictionary" -Name $name -Identity $identity -Source "KeywordDictionary" -Properties @{ Missing = $false } | Out-Null
    }

    foreach ($label in @($Labels)) {
        if (-not $label) { continue }
        $code = Get-DeploymentGraphObjectValue -InputObject $label -Names @("code", "Code", "LabelCode")
        $name = Get-DeploymentGraphObjectValue -InputObject $label -Names @("name", "Name", "fullName", "displayName", "DisplayName")
        $identity = Get-DeploymentGraphObjectValue -InputObject $label -Names @("Identity", "Guid", "Id")
        $nodeValue = if ($identity) { $identity } elseif ($name) { $name } elseif ($code) { $code } else { $null }
        if (-not $nodeValue) { continue }
        $nodeId = New-DeploymentGraphNodeId -Prefix "label" -Value $nodeValue
        Add-GraphNode -Id $nodeId -Type "Label" -Name $name -Identity $identity -Source "LabelConfig" -Properties @{ Code = $code } | Out-Null
        if ($code -and -not $labelIdByCode.ContainsKey($code)) {
            $labelIdByCode[$code] = $nodeId
        }
    }

    foreach ($policy in @($DlpPolicies)) {
        if (-not $policy) { continue }
        $name = Get-DeploymentGraphObjectValue -InputObject $policy -Names @("Name", "Identity", "DisplayName")
        $identity = Get-DeploymentGraphObjectValue -InputObject $policy -Names @("Identity", "Id", "Guid")
        $nodeValue = if ($name) { $name } elseif ($identity) { $identity } else { $null }
        if (-not $nodeValue) { continue }
        $nodeId = New-DeploymentGraphNodeId -Prefix "dlpPolicy" -Value $nodeValue
        Add-GraphNode -Id $nodeId -Type "DlpPolicy" -Name $name -Identity $identity -Source "DlpPolicy" -Properties @{ Missing = $false } | Out-Null
    }

    foreach ($package in @($SitPackages)) {
        if (-not $package) { continue }
        $info = Get-DeploymentGraphRulePackageInfo -Package $package
        if (-not $info.Parsed) { $unparsedPackageCount++ }
        $packageValue = if ($info.RulePackId) { $info.RulePackId } elseif ($info.Identity) { $info.Identity } elseif ($info.Name) { $info.Name } else { $null }
        if (-not $packageValue) { continue }

        $packageNodeId = New-DeploymentGraphNodeId -Prefix "sitPackage" -Value $packageValue
        Add-GraphNode -Id $packageNodeId -Type "SitPackage" -Name $info.Name -Identity $info.Identity -Source "DlpRulePackage" -Properties @{
            RulePackId = $info.RulePackId
            Publisher = $info.Publisher
            Parsed = [bool]$info.Parsed
            ParseError = $info.ParseError
        } | Out-Null

        if (-not $info.Parsed -or -not $info.Xml) { continue }
        $rules = $info.Xml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq "Rules" } | Select-Object -First 1
        if (-not $rules) { continue }

        foreach ($entity in @($rules.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -eq "Entity" })) {
            $entityId = $entity.GetAttribute("id")
            if ([string]::IsNullOrWhiteSpace($entityId)) { continue }
            $entityId = $entityId.ToLowerInvariant()
            $sitNodeId = New-DeploymentGraphNodeId -Prefix "sit" -Value $entityId
            $knownSitIds.Add($entityId) | Out-Null
            Add-GraphNode -Id $sitNodeId -Type "SensitiveInformationType" -Name $null -Identity $entityId -Source "RulePackageEntity" -Properties @{
                RulePackId = $info.RulePackId
                PackageIdentity = $info.Identity
                PackageName = $info.Name
            } | Out-Null
            Add-GraphEdge -From $packageNodeId -To $sitNodeId -Type "packageContainsSit" -Source "RulePackageEntity" -Properties @{ RulePackId = $info.RulePackId } | Out-Null

            foreach ($dictionaryId in @(Get-DictionaryGuidReferences -PackageXmlText $entity.OuterXml)) {
                $dictionaryNodeId = New-DeploymentGraphNodeId -Prefix "dictionary" -Value $dictionaryId
                $missing = -not $nodesById.ContainsKey($dictionaryNodeId)
                Add-GraphNode -Id $dictionaryNodeId -Type "KeywordDictionary" -Name $null -Identity $dictionaryId -Source "RulePackageDictionaryReference" -Properties @{ Missing = $missing } | Out-Null
                Add-GraphEdge -From $dictionaryNodeId -To $sitNodeId -Type "dictionaryFeedsSit" -Source "RulePackageEntity" -Properties @{ RulePackId = $info.RulePackId } | Out-Null
            }
        }
    }

    $labelCodesByLength = @($labelIdByCode.Keys | Sort-Object { $_.Length } -Descending)
    $guidPattern = '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
    foreach ($rule in @($DlpRules)) {
        if (-not $rule) { continue }
        $ruleName = Get-DeploymentGraphObjectValue -InputObject $rule -Names @("Name", "Identity", "DisplayName")
        $ruleIdentity = Get-DeploymentGraphObjectValue -InputObject $rule -Names @("Identity", "Id", "Guid")
        $ruleValue = if ($ruleName) { $ruleName } elseif ($ruleIdentity) { $ruleIdentity } else { $null }
        if (-not $ruleValue) { continue }
        $ruleNodeId = New-DeploymentGraphNodeId -Prefix "dlpRule" -Value $ruleValue
        Add-GraphNode -Id $ruleNodeId -Type "DlpRule" -Name $ruleName -Identity $ruleIdentity -Source "DlpRule" -Properties @{} | Out-Null

        $ruleText = Get-DlpRuleClassifierReferenceText -Rule $rule
        if ($ruleText) {
            $matchedSitIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($match in [regex]::Matches($ruleText, $guidPattern)) {
                if ($knownSitIds.Contains($match.Value)) {
                    $matchedSitIds.Add($match.Value.ToLowerInvariant()) | Out-Null
                }
            }
            foreach ($sitId in @($matchedSitIds | Sort-Object)) {
                $sitNodeId = New-DeploymentGraphNodeId -Prefix "sit" -Value $sitId
                Add-GraphEdge -From $sitNodeId -To $ruleNodeId -Type "sitReferencedByRule" -Source "DlpRule" -Properties @{} | Out-Null
            }
        }

        $policyNames = @(Get-DlpRulePolicyNames -Rule $rule)
        foreach ($policyName in $policyNames) {
            if ([string]::IsNullOrWhiteSpace($policyName)) { continue }
            $policyNodeId = New-DeploymentGraphNodeId -Prefix "dlpPolicy" -Value $policyName
            Add-GraphNode -Id $policyNodeId -Type "DlpPolicy" -Name $policyName -Identity $policyName -Source "DlpRulePolicyReference" -Properties @{ Missing = -not $nodesById.ContainsKey($policyNodeId) } | Out-Null
            Add-GraphEdge -From $ruleNodeId -To $policyNodeId -Type "ruleBelongsToPolicy" -Source "DlpRule" -Properties @{} | Out-Null
        }

        foreach ($labelCode in $labelCodesByLength) {
            if ([string]::IsNullOrWhiteSpace($labelCode) -or [string]::IsNullOrWhiteSpace($ruleName)) { continue }
            $escapedCode = [regex]::Escape($labelCode)
            if (-not [regex]::IsMatch($ruleName, "(^|-)$escapedCode(-|$)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
                continue
            }
            $labelNodeId = $labelIdByCode[$labelCode]
            foreach ($policyName in $policyNames) {
                if ([string]::IsNullOrWhiteSpace($policyName)) { continue }
                $policyNodeId = New-DeploymentGraphNodeId -Prefix "dlpPolicy" -Value $policyName
                Add-GraphEdge -From $policyNodeId -To $labelNodeId -Type "policyTargetsLabel" -Source "DlpRuleName" -Properties @{ LabelCode = $labelCode; RuleName = $ruleName } | Out-Null
            }
            break
        }
    }

    $nodeArray = @($nodes.ToArray())
    $edgeArray = @($edges.ToArray())

    return [pscustomobject]@{
        Nodes   = $nodeArray
        Edges   = $edgeArray
        Summary = [pscustomobject]@{
            NodeCount            = $nodeArray.Count
            EdgeCount            = $edgeArray.Count
            DictionaryCount      = @($nodeArray | Where-Object { $_.Type -eq "KeywordDictionary" }).Count
            SitPackageCount      = @($nodeArray | Where-Object { $_.Type -eq "SitPackage" }).Count
            SitCount             = @($nodeArray | Where-Object { $_.Type -eq "SensitiveInformationType" }).Count
            DlpRuleCount         = @($nodeArray | Where-Object { $_.Type -eq "DlpRule" }).Count
            DlpPolicyCount       = @($nodeArray | Where-Object { $_.Type -eq "DlpPolicy" }).Count
            LabelCount           = @($nodeArray | Where-Object { $_.Type -eq "Label" }).Count
            UnparsedPackageCount = $unparsedPackageCount
        }
    }
}
