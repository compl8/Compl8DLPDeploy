function Get-DlpClassifierRuleReferences {
    param([Parameter(Mandatory)][string[]]$CandidateIds)

    $candidateLookup = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @($CandidateIds)) {
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $candidateLookup.Add($id.ToString()) | Out-Null
        }
    }

    $result = [pscustomobject]@{
        CandidateIdCount = $candidateLookup.Count
        RulesScanned     = 0
        MatchingRuleCount = 0
        References       = @()
    }
    if ($candidateLookup.Count -eq 0) { return $result }

    try {
        $rules = @(Get-DlpComplianceRule -ErrorAction Stop)
    } catch {
        Write-Warning "Could not retrieve DLP rules for classifier reference check: $($_.Exception.Message)"
        return $result
    }

    $guidPattern = '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
    $references = @()
    foreach ($rule in $rules) {
        $result.RulesScanned++
        $ruleText = Get-DlpRuleClassifierReferenceText -Rule $rule
        if (-not $ruleText) { continue }

        $matchedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($match in [regex]::Matches($ruleText, $guidPattern)) {
            if ($candidateLookup.Contains($match.Value)) {
                $matchedIds.Add($match.Value.ToLowerInvariant()) | Out-Null
            }
        }
        if ($matchedIds.Count -eq 0) { continue }

        $references += [pscustomobject]@{
            RuleName = if ($rule.Name) { $rule.Name.ToString() } elseif ($rule.Identity) { $rule.Identity.ToString() } else { "(unknown)" }
            PolicyNames = @(Get-DlpRulePolicyNames -Rule $rule)
            MatchedClassifierIds = @($matchedIds | Sort-Object)
        }
    }

    $result.MatchingRuleCount = @($references).Count
    $result.References = @($references)
    return $result
}
