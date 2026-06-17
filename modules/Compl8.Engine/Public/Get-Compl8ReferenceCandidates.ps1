function Get-Compl8ReferenceCandidates {
    <#
    .SYNOPSIS
        Collects the NAMED IDENTITY references a desired deploy carries, to feed
        Get-Compl8ReferenceReadiness (the reference-existence blocker). Pure.

    .DESCRIPTION
        Walks the desired DLP rule records (Resolve-DesiredDlpRules output — each carries a .content
        param set) and extracts the values of the identity-bearing RECIPIENT fields (GenerateIncidentReport
        and NotifyUser by default), splitting comma/semicolon-separated lists into individual references.
        Each reference records its source (field + rule) so a missing one can be pinpointed.

        What it does NOT collect: rule SCOPE FILTERS (e.g. AccessScope=NotInOrganization) — those are
        condition predicates, not tenant identities, so they are never validated for existence. The
        -RecipientFields parameter is the extension point: as the config grows other identity-bearing
        fields (named groups/users/SharePoint sites in conditions or policy scope), add them here and they
        flow through the same readiness check.

    .PARAMETER DesiredRules
        Desired DLP rule records (objects with .ruleName and .content — a hashtable or pscustomobject of
        rule params, e.g. from Resolve-DesiredDlpRules or the persisted desired/resolved/dlp-rules.json).

    .PARAMETER DesiredPolicies
        Optional desired policy records. Reserved for policy-scope identity members (none in the current
        config model — policy scope is location='All' / rule-level filters, not named entities).

    .PARAMETER RecipientFields
        The content fields whose values are tenant-identity references (default GenerateIncidentReport,
        NotifyUser). Each value is split on ',' and ';'.

    .OUTPUTS
        Zero or more references: { value; source } (deterministically ordered by value then source).
    #>
    [CmdletBinding()]
    param(
        [object[]]$DesiredRules = @(),
        [object[]]$DesiredPolicies = @(),
        [string[]]$RecipientFields = @('GenerateIncidentReport', 'NotifyUser')
    )

    # Read a field from rule .content whether it is a hashtable or a pscustomobject.
    function Get-ContentField { param($Content, [string]$Field)
        if ($null -eq $Content) { return $null }
        if ($Content -is [System.Collections.IDictionary]) {
            if ($Content.Contains($Field)) { return $Content[$Field] } else { return $null }
        }
        $p = $Content.PSObject.Properties[$Field]
        if ($p) { return $p.Value } else { return $null }
    }

    $refs = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in @($DesiredRules)) {
        if (-not $rule) { continue }
        $ruleName = if ($rule.PSObject.Properties['ruleName']) { [string]$rule.ruleName } else { '' }
        $content  = if ($rule.PSObject.Properties['content'])  { $rule.content } else { $null }
        foreach ($field in @($RecipientFields)) {
            $val = Get-ContentField -Content $content -Field $field
            if ($null -eq $val -or [string]::IsNullOrWhiteSpace([string]$val)) { continue }
            foreach ($piece in ([string]$val -split '[;,]')) {
                $p = $piece.Trim()
                if ($p) { $refs.Add([pscustomobject]@{ value = $p; source = "$field ($ruleName)" }) | Out-Null }
            }
        }
    }

    @($refs | Sort-Object @{ Expression = { $_.value } }, @{ Expression = { $_.source } })
}
