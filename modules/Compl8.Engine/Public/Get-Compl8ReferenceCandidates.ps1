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
        NotifyUser) — emitted with kind='recipient' (validated as identities). Each value is split on ',' / ';'.

    .PARAMETER DomainFields
        The content fields whose values are DOMAIN references (a 'recipient domain is X' style condition) —
        emitted with kind='domain' (exempt as external). Default none (the current config has no such
        field); this is the extension point so a bare domain is never mis-validated as a recipient alias.

    .OUTPUTS
        Zero or more references: { value; source; kind ('recipient'|'domain') } (ordered by value, source).
    #>
    [CmdletBinding()]
    param(
        [object[]]$DesiredRules = @(),
        [object[]]$DesiredPolicies = @(),
        [string[]]$RecipientFields = @('GenerateIncidentReport', 'NotifyUser'),
        [string[]]$DomainFields = @()
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

    # Each field maps to a reference KIND: a 'recipient' field's no-'@' value is an identity ALIAS that
    # must be validated; a 'domain' field's value is a domain that is exempt (external). The kind — not
    # the value's shape — is what distinguishes a dotted alias ('DL.Security') from a bare domain.
    $fieldKinds = [ordered]@{}
    foreach ($f in @($RecipientFields)) { if ($f) { $fieldKinds[$f] = 'recipient' } }
    foreach ($f in @($DomainFields))    { if ($f) { $fieldKinds[$f] = 'domain' } }

    $refs = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in @($DesiredRules)) {
        if (-not $rule) { continue }
        $ruleName = if ($rule.PSObject.Properties['ruleName']) { [string]$rule.ruleName } else { '' }
        $content  = if ($rule.PSObject.Properties['content'])  { $rule.content } else { $null }
        foreach ($field in @($fieldKinds.Keys)) {
            $val = Get-ContentField -Content $content -Field $field
            if ($null -eq $val) { continue }
            # A boolean is an enabled-SWITCH (e.g. GenerateIncidentReport = $true via an override / persisted
            # projection), NOT a named identity — skip it, or the resolver would classify "True" as a
            # missing recipient and false-block the deploy (codex).
            if ($val -is [bool]) { continue }
            if ([string]::IsNullOrWhiteSpace([string]$val)) { continue }
            foreach ($piece in ([string]$val -split '[;,]')) {
                $p = $piece.Trim()
                if (-not $p) { continue }
                if ($p -in 'True', 'False') { continue }   # stringified switch (defensive)
                $refs.Add([pscustomobject]@{ value = $p; source = "$field ($ruleName)"; kind = $fieldKinds[$field] }) | Out-Null
            }
        }
    }

    @($refs | Sort-Object @{ Expression = { $_.value } }, @{ Expression = { $_.source } })
}
