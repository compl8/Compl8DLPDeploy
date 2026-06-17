function Get-Compl8ReferenceReadiness {
    <#
    .SYNOPSIS
        The reference-existence pre-flight BLOCKER (planner depth): given the NAMED identities a deploy
        references, decide whether the deploy may proceed — it must NOT if any INTERNAL identity (a tenant
        object the deployable points at) does not exist. "Fix it before deploy."

    .DESCRIPTION
        Pure given an injectable -Resolver (the connected tenant lookup), so the collection, classification
        and block decision are fully unit-testable. Each reference is classified:

          * BUILT-IN TOKEN — SiteAdmin / Owner / LastModifier (the Purview special recipients). Not tenant
            objects; always valid; EXEMPT (never probed).
          * EXTERNAL — an external domain or external email (e.g. a partner address, a bare domain). Not a
            tenant object; EXEMPT (the stated exception — external domains/emails are never required to
            exist). The -Resolver reports these as 'external'.
          * INTERNAL, EXISTS — a tenant identity (mailbox / group / site) the -Resolver confirms exists. OK.
          * INTERNAL, MISSING — a tenant identity the -Resolver reports absent. This is BLOCKING: the deploy
            references an object that does not exist and must be fixed first.
          * UNVERIFIED — the -Resolver could not determine (returned $null / unknown), or no -Resolver was
            supplied (offline). Reported, but NOT a hard block (you cannot block on what you could not
            check — run the pre-flight connected). Surfaced so it is not silently ignored.

        readiness is $false iff there is at least one MISSING (blocking) internal identity. The deploy
        path runs this connected BEFORE apply and halts on not-ready, listing exactly what to fix.

    .PARAMETER References
        The named-identity references to validate: objects with .value (the referenced name/address) and
        .source (where it came from, e.g. 'incidentReportRecipient', 'notifyUser', 'scope'). Collected by
        the caller from the desired DLP rules / policies / auto-label config.

    .PARAMETER Resolver
        Optional scriptblock invoked as & $Resolver $value for each non-token reference; it returns
        'exists' | 'missing' | 'external' | 'unverified' (or $null/unknown => unverified). It is the
        CONNECTED tenant lookup (Get-Compl8IdentityResolver / Get-Recipient / Get-Group / Get-SPOSite +
        accepted-domains) and is injected so this function stays pure. Absent => every non-token reference
        is 'unverified' (offline cannot validate).

    .PARAMETER BuiltInTokens
        The Purview special-recipient tokens treated as always-valid (default SiteAdmin/Owner/LastModifier).

    .OUTPUTS
        [pscustomobject] { ready = [bool]; findings = @({ value; source; status }); blocking = @({...});
        exempt = @({...}); unverified = @({...}) } — findings is every reference with its resolved status.
    #>
    [CmdletBinding()]
    param(
        [object[]]$References = @(),
        [scriptblock]$Resolver,
        [string[]]$BuiltInTokens = @('SiteAdmin', 'Owner', 'LastModifier')
    )

    $tokenSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in @($BuiltInTokens)) { if ($t) { $tokenSet.Add([string]$t) | Out-Null } }

    $findings   = [System.Collections.Generic.List[object]]::new()
    $blocking   = [System.Collections.Generic.List[object]]::new()
    $exempt     = [System.Collections.Generic.List[object]]::new()
    $unverified = [System.Collections.Generic.List[object]]::new()
    # Dedup (value|source) so the same reference listed by several deployables is judged once.
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($ref in @($References)) {
        if (-not $ref) { continue }
        $value  = ([string]$ref.value).Trim()
        $source = if ($ref.PSObject.Properties['source']) { [string]$ref.source } else { '' }
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        $key = "$value|$source"
        if (-not $seen.Add($key)) { continue }

        $status = $null
        if ($tokenSet.Contains($value)) {
            $status = 'token'
        } elseif ($Resolver) {
            $verdict = $null
            try { $verdict = [string](& $Resolver $value) } catch { $verdict = $null }
            switch ($verdict) {
                'exists'   { $status = 'exists' }
                'external' { $status = 'external' }
                'missing'  { $status = 'missing' }
                default    { $status = 'unverified' }
            }
        } else {
            $status = 'unverified'
        }

        $rec = [pscustomobject]@{ value = $value; source = $source; status = $status }
        $findings.Add($rec) | Out-Null
        switch ($status) {
            'missing'    { $blocking.Add($rec) | Out-Null }
            'unverified' { $unverified.Add($rec) | Out-Null }
            default      { $exempt.Add($rec) | Out-Null }   # token / external / exists are all 'ok to deploy'
        }
    }

    [pscustomobject]@{
        ready      = ($blocking.Count -eq 0)
        findings   = @($findings)
        blocking   = @($blocking)
        exempt     = @($exempt)
        unverified = @($unverified)
    }
}
