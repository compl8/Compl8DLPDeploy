function Get-Compl8IdentityResolver {
    <#
    .SYNOPSIS
        Returns the CONNECTED identity resolver — a scriptblock that classifies a reference for
        Get-Compl8ReferenceReadiness as 'exists' | 'missing' | 'external' | 'unverified' by looking it up
        in the tenant. This is the live half of the reference-existence blocker (the pure half does
        collection + token exemption + the block decision).

    .DESCRIPTION
        The returned scriptblock, invoked as & $resolver $value, classifies one reference:

          * EXTERNAL — an email whose domain is NOT a tenant ACCEPTED domain (Get-AcceptedDomain): not a
            tenant object, so EXEMPT (the stated exception). NOTE: a BARE domain is NOT classified here —
            domain-context references are exempted upstream by their reference KIND (kind='domain' in
            Get-Compl8ReferenceReadiness), because a bare domain and a dotted recipient ALIAS ('DL.Security')
            are syntactically identical and only the source field distinguishes them. So a no-'@' value
            reaching this resolver is always treated as a recipient identity to validate.
          * EXISTS / MISSING — an internal identity (a name/alias, or an email at an accepted domain): looked up
            with Get-Recipient (which spans mailboxes, mail-enabled groups and distribution lists). Found
            => 'exists'; not found => 'missing' (this is the blocking case — the deploy points at a tenant
            object that does not exist).
          * UNVERIFIED — the tenant could not be queried (cmdlet unavailable / call failed), or an email's
            domain could not be classified for lack of accepted-domain data. Reported, not blocking — a
            connected re-run resolves it (you cannot block on what you could not check).

        Fail-safe: any cmdlet that is absent or throws yields 'unverified', never a false 'missing'. NOTE:
        SharePoint site references (a future broad-scope case) are not resolved here — Get-Recipient does
        not cover sites; add a Get-SPOSite branch when policies carry site scope members.

    .OUTPUTS
        A [scriptblock] of the form { param([string]$Value) -> 'exists'|'missing'|'external'|'unverified' }.
    #>
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param()

    {
        param([string]$Value)
        $v = ([string]$Value).Trim()
        if ([string]::IsNullOrWhiteSpace($v)) { return 'unverified' }

        # Resolve an internal identity (name or internal email) via Get-Recipient (spans mailbox/group/DL).
        # CRITICAL fail-safe: an EXO cmdlet that is present but NOT CONNECTED must yield 'unverified', not a
        # false 'missing'. We cannot rely on -ErrorAction SilentlyContinue + empty result to mean
        # "not found" (a disconnected session also returns empty). So use -ErrorAction Stop and CLASSIFY
        # the failure: a genuine not-found error => 'missing' (blocking); any other failure (not connected,
        # auth, transient) => 'unverified' (re-run connected).
        $resolveRecipient = {
            param([string]$Identity)
            if (-not (Get-Command Get-Recipient -ErrorAction SilentlyContinue)) { return 'unverified' }
            try {
                $hit = Get-Recipient -Identity $Identity -ErrorAction Stop
                if ($hit) { 'exists' } else { 'missing' }
            } catch {
                $msg = [string]$_.Exception.Message
                if ($msg -match "couldn't be found|could not be found|wasn't found|was not found|isn't a valid|not found|ManagementObjectNotFound") { 'missing' } else { 'unverified' }
            }
        }

        if ($v -match '@') {
            # An email: external unless its domain is a tenant accepted domain.
            $domain = ($v -split '@', 2)[1]
            $accepted = $null
            if (Get-Command Get-AcceptedDomain -ErrorAction SilentlyContinue) {
                try {
                    $accepted = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($d in @(Get-AcceptedDomain -ErrorAction Stop)) {
                        foreach ($f in 'DomainName', 'Name', 'Id') { if ($d.PSObject.Properties[$f] -and $d.$f) { $accepted.Add([string]$d.$f) | Out-Null } }
                    }
                } catch { $accepted = $null }
            }
            if ($null -eq $accepted) {
                # Can't tell internal vs external by domain — try a recipient lookup; if found it's
                # internal+exists, otherwise we genuinely can't classify it (avoid a false 'missing').
                $r = & $resolveRecipient $v
                if ($r -eq 'exists') { return 'exists' }
                return 'unverified'
            }
            if ($accepted.Contains($domain)) { return (& $resolveRecipient $v) }   # internal email
            return 'external'
        }

        # No '@'. In a RECIPIENT context (the only references collected today — GenerateIncidentReport /
        # NotifyUser) a no-'@' value is an internal identity ALIAS, even when it contains dots (e.g.
        # 'DL.Security', 'ops.team'). It must be validated as a recipient, NOT exempted as a "bare domain"
        # — a missing alias has to BLOCK, not slip through (codex). External-DOMAIN exemption applies only
        # to emails (the '@' branch above); a genuine domain-context condition field (a future broad-scope
        # case) would be tagged by the collector and classified separately when such fields are collected.
        return (& $resolveRecipient $v)
    }
}
