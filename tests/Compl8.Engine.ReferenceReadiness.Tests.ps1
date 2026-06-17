#Requires -Modules Pester

# =====================================================================================
# Planner depth #2 (reframed) — Get-Compl8ReferenceReadiness: the reference-existence BLOCKER.
#
# "If an object a deployable references doesn't exist in the tenant (except external domains/emails)
# it must be fixed before deploy." This is the pre-flight that enforces that: it collects every NAMED
# identity a desired DLP rule / policy / auto-label references (incident-report + notify recipients,
# and any condition/scope groups/users/sites), classifies each, and BLOCKS the deploy if an internal
# identity is missing. Built-in Purview tokens (SiteAdmin/Owner/LastModifier) and external
# domains/emails are EXEMPT. The tenant lookup is an injectable resolver (connected); this pure layer
# does the collection, token-exemption and block decision, so it is fully unit-testable.
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $script:RepoRoot 'modules' 'Compl8.Engine') -Force

    # A resolver fake: classifies a reference value as it would against a live tenant.
    $script:Resolver = {
        param([string]$Value)
        switch -Regex ($Value) {
            '@(partner|gmail|external)\.'      { 'external' }   # external email
            '^[A-Za-z0-9.-]+\.(com|org|net)$'  { 'external' }   # bare external domain
            '^DL-Security$|^security@contoso\.com$' { 'exists' } # known internal identities
            '^Ghost-Group$|^missing@contoso\.com$'  { 'missing' } # internal, does NOT exist
            default { 'unverified' }
        }
    }
}

Describe 'Get-Compl8ReferenceReadiness — surface + classification' {
    It 'is exported from Compl8.Engine' {
        (Get-Command -Name Get-Compl8ReferenceReadiness -Module Compl8.Engine -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }
    It 'exempts built-in Purview tokens (SiteAdmin/Owner/LastModifier) without probing' {
        $refs = @(
            [pscustomobject]@{ value = 'SiteAdmin';     source = 'incidentReportRecipient' }
            [pscustomobject]@{ value = 'Owner';         source = 'notifyUser' }
            [pscustomobject]@{ value = 'LastModifier';  source = 'notifyUser' }
        )
        $r = Get-Compl8ReferenceReadiness -References $refs -Resolver { param($v) throw "should not probe a token: $v" }
        $r.ready | Should -BeTrue
        @($r.blocking).Count | Should -Be 0
        @($r.exempt).Count   | Should -Be 3
    }
    It 'exempts external domains/emails (the stated exception)' {
        $refs = @(
            [pscustomobject]@{ value = 'partner@partner.com'; source = 'notifyUser' }
            [pscustomobject]@{ value = 'contoso.com';         source = 'scope' }
        )
        $r = Get-Compl8ReferenceReadiness -References $refs -Resolver $script:Resolver
        $r.ready | Should -BeTrue
        @($r.blocking).Count | Should -Be 0
    }
    It 'passes an internal identity that EXISTS in the tenant' {
        $refs = @([pscustomobject]@{ value = 'DL-Security'; source = 'incidentReportRecipient' })
        (Get-Compl8ReferenceReadiness -References $refs -Resolver $script:Resolver).ready | Should -BeTrue
    }
    It 'exempts a kind=domain reference WITHOUT probing (a domain-context reference is external by rule)' {
        # A bare domain is indistinguishable from a dotted recipient alias by value — the KIND decides.
        $refs = @([pscustomobject]@{ value = 'partner.com'; source = 'RecipientDomainIs (R)'; kind = 'domain' })
        $r = Get-Compl8ReferenceReadiness -References $refs -Resolver { param($v) throw "should not probe a domain-kind ref: $v" }
        $r.ready | Should -BeTrue
        @($r.blocking).Count | Should -Be 0
        @($r.exempt | Where-Object { $_.value -eq 'partner.com' }).Count | Should -Be 1
    }
    It 'still VALIDATES a kind=recipient dotted alias (not exempted as a domain)' {
        $refs = @([pscustomobject]@{ value = 'DL.Security'; source = 'GenerateIncidentReport (R)'; kind = 'recipient' })
        $r = Get-Compl8ReferenceReadiness -References $refs -Resolver { param($v) 'missing' }
        $r.ready | Should -BeFalse
        @($r.blocking | Where-Object { $_.value -eq 'DL.Security' }).Count | Should -Be 1
    }
}

Describe 'Get-Compl8ReferenceReadiness — blocks a missing internal identity' {
    It 'is NOT ready and lists the missing internal identity as blocking' {
        $refs = @(
            [pscustomobject]@{ value = 'DL-Security';  source = 'incidentReportRecipient' }   # exists
            [pscustomobject]@{ value = 'Ghost-Group';  source = 'scope' }                       # MISSING (internal)
            [pscustomobject]@{ value = 'SiteAdmin';    source = 'notifyUser' }                  # token
        )
        $r = Get-Compl8ReferenceReadiness -References $refs -Resolver $script:Resolver
        $r.ready                 | Should -BeFalse
        @($r.blocking).Count     | Should -Be 1
        $r.blocking[0].value     | Should -Be 'Ghost-Group'
        $r.blocking[0].source    | Should -Be 'scope'
    }
    It 'an external/missing-looking ref that the resolver calls external does NOT block' {
        $refs = @([pscustomobject]@{ value = 'partner@partner.com'; source = 'notifyUser' })
        (Get-Compl8ReferenceReadiness -References $refs -Resolver $script:Resolver).ready | Should -BeTrue
    }
}

Describe 'Get-Compl8ReferenceReadiness — undetermined (no/failed resolver)' {
    It 'reports non-token refs as unverified (not blocking) when no resolver is supplied' {
        $refs = @([pscustomobject]@{ value = 'DL-Security'; source = 'incidentReportRecipient' })
        $r = Get-Compl8ReferenceReadiness -References $refs
        @($r.unverified).Count | Should -Be 1
        @($r.blocking).Count   | Should -Be 0
        $r.ready               | Should -BeTrue   # cannot block on what we could not check (run connected)
    }
    It 'a resolver returning $null/garbage for a ref is unverified, not a false block' {
        $refs = @([pscustomobject]@{ value = 'Mystery'; source = 'scope' })
        $r = Get-Compl8ReferenceReadiness -References $refs -Resolver { param($v) $null }
        @($r.unverified).Count | Should -Be 1
        @($r.blocking).Count   | Should -Be 0
    }
}
