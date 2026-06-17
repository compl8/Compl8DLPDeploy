#Requires -Modules Pester

# =====================================================================================
# Planner depth #2 (reframed) — Get-Compl8IdentityResolver: the connected identity classifier.
# Returns a scriptblock that classifies a reference exists/missing/external/unverified via Get-Recipient
# + Get-AcceptedDomain. Fail-safe: absent/throwing cmdlets => 'unverified' (never a false 'missing').
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $script:RepoRoot 'modules' 'Compl8.Engine') -Force
}

Describe 'Get-Compl8IdentityResolver' {
    AfterEach {
        Remove-Item function:global:Get-Recipient -ErrorAction SilentlyContinue
        Remove-Item function:global:Get-AcceptedDomain -ErrorAction SilentlyContinue
    }

    It 'is exported and returns a scriptblock' {
        (Get-Command -Name Get-Compl8IdentityResolver -Module Compl8.Engine -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        (Get-Compl8IdentityResolver) | Should -BeOfType ([scriptblock])
    }
    It "classifies an internal name that exists as 'exists'" {
        function global:Get-Recipient { param($Identity, $ErrorAction) [pscustomobject]@{ Name = $Identity } }
        (& (Get-Compl8IdentityResolver) 'DL-Security') | Should -Be 'exists'
    }
    It "classifies an internal name that is absent as 'missing' (the blocking case)" {
        function global:Get-Recipient { param($Identity, $ErrorAction) $null }
        (& (Get-Compl8IdentityResolver) 'Ghost-Group') | Should -Be 'missing'
    }
    It "treats a dotted no-@ recipient alias as an identity to validate — missing => 'missing', NOT exempt (codex)" {
        # 'DL.Security' / 'ops.team' look domain-ish but are recipient aliases; a missing one must BLOCK,
        # not be exempted as an 'external domain'.
        function global:Get-Recipient { param($Identity, $ErrorAction) $null }   # not found
        (& (Get-Compl8IdentityResolver) 'DL.Security') | Should -Be 'missing'
        (& (Get-Compl8IdentityResolver) 'ops.team')    | Should -Be 'missing'
    }
    It "classifies an email at a NON-accepted domain as 'external'" {
        function global:Get-Recipient { param($Identity, $ErrorAction) $null }
        function global:Get-AcceptedDomain { param($ErrorAction) @([pscustomobject]@{ DomainName = 'tenant.onmicrosoft.com' }) }
        (& (Get-Compl8IdentityResolver) 'partner@external.com') | Should -Be 'external'
    }
    It "classifies an email at an ACCEPTED domain by recipient existence (missing => blocking)" {
        function global:Get-Recipient { param($Identity, $ErrorAction) $null }   # not found
        function global:Get-AcceptedDomain { param($ErrorAction) @([pscustomobject]@{ DomainName = 'contoso.com' }) }
        (& (Get-Compl8IdentityResolver) 'missing@contoso.com') | Should -Be 'missing'
    }
    It "a subdomain address is internal only under a WILDCARD accepted domain (Exchange semantics; codex)" {
        function global:Get-Recipient { param($Identity, $ErrorAction) $null }   # not found
        # WILDCARD '*.contoso.com' covers the subdomain -> internal -> missing (blocks).
        function global:Get-AcceptedDomain { param($ErrorAction) @([pscustomobject]@{ DomainName = '*.contoso.com' }) }
        (& (Get-Compl8IdentityResolver) 'user@dept.contoso.com') | Should -Be 'missing'
    }
    It "a PLAIN accepted domain does NOT cover its subdomains (subdomain address => external; codex)" {
        function global:Get-Recipient { param($Identity, $ErrorAction) $null }
        function global:Get-AcceptedDomain { param($ErrorAction) @([pscustomobject]@{ DomainName = 'contoso.com' }) }
        (& (Get-Compl8IdentityResolver) 'user@dept.contoso.com') | Should -Be 'external'
    }
    It "is fail-safe: a NOT-CONNECTED tenant query returns 'unverified', never a false 'missing'" {
        # The realistic failure: Get-Recipient is present (EXO module) but the session is not connected,
        # so the call throws a connection error. That must NOT be read as 'missing'.
        function global:Get-Recipient { param($Identity, $ErrorAction) throw "Connect-IPPSSession: the session isn't connected." }
        (& (Get-Compl8IdentityResolver) 'Some-Internal-Name') | Should -Be 'unverified'
    }
    It "classifies a genuine not-found error as 'missing' (blocking)" {
        function global:Get-Recipient { param($Identity, $ErrorAction) throw "The object $Identity couldn't be found on domain controller." }
        (& (Get-Compl8IdentityResolver) 'Ghost-Group') | Should -Be 'missing'
    }
}
