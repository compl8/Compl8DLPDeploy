#Requires -Modules Pester

# =====================================================================================
# Planner depth #2 (reframed) — Get-Compl8ReferenceCandidates: collect the named identities a deploy
# references, to feed Get-Compl8ReferenceReadiness. Extracts from the identity-bearing recipient fields
# of the desired DLP rules (GenerateIncidentReport, NotifyUser) — splitting comma/semicolon lists — and
# is extensible to condition/scope identity fields. Scope FILTERS (AccessScope=NotInOrganization) are NOT
# identities and are deliberately excluded. Pure.
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $script:RepoRoot 'modules' 'Compl8.Engine') -Force

    # Desired rule records as Resolve-DesiredDlpRules emits them (content = the rule params).
    $script:Rules = @(
        [pscustomobject]@{ ruleName = 'P01-R01-ECH-OFFI'; content = @{
            Name = 'P01-R01-ECH-OFFI'; Policy = 'P01'; AccessScope = 'NotInOrganization'
            GenerateIncidentReport = 'DL-Security'; NotifyUser = 'SiteAdmin,LastModifier,Owner'
        } }
        [pscustomobject]@{ ruleName = 'P02-R01-ECH-OFFI'; content = @{
            Name = 'P02-R01-ECH-OFFI'; Policy = 'P02'
            GenerateIncidentReport = 'security@contoso.com;partner@external.com'
        } }
    )
}

Describe 'Get-Compl8ReferenceCandidates' {
    BeforeAll { $script:Refs = @(Get-Compl8ReferenceCandidates -DesiredRules $script:Rules) }

    It 'is exported from Compl8.Engine' {
        (Get-Command -Name Get-Compl8ReferenceCandidates -Module Compl8.Engine -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }
    It 'collects the incident-report recipient and notify recipients' {
        @($script:Refs | Where-Object { $_.value -eq 'DL-Security' }).Count   | Should -Be 1
        @($script:Refs | Where-Object { $_.value -eq 'SiteAdmin' }).Count      | Should -Be 1
        @($script:Refs | Where-Object { $_.value -eq 'Owner' }).Count          | Should -Be 1
        @($script:Refs | Where-Object { $_.value -eq 'LastModifier' }).Count   | Should -Be 1
    }
    It 'splits comma- and semicolon-separated recipient lists' {
        @($script:Refs | Where-Object { $_.value -eq 'security@contoso.com' }).Count | Should -Be 1
        @($script:Refs | Where-Object { $_.value -eq 'partner@external.com' }).Count | Should -Be 1
    }
    It 'records the source field + rule on each reference' {
        $r = @($script:Refs | Where-Object { $_.value -eq 'DL-Security' })[0]
        $r.source | Should -Match 'GenerateIncidentReport'
        $r.source | Should -Match 'P01-R01-ECH-OFFI'
    }
    It 'does NOT collect scope FILTER values (AccessScope=NotInOrganization is not an identity)' {
        @($script:Refs | Where-Object { $_.value -eq 'NotInOrganization' }).Count | Should -Be 0
    }
    It 'reads content whether it is a hashtable or a pscustomobject (persisted dlp-rules.json shape)' {
        $asObj = @([pscustomobject]@{ ruleName = 'X'; content = [pscustomobject]@{ GenerateIncidentReport = 'DL-Ops' } })
        @(Get-Compl8ReferenceCandidates -DesiredRules $asObj | Where-Object { $_.value -eq 'DL-Ops' }).Count | Should -Be 1
    }
}
