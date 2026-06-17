#Requires -Modules Pester

# =====================================================================================
# Planner depth #1 — Get-Compl8SitVisibilityProbe: the production propagation probe.
#
# Returns the scriptblock Invoke-Compl8Apply -PropagationProbe uses to resolve classifier propagation by
# real tenant VISIBILITY (Get-DlpSensitiveInformationType) — the authoritative signal the leaf uses —
# instead of the 4-hour time-window folklore. The scriptblock returns $true (all required SITs visible),
# $false (some still missing), or $null (tenant unqueryable -> the gate falls back to its time window).
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $script:RepoRoot 'modules' 'Compl8.Engine') -Force
}

Describe 'Get-Compl8SitVisibilityProbe' {
    AfterEach {
        Remove-Item function:global:Get-DlpSensitiveInformationType -ErrorAction SilentlyContinue
    }
    It 'is exported and returns a scriptblock' {
        (Get-Command -Name Get-Compl8SitVisibilityProbe -Module Compl8.Engine -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        (Get-Compl8SitVisibilityProbe) | Should -BeOfType ([scriptblock])
    }
    It 'returns $true when every required SIT is visible in the tenant' {
        function global:Get-DlpSensitiveInformationType { @(
            [pscustomobject]@{ Identity = '11111111-1111-4111-8111-111111111111'; Name = 'A' }
            [pscustomobject]@{ Identity = '22222222-2222-4222-8222-222222222222'; Name = 'B' }
        ) }
        $probe = Get-Compl8SitVisibilityProbe
        (& $probe @('11111111-1111-4111-8111-111111111111')) | Should -BeTrue
        (& $probe @('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222')) | Should -BeTrue
    }
    It 'returns $false when a required SIT is not yet visible (propagation incomplete)' {
        function global:Get-DlpSensitiveInformationType { @([pscustomobject]@{ Identity = '22222222-2222-4222-8222-222222222222'; Name = 'B' }) }
        $probe = Get-Compl8SitVisibilityProbe
        (& $probe @('11111111-1111-4111-8111-111111111111')) | Should -BeFalse
    }
    It 'returns $null when the tenant cannot be queried (undetermined -> time fallback)' {
        function global:Get-DlpSensitiveInformationType { throw 'not connected' }
        $probe = Get-Compl8SitVisibilityProbe
        (& $probe @('11111111-1111-4111-8111-111111111111')) | Should -BeNullOrEmpty
    }
    It 'returns $null for an empty required set (nothing to confirm)' {
        function global:Get-DlpSensitiveInformationType { @() }
        (& (Get-Compl8SitVisibilityProbe) @()) | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-Compl8Deploy — wires the visibility probe into the production apply path (codex)' {
    It 'defaults -PropagationProbe and threads it into Invoke-Compl8Apply' {
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'modules' 'Compl8.Engine' 'Public' 'Invoke-Compl8Deploy.ps1') -Raw
        # Defaulted from the shared probe…
        ($src -match '\[scriptblock\]\$PropagationProbe\s*=\s*\(Get-Compl8SitVisibilityProbe\)') | Should -BeTrue
        # …and threaded into the apply call so a real deployment uses the authoritative signal.
        ($src -match 'applyArgs\[''PropagationProbe''\]\s*=\s*\$PropagationProbe') | Should -BeTrue
    }
}
