#Requires -Modules Pester

# Static guard: the TUI's classifier removal must go through the gated guided flow, never a
# raw Remove-DlpSensitiveInformationTypeRulePackage call.

Describe 'Guided classifier removal wiring' {
    BeforeAll {
        $script:Tui = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'Start-DLPDeploy.ps1') -Raw
    }

    It 'defines Invoke-GuidedClassifierRemoval' {
        ($script:Tui -match 'function\s+Invoke-GuidedClassifierRemoval') | Should -BeTrue
    }

    It 'routes menu option 10 to the guided flow' {
        ($script:Tui -match '"10"\s*\{\s*Invoke-GuidedClassifierRemoval') | Should -BeTrue
    }

    It 'no longer defines the raw Invoke-RemovePackages function' {
        ($script:Tui -match 'function\s+Invoke-RemovePackages') | Should -BeFalse
    }

    It 'contains no raw Remove-DlpSensitiveInformationTypeRulePackage call in the TUI' {
        ($script:Tui -match 'Remove-DlpSensitiveInformationTypeRulePackage') | Should -BeFalse -Because 'removal must go through Deploy-Classifiers -Action Remove'
    }

    It 'the guided flow invokes the gated remove with an approved refit plan' {
        ($script:Tui -match 'Export-TenantSnapshot\.ps1') | Should -BeTrue
        ($script:Tui -match '-Action["'',\s]+Remove') | Should -BeTrue
        ($script:Tui -match '-RefitPlanPath') | Should -BeTrue
        ($script:Tui -match '-ApproveRefitPlan') | Should -BeTrue
    }
}

Describe 'Rollout wizard replace-lifecycle enhancements' {
    BeforeAll {
        $script:Tui2 = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'Start-DLPDeploy.ps1') -Raw
    }

    It 'runs a pre-destructive snapshot in the rollout wizard' {
        ($script:Tui2 -match 'rolloutSnapshotRan') | Should -BeTrue
        ($script:Tui2 -match 'Export-TenantSnapshot\.ps1') | Should -BeTrue
    }

    It 'offers a fit/coverage preview before destructive phases' {
        ($script:Tui2 -match '-Action["'',\s]+CapacityPlan') | Should -BeTrue
    }

    It 'offers the gated per-package removal in the cleanup phase' {
        ($script:Tui2 -match 'Invoke-GuidedClassifierRemoval\s+-Connected\s+\$Connected\s+-SnapshotAlreadyRun') | Should -BeTrue
    }

    It 'has a SIT-propagation checkpoint between classifiers and rules' {
        ($script:Tui2 -match 'propagat') | Should -BeTrue
    }
}
