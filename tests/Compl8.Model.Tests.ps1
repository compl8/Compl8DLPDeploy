#Requires -Modules Pester

BeforeAll {
    $script:ModuleDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'Compl8.Model'
    Import-Module $script:ModuleDir -Force
}

Describe 'Get-DeploymentLimits' {
    It 'returns the authoring-class rule package limits (sit-limits, MS-verified 2026-06-10)' {
        $l = Get-DeploymentLimits
        $l.MaxSitsPerRulePackage    | Should -Be 50
        $l.MaxRulePackageBytes      | Should -Be 153600   # 150 KB
        $l.PreferredRulePackageBytes | Should -Be 151552  # 148 KB self-imposed margin
        $l.MaxRulePackagesPerTenant | Should -Be 10
    }
    It 'returns dictionary budget thresholds' {
        $l = Get-DeploymentLimits
        $l.DictionaryBudgetWarnBytes | Should -Be 491520   # 480 KB conservative warn
        $l.DictionaryBudgetMaxBytes  | Should -Be 1048576  # 1 MB hard cap
    }
    It 'keeps the auto-label CONSUMPTION limit separate from the authoring cap' {
        (Get-DeploymentLimits).AutoLabelMaxSitsPerRule | Should -Be 125
    }
}

Describe 'DLP-Deploy facade' {
    It 'exposes Get-DeploymentLimits through the legacy module' {
        $facade = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'DLP-Deploy.psm1'
        Import-Module $facade -Force
        Get-Command Get-DeploymentLimits -Module DLP-Deploy | Should -Not -BeNullOrEmpty
    }
}
