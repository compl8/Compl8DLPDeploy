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

Describe 'Compl8.Model standalone exports (naming)' {
    BeforeAll {
        # Reload Compl8.Model in a clean state; the DLP-Deploy facade Describe above
        # dot-sources the same files into DLP-Deploy scope which can shift function
        # ownership away from Compl8.Model.  Re-importing ensures the module's own
        # Export-ModuleMember list is current for the -Module filter below.
        Remove-Module DLP-Deploy -ErrorAction SilentlyContinue
        $script:ModelDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'Compl8.Model'
        Import-Module $script:ModelDir -Force
    }
    It 'exports the naming functions without loading DLP-Deploy' {
        $names = @(
            'ConvertTo-DeploymentNameTemplates', 'Remove-DeploymentNamePrefix',
            'Expand-DeploymentNameTemplate', 'Get-DeploymentObjectName',
            'Get-PolicyName', 'Get-RuleName',
            'Get-PurviewUnsafeNameCharacterSummary', 'Test-PurviewObjectNameSafety',
            'Assert-PurviewObjectNameSafety'
        )
        foreach ($n in $names) {
            (Get-Command -Name $n -Module Compl8.Model -ErrorAction SilentlyContinue) |
                Should -Not -BeNullOrEmpty -Because "$n should be exported by Compl8.Model"
        }
    }
    It 'expands a name template standalone' {
        # Exercises Expand-DeploymentNameTemplate directly — matches the DLP-Deploy.Tests.ps1
        # Get-PolicyName legacy-format assertion (P01-ECH-QGISCF-EXT-ADT) but via the
        # template engine so the test is independent of Get-ModuleDefaults.
        $result = Expand-DeploymentNameTemplate -Template 'P{policyNumber}-{policyCode}-{prefix}-{suffix}' `
            -Tokens @{ policyNumber = '01'; policyCode = 'ECH'; prefix = 'QGISCF'; suffix = 'EXT-ADT' }
        $result | Should -Be 'P01-ECH-QGISCF-EXT-ADT'
    }
}
