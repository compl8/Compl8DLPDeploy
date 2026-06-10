#Requires -Modules Pester

BeforeAll {
    $script:TenantDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'Compl8.Tenant'
    # Isolation: DLP-Deploy's facade dot-source claims ownership of these functions when loaded;
    # remove it so -Module Compl8.Tenant attribution is testable (same pattern as Compl8.Model.Tests.ps1).
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:TenantDir -Force
}

Describe 'Compl8.Tenant standalone exports' {
    It 'exports the gates and tenant readers' {
        $names = @(
            'Test-IsInteractive', 'Assert-OrchestrationGate',
            'Get-DeploymentTenantInfo', 'Test-DeploymentTenantFingerprint',
            'Get-DlpClassifierRuleReferences', 'Test-DlpRulePackageRemovalReferenceGuard'
        )
        foreach ($n in $names) {
            (Get-Command -Name $n -Module Compl8.Tenant -ErrorAction SilentlyContinue) |
                Should -Not -BeNullOrEmpty -Because "$n should be exported by Compl8.Tenant"
        }
    }
    It 'orchestration gate passes standalone when COMPL8_ORCHESTRATED is set' {
        $env:COMPL8_ORCHESTRATED = '1'
        try { { Assert-OrchestrationGate -ScriptName 'X' } | Should -Not -Throw }
        finally { Remove-Item Env:\COMPL8_ORCHESTRATED -ErrorAction SilentlyContinue }
    }
    It 'loads its Compl8.Model dependency for the reference guard' {
        (Get-Command -Name Get-DeploymentReferenceGraph -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
}
