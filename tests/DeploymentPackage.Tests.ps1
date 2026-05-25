#Requires -Modules Pester

BeforeAll {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'DeploymentPackage.psm1'
    Import-Module $ModulePath -Force
}

Describe 'DeploymentPackage module loads' {
    It 'exports the lifecycle functions' {
        $expected = @(
            'New-DeploymentTargetSnapshot',
            'Get-TenantActualState',
            'Compare-DeploymentState',
            'Update-PendingPackage',
            'Get-PendingDeploymentPackage',
            'Read-DeploymentPackageManifest',
            'Add-DeploymentPlanAdjustment',
            'Add-DeploymentPhaseResult',
            'Move-DeploymentPackageToArchive'
        )
        $actual = (Get-Command -Module DeploymentPackage).Name
        foreach ($name in $expected) { $actual | Should -Contain $name }
        $actual.Count | Should -Be 9
    }
}
