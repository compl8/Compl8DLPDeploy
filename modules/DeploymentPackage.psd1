@{
    # Module manifest for DeploymentPackage
    # Generated: 2026-05-25

    RootModule        = 'DeploymentPackage.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'a6b1c5d2-9e21-4d8b-bf2c-2f4a3b9d1e7f'
    Author            = 'Compl8 DLP Deploy'
    CompanyName       = ''
    Copyright         = '(c) 2026. All rights reserved.'
    Description       = 'Tenant deployment package lifecycle: target snapshot, plan adjustments, phase results, verification, archive. Requires PowerShell 7+ (uses ConvertFrom-Json -AsHashtable).'
    PowerShellVersion = '7.0'

    FunctionsToExport = @(
        'New-DeploymentTargetSnapshot'
        'Get-TenantActualState'
        'Compare-DeploymentState'
        'Update-PendingPackage'
        'Get-PendingDeploymentPackage'
        'Read-DeploymentPackageManifest'
        'Add-DeploymentPlanAdjustment'
        'Add-DeploymentPhaseResult'
        'Move-DeploymentPackageToArchive'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('DLP', 'Purview', 'Compliance', 'SensitivityLabels')
            LicenseUri = ''
            ProjectUri = ''
        }
    }
}
