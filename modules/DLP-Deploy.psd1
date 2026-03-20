@{
    # Module manifest for DLP-Deploy
    # Generated: 2026-02-23

    RootModule        = 'DLP-Deploy.psm1'
    ModuleVersion     = '2.0.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'Compl8 DLP Deploy'
    CompanyName       = ''
    Copyright         = '(c) 2026. All rights reserved.'
    Description       = 'Shared functions for DLP deployment to Microsoft Purview'
    PowerShellVersion = '5.1'

    RequiredModules   = @('ExchangeOnlineManagement')

    FunctionsToExport = @(
        'Get-ModuleDefaults'
        'Connect-DLPSession'
        'Assert-DLPSession'
        'Disconnect-DLPSession'
        'Import-JsonConfig'
        'Merge-GlobalConfig'
        'Assert-ConfigCustomised'
        'Resolve-PolicyConfig'
        'Resolve-ClassifierConfig'
        'Resolve-LabelConfig'
        'Resolve-RuleOverrides'
        'Get-PolicyName'
        'Get-RuleName'
        'New-DLPSITCondition'
        'New-AdvancedRuleJson'
        'Resolve-PolicyMode'
        'Get-MergedRuleParams'
        'Invoke-WithRetry'
        'Start-DeploymentLog'
        'Test-SITRulePackageXml'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('DLP', 'Purview', 'Compliance', 'SensitivityLabels')
            LicenseUri = ''
            ProjectUri = ''
        }
    }
}
