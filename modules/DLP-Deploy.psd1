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

    # Keep in sync with Export-ModuleMember in DLP-Deploy.psm1. The effective public
    # surface is the intersection of this list and that one, so both must match.
    FunctionsToExport = @(
        'Add-DeploymentManifestEvent'
        'Assert-ConfigCustomised'
        'Assert-DLPSession'
        'Assert-PurviewObjectNameSafety'
        'Complete-DeploymentManifest'
        'Connect-DLPSession'
        'Convert-DlpSerializedRulePackageToText'
        'Disconnect-DLPSession'
        'Get-ChunkLetter'
        'Get-CleanupConfirmationPhrase'
        'Get-DeploymentFileArtifact'
        'Get-DeploymentTenantInfo'
        'Get-DlpClassifierRuleReferences'
        'Get-DlpRulePackageEntityIds'
        'Get-MergedRuleParams'
        'Get-ModuleDefaults'
        'Get-PolicyName'
        'Get-RuleName'
        'Import-JsonConfig'
        'Invoke-CleanupPlan'
        'Invoke-WithRetry'
        'Merge-GlobalConfig'
        'New-AdvancedRuleJson'
        'New-DeploymentManifest'
        'New-DLPSITCondition'
        'Remove-PurviewObject'
        'Remove-PurviewObjects'
        'Resolve-ClassifierConfig'
        'Resolve-CleanupTargets'
        'Resolve-LabelConfig'
        'Resolve-PolicyConfig'
        'Resolve-PolicyMode'
        'Resolve-RuleOverrides'
        'Save-DeploymentManifest'
        'Set-DeploymentConfigPrefix'
        'Show-CleanupPlan'
        'Split-ClassifierChunks'
        'Start-DeploymentLog'
        'Stop-DeploymentLog'
        'Sync-DlpKeywordDictionaries'
        'Test-DeploymentTenantFingerprint'
        'Test-DlpRulePackageRemovalReferenceGuard'
        'Test-PurviewNameConflicts'
        'Test-PurviewObjectNameSafety'
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
