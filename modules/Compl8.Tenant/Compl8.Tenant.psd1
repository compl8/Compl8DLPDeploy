@{
    RootModule        = 'Compl8.Tenant.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '9e1f5b73-6a2c-48d9-b0e4-c83a51d27f06'
    Author            = 'Compl8 DLP Deploy'
    Description       = 'Compl8 tenant boundary: SCC session management, fingerprint/orchestration gates, tenant readers.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Assert-OrchestrationGate'
        'Get-DeploymentTenantInfo'
        'Get-DlpClassifierRuleReferences'
        'Test-DeploymentTenantFingerprint'
        'Test-DlpRulePackageRemovalReferenceGuard'
        'Test-IsInteractive'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
