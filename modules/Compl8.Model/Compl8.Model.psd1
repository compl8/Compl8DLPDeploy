@{
    RootModule        = 'Compl8.Model.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '4c6d8a2e-91b3-4f7a-8c5d-2e0a7b6f1d93'
    Author            = 'Compl8 DLP Deploy'
    Description       = 'Compl8 pure model layer: limits, naming templates, rule-package parsing, reference graph. No tenant calls.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Get-DeploymentLimits'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
