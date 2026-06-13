@{
    RootModule        = 'Compl8.Engine.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'c5a09f28-1d64-4b3e-a7f0-94e2d8c61b57'
    Author            = 'Compl8 DLP Deploy'
    Description       = 'Compl8 engine layer: assess, plan, apply — the only tenant-mutating layer (Stage 4).'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Compare-Compl8Plan',
        'Get-Compl8AssessmentReport',
        'Get-Compl8PlanOrder',
        'Invoke-Compl8Apply',
        'Invoke-Compl8Assess',
        'New-Compl8Plan',
        'Test-Compl8Gate',
        'Test-Compl8PlanCurrent'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
