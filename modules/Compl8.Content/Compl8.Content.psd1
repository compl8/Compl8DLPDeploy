@{
    RootModule        = 'Compl8.Content.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '2b8e4d61-3f9a-4c07-95e8-7d1c6a40b3f2'
    Author            = 'Compl8 DLP Deploy'
    Description       = 'Compl8 content layer: curated release + overlay merge + repack engine (Stage 3).'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Get-Compl8WorkspacePath'
        'Get-EntityLedger'
        'Import-ContentRelease'
        'Initialize-EntityLedger'
        'Update-EntityLedger'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
