#Requires -Modules Pester

BeforeAll {
    $script:LauncherPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Start-DLPDeploy.ps1'

    function Import-LauncherFunction {
        param([Parameter(Mandatory)][string]$Name)

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:LauncherPath,
            [ref]$tokens,
            [ref]$errors
        )
        if ($errors.Count -gt 0) {
            throw "Could not parse Start-DLPDeploy.ps1: $($errors[0].Message)"
        }

        $functionAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $Name
        }, $true)
        if (-not $functionAst) {
            throw "Function '$Name' not found in Start-DLPDeploy.ps1."
        }

        Invoke-Expression "function script:$Name $($functionAst.Body.Extent.Text)"
    }

    Import-LauncherFunction -Name 'Convert-ArgumentListToSplat'
}

Describe 'Start-DLPDeploy launcher dispatch' {
    It 'converts parameter-token arrays into named splats' {
        $binding = Convert-ArgumentListToSplat -ArgumentList @(
            '-Action', 'ApplyRefitPlan',
            '-RefitPlanPath', 'reports/refit-plans/run/refit-plan.json',
            '-WhatIf',
            '-ApproveRefitPlan',
            '-Tenant', 'customer.gov.au'
        )

        $binding.Positional.Count | Should -Be 0
        $binding.Named.Action | Should -Be 'ApplyRefitPlan'
        $binding.Named.RefitPlanPath | Should -Be 'reports/refit-plans/run/refit-plan.json'
        $binding.Named.WhatIf | Should -BeTrue
        $binding.Named.ApproveRefitPlan | Should -BeTrue
        $binding.Named.Tenant | Should -Be 'customer.gov.au'
    }

    It 'preserves non-parameter tokens as positional arguments' {
        $binding = Convert-ArgumentListToSplat -ArgumentList @('positional-value', '-SwitchOnly')

        $binding.Positional | Should -Be @('positional-value')
        $binding.Named.SwitchOnly | Should -BeTrue
    }
}
