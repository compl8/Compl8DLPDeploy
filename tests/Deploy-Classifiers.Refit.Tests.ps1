#Requires -Modules Pester

<#
.SYNOPSIS
    Focused tests for Deploy-Classifiers refit plan hardening.
    The deploy script runs main logic on load, so these tests import only
    selected function definitions from its AST instead of dot-sourcing it.
#>

BeforeAll {
    $script:ProjectRoot = Split-Path $PSScriptRoot -Parent
    $script:DeployClassifiersPath = Join-Path $script:ProjectRoot 'scripts' 'Deploy-Classifiers.ps1'

    function Import-DeployClassifierFunction {
        param([Parameter(Mandatory)][string[]]$Name)

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:DeployClassifiersPath,
            [ref]$tokens,
            [ref]$errors
        )
        if ($errors.Count -gt 0) {
            throw "Could not parse Deploy-Classifiers.ps1: $($errors[0].Message)"
        }

        foreach ($functionName in $Name) {
            $functionAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $functionName
            }, $true)

            if (-not $functionAst) {
                throw "Function '$functionName' not found in Deploy-Classifiers.ps1."
            }

            Invoke-Expression "function script:$functionName $($functionAst.Body.Extent.Text)"
        }
    }

    Import-DeployClassifierFunction -Name @(
        'Get-FileSha256',
        'Import-ClassifierRefitPlan',
        'Test-RefitAssignmentCreatesNewPackage',
        'Assert-CurrentRefitPlanForPackageRemoval'
    )

    function New-TestRefitPlan {
        param(
            [Parameter(Mandatory)][string]$Directory,
            [object[]]$PackageClassifications = @(),
            [datetime]$GeneratedUtc = (Get-Date).ToUniversalTime()
        )

        New-Item -ItemType Directory -Path $Directory -Force | Out-Null
        $path = Join-Path $Directory 'refit-plan.json'
        $plan = [ordered]@{
            schemaVersion = 'dlpdeploy.classifier-refit-plan/v1'
            generatedUtc = $GeneratedUtc.ToUniversalTime().ToString('r', [System.Globalization.CultureInfo]::InvariantCulture)
            packageClassifications = @($PackageClassifications)
            assignments = @()
        }
        $plan | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
        return $path
    }

    function Write-TestRefitPlanSidecar {
        param([Parameter(Mandatory)][string]$PlanPath)

        $hash = (Get-FileHash -LiteralPath $PlanPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $hashPath = Join-Path (Split-Path -Parent $PlanPath) 'refit-plan.sha256'
        "$hash  refit-plan.json" | Set-Content -LiteralPath $hashPath -Encoding UTF8
        return $hashPath
    }

    function script:Get-DlpRulePackageEntityIds {
        param([object[]]$Packages)
        return @($script:RulePackageInfo)
    }
}

Describe 'Deploy-Classifiers refit hardening' {
    BeforeEach {
        $script:TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null
        $script:RefitPlanPath = $null
        $script:ApproveRefitPlan = $false
        $script:DeploymentManifest = $null
        $script:RulePackageInfo = @()
    }

    AfterEach {
        Remove-Item -LiteralPath $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

Context 'Import-ClassifierRefitPlan sidecar validation' {
    It 'Accepts a matching refit-plan.sha256 sidecar' {
        $planPath = New-TestRefitPlan -Directory $script:TempRoot
        $hashPath = Write-TestRefitPlanSidecar -PlanPath $planPath
        $script:RefitPlanPath = $planPath

        $context = Import-ClassifierRefitPlan

        $context.Path | Should -Be ([System.IO.Path]::GetFullPath($planPath))
        $context.HashPath | Should -Be ([System.IO.Path]::GetFullPath($hashPath))
        $context.PlanSha256 | Should -Be (Get-FileHash -LiteralPath $planPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    It 'Rejects a missing sidecar' {
        $script:RefitPlanPath = New-TestRefitPlan -Directory $script:TempRoot

        { Import-ClassifierRefitPlan } | Should -Throw '*hash file not found*'
    }

    It 'Rejects a mismatched sidecar' {
        $planPath = New-TestRefitPlan -Directory $script:TempRoot
        ('0' * 64) | Set-Content -LiteralPath (Join-Path $script:TempRoot 'refit-plan.sha256') -Encoding UTF8
        $script:RefitPlanPath = $planPath

        { Import-ClassifierRefitPlan } | Should -Throw '*hash mismatch*'
    }
}

Context 'Test-RefitAssignmentCreatesNewPackage' {
    It 'Recognizes supported create-new-package flags and states' {
        $supported = @(
            [pscustomobject]@{ operation = 'CreateInFreeSlot' },
            [pscustomobject]@{ approvedNewSlot = $true },
            [pscustomobject]@{ createNewPackage = $true },
            [pscustomobject]@{ state = 'CreateInFreeSlot' },
            [pscustomobject]@{ state = 'NewFreeSlot' },
            [pscustomobject]@{ recommendation = 'CreateInFreeSlot' },
            [pscustomobject]@{ recommendation = 'NewFreeSlot' }
        )

        foreach ($assignment in $supported) {
            Test-RefitAssignmentCreatesNewPackage -Assignment $assignment | Should -BeTrue
        }
    }

    It 'Does not treat ordinary update assignments as new package creates' {
        Test-RefitAssignmentCreatesNewPackage -Assignment ([pscustomobject]@{
            operation = 'UpdateExisting'
            approvedNewSlot = $false
            createNewPackage = $false
            state = 'ReusableReferencedSlot'
            recommendation = 'UpdateExisting'
        }) | Should -BeFalse
    }
}

Context 'Assert-CurrentRefitPlanForPackageRemoval' {
    It 'Refuses package removal when RefitPlanPath is missing' {
        $script:ApproveRefitPlan = $true

        { Assert-CurrentRefitPlanForPackageRemoval -Packages @([pscustomobject]@{ Identity = 'pkg-a' }) -OperationName 'DeletePackage' } |
            Should -Throw '*requires a current approved refit plan*'
    }

    It 'Refuses package removal when ApproveRefitPlan is missing' {
        $script:RefitPlanPath = New-TestRefitPlan -Directory $script:TempRoot
        Write-TestRefitPlanSidecar -PlanPath $script:RefitPlanPath | Out-Null

        { Assert-CurrentRefitPlanForPackageRemoval -Packages @([pscustomobject]@{ Identity = 'pkg-a' }) -OperationName 'DeletePackage' } |
            Should -Throw '*requires a current approved refit plan*'
    }

    It 'Accepts only approved retire and reusable free-slot classifications from a fresh plan' {
        $allowedStates = @('RetireCandidate', 'ReusableEmptySlot', 'ReusableUnreferencedSlot')

        foreach ($state in $allowedStates) {
            $caseDir = Join-Path $script:TempRoot $state
            $planPath = New-TestRefitPlan -Directory $caseDir -PackageClassifications @(
                [pscustomobject]@{
                    rulePackId = '11111111-1111-1111-1111-111111111111'
                    name = "package-$state"
                    state = $state
                }
            )
            Write-TestRefitPlanSidecar -PlanPath $planPath | Out-Null
            $script:RefitPlanPath = $planPath
            $script:ApproveRefitPlan = $true
            $script:RulePackageInfo = @([pscustomobject]@{
                Identity = "package-$state"
                Name = "package-$state"
                RulePackId = '11111111-1111-1111-1111-111111111111'
                Package = [pscustomobject]@{ Identity = "package-$state" }
            })

            $context = Assert-CurrentRefitPlanForPackageRemoval -Packages @($script:RulePackageInfo[0].Package) -OperationName 'DeletePackage'

            $context.Path | Should -Be ([System.IO.Path]::GetFullPath($planPath))
        }
    }

    It 'Rejects a fresh plan classification that is not an approved retire or reusable free-slot state' {
        $planPath = New-TestRefitPlan -Directory $script:TempRoot -PackageClassifications @(
            [pscustomobject]@{
                rulePackId = '22222222-2222-2222-2222-222222222222'
                name = 'package-blocked'
                state = 'ReusableReferencedSlot'
            }
        )
        Write-TestRefitPlanSidecar -PlanPath $planPath | Out-Null
        $script:RefitPlanPath = $planPath
        $script:ApproveRefitPlan = $true
        $script:RulePackageInfo = @([pscustomobject]@{
            Identity = 'package-blocked'
            Name = 'package-blocked'
            RulePackId = '22222222-2222-2222-2222-222222222222'
            Package = [pscustomobject]@{ Identity = 'package-blocked' }
        })

        { Assert-CurrentRefitPlanForPackageRemoval -Packages @($script:RulePackageInfo[0].Package) -OperationName 'DeletePackage' } |
            Should -Throw "*not an approved retire/free-slot candidate*"
    }
}
}
