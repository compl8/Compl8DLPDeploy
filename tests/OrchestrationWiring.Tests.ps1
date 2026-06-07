#Requires -Modules Pester

# Guards the orchestration-gate wiring end to end. The gate is only safe if BOTH
# halves are present together (the bug that caused the earlier revert was adding the
# leaf guards without the orchestrators setting COMPL8_ORCHESTRATED):
#   1. Every tenant-mutating leaf script calls Assert-OrchestrationGate.
#   2. Every orchestrator entry point sets COMPL8_ORCHESTRATED so its &-invoked
#      children pass the gate.
#   3. Non-orchestrated automated callers (CI) pass -AllowDirectRun.
#
# -ForEach data is defined at discovery scope; runtime paths in BeforeAll.

$GuardedLeafScripts = @(
    'scripts/Deploy-Labels.ps1'
    'scripts/Deploy-Classifiers.ps1'
    'scripts/Deploy-DLPRules.ps1'
    'scripts/Deploy-AutoLabeling.ps1'
    'scripts/Remove-OrphanedPolicies.ps1'
    'scripts/Reset-DeploymentScope.ps1'
)

$OrchestratorScripts = @(
    'scripts/Invoke-FullDeployment.ps1'
    'scripts/Invoke-GreenfieldDeployment.ps1'
    'Start-DLPDeploy.ps1'
)

Describe 'Orchestration gate wiring' {
    BeforeAll { $script:ProjectRoot = Split-Path $PSScriptRoot -Parent }

    It '<_> calls Assert-OrchestrationGate' -ForEach $GuardedLeafScripts {
        $content = Get-Content -LiteralPath (Join-Path $script:ProjectRoot $_) -Raw
        ($content -match 'Assert-OrchestrationGate') |
            Should -BeTrue -Because "$_ is tenant-mutating and must guard against raw direct runs"
    }

    It '<_> sets COMPL8_ORCHESTRATED so its child leaf scripts pass the gate' -ForEach $OrchestratorScripts {
        $content = Get-Content -LiteralPath (Join-Path $script:ProjectRoot $_) -Raw
        ($content -match '\$env:COMPL8_ORCHESTRATED\s*=') |
            Should -BeTrue -Because "$_ invokes leaf scripts in-process and must mark them orchestrated"
    }

    It 'Invoke-CIChecks passes -AllowDirectRun to its Deploy-Classifiers validate call' {
        $content = Get-Content -LiteralPath (Join-Path $script:ProjectRoot 'scripts/Invoke-CIChecks.ps1') -Raw
        ($content -match 'Deploy-Classifiers\.ps1"\s*\)\s*-Action Validate -AllowDirectRun') |
            Should -BeTrue -Because 'CI runs the validator with no orchestrator and must acknowledge the direct run'
    }
}

Describe 'Orchestration gate honours an inherited COMPL8_ORCHESTRATED' {
    BeforeAll { $script:ProjectRoot = Split-Path $PSScriptRoot -Parent }

    It 'a child script invoked via & inherits the env var and passes the gate' {
        $child = Join-Path ([System.IO.Path]::GetTempPath()) ("gate-child-{0}.ps1" -f ([guid]::NewGuid().ToString('N')))
        $modulePath = (Join-Path $script:ProjectRoot 'modules/DLP-Deploy.psm1') -replace "'", "''"
        @"
Import-Module '$modulePath' -Force
Assert-OrchestrationGate -ScriptName 'child-leaf'
'OK'
"@ | Set-Content -LiteralPath $child -Encoding UTF8

        $prior = $env:COMPL8_ORCHESTRATED
        try {
            $env:COMPL8_ORCHESTRATED = '1'   # as an orchestrator would set before calling children
            { & $child } | Should -Not -Throw
        } finally {
            $env:COMPL8_ORCHESTRATED = $prior
            Remove-Item -LiteralPath $child -Force -ErrorAction SilentlyContinue
        }
    }
}
