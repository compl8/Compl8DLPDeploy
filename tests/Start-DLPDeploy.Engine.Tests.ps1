#Requires -Modules Pester

# =====================================================================================
# Start-DLPDeploy.ps1 — Engine-path wiring (Stage 5 PHASE 5B, Task 5B-3).
#
# The interactive TUI gains the SAME opt-in Engine path as the CLI (5B-2): under -UseEngine
# the per-type deploy menu items (Labels / Classifiers / DLP Rules) and the rollout wizard's
# matching phases route through Invoke-Compl8Deploy WHEN that object type's route is ON
# (New-Compl8Context engineRoutes; default ALL FALSE). The leaf path (Invoke-ToolkitScript ->
# Deploy-*.ps1), the guided classifier removal, the snapshot/propagation checkpoints and the
# COMPL8_ORCHESTRATED marker are all KEPT (D5 — old paths stay live), so the existing TUI
# wiring suites (GuidedClassifierRemovalWiring, OrchestrationWiring) stay green and the default
# (no -UseEngine / all routes false) behaviour is unchanged.
#
# Pattern matches 5B-2: static (AST/string) wiring assertions for the orchestrator, plus a
# behavioural test of the routing GATE extracted from the script via AST (with New-Compl8Context
# mocked for the on-demand context build).
# =====================================================================================

BeforeAll {
    $script:ProjectRoot = Split-Path $PSScriptRoot -Parent
    $script:ScriptPath  = Join-Path $script:ProjectRoot 'Start-DLPDeploy.ps1'
    $script:Content     = Get-Content -LiteralPath $script:ScriptPath -Raw

    function Get-ScriptFunctionText {
        param([Parameter(Mandatory)][string]$Name)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name
        }, $true) | Select-Object -First 1
        if (-not $fn) { throw "function '$Name' not found in $script:ScriptPath" }
        $fn.Extent.Text
    }
}

Describe 'Start-DLPDeploy — Engine opt-in surface' {
    It 'declares the -UseEngine opt-in switch' {
        ($script:Content -match '\[switch\]\$UseEngine') | Should -BeTrue
    }
    It 'imports Compl8.Engine only under -UseEngine' {
        ($script:Content -match 'if\s*\(\$UseEngine\)\s*\{[\s\S]*?Compl8\.Engine') | Should -BeTrue
    }
    It 'defines the routing gate + scoped Engine-phase helpers' {
        ($script:Content -match 'function\s+Test-Compl8PhaseRoutesToEngine') | Should -BeTrue
        ($script:Content -match 'function\s+Invoke-Compl8EnginePhase')        | Should -BeTrue
        ($script:Content -match 'function\s+Get-Compl8DeployContext')         | Should -BeTrue
    }
}

Describe 'Start-DLPDeploy — per-type menus + wizard route through the Engine when routed' {
    $routeKeys = @(
        @{ RouteKey = 'label' }
        @{ RouteKey = 'rulePackage' }
        @{ RouteKey = 'dlpRule' }
    )
    It '<RouteKey> has a route-gated Engine branch' -ForEach $routeKeys {
        ($script:Content -match [regex]::Escape("Test-Compl8PhaseRoutesToEngine '$RouteKey'")) |
            Should -BeTrue -Because "a deploy path must check the $RouteKey route"
        ($script:Content -match [regex]::Escape("Invoke-Compl8EnginePhase -RouteKey '$RouteKey'")) |
            Should -BeTrue -Because "a deploy path must route $RouteKey through Invoke-Compl8Deploy"
    }
}

Describe 'Start-DLPDeploy — leaf path + safety wiring PRESERVED' {
    It 'still invokes the leaf deploy scripts via Invoke-ToolkitScript' {
        ($script:Content -match 'Deploy-Labels\.ps1')      | Should -BeTrue
        ($script:Content -match 'Deploy-Classifiers\.ps1') | Should -BeTrue
        ($script:Content -match 'Deploy-DLPRules\.ps1')    | Should -BeTrue
    }
    It 'keeps the orchestration marker, guided removal, and snapshot checkpoints' {
        ($script:Content -match '\$env:COMPL8_ORCHESTRATED\s*=')                     | Should -BeTrue
        ($script:Content -match '"10"\s*\{\s*Invoke-GuidedClassifierRemoval')        | Should -BeTrue
        ($script:Content -match 'Export-TenantSnapshot\.ps1')                        | Should -BeTrue
        ($script:Content -match 'Remove-DlpSensitiveInformationTypeRulePackage')     | Should -BeFalse
    }
}

Describe 'Test-Compl8PhaseRoutesToEngine — the TUI routing GATE (behavioural)' {
    BeforeAll {
        # Dot-source the gate + the on-demand context builder; mock New-Compl8Context so the gate's
        # decision is driven by a fixture context (no workspace/tenant.json needed).
        . ([scriptblock]::Create((Get-ScriptFunctionText -Name 'Get-Compl8DeployContext')))
        . ([scriptblock]::Create((Get-ScriptFunctionText -Name 'Test-Compl8PhaseRoutesToEngine')))
        function New-Compl8Context { param([string]$TargetEnvironment, [string]$WorkspaceRoot, [string]$Prefix, [string]$UPN, [switch]$Delegated) }
    }

    It 'returns FALSE when -UseEngine is off (default = leaf), even with a route ON' {
        $UseEngine = $false
        $script:TargetEnvironment = 'nonprod'
        Mock New-Compl8Context { [pscustomobject]@{ Environment = 'nonprod'; EngineRoutes = [pscustomobject]@{ rulePackage = $true } } }
        Test-Compl8PhaseRoutesToEngine 'rulePackage' | Should -BeFalse
    }
    It 'returns FALSE under -UseEngine when the type route is OFF' {
        $UseEngine = $true
        $script:TargetEnvironment = 'nonprod'
        Mock New-Compl8Context { [pscustomobject]@{ Environment = 'nonprod'; EngineRoutes = [pscustomobject]@{ dictionary = $false; label = $false; rulePackage = $false; dlpRule = $false; autoLabel = $false } } }
        Test-Compl8PhaseRoutesToEngine 'rulePackage' | Should -BeFalse
        Test-Compl8PhaseRoutesToEngine 'label'       | Should -BeFalse
    }
    It 'returns TRUE only for the type whose route is ON under -UseEngine' {
        $UseEngine = $true
        $script:TargetEnvironment = 'nonprod'
        Mock New-Compl8Context { [pscustomobject]@{ Environment = 'nonprod'; EngineRoutes = [pscustomobject]@{ dictionary = $false; label = $false; rulePackage = $true; dlpRule = $false; autoLabel = $false } } }
        Test-Compl8PhaseRoutesToEngine 'rulePackage' | Should -BeTrue
        Test-Compl8PhaseRoutesToEngine 'dlpRule'     | Should -BeFalse
    }
    It 'returns FALSE (leaf) when context resolution throws (no workspace yet)' {
        $UseEngine = $true
        $script:TargetEnvironment = 'nonprod'
        Mock New-Compl8Context { throw 'no tenant pin for env' }
        Test-Compl8PhaseRoutesToEngine 'rulePackage' | Should -BeFalse
    }
    It 'returns FALSE when no environment is selected' {
        $UseEngine = $true
        $script:TargetEnvironment = $null
        Test-Compl8PhaseRoutesToEngine 'rulePackage' | Should -BeFalse
    }
}

Describe 'Invoke-Compl8EnginePhase — plan-only safety until content is wired (codex 5B P1)' {
    BeforeAll {
        . ([scriptblock]::Create((Get-ScriptFunctionText -Name 'Get-Compl8DeployContext')))
        . ([scriptblock]::Create((Get-ScriptFunctionText -Name 'Invoke-Compl8EnginePhase')))
        function New-Compl8Context { param([string]$TargetEnvironment, [string]$WorkspaceRoot, [string]$Prefix, [string]$UPN, [switch]$Delegated) }
        function Invoke-Compl8Deploy { param($Context, $PlanId, $GeneratedUtc, $ProjectRoot, $DesiredContent, [switch]$WhatIf) }
        $script:DeployStamp = '20260615000000'
        $script:DeployGeneratedUtc = '2026-06-15T00:00:00Z'
        $ProjectRoot = $script:ProjectRoot
    }

    It 'forces -WhatIf (plan-only) when NO desired content is supplied' {
        $UseEngine = $true
        $script:TargetEnvironment = 'nonprod'
        Mock New-Compl8Context { [pscustomobject]@{ Environment = 'nonprod'; EngineRoutes = [pscustomobject]@{ rulePackage = $true } } }
        Mock Invoke-Compl8Deploy { [pscustomobject]@{ render = '' } }
        Invoke-Compl8EnginePhase -RouteKey 'rulePackage' -PhaseLabel 'Classifiers' | Out-Null
        Should -Invoke Invoke-Compl8Deploy -Times 1 -ParameterFilter { $WhatIf -eq $true }
    }

    It 'allows a REAL apply (no forced -WhatIf) once desired content IS supplied' {
        $UseEngine = $true
        $script:TargetEnvironment = 'nonprod'
        Mock New-Compl8Context { [pscustomobject]@{ Environment = 'nonprod'; EngineRoutes = [pscustomobject]@{ rulePackage = $true } } }
        Mock Invoke-Compl8Deploy { [pscustomobject]@{ render = '' } }
        $content = @{ 'rulePackage|QGISCF-test-01' = [pscustomobject]@{ name = 'QGISCF-test-01' } }
        Invoke-Compl8EnginePhase -RouteKey 'rulePackage' -PhaseLabel 'Classifiers' -DesiredContent $content | Out-Null
        Should -Invoke Invoke-Compl8Deploy -Times 1 -ParameterFilter { -not $WhatIf }
    }
}
