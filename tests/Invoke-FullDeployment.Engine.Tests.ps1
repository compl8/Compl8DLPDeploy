#Requires -Modules Pester

# =====================================================================================
# Invoke-FullDeployment.ps1 — Engine-path wiring (Stage 5 PHASE 5B, Task 5B-2).
#
# The CLI orchestrator gains an OPT-IN Engine path: under -UseEngine the 7-field bundle is
# mapped into a New-Compl8Context and EACH phase routes through Invoke-Compl8Deploy WHEN its
# object type's route is ON (tenant.json engineRoutes; default ALL FALSE). The leaf path is
# KEPT for every un-routed type (D5 — old paths stay live until each type's nonprod shadow
# trial passes). WITHOUT -UseEngine, or with all routes false, the orchestrator behaves
# byte-for-byte as today (the existing OrchestrationWiring / OrchestratorArgForwarding /
# ConfigResolutionWiring suites continue to assert that leaf behaviour).
#
# Orchestrators are NOT executed in tests (the leaf `& <path>.ps1` invocations are not
# mockable) — the established pattern is static (AST/string) wiring assertions, plus here a
# behavioural test of the routing GATE (the safety-critical all-false => leaf guarantee),
# extracted from the script via AST so it runs in isolation.
# =====================================================================================

BeforeAll {
    $script:ProjectRoot = Split-Path $PSScriptRoot -Parent
    $script:ScriptPath  = Join-Path $script:ProjectRoot 'scripts' 'Invoke-FullDeployment.ps1'
    $script:Content     = Get-Content -LiteralPath $script:ScriptPath -Raw

    # Extract a single top-level function's source text from the script via AST (no main body runs).
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

Describe 'Invoke-FullDeployment — Engine opt-in surface' {
    It 'declares the -UseEngine opt-in switch' {
        ($script:Content -match '\[switch\]\$UseEngine') | Should -BeTrue
    }
    It 'builds the context only under -UseEngine (default path imports no Engine module)' {
        # The Compl8.Engine import + New-Compl8Context live inside an `if ($UseEngine)` block.
        ($script:Content -match 'if\s*\(\$UseEngine\)\s*\{[\s\S]*?New-Compl8Context') | Should -BeTrue
    }
    It 'maps the 7-field bundle into New-Compl8Context (TargetEnvironment + Prefix/UPN/Delegated)' {
        ($script:Content -match 'New-Compl8Context\s+@ctxArgs') | Should -BeTrue
        ($script:Content -match '\$ctxArgs\[["'']TargetEnvironment["'']\]|TargetEnvironment\s*=\s*\$TargetEnvironment') | Should -BeTrue
        ($script:Content -match '\$ctxArgs\["Prefix"\]\s*=\s*\$Prefix') | Should -BeTrue
        ($script:Content -match '\$ctxArgs\["UPN"\]\s*=\s*\$UPN') | Should -BeTrue
        ($script:Content -match '\$ctxArgs\["Delegated"\]\s*=\s*\$true') | Should -BeTrue
    }
}

Describe 'Invoke-FullDeployment — every phase has a route-gated Engine branch' {
    # phase label -> the route key its object type maps to.
    $phaseRoutes = @(
        @{ Phase = 'Labels';       RouteKey = 'label' }
        @{ Phase = 'Dictionaries'; RouteKey = 'dictionary' }
        @{ Phase = 'Classifiers';  RouteKey = 'rulePackage' }
        @{ Phase = 'DLPRules';     RouteKey = 'dlpRule' }
    )

    It '<Phase> routes through the Engine gated on the <RouteKey> route' -ForEach $phaseRoutes {
        $guard = "Test-Compl8PhaseRoutesToEngine '$RouteKey'"
        ($script:Content -match [regex]::Escape($guard)) |
            Should -BeTrue -Because "the $Phase phase must check the $RouteKey route before using the Engine"
        $call = "Invoke-Compl8EnginePhase -Context `$DeployContext -RouteKey '$RouteKey'"
        ($script:Content -match [regex]::Escape($call)) |
            Should -BeTrue -Because "the $Phase phase must route its type through Invoke-Compl8Deploy when routed"
    }
}

Describe 'Invoke-FullDeployment — leaf path PRESERVED (un-routed types unchanged)' {
    It 'still splat-invokes all three leaf deploy scripts (D5: old paths stay live)' {
        ($script:Content -match '& \(Join-Path \$PSScriptRoot "Deploy-Labels\.ps1"\) @labelArgs')        | Should -BeTrue
        ($script:Content -match '& \(Join-Path \$PSScriptRoot "Deploy-Classifiers\.ps1"\) @classifierArgs') | Should -BeTrue
        ($script:Content -match '& \(Join-Path \$PSScriptRoot "Deploy-DLPRules\.ps1"\) @ruleArgs')        | Should -BeTrue
    }
    It 'keeps the leaf calls in an else branch of the route gate (engine OR leaf, never both)' {
        # Each routed phase is `if (Test-Compl8PhaseRoutesToEngine ...) { engine } else { leaf }`.
        ($script:Content -match 'Test-Compl8PhaseRoutesToEngine[\s\S]*?\}\s*else\s*\{') | Should -BeTrue
    }
}

Describe 'Test-Compl8PhaseRoutesToEngine — the routing GATE (behavioural)' {
    BeforeAll {
        # Dot-source ONLY the gate function; it reads $UseEngine / $DeployContext from the caller
        # scope (dynamic scoping), so we set those here to drive its decision.
        . ([scriptblock]::Create((Get-ScriptFunctionText -Name 'Test-Compl8PhaseRoutesToEngine')))
    }

    It 'returns FALSE when -UseEngine is not set (default = leaf), even with a route ON' {
        $UseEngine = $false
        $DeployContext = [pscustomobject]@{ EngineRoutes = [pscustomobject]@{ dictionary = $true } }
        Test-Compl8PhaseRoutesToEngine 'dictionary' | Should -BeFalse
    }
    It 'returns FALSE under -UseEngine when the type route is OFF (all-false default => leaf)' {
        $UseEngine = $true
        $DeployContext = [pscustomobject]@{ EngineRoutes = [pscustomobject]@{ dictionary = $false; label = $false; rulePackage = $false; dlpRule = $false; autoLabel = $false } }
        Test-Compl8PhaseRoutesToEngine 'dictionary' | Should -BeFalse
        Test-Compl8PhaseRoutesToEngine 'rulePackage' | Should -BeFalse
    }
    It 'returns TRUE only for the type whose route is ON under -UseEngine' {
        $UseEngine = $true
        $DeployContext = [pscustomobject]@{ EngineRoutes = [pscustomobject]@{ dictionary = $true; label = $false; rulePackage = $false; dlpRule = $false; autoLabel = $false } }
        Test-Compl8PhaseRoutesToEngine 'dictionary' | Should -BeTrue
        Test-Compl8PhaseRoutesToEngine 'label'      | Should -BeFalse
    }
    It 'returns FALSE when no context was built (no -UseEngine workspace)' {
        $UseEngine = $true
        $DeployContext = $null
        Test-Compl8PhaseRoutesToEngine 'dictionary' | Should -BeFalse
    }
}

Describe 'Invoke-Compl8EnginePhase — plan-only safety until content is wired (codex 5B P1)' {
    BeforeAll {
        . ([scriptblock]::Create((Get-ScriptFunctionText -Name 'Invoke-Compl8EnginePhase')))
        function Invoke-Compl8Deploy { param($Context, $PlanId, $GeneratedUtc, $ProjectRoot, $DesiredContent, [switch]$WhatIf) }
        $script:DeployStamp = '20260615000000'
        $script:DeployGeneratedUtc = '2026-06-15T00:00:00Z'
        $ProjectRoot = $script:ProjectRoot
        $script:Ctx = [pscustomobject]@{ Environment = 'nonprod'; EngineRoutes = [pscustomobject]@{ dictionary = $true } }
    }

    It 'forces -WhatIf (plan-only) when NO desired content is supplied and not already -WhatIf' {
        Mock Invoke-Compl8Deploy { [pscustomobject]@{ render = '' } }
        Invoke-Compl8EnginePhase -Context $script:Ctx -RouteKey 'dictionary' -PhaseLabel 'Dictionaries' | Out-Null
        Should -Invoke Invoke-Compl8Deploy -Times 1 -ParameterFilter { $WhatIf -eq $true }
    }

    It 'allows a REAL apply (no forced -WhatIf) once desired content IS supplied' {
        Mock Invoke-Compl8Deploy { [pscustomobject]@{ render = '' } }
        $content = @{ 'dictionary|{{DICT_X}}' = [pscustomobject]@{ name = 'X' } }
        Invoke-Compl8EnginePhase -Context $script:Ctx -RouteKey 'dictionary' -PhaseLabel 'Dictionaries' -DesiredContent $content | Out-Null
        Should -Invoke Invoke-Compl8Deploy -Times 1 -ParameterFilter { -not $WhatIf }
    }
}
