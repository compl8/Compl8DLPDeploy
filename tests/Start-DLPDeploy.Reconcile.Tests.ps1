#Requires -Modules Pester

# =====================================================================================
# Start-DLPDeploy.ps1 — Reconcile / Migrate walk wiring (Stage 5 Reconciliation R5).
#
# The interactive TUI gains an opt-in [M] Reconcile / Migrate item (shown + dispatched only under
# -UseEngine). Its handler (Invoke-Compl8ReconcileMenu) WALKS the reconciliation: assess -> surface
# the walkable conflict/orphan set with blast-radius (Get-Compl8ReconcileCandidates) -> collect a
# per-item resolution -> Invoke-Compl8Reconcile -> render the iteration walk
# (Get-Compl8ReconciliationReport) -> apply iteration 1 behind an explicit confirmation via the
# canonical Invoke-Compl8Apply. Per Stage-5 D6 the TUI holds NO logic — the Engine decides; this
# handler only prompts + prints. The leaf path and all other menu items are untouched.
#
# Pattern matches 5B-3: static (AST/string) wiring assertions (the interactive Read-Host walk + the
# connected apply cannot be unit-driven headlessly; the Engine primitives are tested in their own suites).
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

Describe 'Start-DLPDeploy — Reconcile menu surface (opt-in)' {
    It 'shows the [M] Reconcile / Migrate item ONLY under -UseEngine' {
        # The menu line is emitted inside an `if ($UseEngine)` guard in Show-Menu.
        $menu = Get-ScriptFunctionText -Name 'Show-Menu'
        ($menu -match 'if\s*\(\$UseEngine\)') | Should -BeTrue
        ($menu -match '\[M\]\s+Reconcile\s*/\s*Migrate') | Should -BeTrue
    }
    It 'dispatches "M" to the reconcile handler in the main loop' {
        ($script:Content -match '"M"\s*\{\s*Invoke-Compl8ReconcileMenu') | Should -BeTrue
    }
    It 'offers M in the selection prompt only under -UseEngine' {
        ($script:Content -match '\$UseEngine.*R,\s*M,\s*C,\s*Q') | Should -BeTrue
    }
}

Describe 'Start-DLPDeploy — Invoke-Compl8ReconcileMenu walks via the Engine (D6: no TUI logic)' {
    BeforeAll { $script:Fn = Get-ScriptFunctionText -Name 'Invoke-Compl8ReconcileMenu' }

    It 'is gated on -UseEngine and a resolved Engine context' {
        ($script:Fn -match 'if\s*\(-not\s*\$UseEngine\)') | Should -BeTrue
        ($script:Fn -match 'Get-Compl8DeployContext')      | Should -BeTrue
    }
    It 'reads the recorded actual inventory and assesses against it' {
        ($script:Fn -match "actual'\s*'inventory\.json'") | Should -BeTrue
        ($script:Fn -match 'Invoke-Compl8Assess')          | Should -BeTrue
    }
    It 'surfaces the walkable set and renders it through the Engine primitives' {
        ($script:Fn -match 'Get-Compl8ReconcileCandidates')   | Should -BeTrue
        ($script:Fn -match 'Get-Compl8AssessmentReport')      | Should -BeTrue
        ($script:Fn -match 'Get-Compl8ReconciliationReport')  | Should -BeTrue
    }
    It 'collects per-item resolutions and runs the Engine reconcile verb' {
        ($script:Fn -match 'allowedResolutions')   | Should -BeTrue
        ($script:Fn -match 'Read-Host')            | Should -BeTrue
        ($script:Fn -match 'Invoke-Compl8Reconcile') | Should -BeTrue
    }
    It 'applies iteration 1 behind an explicit confirmation + connection via the canonical apply verb' {
        ($script:Fn -match "-cne\s*'APPLY'")        | Should -BeTrue
        ($script:Fn -match 'Require-Connection')    | Should -BeTrue
        ($script:Fn -match 'Invoke-Compl8Apply')    | Should -BeTrue
    }
    It 'only auto-applies a CLAIM-ONLY iteration 1 — destructive/content-bearing plans are not applied here (codex R5)' {
        # A plan with create/update/remove/dereference needs desired-content + snapshot context the
        # minimal executor map does not carry, so the handler gates direct apply to claim-only plans.
        ($script:Fn -match '\$claimOnly')                              | Should -BeTrue
        ($script:Fn -match "action.*-ne\s*'claim'")                    | Should -BeTrue
        ($script:Fn -match 'if\s*\(-not\s*\$claimOnly\)')              | Should -BeTrue
    }
    It 'honours the APPLY CONTRACT — only iteration 1 is applied, the rest re-walked' {
        ($script:Fn -match 'iterations \| Sort-Object index')[0] | Should -BeTrue
        ($script:Fn -match 'projected|re-record|re-run|re-walk') | Should -BeTrue
    }
}

Describe 'Start-DLPDeploy — existing menu + leaf wiring PRESERVED' {
    It 'keeps the rollout wizard, connect, and quit dispatch' {
        ($script:Content -match '"R"\s*\{\s*Invoke-CustomerRolloutWizard') | Should -BeTrue
        ($script:Content -match '"C"\s*\{\s*Invoke-Connect')               | Should -BeTrue
        ($script:Content -match '"Q"\s*\{')                                | Should -BeTrue
    }
    It 'still invokes the leaf deploy scripts' {
        ($script:Content -match 'Deploy-Labels\.ps1')      | Should -BeTrue
        ($script:Content -match 'Deploy-Classifiers\.ps1') | Should -BeTrue
        ($script:Content -match 'Deploy-DLPRules\.ps1')    | Should -BeTrue
    }
}
