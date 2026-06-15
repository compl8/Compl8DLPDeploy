#Requires -Modules Pester

# Compl8.Engine — Invoke-Compl8Apply + Test-Compl8Gate (Stage 4 PHASE 4C, Task 6).
# The apply framework is the ONLY tenant-mutating layer and the highest-stakes new machinery.
# Hard rules (arch design §5; decisions D3/D4/D5):
#   - apply accepts ONLY a plan FILE PATH (-PlanPath); an inline step list / plan object is
#     REJECTED (throw). -WhatIf = plan-without-apply (short-circuit before any executor call).
#   - re-verifies plan FRESHNESS vs the current inputs (Test-Compl8PlanCurrent, mockable) before
#     anything — a stale plan is refused.
#   - runs the fingerprint gate (Test-DeploymentTenantFingerprint, mockable) before any mutation.
#   - dispatches each step IN DEPENDENCY ORDER to an INJECTABLE executor (an -ExecutorMap of
#     objectType -> scriptblock). The default/production dispatcher fails CLOSED for an unknown
#     objectType. Real executors arrive in later tasks.
#   - CHECKPOINT/RESUME: a per-step checkpoint lands at history/applies/<planId>/<stepId>.json as
#     each step succeeds; re-running the SAME plan path skips checkpointed steps and re-runs the
#     rest; a final history/applies/<planId>/result.json summarises every step.
#   - destructive steps (remove/dereference) re-invoke the reference guard at apply time (D5
#     backstop) before the executor runs; a veto blocks that step.
#   - apply stops at a blocking gate and resumes from checkpoint on the next run.
#
# Test-Compl8Gate (pluggable gate evaluator; INJECTABLE clock -Now, Get-Date BANNED in body):
#   - propagation: blocks until -Now >= notBefore; passes once -Now >= notBefore.
#   - snapshotBeforeDestroy: passes only once the snapshot step has checkpointed.
#   - externalRefs: halts unless -ConfirmExternalRefs is supplied.

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot  = Split-Path $PSScriptRoot -Parent
    $script:EngineDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:EngineDir -Force

    # ------------------------------------------------------------------ plan-on-disk helper
    # Build a compl8.plan/v1 (Model constructors), write it to a temp workspace's
    # history/plans/<id>.json, and return { WorkRoot; PlanPath; Plan }. Apply consumes the path.
    function New-TestPlanFile {
        param(
            [object[]]$Steps,
            [string]$Id = 'plan-apply-test',
            [string]$ResolveHash = 'sha256:aa',
            [string]$InventoryHash = 'sha256:bb',
            [string]$AssessmentHash = 'sha256:cc'
        )
        $plan = New-PlanObject -Workspace 'nonprod' -Id $Id -GeneratedUtc '2026-06-13T00:00:00Z' `
            -ResolveManifestHash $ResolveHash -InventoryHash $InventoryHash -AssessmentHash $AssessmentHash
        foreach ($s in $Steps) {
            $plan = Add-PlanStep -Plan $plan -Id $s.id -Action $s.action -ObjectType $s.objectType `
                -ObjectRef $s.objectRef -DependsOn @($s.dependsOn) -Impact @($s.impact) -Gate $s.gate
        }
        $workRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("compl8apply-" + [guid]::NewGuid())
        $plansDir = Join-Path $workRoot 'history' 'plans'
        New-Item -ItemType Directory -Path $plansDir -Force | Out-Null
        $planPath = Join-Path $plansDir "$Id.json"
        ($plan | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $planPath -Encoding UTF8 -NoNewline
        [pscustomobject]@{ WorkRoot = $workRoot; PlanPath = $planPath; Plan = $plan }
    }

    function New-Step {
        param([string]$Id, [string]$Action, [string]$ObjectType, [string]$ObjectRef,
              [string[]]$DependsOn = @(), [string[]]$Impact = @(), [pscustomobject]$Gate = $null)
        [pscustomobject]@{ id = $Id; action = $Action; objectType = $ObjectType; objectRef = $ObjectRef
            dependsOn = @($DependsOn); impact = @($Impact); gate = $Gate }
    }

    # A simple non-destructive 3-step plan: create dict -> update package -> update rule.
    $script:SimpleSteps = @(
        New-Step -Id 's01' -Action 'create' -ObjectType 'dictionary'  -ObjectRef '{{DICT_X}}'
        New-Step -Id 's02' -Action 'update' -ObjectType 'rulePackage' -ObjectRef 'QGISCF-test-01' -DependsOn @('s01')
        New-Step -Id 's03' -Action 'update' -ObjectType 'dlpRule'     -ObjectRef 'QGISCF-Rule-07'  -DependsOn @('s02')
    )

    $script:ApplyRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("compl8apply-roots-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $script:ApplyRoot -Force | Out-Null
}

AfterAll {
    if ($script:ApplyRoot -and (Test-Path -LiteralPath $script:ApplyRoot)) {
        Remove-Item -LiteralPath $script:ApplyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'module surface' {
    It 'exports Invoke-Compl8Apply and Test-Compl8Gate from Compl8.Engine' {
        foreach ($fn in 'Invoke-Compl8Apply', 'Test-Compl8Gate') {
            (Get-Command -Name $fn -Module Compl8.Engine -ErrorAction SilentlyContinue) |
                Should -Not -BeNullOrEmpty -Because "$fn must be exported"
        }
    }
}

Describe 'Invoke-Compl8Apply — plan-only contract (§5 hard rule)' {
    It 'REJECTS an inline plan object passed directly (no -PlanPath)' {
        $fixture = New-TestPlanFile -Steps $script:SimpleSteps -Id 'plan-reject-obj'
        { Invoke-Compl8Apply -Plan $fixture.Plan -ExecutorMap @{} } |
            Should -Throw
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'REJECTS an inline step list passed directly' {
        { Invoke-Compl8Apply -Steps $script:SimpleSteps -ExecutorMap @{} } | Should -Throw
    }

    It 'accepts a -PlanPath (the only mutation entry point)' {
        $fixture = New-TestPlanFile -Steps $script:SimpleSteps -Id 'plan-accept-path'
        $map = @{
            dictionary  = { param($Step) }
            rulePackage = { param($Step) }
            dlpRule     = { param($Step) }
        }
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }
        { Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map } | Should -Not -Throw
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-Compl8Apply — freshness gate (stale plan refused before any executor)' {
    It 'refuses a stale plan (Test-Compl8PlanCurrent => false) and never calls the executor' {
        $fixture = New-TestPlanFile -Steps $script:SimpleSteps -Id 'plan-stale'
        $script:staleCalls = 0
        $map = @{
            dictionary  = { param($Step) $script:staleCalls++ }
            rulePackage = { param($Step) $script:staleCalls++ }
            dlpRule     = { param($Step) $script:staleCalls++ }
        }
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $false }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }
        { Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:CHANGED' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map } |
            Should -Throw -ExpectedMessage '*stale*'
        $script:staleCalls | Should -Be 0
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-Compl8Apply — fingerprint gate consulted before any mutation' {
    It 'blocks apply when the fingerprint gate fails (passed=false) and never calls the executor' {
        $fixture = New-TestPlanFile -Steps $script:SimpleSteps -Id 'plan-fp-fail'
        $script:fpCalls = 0
        $map = @{
            dictionary  = { param($Step) $script:fpCalls++ }
            rulePackage = { param($Step) $script:fpCalls++ }
            dlpRule     = { param($Step) $script:fpCalls++ }
        }
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $false; mode = 'block' } }
        { Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map } |
            Should -Throw -ExpectedMessage '*fingerprint*'
        $script:fpCalls | Should -Be 0
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'consults the fingerprint gate (mock is invoked)' {
        $fixture = New-TestPlanFile -Steps $script:SimpleSteps -Id 'plan-fp-ok'
        $map = @{
            dictionary  = { param($Step) }
            rulePackage = { param($Step) }
            dlpRule     = { param($Step) }
        }
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }
        Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map | Out-Null
        Should -Invoke -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint -Times 1
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-Compl8Apply — happy path: dependency order + checkpoints + result.json' {
    BeforeAll {
        $fixture = New-TestPlanFile -Steps $script:SimpleSteps -Id 'plan-happy'
        $script:happyWorkRoot = $fixture.WorkRoot
        $script:happyOrder = [System.Collections.Generic.List[string]]::new()
        $map = @{
            dictionary  = { param($Step) $script:happyOrder.Add($Step.id) }
            rulePackage = { param($Step) $script:happyOrder.Add($Step.id) }
            dlpRule     = { param($Step) $script:happyOrder.Add($Step.id) }
        }
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }
        $script:happyResult = Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map
        $script:appliesDir = Join-Path $script:happyWorkRoot 'history' 'applies' 'plan-happy'
    }

    AfterAll {
        if ($script:happyWorkRoot -and (Test-Path -LiteralPath $script:happyWorkRoot)) {
            Remove-Item -LiteralPath $script:happyWorkRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'runs the steps in dependency order (s01 -> s02 -> s03)' {
        @($script:happyOrder) | Should -Be @('s01', 's02', 's03')
    }

    It 'writes a per-step checkpoint history/applies/<planId>/<stepId>.json for every step' {
        foreach ($id in 's01', 's02', 's03') {
            Test-Path -LiteralPath (Join-Path $script:appliesDir "$id.json") | Should -BeTrue -Because "checkpoint for $id"
        }
    }

    It 'writes a result.json that lists every step exactly once' {
        $resultPath = Join-Path $script:appliesDir 'result.json'
        Test-Path -LiteralPath $resultPath | Should -BeTrue
        $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
        $ids = @($result.steps | ForEach-Object stepId)
        @($ids | Sort-Object) | Should -Be @('s01', 's02', 's03')
        ($ids | Group-Object | Where-Object { $_.Count -gt 1 }) | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-Compl8Apply — checkpoint/resume (kill mid-plan, re-run skips completed)' {
    BeforeAll {
        $fixture = New-TestPlanFile -Steps $script:SimpleSteps -Id 'plan-resume'
        $script:resumeWorkRoot = $fixture.WorkRoot
        $script:resumePlanPath = $fixture.PlanPath
        $script:appliesDirR = Join-Path $script:resumeWorkRoot 'history' 'applies' 'plan-resume'

        # Per-step invocation counters prove which steps the executor actually ran.
        $script:invokeCounts = @{ s01 = 0; s02 = 0; s03 = 0 }
        # First run: the dlpRule executor (step s03) THROWS, so apply fails at step 3.
        $script:failOnS03 = $true
        $map = @{
            dictionary  = { param($Step) $script:invokeCounts[$Step.id]++ }
            rulePackage = { param($Step) $script:invokeCounts[$Step.id]++ }
            dlpRule     = { param($Step) $script:invokeCounts[$Step.id]++; if ($script:failOnS03) { throw "boom on $($Step.id)" } }
        }
        $script:resumeMap = $map
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }

        # ---- FIRST RUN: fails at step 3 ----
        $script:firstError = $null
        try {
            Invoke-Compl8Apply -PlanPath $script:resumePlanPath `
                -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
                -ProjectRoot $script:RepoRoot -ExecutorMap $map | Out-Null
        } catch { $script:firstError = $_ }
    }

    AfterAll {
        if ($script:resumeWorkRoot -and (Test-Path -LiteralPath $script:resumeWorkRoot)) {
            Remove-Item -LiteralPath $script:resumeWorkRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'fails the first run at step 3' {
        $script:firstError | Should -Not -BeNullOrEmpty
    }

    It 'checkpoints steps 1-2 but NOT step 3 after the failed first run' {
        Test-Path -LiteralPath (Join-Path $script:appliesDirR 's01.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:appliesDirR 's02.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:appliesDirR 's03.json') | Should -BeFalse
    }

    It 're-running SKIPS the checkpointed steps 1-2 and RETRIES step 3 only' {
        # Let step 3 succeed this time; reset counters so the re-run is measured cleanly.
        $script:invokeCounts = @{ s01 = 0; s02 = 0; s03 = 0 }
        $script:failOnS03 = $false
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }
        Invoke-Compl8Apply -PlanPath $script:resumePlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $script:resumeMap | Out-Null

        $script:invokeCounts['s01'] | Should -Be 0 -Because 's01 was already checkpointed — must be skipped'
        $script:invokeCounts['s02'] | Should -Be 0 -Because 's02 was already checkpointed — must be skipped'
        $script:invokeCounts['s03'] | Should -Be 1 -Because 's03 had no checkpoint — must be retried'
        Test-Path -LiteralPath (Join-Path $script:appliesDirR 's03.json') | Should -BeTrue
    }
}

Describe 'Invoke-Compl8Apply — -WhatIf short-circuits before any executor + no checkpoints' {
    It 'never calls an executor, writes no checkpoint, and reports the steps that would run' {
        $fixture = New-TestPlanFile -Steps $script:SimpleSteps -Id 'plan-whatif'
        $script:whatIfCalls = 0
        $map = @{
            dictionary  = { param($Step) $script:whatIfCalls++ }
            rulePackage = { param($Step) $script:whatIfCalls++ }
            dlpRule     = { param($Step) $script:whatIfCalls++ }
        }
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }
        $report = Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map -WhatIf

        $script:whatIfCalls | Should -Be 0
        $appliesDir = Join-Path $fixture.WorkRoot 'history' 'applies' 'plan-whatif'
        Test-Path -LiteralPath $appliesDir | Should -BeFalse -Because 'WhatIf writes no checkpoints'
        # The report enumerates the steps that WOULD run.
        @($report.wouldRun | ForEach-Object stepId) | Should -Be @('s01', 's02', 's03')
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-Compl8Apply — unknown objectType fails closed (default dispatcher)' {
    It 'throws "no executor registered for <type>" when no executor handles the step type' {
        $steps = @(New-Step -Id 's01' -Action 'create' -ObjectType 'label' -ObjectRef 'QGISCF-Conf')
        $fixture = New-TestPlanFile -Steps $steps -Id 'plan-unknown'
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }
        # ExecutorMap has NO 'label' entry — must fail closed.
        { Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap @{ dictionary = { param($Step) } } } |
            Should -Throw -ExpectedMessage '*no executor registered for*label*'
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-Compl8Apply — destructive step backstop (reference guard, D5)' {
    It 'invokes the reference guard before a remove executor and blocks on a veto (unsafe)' {
        # A snapshot step (so snapshotBeforeDestroy is satisfiable) then a remove of a rulePackage.
        $steps = @(
            New-Step -Id 's00' -Action 'snapshot' -ObjectType 'tenant'      -ObjectRef '*' -Gate ([pscustomobject]@{ type = 'snapshotBeforeDestroy' })
            New-Step -Id 's01' -Action 'remove'   -ObjectType 'rulePackage' -ObjectRef 'QGISCF-doomed' -DependsOn @('s00')
        )
        $fixture = New-TestPlanFile -Steps $steps -Id 'plan-guard-veto'
        $script:guardRemoveCalls = 0
        $map = @{
            tenant      = { param($Step) }   # snapshot executor
            rulePackage = { param($Step) $script:guardRemoveCalls++ }
        }
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }
        # Guard VETOES (Safe=false) the removal.
        Mock -ModuleName Compl8.Engine Test-DlpRulePackageRemovalReferenceGuard {
            [pscustomobject]@{ Safe = $false; ReferencingRuleCount = 2; References = @() }
        }
        $result = Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map -ContinueOnBlock

        Should -Invoke -ModuleName Compl8.Engine Test-DlpRulePackageRemovalReferenceGuard -Times 1
        $script:guardRemoveCalls | Should -Be 0 -Because 'a vetoing guard must block the remove executor'
        # The remove step is recorded blocked, not applied.
        $removeStep = @($result.steps | Where-Object { $_.stepId -eq 's01' })[0]
        $removeStep.status | Should -Be 'blocked'
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'allows the remove executor to run when the guard reports Safe=true' {
        $steps = @(
            New-Step -Id 's00' -Action 'snapshot' -ObjectType 'tenant'      -ObjectRef '*' -Gate ([pscustomobject]@{ type = 'snapshotBeforeDestroy' })
            New-Step -Id 's01' -Action 'remove'   -ObjectType 'rulePackage' -ObjectRef 'QGISCF-safe' -DependsOn @('s00')
        )
        $fixture = New-TestPlanFile -Steps $steps -Id 'plan-guard-ok'
        $script:safeRemoveCalls = 0
        $map = @{
            tenant      = { param($Step) }
            rulePackage = { param($Step) $script:safeRemoveCalls++ }
        }
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }
        Mock -ModuleName Compl8.Engine Test-DlpRulePackageRemovalReferenceGuard {
            [pscustomobject]@{ Safe = $true; ReferencingRuleCount = 0; References = @() }
        }
        Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map | Out-Null
        $script:safeRemoveCalls | Should -Be 1
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-Compl8Apply — SAFETY: a blocked prerequisite skips its dependents (P1)' {
    It 'under -ContinueOnBlock, a blocked step B-dependent is NOT executed; an independent step C IS' {
        # A: blocked by an unsatisfiable externalRefs gate (no -ConfirmExternalRefs).
        # B: dependsOn A, NO gate of its own — must NOT run (its prerequisite was never satisfied).
        # C: independent, no gate — must run.
        $steps = @(
            New-Step -Id 's01' -Action 'update' -ObjectType 'dlpRule'     -ObjectRef 'A-blocked'     -Gate ([pscustomobject]@{ type = 'externalRefs' })
            New-Step -Id 's02' -Action 'update' -ObjectType 'dlpRule'     -ObjectRef 'B-dependent'    -DependsOn @('s01')
            New-Step -Id 's03' -Action 'update' -ObjectType 'rulePackage' -ObjectRef 'C-independent'
        )
        $fixture = New-TestPlanFile -Steps $steps -Id 'plan-dep-skip'
        $script:depRuleCalls = [System.Collections.Generic.List[string]]::new()
        $map = @{
            dlpRule     = { param($Step) $script:depRuleCalls.Add($Step.id) }
            rulePackage = { param($Step) $script:depRuleCalls.Add($Step.id) }
        }
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }

        $result = Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map -ContinueOnBlock

        # A blocked, its executor never ran.
        @($script:depRuleCalls) | Should -Not -Contain 's01'
        $a = @($result.steps | Where-Object { $_.stepId -eq 's01' })[0]
        $a.status | Should -Be 'blocked'

        # B (dependent on A) must NOT have executed — this is the bug the fix closes.
        @($script:depRuleCalls) | Should -Not -Contain 's02' -Because 'a dependent of a blocked step must never mutate the tenant'
        $b = @($result.steps | Where-Object { $_.stepId -eq 's02' })[0]
        $b.status | Should -BeIn @('blocked', 'skipped-dependency')

        # C (independent) MUST have executed.
        @($script:depRuleCalls) | Should -Contain 's03' -Because 'an independent step with no failed prerequisite still runs under -ContinueOnBlock'
        $c = @($result.steps | Where-Object { $_.stepId -eq 's03' })[0]
        $c.status | Should -Be 'applied'

        # B left NO checkpoint (it never ran) so a later run can still attempt it.
        $appliesDir = Join-Path $fixture.WorkRoot 'history' 'applies' 'plan-dep-skip'
        Test-Path -LiteralPath (Join-Path $appliesDir 's02.json') | Should -BeFalse
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'transitively skips a deeper dependent subtree (B->C both skipped when A is blocked)' {
        # A blocked; B dependsOn A; C dependsOn B. Neither B nor C may run.
        $steps = @(
            New-Step -Id 's01' -Action 'update' -ObjectType 'dlpRule' -ObjectRef 'A' -Gate ([pscustomobject]@{ type = 'externalRefs' })
            New-Step -Id 's02' -Action 'update' -ObjectType 'dlpRule' -ObjectRef 'B' -DependsOn @('s01')
            New-Step -Id 's03' -Action 'update' -ObjectType 'dlpRule' -ObjectRef 'C' -DependsOn @('s02')
        )
        $fixture = New-TestPlanFile -Steps $steps -Id 'plan-dep-skip-deep'
        $script:deepCalls = [System.Collections.Generic.List[string]]::new()
        $map = @{ dlpRule = { param($Step) $script:deepCalls.Add($Step.id) } }
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }

        $result = Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map -ContinueOnBlock

        @($script:deepCalls) | Should -BeNullOrEmpty -Because 'no step may run when the root prerequisite is blocked'
        (@($result.steps | Where-Object { $_.stepId -eq 's03' })[0]).status | Should -Be 'skipped-dependency'
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-Compl8Apply — rule-package reference guard is SCOPED to rulePackage removals (P2)' {
    It 'does NOT consult the guard for a dictionary remove or a dlpRule dereference (no false block)' {
        # A dictionary `remove` and a dlpRule `dereference` — neither carries rule-package XML, so the
        # rule-package guard must NOT run for them. The guard is mocked to VETO if it were called, so a
        # false call would block these steps. Assert their executors run normally.
        $steps = @(
            New-Step -Id 's01' -Action 'remove'      -ObjectType 'dictionary' -ObjectRef '{{DICT_DEAD}}'
            New-Step -Id 's02' -Action 'dereference' -ObjectType 'dlpRule'    -ObjectRef 'QGISCF-Rule-strip'
        )
        $fixture = New-TestPlanFile -Steps $steps -Id 'plan-guard-scope'
        $script:scopeCalls = [System.Collections.Generic.List[string]]::new()
        $map = @{
            dictionary = { param($Step) $script:scopeCalls.Add($Step.id) }
            dlpRule    = { param($Step) $script:scopeCalls.Add($Step.id) }
        }
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }
        # The guard would VETO if (wrongly) invoked for these non-rulePackage destructive steps.
        Mock -ModuleName Compl8.Engine Test-DlpRulePackageRemovalReferenceGuard {
            [pscustomobject]@{ Safe = $false; ReferencingRuleCount = 99; References = @() }
        }

        $result = Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map -ContinueOnBlock

        # The guard was never consulted for these steps.
        Should -Invoke -ModuleName Compl8.Engine Test-DlpRulePackageRemovalReferenceGuard -Times 0
        # Both destructive-but-non-rulePackage steps ran and applied (NOT falsely blocked).
        @($script:scopeCalls) | Should -Contain 's01'
        @($script:scopeCalls) | Should -Contain 's02'
        (@($result.steps | Where-Object { $_.stepId -eq 's01' })[0]).status | Should -Be 'applied'
        (@($result.steps | Where-Object { $_.stepId -eq 's02' })[0]).status | Should -Be 'applied'
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'STILL consults the guard for a genuine rulePackage removal and a veto blocks it (D5)' {
        # A real rulePackage `remove` MUST still be guarded; a veto blocks it.
        $steps = @(
            New-Step -Id 's00' -Action 'snapshot' -ObjectType 'tenant'      -ObjectRef '*' -Gate ([pscustomobject]@{ type = 'snapshotBeforeDestroy' })
            New-Step -Id 's01' -Action 'remove'   -ObjectType 'rulePackage' -ObjectRef 'QGISCF-doomed' -DependsOn @('s00')
        )
        $fixture = New-TestPlanFile -Steps $steps -Id 'plan-guard-scope-pkg'
        $script:pkgRemoveCalls = 0
        $map = @{
            tenant      = { param($Step) }
            rulePackage = { param($Step) $script:pkgRemoveCalls++ }
        }
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }
        Mock -ModuleName Compl8.Engine Test-DlpRulePackageRemovalReferenceGuard {
            [pscustomobject]@{ Safe = $false; ReferencingRuleCount = 3; References = @() }
        }

        $result = Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map -ContinueOnBlock

        Should -Invoke -ModuleName Compl8.Engine Test-DlpRulePackageRemovalReferenceGuard -Times 1
        $script:pkgRemoveCalls | Should -Be 0 -Because 'a vetoing guard must block the rule-package remove executor'
        (@($result.steps | Where-Object { $_.stepId -eq 's01' })[0]).status | Should -Be 'blocked'
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'passes the guard REAL package data from -StepContent for a rulePackage removal' {
        # When -StepContent carries the resolved package, the guard receives it as -Packages (real XML)
        # so it can genuinely decide Safe, rather than only the objectRef identity.
        $steps = @(
            New-Step -Id 's00' -Action 'snapshot' -ObjectType 'tenant'      -ObjectRef '*' -Gate ([pscustomobject]@{ type = 'snapshotBeforeDestroy' })
            New-Step -Id 's01' -Action 'remove'   -ObjectType 'rulePackage' -ObjectRef 'QGISCF-content' -DependsOn @('s00')
        )
        $fixture = New-TestPlanFile -Steps $steps -Id 'plan-guard-content'
        $map = @{
            tenant      = { param($Step) }
            rulePackage = { param($Step) }
        }
        $script:guardSawPackages = $null
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }
        Mock -ModuleName Compl8.Engine Test-DlpRulePackageRemovalReferenceGuard {
            $script:guardSawPackages = @($Packages)
            [pscustomobject]@{ Safe = $true; ReferencingRuleCount = 0; References = @() }
        }

        $resolvedPackage = [pscustomobject]@{ Identity = 'QGISCF-content'; Name = 'QGISCF-content'; ClassificationRuleCollectionXml = '<RulePackage/>' }
        $stepContent = @{ s01 = [pscustomobject]@{ Packages = @($resolvedPackage); DlpRules = @() } }

        Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map -StepContent $stepContent | Out-Null

        Should -Invoke -ModuleName Compl8.Engine Test-DlpRulePackageRemovalReferenceGuard -Times 1
        # The guard saw the resolved package object (with XML), not a bare identity stub.
        @($script:guardSawPackages).Count | Should -Be 1
        $script:guardSawPackages[0].ClassificationRuleCollectionXml | Should -Be '<RulePackage/>'
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'reads -StepContent given as a HASHTABLE value (Packages + DlpRules), not only a PSObject' {
        # codex 4C re-review P2: the documented -StepContent value shape is a hashtable
        # (@{ Packages = ...; DlpRules = ... }). A PSObject.Properties[] lookup misses hashtable
        # keys, dropping the real package + rules and falsely vetoing a safe rulePackage removal.
        $steps = @(
            New-Step -Id 's00' -Action 'snapshot' -ObjectType 'tenant'      -ObjectRef '*' -Gate ([pscustomobject]@{ type = 'snapshotBeforeDestroy' })
            New-Step -Id 's01' -Action 'remove'   -ObjectType 'rulePackage' -ObjectRef 'QGISCF-content' -DependsOn @('s00')
        )
        $fixture = New-TestPlanFile -Steps $steps -Id 'plan-guard-hashtable'
        $map = @{
            tenant      = { param($Step) }
            rulePackage = { param($Step) }
        }
        $script:guardSawPackages = $null
        $script:guardSawDlpRules = $null
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }
        Mock -ModuleName Compl8.Engine Test-DlpRulePackageRemovalReferenceGuard {
            $script:guardSawPackages = @($Packages)
            $script:guardSawDlpRules = @($DlpRules)
            [pscustomobject]@{ Safe = $true; ReferencingRuleCount = 0; References = @() }
        }

        $resolvedPackage = [pscustomobject]@{ Identity = 'QGISCF-content'; Name = 'QGISCF-content'; ClassificationRuleCollectionXml = '<RulePackage/>' }
        # The VALUE is a hashtable (the documented shape), not a PSObject.
        $stepContent = @{ s01 = @{ Packages = @($resolvedPackage); DlpRules = @([pscustomobject]@{ Name = 'R1' }) } }

        Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map -StepContent $stepContent | Out-Null

        # The guard received the REAL package XML and the DlpRules from the hashtable value —
        # not the bare identity stub (which would have ClassificationRuleCollectionXml absent).
        @($script:guardSawPackages).Count | Should -Be 1
        $script:guardSawPackages[0].ClassificationRuleCollectionXml | Should -Be '<RulePackage/>'
        @($script:guardSawDlpRules).Count | Should -Be 1
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# =====================================================================================
# Test-Compl8Gate — pluggable gate evaluator with an INJECTABLE clock (-Now).
# =====================================================================================

Describe 'Test-Compl8Gate — propagation (injected clock)' {
    It 'BLOCKS when -Now is before notBefore' {
        $gate = [pscustomobject]@{ type = 'propagation'; notBefore = '2026-06-13T10:00:00Z' }
        $r = Test-Compl8Gate -Gate $gate -Now ([datetime]'2026-06-13T08:00:00Z')
        $r.Passed | Should -BeFalse
        $r.Reason | Should -Match 'propagation'
    }

    It 'PASSES when -Now is at/after notBefore' {
        $gate = [pscustomobject]@{ type = 'propagation'; notBefore = '2026-06-13T10:00:00Z' }
        $r = Test-Compl8Gate -Gate $gate -Now ([datetime]'2026-06-13T10:00:00Z')
        $r.Passed | Should -BeTrue
    }

    It 'derives notBefore from a dependency apply-time + notBeforeOffsetHours when notBefore is absent' {
        # No explicit notBefore: the gate carries an offset; the dependency's apply time is in the
        # context. now < depApplyTime + offset => blocked; now >= => passes.
        $gate = [pscustomobject]@{ type = 'propagation'; notBeforeOffsetHours = 4 }
        $ctx = @{ DependencyAppliedUtc = '2026-06-13T10:00:00Z' }
        (Test-Compl8Gate -Gate $gate -Now ([datetime]'2026-06-13T13:59:00Z') -Context $ctx).Passed | Should -BeFalse
        (Test-Compl8Gate -Gate $gate -Now ([datetime]'2026-06-13T14:00:00Z') -Context $ctx).Passed | Should -BeTrue
    }

    It 'never calls Get-Date in the executable body (deterministic clock)' {
        $src = Get-Content -LiteralPath (Join-Path $script:EngineDir 'Public' 'Test-Compl8Gate.ps1') -Raw
        $code = [regex]::Replace($src, '(?s)<#.*?#>', '')
        $code = ($code -split "`n" | ForEach-Object { ($_ -replace '#.*$', '') }) -join "`n"
        $code | Should -Not -Match 'Get-Date'
    }
}

Describe 'Test-Compl8Gate — snapshotBeforeDestroy' {
    It 'BLOCKS until the snapshot step has checkpointed' {
        $gate = [pscustomobject]@{ type = 'snapshotBeforeDestroy' }
        $ctx = @{ SnapshotApplied = $false }
        (Test-Compl8Gate -Gate $gate -Now ([datetime]'2026-06-13T10:00:00Z') -Context $ctx).Passed | Should -BeFalse
    }

    It 'PASSES once the snapshot step has checkpointed' {
        $gate = [pscustomobject]@{ type = 'snapshotBeforeDestroy' }
        $ctx = @{ SnapshotApplied = $true }
        (Test-Compl8Gate -Gate $gate -Now ([datetime]'2026-06-13T10:00:00Z') -Context $ctx).Passed | Should -BeTrue
    }
}

Describe 'Test-Compl8Gate — externalRefs' {
    It 'HALTS (does not pass) without -ConfirmExternalRefs' {
        $gate = [pscustomobject]@{ type = 'externalRefs' }
        (Test-Compl8Gate -Gate $gate -Now ([datetime]'2026-06-13T10:00:00Z')).Passed | Should -BeFalse
    }

    It 'PASSES with -ConfirmExternalRefs (v1 operator confirmation)' {
        $gate = [pscustomobject]@{ type = 'externalRefs' }
        (Test-Compl8Gate -Gate $gate -Now ([datetime]'2026-06-13T10:00:00Z') -ConfirmExternalRefs).Passed | Should -BeTrue
    }
}

Describe 'Test-Compl8Gate — no gate passes' {
    It 'passes when the step carries no gate (null)' {
        (Test-Compl8Gate -Gate $null -Now ([datetime]'2026-06-13T10:00:00Z')).Passed | Should -BeTrue
    }
}

Describe 'Invoke-Compl8Apply — propagation gate halts a step and resumes after the offset' {
    It 'blocks a propagation-gated step when -Now is before notBefore, then applies it when -Now is after' {
        $steps = @(
            New-Step -Id 's01' -Action 'update' -ObjectType 'rulePackage' -ObjectRef 'QGISCF-pkg-01'
            New-Step -Id 's02' -Action 'update' -ObjectType 'dlpRule'     -ObjectRef 'QGISCF-Rule-09' -DependsOn @('s01') -Gate ([pscustomobject]@{ type = 'propagation'; notBefore = '2026-06-13T14:00:00Z' })
        )
        $fixture = New-TestPlanFile -Steps $steps -Id 'plan-prop'
        $script:propRuleCalls = 0
        $map = @{
            rulePackage = { param($Step) }
            dlpRule     = { param($Step) $script:propRuleCalls++ }
        }
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }

        # FIRST run: clock is BEFORE the propagation notBefore — the rule step is blocked.
        $r1 = Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map -Now ([datetime]'2026-06-13T08:00:00Z') -ContinueOnBlock
        $script:propRuleCalls | Should -Be 0
        $blocked = @($r1.steps | Where-Object { $_.stepId -eq 's02' })[0]
        $blocked.status | Should -Be 'blocked'
        # s01 still checkpointed (it had no gate), s02 not.
        $appliesDir = Join-Path $fixture.WorkRoot 'history' 'applies' 'plan-prop'
        Test-Path -LiteralPath (Join-Path $appliesDir 's01.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $appliesDir 's02.json') | Should -BeFalse

        # SECOND run: clock is AFTER notBefore — s01 skipped (checkpointed), s02 now applies.
        $r2 = Invoke-Compl8Apply -PlanPath $fixture.PlanPath `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' `
            -ProjectRoot $script:RepoRoot -ExecutorMap $map -Now ([datetime]'2026-06-13T15:00:00Z')
        $script:propRuleCalls | Should -Be 1
        Test-Path -LiteralPath (Join-Path $appliesDir 's02.json') | Should -BeTrue
        Remove-Item -LiteralPath $fixture.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
