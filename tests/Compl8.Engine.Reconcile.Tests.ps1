#Requires -Modules Pester

# =====================================================================================
# Reconciliation R4 — Invoke-Compl8Reconcile: the iterative assess -> resolve -> re-assess loop.
#
# The Engine "brain" that turns a one-shot assessment + an operator RESOLUTION SET into an ordered,
# multi-iteration reconciliation (spec §5 / plan D5). It is PURE and DETERMINISTIC (injected ids +
# clock, no Get-Date/Get-Random): it applies the chosen resolutions across iterations — CLAIMS first
# (R2; non-destructive, unblock name-collisions), then the bucketed reconcile (updates + removals with
# the R3 backward cascade) — projecting the assessment forward between rounds until the name-collisions
# are resolved (converged) or a known blockage is deliberately left (blocked). Each iteration emits the
# compl8.plan/v1 to apply (via New-Compl8Plan, so every safety gate is preserved) plus a removal
# blast-radius preview (Get-Compl8RemovalImpact). The TUI (R5) walks these iterations; it holds no logic.
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $script:RepoRoot 'modules' 'Compl8.Engine') -Force

    # --- a reference graph: OldPkg contains sit G1, which LiveRule references ----------------------
    $script:G1 = '33333333-3333-4333-8333-333333333333'
    $pkgXml = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
<Rules><Entity id="$($script:G1)"><Pattern confidenceLevel="75"><Match idRef="$($script:G1)" /></Pattern></Entity></Rules>
</RulePackage>
"@
    $script:Graph = Get-DeploymentReferenceGraph `
        -SitPackages @([pscustomobject]@{ Identity = 'OldPkg'; Name = 'OldPkg'; Publisher = 'Compl8'; SerializedClassificationRuleCollection = $pkgXml }) `
        -DlpRules    @([pscustomobject]@{ Name = 'LiveRule'; Identity = 'lr1'; Policy = 'SomePolicy'
                         ContentContainsSensitiveInformation = [pscustomobject]@{ operator = 'And'; groups = @([pscustomobject]@{ operator = 'Or'; sensitivetypes = @([pscustomobject]@{ id = $script:G1; name = 'g1' }) }) } })

    # --- assessment factory: a mixed scenario ------------------------------------------------------
    #   foreign  dlpRule 'P01-R01-ECH-OFFI'  — name-collision (a not-ours object squats a desired name)
    #   drift    dlpRule 'P02-R02-ECH-OFFI'  — ours, content changed out-of-band (-> update)
    #   orphan   rulePackage 'OldPkg'        — ours, unexpected, referenced by LiveRule (-> remove cascade)
    function script:New-MixedAssessment {
        $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' `
            -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
        $a.buckets.foreign = @([pscustomobject]@{ objectType = 'dlpRule'; ref = 'P01-R01-ECH-OFFI'; reason = 'not ours — never touched' })
        $a.buckets.drift   = @([pscustomobject]@{ objectType = 'dlpRule'; ref = 'P02-R02-ECH-OFFI'; reason = 'ours — content changed out-of-band' })
        $a.buckets.orphan  = @([pscustomobject]@{ objectType = 'rulePackage'; ref = 'OldPkg'; reason = 'ours rule package not in desired' })
        $a.upgradeConflicts = @([pscustomobject]@{ slug = 'P01-R01-ECH-OFFI'; kind = 'name-collision'; detail = "desired dlpRule 'P01-R01-ECH-OFFI' is blocked — a foreign object holds this name." })
        # impact: removing OldPkg dereferences LiveRule (the package-removal cascade reads impact[] by ref).
        $a.impact = @([pscustomobject]@{ objectRef = 'OldPkg'; affects = @('dlp-rule: LiveRule') })
        $a
    }
}

Describe 'Invoke-Compl8Reconcile — surface + determinism' {
    It 'is exported from Compl8.Engine' {
        (Get-Command -Name Invoke-Compl8Reconcile -Module Compl8.Engine -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }
    It 'is deterministic — same inputs produce byte-identical output (no Get-Date/Get-Random)' {
        $res = @(
            [pscustomobject]@{ objectType = 'dlpRule';     ref = 'P01-R01-ECH-OFFI'; resolution = 'claim' }
            [pscustomobject]@{ objectType = 'dlpRule';     ref = 'P02-R02-ECH-OFFI'; resolution = 'update' }
            [pscustomobject]@{ objectType = 'rulePackage'; ref = 'OldPkg';           resolution = 'remove' }
        )
        $args = @{ Assessment = (New-MixedAssessment); Graph = $script:Graph; Resolutions = $res
                   Workspace = 'nonprod'; PlanIdPrefix = 'reconcile-20260616-000000'; GeneratedUtc = '2026-06-16T00:00:00Z' }
        $r1 = Invoke-Compl8Reconcile @args
        $r2 = Invoke-Compl8Reconcile @args
        ($r1 | ConvertTo-Json -Depth 25) | Should -BeExactly ($r2 | ConvertTo-Json -Depth 25)
    }
}

Describe 'Invoke-Compl8Reconcile — mixed scenario converges over iterations' {
    BeforeAll {
        $res = @(
            [pscustomobject]@{ objectType = 'dlpRule';     ref = 'P01-R01-ECH-OFFI'; resolution = 'claim' }
            [pscustomobject]@{ objectType = 'dlpRule';     ref = 'P02-R02-ECH-OFFI'; resolution = 'update' }
            [pscustomobject]@{ objectType = 'rulePackage'; ref = 'OldPkg';           resolution = 'remove' }
        )
        $script:R = Invoke-Compl8Reconcile -Assessment (New-MixedAssessment) -Graph $script:Graph -Resolutions $res `
            -Workspace 'nonprod' -PlanIdPrefix 'reconcile-20260616-000000' -GeneratedUtc '2026-06-16T00:00:00Z'
    }

    It 'reaches a converged terminal state with no unresolved conflicts' {
        $script:R.schemaVersion        | Should -Be 'compl8.reconciliation/v1'
        $script:R.status               | Should -Be 'converged'
        @($script:R.unresolvedConflicts).Count | Should -Be 0
    }
    It 'terminates in a small, bounded number of iterations' {
        $script:R.iterationCount | Should -BeGreaterThan 1
        $script:R.iterationCount | Should -BeLessOrEqual 3
    }
    It 'claims FIRST (D5) — the claim iteration precedes the destructive reconcile iteration' {
        $claimIter     = @($script:R.iterations | Where-Object { $_.phase -eq 'claim' })[0]
        $reconcileIter = @($script:R.iterations | Where-Object { $_.phase -eq 'reconcile' })[0]
        $claimIter     | Should -Not -BeNullOrEmpty
        $reconcileIter | Should -Not -BeNullOrEmpty
        $claimIter.index | Should -BeLessThan $reconcileIter.index
    }
    It 'the claim iteration adopts the colliding rule via a claim step' {
        $claimIter = @($script:R.iterations | Where-Object { $_.phase -eq 'claim' })[0]
        $claimStep = @($claimIter.plan.steps | Where-Object { $_.action -eq 'claim' -and $_.objectRef -eq 'P01-R01-ECH-OFFI' })
        $claimStep.Count        | Should -Be 1
        $claimStep[0].objectType | Should -Be 'dlpRule'
    }
    It 'the reconcile iteration updates BOTH the drifted and the now-claimed rule and removes the orphan' {
        $ri = @($script:R.iterations | Where-Object { $_.phase -eq 'reconcile' })[0]
        $actions = @($ri.plan.steps | ForEach-Object { "$($_.action):$($_.objectType):$($_.objectRef)" })
        $actions | Should -Contain 'update:dlpRule:P01-R01-ECH-OFFI'   # claimed -> drift -> update
        $actions | Should -Contain 'update:dlpRule:P02-R02-ECH-OFFI'   # pre-existing drift
        $actions | Should -Contain 'remove:rulePackage:OldPkg'         # orphan -> remove
    }
    It 'preserves safety gates (D7) — the destructive reconcile plan carries a snapshotBeforeDestroy step and a dereference cascade' {
        $ri = @($script:R.iterations | Where-Object { $_.phase -eq 'reconcile' })[0]
        $snap = @($ri.plan.steps | Where-Object { $_.action -eq 'snapshot' -and $_.gate.type -eq 'snapshotBeforeDestroy' })
        $snap.Count | Should -Be 1
        $deref = @($ri.plan.steps | Where-Object { $_.action -eq 'dereference' -and $_.objectRef -eq 'LiveRule' })
        $deref.Count | Should -Be 1
    }
    It 'surfaces the removal blast-radius preview (R3) for the orphan removal' {
        $ri = @($script:R.iterations | Where-Object { $_.phase -eq 'reconcile' })[0]
        $br = @($ri.blastRadius | Where-Object { $_.ref -eq 'OldPkg' })[0]
        $br                   | Should -Not -BeNullOrEmpty
        $br.referencingRules  | Should -Contain 'LiveRule'
        $br.blocked           | Should -BeTrue
    }
}

Describe 'Invoke-Compl8Reconcile — a left name-collision is reported, loop still terminates' {
    It 'leaving the collision converges the rest but reports status=blocked with the unresolved conflict' {
        $res = @(
            [pscustomobject]@{ objectType = 'dlpRule';     ref = 'P01-R01-ECH-OFFI'; resolution = 'leave' }
            [pscustomobject]@{ objectType = 'dlpRule';     ref = 'P02-R02-ECH-OFFI'; resolution = 'update' }
            [pscustomobject]@{ objectType = 'rulePackage'; ref = 'OldPkg';           resolution = 'remove' }
        )
        $r = Invoke-Compl8Reconcile -Assessment (New-MixedAssessment) -Graph $script:Graph -Resolutions $res `
            -Workspace 'nonprod' -PlanIdPrefix 'reconcile-20260616-000000' -GeneratedUtc '2026-06-16T00:00:00Z'
        $r.status                                | Should -Be 'blocked'
        @($r.unresolvedConflicts).Count          | Should -Be 1
        $r.unresolvedConflicts[0].slug           | Should -Be 'P01-R01-ECH-OFFI'
        # The rest still reconciled: a single reconcile iteration removed the orphan + updated the drift,
        # and there is NO claim iteration (the only collision was left).
        @($r.iterations | Where-Object { $_.phase -eq 'claim' }).Count | Should -Be 0
        $ri = @($r.iterations | Where-Object { $_.phase -eq 'reconcile' })[0]
        @($ri.plan.steps | Where-Object { $_.action -eq 'remove' -and $_.objectRef -eq 'OldPkg' }).Count | Should -Be 1
    }
    It 'does NOT falsely converge on drift the planner cannot step (codex R4 P1)' {
        # The planner steps drift only for content-bearing types it can update (dlpRule/dlpPolicy/
        # autoLabelPolicy); a drifted `sit` produces NO step (its content lives in its rule package).
        # Reconcile must surface it (unreconciled) and report blocked — never clear it and claim
        # converged while the object is unchanged.
        $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
        $a.buckets.drift = @([pscustomobject]@{ objectType = 'sit'; ref = 'QGISCF-medium-01-names'; reason = 'ours — content changed out-of-band' })
        $r = Invoke-Compl8Reconcile -Assessment $a -Graph $script:Graph -Resolutions @() `
            -Workspace 'nonprod' -PlanIdPrefix 'reconcile-20260616-000000' -GeneratedUtc '2026-06-16T00:00:00Z'
        $r.status                       | Should -Be 'blocked'
        @($r.unreconciled).Count        | Should -Be 1
        $r.unreconciled[0].objectType   | Should -Be 'sit'
        # And it did NOT record a bogus iteration with an empty plan.
        @($r.iterations | Where-Object { @($_.plan.steps).Count -eq 0 }).Count | Should -Be 0
    }
    It 'a claimed dlpPolicy IS reconciled (the planner now steps policy drift; codex R4 P2)' {
        # dlpPolicy is claimable AND the executor map updates policies, so a policy name-collision must
        # claim -> drift -> update to a clean converged plan, not stall as unreconciled.
        $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
        $a.buckets.foreign = @([pscustomobject]@{ objectType = 'dlpPolicy'; ref = 'P01-ECH-QGISCF-EXT-ADT'; reason = 'not ours' })
        $a.upgradeConflicts = @([pscustomobject]@{ slug = 'P01-ECH-QGISCF-EXT-ADT'; kind = 'name-collision'; detail = "desired dlpPolicy 'P01-ECH-QGISCF-EXT-ADT' is blocked — a foreign object holds this name." })
        $res = @([pscustomobject]@{ objectType = 'dlpPolicy'; ref = 'P01-ECH-QGISCF-EXT-ADT'; resolution = 'claim' })
        $r = Invoke-Compl8Reconcile -Assessment $a -Graph $script:Graph -Resolutions $res `
            -Workspace 'nonprod' -PlanIdPrefix 'reconcile-20260616-000000' -GeneratedUtc '2026-06-16T00:00:00Z'
        $r.status                | Should -Be 'converged'
        @($r.unreconciled).Count | Should -Be 0
        $claim = @($r.iterations | Where-Object { $_.phase -eq 'claim' })[0]
        @($claim.plan.steps | Where-Object { $_.action -eq 'claim' -and $_.objectType -eq 'dlpPolicy' }).Count | Should -Be 1
        $ri = @($r.iterations | Where-Object { $_.phase -eq 'reconcile' })[0]
        @($ri.plan.steps | Where-Object { $_.action -eq 'update' -and $_.objectType -eq 'dlpPolicy' -and $_.objectRef -eq 'P01-ECH-QGISCF-EXT-ADT' }).Count | Should -Be 1
    }
    It 'does NOT clear a same-name collision of a different objectType when only one is claimed (codex R4 P2)' {
        # A dlpRule 'Foo' and a dlpPolicy 'Foo' are BOTH foreign name-collisions. Claiming only the rule
        # must leave the policy collision unresolved (status blocked) — not silently clear both.
        $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
        $a.buckets.foreign = @(
            [pscustomobject]@{ objectType = 'dlpRule';   ref = 'Foo'; reason = 'not ours' }
            [pscustomobject]@{ objectType = 'dlpPolicy'; ref = 'Foo'; reason = 'not ours' }
        )
        $a.upgradeConflicts = @(
            [pscustomobject]@{ slug = 'Foo'; kind = 'name-collision'; detail = "desired dlpRule 'Foo' is blocked — a foreign object holds this name." }
            [pscustomobject]@{ slug = 'Foo'; kind = 'name-collision'; detail = "desired dlpPolicy 'Foo' is blocked — a foreign object holds this name." }
        )
        $res = @([pscustomobject]@{ objectType = 'dlpRule'; ref = 'Foo'; resolution = 'claim' })   # claim ONLY the rule
        $r = Invoke-Compl8Reconcile -Assessment $a -Graph $script:Graph -Resolutions $res `
            -Workspace 'nonprod' -PlanIdPrefix 'reconcile-20260616-000000' -GeneratedUtc '2026-06-16T00:00:00Z'
        $r.status                       | Should -Be 'blocked'
        $remaining = @($r.unresolvedConflicts | Where-Object { $_.detail -match 'dlpPolicy' })
        @($remaining).Count             | Should -Be 1
    }
    It 'claiming a foreign object that does NOT itself collide is adopt-only — no bogus update (codex R4 P2)' {
        # Only dlpPolicy 'Foo' has a name-collision; a separate foreign dlpRule 'Foo' has NO collision (no
        # desired dlpRule 'Foo'). Claiming the rule must adopt it WITHOUT projecting to drift / planning an
        # update for content that does not exist. The policy collision is left unresolved -> blocked.
        $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
        $a.buckets.foreign = @(
            [pscustomobject]@{ objectType = 'dlpRule';   ref = 'Foo'; reason = 'not ours' }
            [pscustomobject]@{ objectType = 'dlpPolicy'; ref = 'Foo'; reason = 'not ours' }
        )
        $a.upgradeConflicts = @([pscustomobject]@{ slug = 'Foo'; kind = 'name-collision'; detail = "desired dlpPolicy 'Foo' is blocked — a foreign object holds this name." })
        $res = @([pscustomobject]@{ objectType = 'dlpRule'; ref = 'Foo'; resolution = 'claim' })   # claim the NON-colliding rule
        $r = Invoke-Compl8Reconcile -Assessment $a -Graph $script:Graph -Resolutions $res `
            -Workspace 'nonprod' -PlanIdPrefix 'reconcile-20260616-000000' -GeneratedUtc '2026-06-16T00:00:00Z'
        # The rule is adopted (claim step) but NOT updated (no desired dlpRule 'Foo' to reconcile toward).
        $claimSteps = @($r.iterations | ForEach-Object { $_.plan.steps } | Where-Object { $_.action -eq 'claim' -and $_.objectType -eq 'dlpRule' -and $_.objectRef -eq 'Foo' })
        @($claimSteps).Count | Should -Be 1
        $updateSteps = @($r.iterations | ForEach-Object { $_.plan.steps } | Where-Object { $_.action -eq 'update' -and $_.objectType -eq 'dlpRule' -and $_.objectRef -eq 'Foo' })
        @($updateSteps).Count | Should -Be 0
        # The dlpPolicy 'Foo' collision was never resolved.
        $r.status | Should -Be 'blocked'
    }
    It 'an orphan resolved claim is a no-op (already ours) — no broken update, recorded unclaimable (codex R4 P2)' {
        # Claiming adopts a FOREIGN object; an orphan is already ours, and it has no desired counterpart,
        # so a claim->drift->update path would emit an update with no resolved content. Must NOT do that.
        $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
        $a.buckets.orphan = @([pscustomobject]@{ objectType = 'dlpRule'; ref = 'Orphan-Rule-01'; reason = 'ours, unexpected' })
        $res = @([pscustomobject]@{ objectType = 'dlpRule'; ref = 'Orphan-Rule-01'; resolution = 'claim' })
        $r = Invoke-Compl8Reconcile -Assessment $a -Graph $script:Graph -Resolutions $res `
            -Workspace 'nonprod' -PlanIdPrefix 'reconcile-20260616-000000' -GeneratedUtc '2026-06-16T00:00:00Z'
        # No claim step and no update step for the orphan anywhere.
        $allSteps = @($r.iterations | ForEach-Object { $_.plan.steps } | Where-Object { $_.objectRef -eq 'Orphan-Rule-01' })
        @($allSteps).Count                        | Should -Be 0
        @($r.unclaimable | Where-Object { $_.ref -eq 'Orphan-Rule-01' }).Count | Should -Be 1
    }
    It 'a -MaxIterations truncation does NOT report false convergence (codex R4 P2)' {
        $res = @(
            [pscustomobject]@{ objectType = 'dlpRule'; ref = 'P01-R01-ECH-OFFI'; resolution = 'claim' }
            [pscustomobject]@{ objectType = 'dlpRule'; ref = 'P02-R02-ECH-OFFI'; resolution = 'update' }
        )
        # Cap at 1: the claim iteration runs, projecting P01 -> drift, but the reconcile pass never gets
        # to plan the updates. The run must report blocked (work pending), not converged.
        $r = Invoke-Compl8Reconcile -Assessment (New-MixedAssessment) -Graph $script:Graph -Resolutions $res `
            -Workspace 'nonprod' -PlanIdPrefix 'reconcile-20260616-000000' -GeneratedUtc '2026-06-16T00:00:00Z' -MaxIterations 1
        $r.status            | Should -Be 'blocked'
        $r.iterationCapHit   | Should -BeTrue
        @($r.pendingWork).Count | Should -BeGreaterThan 0
    }
    It 'a no-op resolution set (nothing actionable, no conflicts) converges in zero iterations' {
        $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
        $r = Invoke-Compl8Reconcile -Assessment $a -Graph $script:Graph -Resolutions @() `
            -Workspace 'nonprod' -PlanIdPrefix 'reconcile-20260616-000000' -GeneratedUtc '2026-06-16T00:00:00Z'
        $r.status              | Should -Be 'converged'
        $r.iterationCount      | Should -Be 0
        @($r.iterations).Count | Should -Be 0
    }
}
