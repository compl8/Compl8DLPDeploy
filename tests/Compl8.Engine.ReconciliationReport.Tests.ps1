#Requires -Modules Pester

# =====================================================================================
# Reconciliation R5 (Engine half) — Get-Compl8ReconciliationReport: the headless renderer.
#
# Turns a compl8.reconciliation/v1 object (Invoke-Compl8Reconcile output) into an operator-facing
# text summary the TUI prints verbatim — status, per-iteration walk (phase / projected / actions /
# removal blast-radius), and the blocking call-outs (unresolved collisions, pending work, unreconciled,
# unclaimable). Per Stage-5 D6 the Surface holds NO logic: the reconcile intelligence lives in the
# Engine and the TUI renders this. Pure (no I/O), mirroring Get-Compl8AssessmentReport.
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $script:RepoRoot 'modules' 'Compl8.Engine') -Force

    # A reference graph: OldPkg (sit G1) referenced by LiveRule — gives a real removal blast-radius.
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

    # A converged mixed reconciliation: claim a colliding rule, update a drift rule, remove an orphan pkg.
    $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
    $a.buckets.foreign = @([pscustomobject]@{ objectType = 'dlpRule'; ref = 'P01-R01-ECH-OFFI'; reason = 'not ours' })
    $a.buckets.drift   = @([pscustomobject]@{ objectType = 'dlpRule'; ref = 'P02-R02-ECH-OFFI'; reason = 'drift' })
    $a.buckets.orphan  = @([pscustomobject]@{ objectType = 'rulePackage'; ref = 'OldPkg'; reason = 'orphan' })
    $a.upgradeConflicts = @([pscustomobject]@{ slug = 'P01-R01-ECH-OFFI'; kind = 'name-collision'; detail = "desired dlpRule 'P01-R01-ECH-OFFI' is blocked — a foreign object holds this name." })
    $a.impact = @([pscustomobject]@{ objectRef = 'OldPkg'; affects = @('dlp-rule: LiveRule') })
    $res = @(
        [pscustomobject]@{ objectType = 'dlpRule';     ref = 'P01-R01-ECH-OFFI'; resolution = 'claim' }
        [pscustomobject]@{ objectType = 'dlpRule';     ref = 'P02-R02-ECH-OFFI'; resolution = 'update' }
        [pscustomobject]@{ objectType = 'rulePackage'; ref = 'OldPkg';           resolution = 'remove' }
    )
    $script:Recon = Invoke-Compl8Reconcile -Assessment $a -Graph $script:Graph -Resolutions $res `
        -Workspace 'nonprod' -PlanIdPrefix 'reconcile-20260616-000000' -GeneratedUtc '2026-06-16T00:00:00Z'
}

Describe 'Get-Compl8ReconciliationReport — surface + header' {
    It 'is exported from Compl8.Engine' {
        (Get-Command -Name Get-Compl8ReconciliationReport -Module Compl8.Engine -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }
    It 'renders the schema, workspace and terminal status' {
        $r = Get-Compl8ReconciliationReport -Reconciliation $script:Recon
        $r | Should -Match 'compl8\.reconciliation/v1'
        $r | Should -Match "workspace 'nonprod'"
        $r | Should -Match 'Status:\s+converged'
    }
}

Describe 'Get-Compl8ReconciliationReport — iteration walk' {
    BeforeAll { $script:Text = Get-Compl8ReconciliationReport -Reconciliation $script:Recon }
    It 'renders one section per iteration with phase and projected flag' {
        $script:Text | Should -Match 'Iteration 1 \[claim\]'
        $script:Text | Should -Match 'Iteration 2 \[reconcile\]'
        $script:Text | Should -Match 'projected'
    }
    It 'lists the actions taken in an iteration' {
        $script:Text | Should -Match 'claim .*dlpRule.*P01-R01-ECH-OFFI'
        $script:Text | Should -Match 'remove .*rulePackage.*OldPkg'
    }
    It 'shows the removal blast-radius (referencing rules) for a destructive iteration' {
        $script:Text | Should -Match 'OldPkg'
        $script:Text | Should -Match 'LiveRule'
    }
}

Describe 'Get-Compl8ReconciliationReport — blocking call-outs' {
    It 'surfaces unresolved conflicts, pending work, unreconciled and unclaimable when blocked' {
        $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
        $a.buckets.foreign = @([pscustomobject]@{ objectType = 'dlpPolicy'; ref = 'P9-LEFT'; reason = 'not ours' })
        $a.buckets.drift   = @([pscustomobject]@{ objectType = 'sit'; ref = 'QGISCF-sit-09'; reason = 'drift' })
        $a.upgradeConflicts = @([pscustomobject]@{ slug = 'P9-LEFT'; kind = 'name-collision'; detail = "desired dlpPolicy 'P9-LEFT' is blocked — a foreign object holds this name." })
        # Leave the collision, ask to 'update' the sit drift (planner can't step it -> unreconciled).
        $res = @([pscustomobject]@{ objectType = 'dlpPolicy'; ref = 'P9-LEFT'; resolution = 'leave' })
        $recon = Invoke-Compl8Reconcile -Assessment $a -Graph $script:Graph -Resolutions $res `
            -Workspace 'nonprod' -PlanIdPrefix 'reconcile-20260616-000000' -GeneratedUtc '2026-06-16T00:00:00Z'
        $text = Get-Compl8ReconciliationReport -Reconciliation $recon
        $text | Should -Match 'Status:\s+blocked'
        $text | Should -Match 'Unresolved conflicts'
        $text | Should -Match 'P9-LEFT'
        $text | Should -Match 'Unreconciled'
        $text | Should -Match 'QGISCF-sit-09'
    }
}
