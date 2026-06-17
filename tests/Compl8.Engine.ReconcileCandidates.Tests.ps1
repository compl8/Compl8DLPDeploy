#Requires -Modules Pester

# =====================================================================================
# Reconciliation R5 (Engine half) — Get-Compl8ReconcileCandidates: the walkable conflict set.
#
# Turns an assessment + graph into the ordered list of resolvable items the TUI walks: each
# name-collision (-> claim / leave) and each orphan (-> remove / keep / claim), carrying the allowed
# resolutions and, for a destructive candidate, the R3 blast-radius preview. Per Stage-5 D6 the TUI
# holds NO logic — this Engine primitive decides what is walkable and what resolutions apply; the TUI
# only prompts within allowedResolutions and feeds the choices to Invoke-Compl8Reconcile. Pure.
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $script:RepoRoot 'modules' 'Compl8.Engine') -Force

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

    $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
    $a.buckets.foreign = @([pscustomobject]@{ objectType = 'dlpRule'; ref = 'P01-R01-ECH-OFFI'; reason = 'not ours' })
    $a.buckets.orphan  = @([pscustomobject]@{ objectType = 'rulePackage'; ref = 'OldPkg'; reason = 'orphan' })
    $a.upgradeConflicts = @([pscustomobject]@{ slug = 'P01-R01-ECH-OFFI'; kind = 'name-collision'; detail = "desired dlpRule 'P01-R01-ECH-OFFI' is blocked — a foreign object holds this name." })
    $a.impact = @([pscustomobject]@{ objectRef = 'OldPkg'; affects = @('dlp-rule: LiveRule') })
    $script:Assessment = $a
}

Describe 'Get-Compl8ReconcileCandidates' {
    BeforeAll { $script:Cands = @(Get-Compl8ReconcileCandidates -Assessment $script:Assessment -Graph $script:Graph) }

    It 'is exported from Compl8.Engine' {
        (Get-Command -Name Get-Compl8ReconcileCandidates -Module Compl8.Engine -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }
    It 'surfaces the name-collision as a claimable candidate (claim / leave) with its parsed objectType' {
        $coll = @($script:Cands | Where-Object { $_.kind -eq 'name-collision' -and $_.ref -eq 'P01-R01-ECH-OFFI' })[0]
        $coll                     | Should -Not -BeNullOrEmpty
        $coll.objectType          | Should -Be 'dlpRule'
        $coll.allowedResolutions  | Should -Contain 'claim'
        $coll.allowedResolutions  | Should -Contain 'leave'
    }
    It 'surfaces the orphan as a removable candidate (remove / keep) WITH its blast-radius preview' {
        $orph = @($script:Cands | Where-Object { $_.kind -eq 'orphan' -and $_.ref -eq 'OldPkg' })[0]
        $orph                     | Should -Not -BeNullOrEmpty
        $orph.objectType          | Should -Be 'rulePackage'
        $orph.allowedResolutions  | Should -Contain 'remove'
        $orph.allowedResolutions  | Should -Contain 'keep'
        $orph.blastRadius                  | Should -Not -BeNullOrEmpty
        $orph.blastRadius.referencingRules | Should -Contain 'LiveRule'
    }
    It 'resolves an orphan SIT blast-radius via the inventory GUID even though the bucket entry has no identity (codex R5)' {
        # assess emits an orphan sit with only objectType/ref/reason (no GUID); Get-Compl8RemovalImpact
        # keys sits by entity GUID, so without the inventory name->GUID map the impact would be empty and
        # the operator would lose the dereference warning.
        $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
        $a.buckets.orphan = @([pscustomobject]@{ objectType = 'sit'; ref = 'OldPkg-sit-display-name'; reason = 'ours, unexpected' })
        $inv = [pscustomobject]@{ objects = [pscustomobject]@{ sits = @([pscustomobject]@{ name = 'OldPkg-sit-display-name'; identity = $script:G1 }) } }
        $cands = @(Get-Compl8ReconcileCandidates -Assessment $a -Graph $script:Graph -Inventory $inv)
        $orph = @($cands | Where-Object { $_.kind -eq 'orphan' -and $_.ref -eq 'OldPkg-sit-display-name' })[0]
        $orph.blastRadius                  | Should -Not -BeNullOrEmpty
        $orph.blastRadius.resolved         | Should -BeTrue
        $orph.blastRadius.referencingRules | Should -Contain 'LiveRule'
    }
    It 'offers ONLY leave for a name-collision of a non-claimable type (codex R5)' {
        # dictionary/sit/rulePackage/autoLabelPolicy are not claimable; advertising claim would lead the
        # operator to a request the engine reports unclaimable/blocked.
        $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
        $a.upgradeConflicts = @([pscustomobject]@{ slug = 'QGISCF - Names'; kind = 'name-collision'; detail = "desired dictionary 'QGISCF - Names' is blocked — a foreign object holds this name." })
        $cands = @(Get-Compl8ReconcileCandidates -Assessment $a -Graph $script:Graph)
        $dict = @($cands | Where-Object { $_.kind -eq 'name-collision' -and $_.ref -eq 'QGISCF - Names' })[0]
        $dict.objectType         | Should -Be 'dictionary'
        $dict.allowedResolutions | Should -Be @('leave')
        $dict.allowedResolutions | Should -Not -Contain 'claim'
    }
    It 'attaches the strategist risk verdict to an orphan candidate (internal/external + hand-back surfaced in the walk)' {
        # OldPkg (sit G1) is referenced by LiveRule; mark LiveRule FOREIGN -> removing the orphan reaches a
        # not-ours rule -> the candidate's risk hands back, visible while the operator chooses.
        $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
        $a.buckets.orphan = @([pscustomobject]@{ objectType = 'rulePackage'; ref = 'OldPkg'; reason = 'orphan' })
        $inv = [pscustomobject]@{ objects = [pscustomobject]@{
            dlpRules = @([pscustomobject]@{ name = 'LiveRule'; ours = $false })
            dlpPolicies = @(); sits = @(); sitPackages = @([pscustomobject]@{ name = 'OldPkg'; ours = $true }); dictionaries = @()
        } }
        $orph = @(Get-Compl8ReconcileCandidates -Assessment $a -Graph $script:Graph -Inventory $inv | Where-Object { $_.ref -eq 'OldPkg' })[0]
        $orph.risk                 | Should -Not -BeNullOrEmpty
        $orph.risk.handBack        | Should -BeTrue
        @($orph.risk.externalImpact | Where-Object { $_.ref -eq 'LiveRule' }).Count | Should -Be 1
    }
    It 'leaves risk null when no inventory (ownership) is supplied — the walk still works' {
        $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
        $a.buckets.orphan = @([pscustomobject]@{ objectType = 'rulePackage'; ref = 'OldPkg'; reason = 'orphan' })
        $orph = @(Get-Compl8ReconcileCandidates -Assessment $a -Graph $script:Graph | Where-Object { $_.ref -eq 'OldPkg' })[0]
        $orph.risk | Should -BeNullOrEmpty
    }
    It 'returns an empty set when there is nothing to reconcile' {
        $clean = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-16T00:00:00Z' -ResolveManifestHash 'sha256:rm' -InventoryHash 'sha256:inv'
        @(Get-Compl8ReconcileCandidates -Assessment $clean -Graph $script:Graph) | Should -HaveCount 0
    }
}
