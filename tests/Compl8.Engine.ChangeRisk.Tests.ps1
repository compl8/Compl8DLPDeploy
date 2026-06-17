#Requires -Modules Pester

# =====================================================================================
# Strategist — Get-Compl8ChangeRisk: evaluate the RISK + follow-on of a proposed change, and
# describe its effect on INTERNAL (ours) and EXTERNAL (not-ours) rules and classifiers.
#
# The leap from "never touch foreign" (opacity-as-safety) to "never AUTO-APPLY a change whose blast
# radius REACHES foreign". Given a change + the reference graph + an ownership map, it walks the
# downstream blast radius (reusing R3 Get-Compl8RemovalImpact), splits the affected objects into
# internal/external by ownership, scores risk, and recommends proceed / review / hand-back. Per the
# operator's policy: ANY external (not-ours) impact => hand-back (block auto-apply, need approval); a
# very large cascade also hands back ("too complex"). Pure (no I/O); the caller supplies ownership
# from the inventory. External impact is DOWNSTREAM (referencing/dependent foreign objects), NOT the
# action's own target — so an operator-chosen claim of a foreign object is not self-blocking.
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $script:RepoRoot 'modules' 'Compl8.Engine') -Force

    # OurPkg contains sit G1, referenced by BOTH an ours rule and a foreign rule.
    $script:G1 = '44444444-4444-4444-8444-444444444444'
    $pkgXml = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
<Rules><Entity id="$($script:G1)"><Pattern confidenceLevel="75"><Match idRef="$($script:G1)" /></Pattern></Entity></Rules>
</RulePackage>
"@
    $ccsi = { param($id) [pscustomobject]@{ operator = 'And'; groups = @([pscustomobject]@{ operator = 'Or'; sensitivetypes = @([pscustomobject]@{ id = $id; name = 'g' }) }) } }
    $script:Graph = Get-DeploymentReferenceGraph `
        -SitPackages @([pscustomobject]@{ Identity = 'OurPkg'; Name = 'OurPkg'; Publisher = 'Compl8'; SerializedClassificationRuleCollection = $pkgXml }) `
        -DlpRules @(
            [pscustomobject]@{ Name = 'Our-Rule';     Identity = 'our-1'; Policy = 'P-Ours';    ContentContainsSensitiveInformation = (& $ccsi $script:G1) }
            [pscustomobject]@{ Name = 'Foreign-Rule'; Identity = 'frn-1'; Policy = 'P-Foreign'; ContentContainsSensitiveInformation = (& $ccsi $script:G1) }
        )
    # Ownership: our rule + our package's sit are ours; the foreign rule is NOT ours.
    $script:Ownership = @{ 'Our-Rule' = $true; 'Foreign-Rule' = $false; "$($script:G1)" = $true; 'OurPkg' = $true }
}

Describe 'Get-Compl8ChangeRisk — surface' {
    It 'is exported from Compl8.Engine' {
        (Get-Command -Name Get-Compl8ChangeRisk -Module Compl8.Engine -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-Compl8ChangeRisk — a destructive change that reaches a FOREIGN rule hands back' {
    BeforeAll {
        $script:R = Get-Compl8ChangeRisk -Change ([pscustomobject]@{ objectType = 'rulePackage'; action = 'remove'; ref = 'OurPkg' }) `
            -Graph $script:Graph -OwnershipMap $script:Ownership
    }
    It 'describes the EXTERNAL (not-ours) rule the removal would break' {
        @($script:R.externalImpact | Where-Object { $_.ref -eq 'Foreign-Rule' }).Count | Should -Be 1
    }
    It 'describes the INTERNAL (ours) rule affected too' {
        @($script:R.internalImpact | Where-Object { $_.ref -eq 'Our-Rule' }).Count | Should -Be 1
    }
    It 'recommends HAND-BACK (blocks auto-apply) and rates it critical + irreversible' {
        $script:R.handBack       | Should -BeTrue
        $script:R.recommendation | Should -Be 'hand-back'
        $script:R.riskLevel      | Should -Be 'critical'
        $script:R.reversible     | Should -BeFalse
    }
    It 'carries a human-readable rationale + follow-on' {
        $script:R.rationale | Should -Match 'foreign|not-ours|external'
        @($script:R.followOn).Count | Should -BeGreaterThan 0
    }
}

Describe 'Get-Compl8ChangeRisk — a SIT change is keyed by entity GUID (identity), reaching foreign rules (codex)' {
    It 'a sit remove with identity=GUID finds the foreign referencing rule and hands back' {
        # The plan carries a sit by slug; the risk eval must use the entity GUID to walk the graph, or a
        # SIT change reaching a foreign rule would bypass the gate.
        $r = Get-Compl8ChangeRisk -Change ([pscustomobject]@{ objectType = 'sit'; action = 'remove'; ref = 'medium-names-slug'; identity = $script:G1 }) `
            -Graph $script:Graph -OwnershipMap $script:Ownership
        @($r.externalImpact | Where-Object { $_.ref -eq 'Foreign-Rule' }).Count | Should -Be 1
        $r.handBack | Should -BeTrue
    }
}

Describe 'Get-Compl8ChangeRisk — a non-destructive change reaching foreign still hands back (high, reversible)' {
    It 'an UPDATE of a classifier a foreign rule reads is high-risk + hand-back, but reversible' {
        $r = Get-Compl8ChangeRisk -Change ([pscustomobject]@{ objectType = 'rulePackage'; action = 'update'; ref = 'OurPkg' }) `
            -Graph $script:Graph -OwnershipMap $script:Ownership
        $r.handBack       | Should -BeTrue
        $r.riskLevel      | Should -Be 'high'
        $r.recommendation | Should -Be 'hand-back'
        $r.reversible     | Should -BeTrue
        @($r.externalImpact | Where-Object { $_.ref -eq 'Foreign-Rule' }).Count | Should -Be 1
    }
}

Describe 'Get-Compl8ChangeRisk — internal-only impact proceeds (no external reach)' {
    BeforeAll {
        # A graph where OurPkg's sit is referenced ONLY by the ours rule (no foreign consumer).
        $pkgXml2 = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
<Rules><Entity id="55555555-5555-4555-8555-555555555555"><Pattern confidenceLevel="75"><Match idRef="55555555-5555-4555-8555-555555555555" /></Pattern></Entity></Rules>
</RulePackage>
"@
        $ccsi2 = [pscustomobject]@{ operator = 'And'; groups = @([pscustomobject]@{ operator = 'Or'; sensitivetypes = @([pscustomobject]@{ id = '55555555-5555-4555-8555-555555555555'; name = 'g' }) }) }
        $script:GraphInternal = Get-DeploymentReferenceGraph `
            -SitPackages @([pscustomobject]@{ Identity = 'InPkg'; Name = 'InPkg'; Publisher = 'Compl8'; SerializedClassificationRuleCollection = $pkgXml2 }) `
            -DlpRules @([pscustomobject]@{ Name = 'Internal-Rule'; Identity = 'in-1'; Policy = 'P'; ContentContainsSensitiveInformation = $ccsi2 })
        $script:OwnInternal = @{ 'Internal-Rule' = $true; 'InPkg' = $true; '55555555-5555-4555-8555-555555555555' = $true }
    }
    It 'a destructive change touching only OURS rules is review/medium (NOT hand-back)' {
        $r = Get-Compl8ChangeRisk -Change ([pscustomobject]@{ objectType = 'rulePackage'; action = 'remove'; ref = 'InPkg' }) `
            -Graph $script:GraphInternal -OwnershipMap $script:OwnInternal
        $r.handBack       | Should -BeFalse
        @($r.externalImpact).Count | Should -Be 0
        @($r.internalImpact | Where-Object { $_.ref -eq 'Internal-Rule' }).Count | Should -Be 1
        $r.riskLevel      | Should -Be 'medium'
        $r.recommendation | Should -Be 'review'
    }
    It 'a create/claim with no downstream blast radius proceeds (low risk)' {
        $r = Get-Compl8ChangeRisk -Change ([pscustomobject]@{ objectType = 'dlpRule'; action = 'create'; ref = 'Brand-New-Rule' }) `
            -Graph $script:GraphInternal -OwnershipMap $script:OwnInternal
        $r.handBack       | Should -BeFalse
        $r.riskLevel      | Should -Be 'low'
        $r.recommendation | Should -Be 'proceed'
    }
}

Describe 'Get-Compl8ChangeRisk — too-complex cascade hands back even when fully internal' {
    It 'hands back when the affected count exceeds the cascade threshold' {
        $r = Get-Compl8ChangeRisk -Change ([pscustomobject]@{ objectType = 'rulePackage'; action = 'remove'; ref = 'OurPkg' }) `
            -Graph $script:Graph -OwnershipMap @{ 'Our-Rule' = $true; 'Foreign-Rule' = $true; "$($script:G1)" = $true } `
            -CascadeThreshold 1
        # Both rules are ours here (no external), but 2 affected > threshold 1 => hand back as too complex.
        @($r.externalImpact).Count | Should -Be 0
        $r.handBack | Should -BeTrue
        $r.rationale | Should -Match 'complex|cascade|large'
    }
}

Describe 'Get-Compl8ChangeRisk — unknown ownership is treated as foreign (conservative)' {
    It 'an affected rule absent from the ownership map is external (hand-back), not silently internal' {
        $r = Get-Compl8ChangeRisk -Change ([pscustomobject]@{ objectType = 'rulePackage'; action = 'remove'; ref = 'OurPkg' }) `
            -Graph $script:Graph -OwnershipMap @{ 'Our-Rule' = $true }   # Foreign-Rule not in the map
        @($r.externalImpact | Where-Object { $_.ref -eq 'Foreign-Rule' }).Count | Should -Be 1
        $r.handBack | Should -BeTrue
    }
}
