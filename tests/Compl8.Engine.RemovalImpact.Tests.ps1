#Requires -Modules Pester

# =====================================================================================
# Reconciliation R3 — Get-Compl8RemovalImpact: the blast-radius PREVIEW.
#
# Walks the (complete, R1) reference graph BACKWARD from a removal candidate to report what the
# removal cascades to — contained SITs -> referencing rules -> affected policies, plus the
# dereferences that must run first and whether a raw removal is blocked (still-referenced). This
# is what the reconcile loop (R4) shows the operator BEFORE a destructive choice (spec §5:
# reference guard -> planner).
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $script:RepoRoot 'modules' 'Compl8.Engine') -Force

    $sitGuid  = '11111111-1111-4111-8111-111111111111'
    $dictGuid = '22222222-2222-4222-8222-222222222222'
    $pkgXml = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
<Rules><Entity id="$sitGuid"><Pattern confidenceLevel="75"><Match idRef="$dictGuid" /></Pattern></Entity></Rules>
</RulePackage>
"@
    $script:Graph = Get-DeploymentReferenceGraph `
        -Dictionaries @([pscustomobject]@{ Identity = $dictGuid; Name = 'QGISCF - Names' }) `
        -SitPackages  @([pscustomobject]@{ Identity = 'QGISCF-medium-01'; Name = 'QGISCF-medium-01'; Publisher = 'Compl8'; SerializedClassificationRuleCollection = $pkgXml }) `
        -DlpRules     @([pscustomobject]@{ Name = 'P01-R01-ECH-OFFI'; Identity = 'r1'; Policy = 'P01-ECH-QGISCF-EXT-ADT'
                          ContentContainsSensitiveInformation = [pscustomobject]@{ operator = 'And'; groups = @([pscustomobject]@{ operator = 'Or'; sensitivetypes = @([pscustomobject]@{ id = $sitGuid; name = 'names' }) }) } }) `
        -DlpPolicies  @([pscustomobject]@{ Name = 'P01-ECH-QGISCF-EXT-ADT'; Identity = 'p1' }) `
        -Labels       @([pscustomobject]@{ code = 'OFFI'; name = 'OFFICIAL' })
    $script:SitGuid = $sitGuid
}

Describe 'Get-Compl8RemovalImpact — package removal cascade' {
    BeforeAll { $script:I = @(Get-Compl8RemovalImpact -Graph $script:Graph -Target @([pscustomobject]@{ objectType = 'rulePackage'; ref = 'QGISCF-medium-01' }))[0] }
    It 'resolves the package and lists its contained SIT' {
        $script:I.resolved        | Should -BeTrue
        $script:I.containedSits   | Should -Contain $script:SitGuid
    }
    It 'cascades to the referencing rule and its policy' {
        $script:I.referencingRules | Should -Contain 'P01-R01-ECH-OFFI'
        $script:I.affectedPolicies | Should -Contain 'P01-ECH-QGISCF-EXT-ADT'
    }
    It 'flags the removal blocked and lists the dereferences required first' {
        $script:I.blocked            | Should -BeTrue
        $script:I.dereferencesNeeded | Should -Contain 'P01-R01-ECH-OFFI'
    }
}

Describe 'Get-Compl8RemovalImpact — other candidate types' {
    It 'a dictionary removal cascades through the SIT it feeds to the rules' {
        $i = @(Get-Compl8RemovalImpact -Graph $script:Graph -Target @([pscustomobject]@{ objectType = 'dictionary'; ref = 'QGISCF - Names' }))[0]
        $i.containedSits    | Should -Contain $script:SitGuid
        $i.referencingRules | Should -Contain 'P01-R01-ECH-OFFI'
        $i.blocked          | Should -BeTrue
    }
    It 'a dictionary removal BY IDENTITY (GUID) cascades identically to the Name form (codex R3 P2)' {
        # The documented Identity form must hit the cascade — indexes are keyed by canonical node Id,
        # so resolving the GUID-form ref to its node must not produce an empty/hidden blast radius.
        $i = @(Get-Compl8RemovalImpact -Graph $script:Graph -Target @([pscustomobject]@{ objectType = 'dictionary'; ref = '22222222-2222-4222-8222-222222222222' }))[0]
        $i.resolved         | Should -BeTrue
        $i.containedSits    | Should -Contain $script:SitGuid
        $i.referencingRules | Should -Contain 'P01-R01-ECH-OFFI'
        $i.blocked          | Should -BeTrue
    }
    It 'a dlpRule removal lists its policy and is NOT blocked (no dereference needed)' {
        $i = @(Get-Compl8RemovalImpact -Graph $script:Graph -Target @([pscustomobject]@{ objectType = 'dlpRule'; ref = 'P01-R01-ECH-OFFI' }))[0]
        $i.affectedPolicies   | Should -Contain 'P01-ECH-QGISCF-EXT-ADT'
        $i.blocked            | Should -BeFalse
        @($i.dereferencesNeeded).Count | Should -Be 0
    }
    It 'an unresolved candidate reports resolved=false with empty cascade' {
        $i = @(Get-Compl8RemovalImpact -Graph $script:Graph -Target @([pscustomobject]@{ objectType = 'rulePackage'; ref = 'no-such-package' }))[0]
        $i.resolved              | Should -BeFalse
        @($i.referencingRules).Count | Should -Be 0
    }
    It 'a SIT removal (by entity GUID) cascades to its referencing rules' {
        $i = @(Get-Compl8RemovalImpact -Graph $script:Graph -Target @([pscustomobject]@{ objectType = 'sit'; ref = $script:SitGuid }))[0]
        $i.referencingRules | Should -Contain 'P01-R01-ECH-OFFI'
        $i.blocked          | Should -BeTrue
    }
}
