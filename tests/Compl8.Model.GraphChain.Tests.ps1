#Requires -Modules Pester

# =====================================================================================
# Get-DeploymentReferenceGraph — the COMPLETE reference chain.
#
# The graph is the backbone of intelligent reconciliation (plan §R1/D1): every decision
# (impact, ordering, removal cascade) reads ONE graph. The function builds the full chain
#   keyword dictionary -> SIT -> DLP rule -> DLP policy -> label
# but only if it is fed all five object families. assess/deploy previously starved it
# (packages + rules only); R1 feeds the full set. This test guards the completeness
# contract — every node type and every edge type in the chain — so the cascade/reconcile
# work in R3/R4 can rely on it.
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $script:RepoRoot 'modules' 'Compl8.Model') -Force

    $script:SitGuid  = '11111111-1111-4111-8111-111111111111'
    $script:DictGuid = '22222222-2222-4222-8222-222222222222'

    # A package whose entity (the SIT) references a keyword dictionary via <Match idRef="GUID"/>
    # inside its <Pattern> (the dictionaryFeedsSit trigger).
    $pkgXml = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
<Rules>
<Entity id="$script:SitGuid"><Pattern confidenceLevel="75"><Match idRef="$script:DictGuid" /></Pattern></Entity>
</Rules>
</RulePackage>
"@
    $script:Graph = Get-DeploymentReferenceGraph `
        -Dictionaries @([pscustomobject]@{ Identity = $script:DictGuid; Name = 'QGISCF - Names' }) `
        -SitPackages  @([pscustomobject]@{ Identity = 'QGISCF-medium-01'; Name = 'QGISCF-medium-01'; Publisher = 'Compl8'; SerializedClassificationRuleCollection = $pkgXml }) `
        -DlpRules     @([pscustomobject]@{ Name = 'P01-R01-ECH-OFFI'; Identity = 'r1'; Policy = 'P01-ECH-QGISCF-EXT-ADT'
                          ContentContainsSensitiveInformation = [pscustomobject]@{ operator = 'And'; groups = @([pscustomobject]@{ operator = 'Or'; sensitivetypes = @([pscustomobject]@{ id = $script:SitGuid; name = 'names' }) }) } }) `
        -DlpPolicies  @([pscustomobject]@{ Name = 'P01-ECH-QGISCF-EXT-ADT'; Identity = 'p1' }) `
        -Labels       @([pscustomobject]@{ code = 'OFFI'; name = 'OFFICIAL'; displayName = 'OFFICIAL' })

    function script:HasEdge { param([string]$Type) @($script:Graph.Edges | Where-Object { $_.Type -eq $Type }).Count -gt 0 }
    function script:NodeTypes { @($script:Graph.Nodes | ForEach-Object { $_.Type } | Sort-Object -Unique) }
}

Describe 'Get-DeploymentReferenceGraph — complete chain when fed all five families' {
    It 'builds a node for every object type in the chain' {
        foreach ($t in 'KeywordDictionary', 'SitPackage', 'SensitiveInformationType', 'DlpRule', 'DlpPolicy', 'Label') {
            (NodeTypes) | Should -Contain $t -Because "the graph should carry a $t node"
        }
    }
    It 'wires the full dependency chain: dict -> sit -> rule -> policy -> label' {
        HasEdge 'dictionaryFeedsSit'   | Should -BeTrue -Because 'the SIT references the dictionary via <Match idRef>'
        HasEdge 'packageContainsSit'   | Should -BeTrue
        HasEdge 'sitReferencedByRule'  | Should -BeTrue
        HasEdge 'ruleBelongsToPolicy'  | Should -BeTrue
        HasEdge 'policyTargetsLabel'   | Should -BeTrue -Because 'the rule name carries the label code OFFI'
    }
    It 'marks the referenced dictionary present (not Missing) because it was fed as an input' {
        $dictNode = @($script:Graph.Nodes | Where-Object { $_.Type -eq 'KeywordDictionary' -and $_.Identity -eq $script:DictGuid })[0]
        $dictNode | Should -Not -BeNullOrEmpty
        $dictNode.Properties.Missing | Should -BeFalse
    }
}
