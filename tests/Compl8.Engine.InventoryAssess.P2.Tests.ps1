#Requires -Modules Pester

# Compl8 — codex 4A re-review (P2-A / P2-B / P2-C) seam tests.
#
# These extend the inventory -> assess round-trip with the three regressions codex flagged:
#
#   P2-A  The per-SIT content hash must cover the entity's TRANSITIVE idRef closure (its
#         sibling <Regex>/<Keyword>/<Filter>/<Validator> support elements). A deployed package
#         that differs from desired ONLY in a referenced <Regex> body (the <Entity> node itself
#         byte-identical) must surface that SIT in `drift` and its package in `update-in-place`.
#         The inverse — only serialisation differs (regex identical) — must land in NO bucket.
#
#   P2-B  When a deployed package's SerializedClassificationRuleCollection is missing/garbage,
#         the reader must emit contentHash = $null, and assess must NOT bucket the same-name
#         desired package update-in-place on hash grounds (cannot-compare safe fallback).
#
#   P2-C  A DLP rule that references a SIT GUID ONLY via ExceptIfContentContainsSensitiveInformation
#         (or AdvancedRule) must still produce the impact edge for that SIT.
#
# As required, the inventory consumed by assess is PRODUCED by Get-TenantInventory from mocked
# cmdlets (never hand-written), so each fix is proven end to end through the real reader.

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot  = Split-Path $PSScriptRoot -Parent
    $script:TenantDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Tenant'
    $script:EngineDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:TenantDir -Force
    Import-Module $script:EngineDir -Force

    $script:Prefix = 'QGISCF'

    function script:New-Utf16BomBytes {
        param([string]$Text)
        $ms = New-Object System.IO.MemoryStream
        $pre = [System.Text.Encoding]::Unicode.GetPreamble()
        $body = [System.Text.Encoding]::Unicode.GetBytes($Text)
        $ms.Write($pre, 0, $pre.Length)
        $ms.Write($body, 0, $body.Length)
        $bytes = $ms.ToArray()
        $ms.Dispose()
        # Return as a SINGLE byte[] object — the unary comma stops PowerShell from unrolling the
        # array into the pipeline (which would yield an Object[] the decoder won't treat as bytes).
        return , $bytes
    }

    # Stub the read cmdlets (not installed in CI) so Mock -ModuleName can override them.
    foreach ($fn in 'Get-DlpKeywordDictionary', 'Get-DlpSensitiveInformationTypeRulePackage',
        'Get-DlpComplianceRule', 'Get-DlpCompliancePolicy', 'Get-Label', 'Get-LabelPolicy',
        'Get-AutoSensitivityLabelPolicy', 'Get-AutoSensitivityLabelRule') {
        Set-Item -Path "function:global:$fn" -Value { } -Force
    }
}

AfterAll {
    foreach ($fn in 'Get-DlpKeywordDictionary', 'Get-DlpSensitiveInformationTypeRulePackage',
        'Get-DlpComplianceRule', 'Get-DlpCompliancePolicy', 'Get-Label', 'Get-LabelPolicy',
        'Get-AutoSensitivityLabelPolicy', 'Get-AutoSensitivityLabelRule') {
        Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
    }
    foreach ($ws in $script:WsA, $script:WsB) {
        if ($ws -and (Test-Path -LiteralPath $ws)) { Remove-Item -LiteralPath $ws -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'P2-A — referenced <Regex> edit (entity node identical) surfaces drift + update-in-place' {
    BeforeAll {
        $script:GuidA = 'aaaaaaaa-1111-4aaa-8aaa-aaaaaaaaaaaa'   # only serialisation differs -> no bucket
        $script:GuidB = 'bbbbbbbb-2222-4bbb-8bbb-bbbbbbbbbbbb'   # referenced regex edited -> drift
        $script:PkgName = 'QGISCF-p2a-01'

        $script:WsA = Join-Path ([System.IO.Path]::GetTempPath()) ("p2a-" + [guid]::NewGuid().ToString('N'))
        $resolvedDir = Join-Path $script:WsA 'desired' 'resolved'
        New-Item -ItemType Directory -Path $resolvedDir -Force | Out-Null

        # DESIRED: two entities, each referencing a sibling <Regex> by idRef. Both entity NODES
        # are simple; the detection logic is in the referenced <Regex> bodies.
        $desiredXml = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
<RulePack id="dddddddd-4444-4ddd-8ddd-dddddddddddd">
<Details defaultLangCode="en-us"><LocalizedDetails langcode="en-us"><Name>$($script:PkgName)</Name></LocalizedDetails></Details>
</RulePack>
<Rules>
<Entity id="$($script:GuidA)" patternsProximity="300" recommendedConfidence="75" relaxProximity="false">
<Pattern confidenceLevel="75"><IdMatch idRef="Pattern_alpha_terms_alpha-sit" /></Pattern>
</Entity>
<Entity id="$($script:GuidB)" patternsProximity="300" recommendedConfidence="75" relaxProximity="false">
<Pattern confidenceLevel="75"><IdMatch idRef="Pattern_beta_terms_beta-sit" /></Pattern>
</Entity>
<Regex id="Pattern_alpha_terms_alpha-sit">(?i)\balpha\b</Regex>
<Regex id="Pattern_beta_terms_beta-sit">(?i)\bbeta-ORIGINAL\b</Regex>
<LocalizedStrings>
<Resource idRef="$($script:GuidA)"><Name default="true" langcode="en-us">Alpha</Name></Resource>
<Resource idRef="$($script:GuidB)"><Name default="true" langcode="en-us">Beta</Name></Resource>
</LocalizedStrings>
</Rules>
</RulePackage>
"@
        $pkgFile = "$($script:PkgName).xml"
        Set-Content -LiteralPath (Join-Path $resolvedDir $pkgFile) -Value $desiredXml -Encoding UTF8 -NoNewline

        $manifest = [ordered]@{
            schemaVersion = 'compl8.resolve-manifest/v1'
            generatedUtc  = '2026-06-13T00:00:00Z'
            packing       = [ordered]@{ assignments = [ordered]@{ 'alpha-sit' = $script:PkgName; 'beta-sit' = $script:PkgName } }
            packages      = @([ordered]@{ name = $script:PkgName; file = $pkgFile; rulePackId = 'dddddddd-4444-4ddd-8ddd-dddddddddddd'; entities = 2 })
            warnings      = @()
        }
        $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $resolvedDir 'resolve-manifest.json') -Encoding UTF8

        # DEPLOYED: the ENTITY nodes are byte-identical in meaning to desired (alpha re-serialised
        # with indentation/end-tags; beta's entity node IDENTICAL). The only real change is the
        # referenced beta <Regex> body ORIGINAL -> EDITED. Encoded UTF-16+BOM (a re-serialisation).
        $deployedXml = @"
<?xml version="1.0" encoding="utf-16"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
    <RulePack id="dddddddd-4444-4ddd-8ddd-dddddddddddd">
        <Details defaultLangCode="en-us"><LocalizedDetails langcode="en-us"><Name>$($script:PkgName)</Name></LocalizedDetails></Details>
    </RulePack>
    <Rules>
        <Entity id="$($script:GuidA)"   patternsProximity="300" recommendedConfidence="75" relaxProximity="false">
            <Pattern confidenceLevel="75"><IdMatch idRef="Pattern_alpha_terms_alpha-sit"></IdMatch></Pattern>
        </Entity>
        <Entity id="$($script:GuidB)" patternsProximity="300" recommendedConfidence="75" relaxProximity="false">
            <Pattern confidenceLevel="75"><IdMatch idRef="Pattern_beta_terms_beta-sit"></IdMatch></Pattern>
        </Entity>
        <Regex id="Pattern_alpha_terms_alpha-sit">(?i)\balpha\b</Regex>
        <Regex id="Pattern_beta_terms_beta-sit">(?i)\bbeta-EDITED\b</Regex>
        <LocalizedStrings>
            <Resource idRef="$($script:GuidA)"><Name default="true" langcode="en-us">Alpha</Name></Resource>
            <Resource idRef="$($script:GuidB)"><Name default="true" langcode="en-us">Beta</Name></Resource>
        </LocalizedStrings>
    </Rules>
</RulePackage>
"@
        $deployedBytes = New-Utf16BomBytes -Text $deployedXml
        $pkgNameLocal = $script:PkgName
        $guidBLocal = $script:GuidB

        Mock -ModuleName Compl8.Tenant Get-DlpKeywordDictionary { @() }
        Mock -ModuleName Compl8.Tenant Get-DlpSensitiveInformationTypeRulePackage {
            @([pscustomobject]@{
                Name = $pkgNameLocal; Identity = $pkgNameLocal; Publisher = 'QGISCF DLP Deploy'
                RulePackId = 'dddddddd-4444-4ddd-8ddd-dddddddddddd'
                SerializedClassificationRuleCollection = $deployedBytes
            })
        }
        Mock -ModuleName Compl8.Tenant Get-DlpComplianceRule {
            @([pscustomobject]@{
                Name = 'QGISCF-Beta-Email-01'; Identity = 'QGISCF-Beta-Email-01'; Policy = 'P01-QGISCF-EXT'; Priority = 0; Disabled = $false
                ContentContainsSensitiveInformation = @([pscustomobject]@{ name = 'beta-sit'; id = $guidBLocal })
            })
        }
        Mock -ModuleName Compl8.Tenant Get-DlpCompliancePolicy { @() }
        Mock -ModuleName Compl8.Tenant Get-Label { @() }
        Mock -ModuleName Compl8.Tenant Get-LabelPolicy { @() }
        Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelPolicy { @() }
        Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelRule { @() }

        $script:Inv = Get-TenantInventory -Prefix $script:Prefix -GeneratedUtc '2026-06-13T00:00:00Z'
        $script:Assessment = Invoke-Compl8Assess -WorkspacePath $script:WsA -Inventory $script:Inv -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'

        function script:Refs { param($A, [string]$B) @($A.buckets.$B | ForEach-Object { $_.ref }) }
    }

    It 'drifts the SIT whose referenced <Regex> body was edited (entity node unchanged)' {
        Refs $script:Assessment 'drift' | Should -Contain 'beta-sit' `
            -Because 'the <Entity> node is identical; only the referenced sibling <Regex> body changed — the closure hash must catch it'
    }

    It 'does NOT drift the only-serialisation-different SIT (regex identical)' {
        foreach ($bucket in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'foreign', 'drift') {
            Refs $script:Assessment $bucket | Should -Not -Contain 'alpha-sit' `
                -Because "alpha-sit's entity and regex are semantically identical across sides — '$bucket' must not list it"
        }
    }

    It 'buckets the package as update-in-place (a referenced regex changed)' {
        $entry = @($script:Assessment.buckets.'update-in-place' | Where-Object { $_.ref -eq $script:PkgName })[0]
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'rulePackage'
    }

    It 'derives the impact edge for the drifted classifier' {
        $impact = @($script:Assessment.impact | Where-Object { $_.objectRef -eq 'beta-sit' })[0]
        $impact | Should -Not -BeNullOrEmpty
        @($impact.affects) -join '; ' | Should -Match 'QGISCF-Beta-Email-01'
    }
}

Describe 'P2-B — unparsable deployed package: contentHash omitted, no false update-in-place' {
    BeforeAll {
        $script:PkgName = 'QGISCF-p2b-01'
        $script:GuidA = 'aaaaaaaa-9999-4aaa-8aaa-aaaaaaaaaaaa'

        $script:WsB = Join-Path ([System.IO.Path]::GetTempPath()) ("p2b-" + [guid]::NewGuid().ToString('N'))
        $resolvedDir = Join-Path $script:WsB 'desired' 'resolved'
        New-Item -ItemType Directory -Path $resolvedDir -Force | Out-Null

        # DESIRED: a real, well-formed package WITH an entity (so it has a real content hash).
        $desiredXml = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
<RulePack id="dddddddd-5555-4ddd-8ddd-dddddddddddd">
<Details defaultLangCode="en-us"><LocalizedDetails langcode="en-us"><Name>$($script:PkgName)</Name></LocalizedDetails></Details>
</RulePack>
<Rules>
<Entity id="$($script:GuidA)" patternsProximity="300" recommendedConfidence="75" relaxProximity="false">
<Pattern confidenceLevel="75"><IdMatch idRef="Pattern_alpha_terms_alpha-sit" /></Pattern>
</Entity>
<Regex id="Pattern_alpha_terms_alpha-sit">(?i)\balpha\b</Regex>
<LocalizedStrings><Resource idRef="$($script:GuidA)"><Name default="true" langcode="en-us">Alpha</Name></Resource></LocalizedStrings>
</Rules>
</RulePackage>
"@
        $pkgFile = "$($script:PkgName).xml"
        Set-Content -LiteralPath (Join-Path $resolvedDir $pkgFile) -Value $desiredXml -Encoding UTF8 -NoNewline

        $manifest = [ordered]@{
            schemaVersion = 'compl8.resolve-manifest/v1'
            generatedUtc  = '2026-06-13T00:00:00Z'
            packing       = [ordered]@{ assignments = [ordered]@{ 'alpha-sit' = $script:PkgName } }
            packages      = @([ordered]@{ name = $script:PkgName; file = $pkgFile; rulePackId = 'dddddddd-5555-4ddd-8ddd-dddddddddddd'; entities = 1 })
            warnings      = @()
        }
        $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $resolvedDir 'resolve-manifest.json') -Encoding UTF8

        # DEPLOYED: the SAME-NAME ours package, but its serialized collection is GARBAGE (cannot
        # be parsed to entities). Without the P2-B fix the reader would emit a valid-looking hash
        # for an empty <pkg/> projection, and assess would falsely bucket it update-in-place.
        $pkgNameLocal = $script:PkgName
        Mock -ModuleName Compl8.Tenant Get-DlpKeywordDictionary { @() }
        Mock -ModuleName Compl8.Tenant Get-DlpSensitiveInformationTypeRulePackage {
            @([pscustomobject]@{
                Name = $pkgNameLocal; Identity = $pkgNameLocal; Publisher = 'QGISCF DLP Deploy'
                RulePackId = 'dddddddd-5555-4ddd-8ddd-dddddddddddd'
                SerializedClassificationRuleCollection = 'this is not <xml at all &&& <<< garbage'
            })
        }
        Mock -ModuleName Compl8.Tenant Get-DlpComplianceRule { @() }
        Mock -ModuleName Compl8.Tenant Get-DlpCompliancePolicy { @() }
        Mock -ModuleName Compl8.Tenant Get-Label { @() }
        Mock -ModuleName Compl8.Tenant Get-LabelPolicy { @() }
        Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelPolicy { @() }
        Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelRule { @() }

        $script:Inv = Get-TenantInventory -Prefix $script:Prefix -GeneratedUtc '2026-06-13T00:00:00Z'
        $script:Assessment = Invoke-Compl8Assess -WorkspacePath $script:WsB -Inventory $script:Inv -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'
    }

    It 'reader omits contentHash ($null) for the unparsable package' {
        $pkg = @($script:Inv.objects.sitPackages | Where-Object { $_.name -eq $script:PkgName })[0]
        $pkg | Should -Not -BeNullOrEmpty
        $pkg.contentHash | Should -BeNullOrEmpty -Because 'a package with zero comparable entities must not carry a valid-looking hash'
    }

    It 'assess does NOT bucket the same-name desired package update-in-place on hash grounds' {
        @($script:Assessment.buckets.'update-in-place' | Where-Object { $_.ref -eq $script:PkgName }).Count |
            Should -Be 0 -Because 'the actual package hash is null (cannot compare) — the safe fallback leaves it out of update-in-place'
    }
}

Describe 'P2-C — SIT referenced ONLY via ExceptIf / AdvancedRule still produces an impact edge' {
    BeforeAll {
        $script:GuidB = 'bbbbbbbb-7777-4bbb-8bbb-bbbbbbbbbbbb'
        $script:PkgName = 'QGISCF-p2c-01'

        $resolvedDir = Join-Path $script:WsA 'desired' 'resolved'  # reuse the P2-A workspace dir is unsafe across Describe; build a fresh one.
        $script:WsC = Join-Path ([System.IO.Path]::GetTempPath()) ("p2c-" + [guid]::NewGuid().ToString('N'))
        $resolvedDir = Join-Path $script:WsC 'desired' 'resolved'
        New-Item -ItemType Directory -Path $resolvedDir -Force | Out-Null

        # DESIRED + DEPLOYED package that DRIFTS the beta SIT (so it becomes a changed classifier
        # whose impact we expect). Beta's referenced regex differs across the two sides.
        $desiredXml = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
<RulePack id="dddddddd-6666-4ddd-8ddd-dddddddddddd"><Details defaultLangCode="en-us"><LocalizedDetails langcode="en-us"><Name>$($script:PkgName)</Name></LocalizedDetails></Details></RulePack>
<Rules>
<Entity id="$($script:GuidB)" patternsProximity="300" recommendedConfidence="75" relaxProximity="false">
<Pattern confidenceLevel="75"><IdMatch idRef="Pattern_beta_terms_beta-sit" /></Pattern>
</Entity>
<Regex id="Pattern_beta_terms_beta-sit">(?i)\bbeta-ORIGINAL\b</Regex>
<LocalizedStrings><Resource idRef="$($script:GuidB)"><Name default="true" langcode="en-us">Beta</Name></Resource></LocalizedStrings>
</Rules>
</RulePackage>
"@
        $pkgFile = "$($script:PkgName).xml"
        Set-Content -LiteralPath (Join-Path $resolvedDir $pkgFile) -Value $desiredXml -Encoding UTF8 -NoNewline
        $manifest = [ordered]@{
            schemaVersion = 'compl8.resolve-manifest/v1'; generatedUtc = '2026-06-13T00:00:00Z'
            packing = [ordered]@{ assignments = [ordered]@{ 'beta-sit' = $script:PkgName } }
            packages = @([ordered]@{ name = $script:PkgName; file = $pkgFile; rulePackId = 'dddddddd-6666-4ddd-8ddd-dddddddddddd'; entities = 1 })
            warnings = @()
        }
        $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $resolvedDir 'resolve-manifest.json') -Encoding UTF8

        $deployedXml = @"
<?xml version="1.0" encoding="utf-16"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
<RulePack id="dddddddd-6666-4ddd-8ddd-dddddddddddd"><Details defaultLangCode="en-us"><LocalizedDetails langcode="en-us"><Name>$($script:PkgName)</Name></LocalizedDetails></Details></RulePack>
<Rules>
<Entity id="$($script:GuidB)" patternsProximity="300" recommendedConfidence="75" relaxProximity="false">
<Pattern confidenceLevel="75"><IdMatch idRef="Pattern_beta_terms_beta-sit"></IdMatch></Pattern>
</Entity>
<Regex id="Pattern_beta_terms_beta-sit">(?i)\bbeta-EDITED\b</Regex>
<LocalizedStrings><Resource idRef="$($script:GuidB)"><Name default="true" langcode="en-us">Beta</Name></Resource></LocalizedStrings>
</Rules>
</RulePackage>
"@
        $deployedBytes = New-Utf16BomBytes -Text $deployedXml
        $pkgNameLocal = $script:PkgName
        $guidBLocal = $script:GuidB

        Mock -ModuleName Compl8.Tenant Get-DlpKeywordDictionary { @() }
        Mock -ModuleName Compl8.Tenant Get-DlpSensitiveInformationTypeRulePackage {
            @([pscustomobject]@{
                Name = $pkgNameLocal; Identity = $pkgNameLocal; Publisher = 'QGISCF DLP Deploy'
                RulePackId = 'dddddddd-6666-4ddd-8ddd-dddddddddddd'
                SerializedClassificationRuleCollection = $deployedBytes
            })
        }
        # The live rule references the beta SIT GUID ONLY via ExceptIfContentContainsSensitiveInformation
        # (its primary ContentContainsSensitiveInformation names a DIFFERENT, unrelated SIT). The old
        # Get-RuleClassifierField early-returned on the primary field and dropped the ExceptIf GUID,
        # so assess produced NO impact edge for beta-sit.
        Mock -ModuleName Compl8.Tenant Get-DlpComplianceRule {
            @([pscustomobject]@{
                Name = 'QGISCF-ExceptIf-Rule-01'; Identity = 'QGISCF-ExceptIf-Rule-01'; Policy = 'P01-QGISCF-EXT'; Priority = 0; Disabled = $false
                ContentContainsSensitiveInformation = @([pscustomobject]@{ name = 'unrelated'; id = '99999999-0000-4000-8000-000000000000' })
                ExceptIfContentContainsSensitiveInformation = @([pscustomobject]@{ name = 'beta-sit'; id = $guidBLocal })
            })
        }
        Mock -ModuleName Compl8.Tenant Get-DlpCompliancePolicy { @() }
        Mock -ModuleName Compl8.Tenant Get-Label { @() }
        Mock -ModuleName Compl8.Tenant Get-LabelPolicy { @() }
        Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelPolicy { @() }
        Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelRule { @() }

        $script:Inv = Get-TenantInventory -Prefix $script:Prefix -GeneratedUtc '2026-06-13T00:00:00Z'
        $script:Assessment = Invoke-Compl8Assess -WorkspacePath $script:WsC -Inventory $script:Inv -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'
    }

    AfterAll {
        if ($script:WsC -and (Test-Path -LiteralPath $script:WsC)) { Remove-Item -LiteralPath $script:WsC -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'reader keeps the ExceptIf-only SIT GUID in the classifier-reference field' {
        $rule = @($script:Inv.objects.dlpRules | Where-Object { $_.name -eq 'QGISCF-ExceptIf-Rule-01' })[0]
        $rule.contentContainsSensitiveInformation | Should -Match ([regex]::Escape($script:GuidB)) `
            -Because 'a GUID referenced only via ExceptIf must survive into the reference text'
    }

    It 'produces the impact edge for the drifted SIT referenced only via ExceptIf' {
        $impact = @($script:Assessment.impact | Where-Object { $_.objectRef -eq 'beta-sit' })[0]
        $impact | Should -Not -BeNullOrEmpty -Because 'the ExceptIf reference must still raise impact'
        @($impact.affects) -join '; ' | Should -Match 'QGISCF-ExceptIf-Rule-01'
    }
}
