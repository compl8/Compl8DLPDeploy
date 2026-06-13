#Requires -Modules Pester

# Compl8 — INVENTORY -> ASSESS round-trip (Stage 4 PHASE 4A; closes codex 4A P1).
#
# This is the seam-closing test codex asked for. It proves the loop end to end:
#   1. Mocked Get-Dlp*/Get-Label*/Get-AutoSensitivity* cmdlets (-ModuleName Compl8.Tenant)
#      return REALISTIC deployed tenant objects, including a deployed SIT rule package whose
#      SerializedClassificationRuleCollection is built to be:
#        * SERIALLY DIFFERENT but SEMANTICALLY EQUAL to a desired resolved entity
#          (indented, explicit end tags, UTF-16 encoded with a BOM) — must NOT drift, and
#        * GENUINELY CHANGED for a second entity (a changed confidenceLevel) — must surface
#          as drift, and bubble up to an update-in-place on the package.
#   2. Get-TenantInventory PRODUCES the inventory from those mocks (NOT hand-written).
#   3. That produced inventory is fed straight into Invoke-Compl8Assess.
#   4. We assert the buckets: the no-false-drift entity is in NO bucket; the changed entity is
#      drift; the package is update-in-place; a missing desired sit is create; impact is derived.
#
# The whole point is that the inventory consumed by assess in THIS test comes from the READER,
# so the canonical-hash convention closes the desired(file)/actual(re-serialized) boundary.

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot  = Split-Path $PSScriptRoot -Parent
    $script:TenantDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Tenant'
    $script:EngineDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:TenantDir -Force
    Import-Module $script:EngineDir -Force

    $script:Prefix = 'QGISCF'

    # ---- DESIRED side: a self-contained resolved workspace in TEMP -----------------------
    # Two entities are assigned to the package; a third desired slug (gamma-sit) has NO actual
    # entity -> create. The package XML is the operator-facing resolved artefact.
    $script:Ws = Join-Path ([System.IO.Path]::GetTempPath()) ("rt-" + [guid]::NewGuid().ToString('N'))
    $resolvedDir = Join-Path $script:Ws 'desired' 'resolved'
    New-Item -ItemType Directory -Path $resolvedDir -Force | Out-Null

    $script:PkgName = 'QGISCF-roundtrip-01'
    $script:GuidA = 'aaaaaaaa-1111-4aaa-8aaa-aaaaaaaaaaaa'   # alpha-sit  — no drift
    $script:GuidB = 'bbbbbbbb-2222-4bbb-8bbb-bbbbbbbbbbbb'   # beta-sit   — real drift
    $script:GuidG = 'cccccccc-3333-4ccc-8ccc-cccccccccccc'   # gamma-sit  — desired-only (create)

    $desiredXml = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
<RulePack id="dddddddd-4444-4ddd-8ddd-dddddddddddd">
<Version major="1" minor="0" build="0" revision="0" />
<Publisher id="dddddddd-4444-4ddd-8ddd-dddddddddddd" />
<Details defaultLangCode="en-us">
<LocalizedDetails langcode="en-us">
<PublisherName>QGISCF DLP Deploy</PublisherName>
<Name>$($script:PkgName)</Name>
<Description>Round-trip seam fixture</Description>
</LocalizedDetails>
</Details>
</RulePack>
<Rules>
<Entity id="$($script:GuidA)" patternsProximity="300" recommendedConfidence="75" relaxProximity="false">
<Pattern confidenceLevel="75">
<IdMatch idRef="Pattern_alpha_terms_alpha-sit" />
</Pattern>
</Entity>
<Entity id="$($script:GuidB)" patternsProximity="300" recommendedConfidence="75" relaxProximity="false">
<Pattern confidenceLevel="75">
<IdMatch idRef="Pattern_beta_terms_beta-sit" />
</Pattern>
</Entity>
<Entity id="$($script:GuidG)" patternsProximity="300" recommendedConfidence="75" relaxProximity="false">
<Pattern confidenceLevel="75">
<IdMatch idRef="Pattern_gamma_terms_gamma-sit" />
</Pattern>
</Entity>
<Regex id="Pattern_alpha_terms_alpha-sit">(?i)\balpha\b</Regex>
<Regex id="Pattern_beta_terms_beta-sit">(?i)\bbeta\b</Regex>
<Regex id="Pattern_gamma_terms_gamma-sit">(?i)\bgamma\b</Regex>
<LocalizedStrings>
<Resource idRef="$($script:GuidA)"><Name default="true" langcode="en-us">Alpha</Name></Resource>
<Resource idRef="$($script:GuidB)"><Name default="true" langcode="en-us">Beta</Name></Resource>
<Resource idRef="$($script:GuidG)"><Name default="true" langcode="en-us">Gamma</Name></Resource>
</LocalizedStrings>
</Rules>
</RulePackage>
"@
    $pkgFile = 'QGISCF-roundtrip-01.xml'
    Set-Content -LiteralPath (Join-Path $resolvedDir $pkgFile) -Value $desiredXml -Encoding UTF8 -NoNewline

    $manifest = [ordered]@{
        schemaVersion = 'compl8.resolve-manifest/v1'
        generatedUtc  = '2026-06-13T00:00:00Z'
        packing       = [ordered]@{ assignments = [ordered]@{
            'alpha-sit' = $script:PkgName
            'beta-sit'  = $script:PkgName
            'gamma-sit' = $script:PkgName
        } }
        packages      = @([ordered]@{
            name       = $script:PkgName
            file       = $pkgFile
            sha256     = 'unused-by-the-canonical-path'
            rulePackId = 'dddddddd-4444-4ddd-8ddd-dddddddddddd'
            entities   = 3
        })
        warnings      = @()
    }
    $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $resolvedDir 'resolve-manifest.json') -Encoding UTF8

    # ---- DEPLOYED side: the bytes a live tenant would hand back -------------------------
    # Entity A: indented, explicit end tags, leading whitespace differences (semantically
    # identical to desired). Entity B: confidenceLevel 75 -> 85 (a real out-of-band edit).
    # Encoded as UTF-16 with a BOM to exercise Convert-DlpSerializedRulePackageToText.
    $deployedXml = @"
<?xml version="1.0" encoding="utf-16"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
    <RulePack id="dddddddd-4444-4ddd-8ddd-dddddddddddd">
        <Version major="1" minor="0" build="0" revision="0"></Version>
        <Publisher id="dddddddd-4444-4ddd-8ddd-dddddddddddd"></Publisher>
        <Details defaultLangCode="en-us">
            <LocalizedDetails langcode="en-us">
                <PublisherName>QGISCF DLP Deploy</PublisherName>
                <Name>$($script:PkgName)</Name>
                <Description>Round-trip seam fixture</Description>
            </LocalizedDetails>
        </Details>
    </RulePack>
    <Rules>
        <Entity id="$($script:GuidA)"   patternsProximity="300" recommendedConfidence="75" relaxProximity="false">
            <Pattern confidenceLevel="75">
                <IdMatch idRef="Pattern_alpha_terms_alpha-sit"></IdMatch>
            </Pattern>
        </Entity>
        <Entity id="$($script:GuidB)" patternsProximity="300" recommendedConfidence="75" relaxProximity="false">
            <Pattern confidenceLevel="85">
                <IdMatch idRef="Pattern_beta_terms_beta-sit"></IdMatch>
            </Pattern>
        </Entity>
        <Regex id="Pattern_alpha_terms_alpha-sit">(?i)\balpha\b</Regex>
        <Regex id="Pattern_beta_terms_beta-sit">(?i)\bbeta\b</Regex>
        <LocalizedStrings>
            <Resource idRef="$($script:GuidA)"><Name default="true" langcode="en-us">Alpha</Name></Resource>
            <Resource idRef="$($script:GuidB)"><Name default="true" langcode="en-us">Beta</Name></Resource>
        </LocalizedStrings>
    </Rules>
</RulePackage>
"@
    # Build a CONTIGUOUS byte[] (BOM + UTF-16 body). Note: 'byte[] + byte[]' in PowerShell
    # yields an Object[], which Convert-DlpSerializedRulePackageToText would not treat as bytes —
    # so assemble via a MemoryStream to guarantee a real byte[] the decoder recognises.
    $ms = New-Object System.IO.MemoryStream
    $preamble = [System.Text.Encoding]::Unicode.GetPreamble()
    $body = [System.Text.Encoding]::Unicode.GetBytes($deployedXml)
    $ms.Write($preamble, 0, $preamble.Length)
    $ms.Write($body, 0, $body.Length)
    $script:DeployedBytes = $ms.ToArray()
    $ms.Dispose()

    # ---- Mock the read cmdlets so Get-TenantInventory PRODUCES the inventory -------------
    # The cmdlets are not installed in CI; define global stubs then Mock -ModuleName overrides.
    function global:Get-DlpKeywordDictionary { [CmdletBinding()] param() }
    function global:Get-DlpSensitiveInformationTypeRulePackage { [CmdletBinding()] param() }
    function global:Get-DlpComplianceRule { [CmdletBinding()] param() }
    function global:Get-DlpCompliancePolicy { [CmdletBinding()] param() }
    function global:Get-Label { [CmdletBinding()] param() }
    function global:Get-LabelPolicy { [CmdletBinding()] param() }
    function global:Get-AutoSensitivityLabelPolicy { [CmdletBinding()] param() }
    function global:Get-AutoSensitivityLabelRule { [CmdletBinding()] param() }

    $deployedBytesLocal = $script:DeployedBytes
    $pkgNameLocal = $script:PkgName
    $guidBLocal = $script:GuidB

    Mock -ModuleName Compl8.Tenant Get-DlpKeywordDictionary { @() }
    Mock -ModuleName Compl8.Tenant Get-DlpSensitiveInformationTypeRulePackage {
        @(
            [pscustomobject]@{
                Name       = $pkgNameLocal
                Identity   = $pkgNameLocal
                Publisher  = 'QGISCF DLP Deploy'
                RulePackId = 'dddddddd-4444-4ddd-8ddd-dddddddddddd'
                SerializedClassificationRuleCollection = $deployedBytesLocal
            }
            # A foreign Microsoft package — opacity-as-safety; never actionable.
            [pscustomobject]@{
                Name       = 'Microsoft Rule Package'
                Identity   = 'Microsoft Rule Package'
                Publisher  = 'Microsoft Corporation'
                RulePackId = '00000000-0000-0000-0000-000000000001'
                SerializedClassificationRuleCollection = $null
            }
        )
    }
    Mock -ModuleName Compl8.Tenant Get-DlpComplianceRule {
        @(
            [pscustomobject]@{
                Name     = 'QGISCF-Beta-Email-01'
                Identity = 'QGISCF-Beta-Email-01'
                Policy   = 'P01-QGISCF-EXT'
                Priority = 0
                Disabled = $false
                # Names the BETA sit GUID -> impact edge once beta drifts.
                ContentContainsSensitiveInformation = @(
                    [pscustomobject]@{ name = 'beta-sit'; id = $guidBLocal }
                )
            }
        )
    }
    Mock -ModuleName Compl8.Tenant Get-DlpCompliancePolicy {
        @([pscustomobject]@{ Name = 'P01-QGISCF-EXT'; Identity = 'P01-QGISCF-EXT'; Mode = 'Enable' })
    }
    Mock -ModuleName Compl8.Tenant Get-Label { @() }
    Mock -ModuleName Compl8.Tenant Get-LabelPolicy { @() }
    Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelPolicy { @() }
    Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelRule { @() }

    # 1) READER produces the inventory from the mocked tenant.
    $script:Inv = Get-TenantInventory -Prefix $script:Prefix -GeneratedUtc '2026-06-13T00:00:00Z'

    # 2) ASSESS consumes the reader's inventory object directly (the closed loop).
    $script:Assessment = Invoke-Compl8Assess -WorkspacePath $script:Ws -Inventory $script:Inv `
        -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'

    function Get-RTBucketRefs {
        param($Assessment, [string]$Bucket)
        @($Assessment.buckets.$Bucket | ForEach-Object { $_.ref })
    }
}

AfterAll {
    foreach ($fn in 'Get-DlpKeywordDictionary', 'Get-DlpSensitiveInformationTypeRulePackage',
        'Get-DlpComplianceRule', 'Get-DlpCompliancePolicy', 'Get-Label', 'Get-LabelPolicy',
        'Get-AutoSensitivityLabelPolicy', 'Get-AutoSensitivityLabelRule') {
        Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
    }
    if ($script:Ws -and (Test-Path -LiteralPath $script:Ws)) {
        Remove-Item -LiteralPath $script:Ws -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Get-TenantInventory — produces the assess-consumable SIT shape from deployed packages' {
    It 'emits objects.sits — one record per deployed entity (slug, GUID, package, contentHash)' {
        $sits = @($script:Inv.objects.sits)
        $sits.Count | Should -Be 2 -Because 'the deployed package has two entities'
        $alpha = @($sits | Where-Object { $_.name -eq 'alpha-sit' })[0]
        $alpha | Should -Not -BeNullOrEmpty
        $alpha.identity    | Should -Be $script:GuidA
        $alpha.package     | Should -Be $script:PkgName
        $alpha.ours        | Should -BeTrue
        $alpha.contentHash | Should -Match '^sha256:[0-9a-f]{64}$'
    }

    It 'gives sitPackages a comparable contentHash and an entityId list' {
        $pkg = @($script:Inv.objects.sitPackages | Where-Object { $_.name -eq $script:PkgName })[0]
        $pkg.contentHash | Should -Match '^sha256:[0-9a-f]{64}$'
        @($pkg.entityIds) | Should -Contain $script:GuidA
        @($pkg.entityIds) | Should -Contain $script:GuidB
    }

    It 'recovers the deployed entity content hash EQUAL to the desired entity (no false drift)' {
        # The whole comparability claim: a deployed entity that the SERVICE re-serialized with
        # different whitespace/encoding (UTF-16, indentation, explicit end tags) hashes to the
        # SAME canonical value as the resolved DESIRED entity. We take the desired entity exactly
        # as assess sees it — parsed out of the namespaced resolved package XML — so the only
        # differences between the two sides are the serialisation ones the canonical hash erases.
        $resolved = Get-Content -LiteralPath (Join-Path $script:Ws 'desired' 'resolved' 'QGISCF-roundtrip-01.xml') -Raw
        [xml]$rdoc = $resolved
        $rrules = $rdoc.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq 'Rules' } | Select-Object -First 1
        $desiredEntityXml = (@($rrules.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -eq 'Entity' -and $_.GetAttribute('id') -eq $script:GuidA })[0]).OuterXml
        $desiredHash = Get-DlpEntityContentHash -EntityXml $desiredEntityXml

        $alpha = @($script:Inv.objects.sits | Where-Object { $_.name -eq 'alpha-sit' })[0]
        $alpha.contentHash | Should -Be $desiredHash -Because 'the canonical hash erases the serialisation differences between desired and deployed'
    }

    It 'carries the dlp rule classifier-reference field for impact' {
        $rule = @($script:Inv.objects.dlpRules)[0]
        $rule.PSObject.Properties.Name | Should -Contain 'contentContainsSensitiveInformation'
        $rule.contentContainsSensitiveInformation | Should -Match 'bbbbbbbb-2222-4bbb-8bbb-bbbbbbbbbbbb'
    }
}

Describe 'Inventory -> Assess round-trip — buckets are correct on reader-produced inventory' {
    It 'puts the semantically-equal (serially-different) entity in NO bucket (no false drift)' {
        foreach ($bucket in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'foreign', 'drift') {
            Get-RTBucketRefs $script:Assessment $bucket |
                Should -Not -Contain 'alpha-sit' -Because "alpha-sit is byte-different but semantically equal — it must NOT appear in '$bucket'"
        }
    }

    It 'puts the genuinely-changed entity in drift' {
        Get-RTBucketRefs $script:Assessment 'drift' | Should -Contain 'beta-sit'
    }

    It 'surfaces the package as update-in-place (an entity changed)' {
        $entry = @($script:Assessment.buckets.'update-in-place' | Where-Object { $_.ref -eq $script:PkgName })[0]
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'rulePackage'
    }

    It 'puts the desired-only sit (no deployed entity) in create' {
        Get-RTBucketRefs $script:Assessment 'create' | Should -Contain 'gamma-sit'
    }

    It 'never lists the foreign Microsoft package in an actionable bucket' {
        foreach ($actionable in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'drift') {
            Get-RTBucketRefs $script:Assessment $actionable |
                Should -Not -Contain 'Microsoft Rule Package'
        }
        Get-RTBucketRefs $script:Assessment 'foreign' | Should -Contain 'Microsoft Rule Package'
    }

    It 'derives impact for the drifted classifier from the live DLP rule reference' {
        $impact = @($script:Assessment.impact | Where-Object { $_.objectRef -eq 'beta-sit' })[0]
        $impact | Should -Not -BeNullOrEmpty
        @($impact.affects) -join '; ' | Should -Match 'QGISCF-Beta-Email-01'
    }

    It 'passes the assessment schema (a real compl8.assessment/v1 from reader input)' {
        $r = Test-AssessmentSchema -Assessment $script:Assessment
        $r.Valid | Should -BeTrue -Because (@($r.Errors) -join '; ')
    }
}
