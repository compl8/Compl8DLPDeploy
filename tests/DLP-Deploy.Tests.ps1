#Requires -Modules Pester

<#
.SYNOPSIS
    Pester v5 tests for the DLP-Deploy shared module.
    Tests pure functions that do not require a Purview connection.
#>

BeforeAll {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'DLP-Deploy.psm1'
    Import-Module $ModulePath -Force
}

Describe 'Get-PolicyName' {
    It 'Returns correctly formatted policy name' {
        $result = Get-PolicyName -PolicyNumber 1 -PolicyCode 'ECH' -Prefix 'QGISCF' -Suffix 'EXT-ADT'
        $result | Should -Be 'P01-ECH-QGISCF-EXT-ADT'
    }

    It 'Zero-pads single-digit policy numbers' {
        $result = Get-PolicyName -PolicyNumber 3 -PolicyCode 'SPO' -Prefix 'QGISCF' -Suffix 'EXT-ADT'
        $result | Should -Be 'P03-SPO-QGISCF-EXT-ADT'
    }

    It 'Handles double-digit policy numbers' {
        $result = Get-PolicyName -PolicyNumber 12 -PolicyCode 'TMS' -Prefix 'TEST' -Suffix 'V2'
        $result | Should -Be 'P12-TMS-TEST-V2'
    }
}

Describe 'Get-RuleName' {
    It 'Returns correctly formatted rule name' {
        $result = Get-RuleName -PolicyNumber 1 -RuleNumber 1 -PolicyCode 'ECH' -LabelCode 'OFFI' -Suffix 'EXT-ADT'
        $result | Should -Be 'P01-R01-ECH-OFFI-EXT-ADT'
    }

    It 'Zero-pads both policy and rule numbers' {
        $result = Get-RuleName -PolicyNumber 2 -RuleNumber 5 -PolicyCode 'ODB' -LabelCode 'SENS_Pvc' -Suffix 'EXT-ADT'
        $result | Should -Be 'P02-R05-ODB-SENS_Pvc-EXT-ADT'
    }

    It 'Handles double-digit numbers' {
        $result = Get-RuleName -PolicyNumber 10 -RuleNumber 14 -PolicyCode 'SPO' -LabelCode 'PROT' -Suffix 'V2'
        $result | Should -Be 'P10-R14-SPO-PROT-V2'
    }
}

Describe 'Test-PurviewObjectNameSafety' {
    It 'Allows generated deployment-safe names' {
        $result = Test-PurviewObjectNameSafety -Name 'P01-R01-ECH-SENS_Pvc-EXT-ADT' -ObjectType 'DLP rule'

        $result.IsSafe | Should -Be $true
        $result.Reasons.Count | Should -Be 0
    }

    It 'Rejects names with spaces and punctuation outside the deployment-safe set' {
        $result = Test-PurviewObjectNameSafety -Name 'P01 R01: ECH' -ObjectType 'DLP rule'

        $result.IsSafe | Should -Be $false
        ($result.Reasons -join ' ') | Should -BeLike '*space*'
        ($result.Reasons -join ' ') | Should -BeLike "*':'*"
    }

    It 'Rejects non-ASCII punctuation that Purview cmdlets may accept but later struggle to remove' {
        $unsafeName = "P01-R01-ECH$([char]0x2013)OFFI-EXT-ADT"
        $result = Test-PurviewObjectNameSafety -Name $unsafeName -ObjectType 'DLP rule'

        $result.IsSafe | Should -Be $false
        ($result.Reasons -join ' ') | Should -BeLike '*U+2013*'
    }

    It 'Requires the name to start with an ASCII letter or digit' {
        $result = Test-PurviewObjectNameSafety -Name '-P01-R01-ECH-OFFI-EXT-ADT' -ObjectType 'DLP rule'

        $result.IsSafe | Should -Be $false
        ($result.Reasons -join ' ') | Should -BeLike '*must match*'
    }

    It 'Throws from Assert-PurviewObjectNameSafety before tenant submission' {
        { Assert-PurviewObjectNameSafety -Names @('Safe-Name', 'Unsafe Name') -ObjectType 'DLP rule' } |
            Should -Throw '*Unsafe Purview object name*'
    }
}

Describe 'Merge-GlobalConfig' {
    BeforeAll {
        $defaults = Get-ModuleDefaults
    }

    It 'Returns all default keys when GlobalJson is null' {
        $result = Merge-GlobalConfig -Defaults $defaults -GlobalJson $null
        $result.Keys.Count | Should -Be $defaults.Keys.Count
        $result.auditMode | Should -Be $true
        $result.namingPrefix | Should -Be 'DLP'
    }

    It 'Overrides known keys from GlobalJson' {
        $json = [PSCustomObject]@{
            auditMode    = $false
            namingPrefix = 'TEST'
        }
        $result = Merge-GlobalConfig -Defaults $defaults -GlobalJson $json
        $result.auditMode | Should -Be $false
        $result.namingPrefix | Should -Be 'TEST'
    }

    It 'Preserves defaults for keys not present in GlobalJson' {
        $json = [PSCustomObject]@{
            auditMode = $false
        }
        $result = Merge-GlobalConfig -Defaults $defaults -GlobalJson $json
        $result.namingSuffix | Should -Be 'EXT-ADT'
        $result.maxRetries | Should -Be 3
        $result.suppressRuleOutput | Should -Be $true
    }

    It 'Ignores unknown keys in GlobalJson' {
        $json = [PSCustomObject]@{
            unknownKey   = 'should be ignored'
            auditMode    = $false
        }
        $result = Merge-GlobalConfig -Defaults $defaults -GlobalJson $json
        $result.ContainsKey('unknownKey') | Should -Be $false
        $result.auditMode | Should -Be $false
    }
}

Describe 'Get-MergedRuleParams' {
    It 'Returns base params unchanged when no overrides match' {
        $base = @{ Name = 'R01'; Policy = 'P01'; ReportSeverityLevel = 'Low' }
        $overrides = @{ byLabel = @{}; byPolicy = @{}; byRule = @{} }

        $result = Get-MergedRuleParams -BaseParams $base -Overrides $overrides -LabelCode 'OFFI' -PolicyCode 'ECH' -RuleName 'R01'
        $result.ReportSeverityLevel | Should -Be 'Low'
    }

    It 'Applies byPolicy overrides' {
        $base = @{ Name = 'R01'; Disabled = $false }
        $overrides = @{
            byLabel  = @{}
            byPolicy = @{ 'ECH' = @{ Disabled = $true } }
            byRule   = @{}
        }

        $result = Get-MergedRuleParams -BaseParams $base -Overrides $overrides -LabelCode 'OFFI' -PolicyCode 'ECH' -RuleName 'R01'
        $result.Disabled | Should -Be $true
    }

    It 'byLabel overrides byPolicy' {
        $base = @{ Name = 'R01'; ReportSeverityLevel = 'Low' }
        $overrides = @{
            byLabel  = @{ 'OFFI' = @{ ReportSeverityLevel = 'High' } }
            byPolicy = @{ 'ECH'  = @{ ReportSeverityLevel = 'Medium' } }
            byRule   = @{}
        }

        $result = Get-MergedRuleParams -BaseParams $base -Overrides $overrides -LabelCode 'OFFI' -PolicyCode 'ECH' -RuleName 'R01'
        $result.ReportSeverityLevel | Should -Be 'High'
    }

    It 'byRule overrides byLabel and byPolicy' {
        $base = @{ Name = 'R01'; ReportSeverityLevel = 'Low' }
        $overrides = @{
            byLabel  = @{ 'OFFI' = @{ ReportSeverityLevel = 'High' } }
            byPolicy = @{ 'ECH'  = @{ ReportSeverityLevel = 'Medium' } }
            byRule   = @{ 'R01'  = @{ ReportSeverityLevel = 'None' } }
        }

        $result = Get-MergedRuleParams -BaseParams $base -Overrides $overrides -LabelCode 'OFFI' -PolicyCode 'ECH' -RuleName 'R01'
        $result.ReportSeverityLevel | Should -Be 'None'
    }

    It 'Merges multiple override levels without losing unrelated keys' {
        $base = @{ Name = 'R01'; Disabled = $false; Comment = 'original' }
        $overrides = @{
            byLabel  = @{ 'OFFI' = @{ Comment = 'label-comment' } }
            byPolicy = @{ 'ECH'  = @{ Disabled = $true } }
            byRule   = @{}
        }

        $result = Get-MergedRuleParams -BaseParams $base -Overrides $overrides -LabelCode 'OFFI' -PolicyCode 'ECH' -RuleName 'R01'
        $result.Disabled | Should -Be $true
        $result.Comment | Should -Be 'label-comment'
        $result.Name | Should -Be 'R01'
    }
}

Describe 'Resolve-PolicyMode' {
    It 'Returns TestWithoutNotifications for audit mode without notifications' {
        Resolve-PolicyMode -AuditMode $true -NotifyUser $false | Should -Be 'TestWithoutNotifications'
    }

    It 'Returns TestWithNotifications for audit mode with notifications' {
        Resolve-PolicyMode -AuditMode $true -NotifyUser $true | Should -Be 'TestWithNotifications'
    }

    It 'Returns Enable when audit mode is off' {
        Resolve-PolicyMode -AuditMode $false -NotifyUser $false | Should -Be 'Enable'
        Resolve-PolicyMode -AuditMode $false -NotifyUser $true | Should -Be 'Enable'
    }
}

Describe 'Get-ModuleDefaults' {
    It 'Returns a hashtable with expected keys' {
        $defaults = Get-ModuleDefaults
        $defaults | Should -BeOfType [hashtable]
        $defaults.ContainsKey('auditMode') | Should -Be $true
        $defaults.ContainsKey('namingPrefix') | Should -Be $true
        $defaults.ContainsKey('maxRetries') | Should -Be $true
        $defaults.ContainsKey('sitConfidenceLevel') | Should -Be $true
    }

    It 'Has sensible default values' {
        $defaults = Get-ModuleDefaults
        $defaults.auditMode | Should -Be $true
        $defaults.sitMinCount | Should -Be 1
        $defaults.sitMaxCount | Should -Be -1
        $defaults.sitConfidenceLevel | Should -Be 'High'
        $defaults.baseDelaySec | Should -Be 300
    }
}

Describe 'Resolve-RuleOverrides' {
    It 'Returns empty structure when input is null' {
        $result = Resolve-RuleOverrides -OverridesJson $null
        $result.byLabel.Count | Should -Be 0
        $result.byPolicy.Count | Should -Be 0
        $result.byRule.Count | Should -Be 0
    }

    It 'Parses byLabel overrides' {
        $json = [PSCustomObject]@{
            byLabel  = [PSCustomObject]@{ OFFI = [PSCustomObject]@{ Disabled = $true } }
            byPolicy = [PSCustomObject]@{}
            byRule   = [PSCustomObject]@{}
        }
        $result = Resolve-RuleOverrides -OverridesJson $json
        $result.byLabel.ContainsKey('OFFI') | Should -Be $true
        $result.byLabel['OFFI']['Disabled'] | Should -Be $true
    }
}

Describe 'Resolve-LabelConfig' {
    It 'Filters out group labels' {
        $labels = @(
            [PSCustomObject]@{ code = $null; name = 'SENSITIVE'; displayName = 'SENSITIVE'; isGroup = $true }
            [PSCustomObject]@{ code = 'SENS'; name = 'SENSITIVE-Default'; displayName = 'SENSITIVE'; isGroup = $false }
            [PSCustomObject]@{ code = 'OFFI'; name = 'OFFICIAL'; displayName = 'OFFICIAL'; isGroup = $false }
        )
        $result = @(Resolve-LabelConfig -LabelsJson $labels)
        $result.Count | Should -Be 2
        $result[0].code | Should -BeIn @('SENS', 'OFFI')
    }

    It 'Uses displayName when available' {
        $labels = @(
            [PSCustomObject]@{ code = 'OFFI'; name = 'OFFICIAL'; displayName = 'OFFICIAL Display'; isGroup = $false }
        )
        $result = @(Resolve-LabelConfig -LabelsJson $labels)
        $result[0].fullName | Should -Be 'OFFICIAL Display'
    }

    It 'Falls back to name when displayName is missing' {
        $labels = @(
            [PSCustomObject]@{ code = 'OFFI'; name = 'OFFICIAL'; displayName = $null; isGroup = $false }
        )
        $result = @(Resolve-LabelConfig -LabelsJson $labels)
        $result[0].fullName | Should -Be 'OFFICIAL'
    }
}

Describe 'Split-ClassifierChunks' {
    It 'Returns single chunk when count <= limit' {
        $classifiers = 1..100 | ForEach-Object { @{ Name = "SIT-$_"; Id = [guid]::NewGuid().ToString() } }
        $result = @(Split-ClassifierChunks -ClassifierList $classifiers -MaxPerRule 125)
        $result.Count | Should -Be 1
        $result[0].Count | Should -Be 100
    }

    It 'Splits evenly when count exceeds limit' {
        $classifiers = 1..156 | ForEach-Object { @{ Name = "SIT-$_"; Id = [guid]::NewGuid().ToString() } }
        $result = @(Split-ClassifierChunks -ClassifierList $classifiers -MaxPerRule 125)
        $result.Count | Should -Be 2
        $result[0].Count | Should -Be 78
        $result[1].Count | Should -Be 78
    }

    It 'Handles exact limit boundary' {
        $classifiers = 1..125 | ForEach-Object { @{ Name = "SIT-$_"; Id = [guid]::NewGuid().ToString() } }
        $result = @(Split-ClassifierChunks -ClassifierList $classifiers -MaxPerRule 125)
        $result.Count | Should -Be 1
        $result[0].Count | Should -Be 125
    }

    It 'Handles 126 items (one over limit)' {
        $classifiers = 1..126 | ForEach-Object { @{ Name = "SIT-$_"; Id = [guid]::NewGuid().ToString() } }
        $result = @(Split-ClassifierChunks -ClassifierList $classifiers -MaxPerRule 125)
        $result.Count | Should -Be 2
        $result[0].Count | Should -Be 63
        $result[1].Count | Should -Be 63
    }

    It 'Handles 375 items (three chunks)' {
        $classifiers = 1..375 | ForEach-Object { @{ Name = "SIT-$_"; Id = [guid]::NewGuid().ToString() } }
        $result = @(Split-ClassifierChunks -ClassifierList $classifiers -MaxPerRule 125)
        $result.Count | Should -Be 3
        ($result | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum | Should -Be 375
        $result[0].Count | Should -BeLessOrEqual 125
    }

    It 'Returns single empty chunk for empty input' {
        $result = @(Split-ClassifierChunks -ClassifierList @() -MaxPerRule 125)
        $result.Count | Should -Be 1
        $result[0].Count | Should -Be 0
    }

    It 'Preserves all items across chunks' {
        $classifiers = 1..200 | ForEach-Object { @{ Name = "SIT-$_"; Id = [guid]::NewGuid().ToString() } }
        $result = @(Split-ClassifierChunks -ClassifierList $classifiers -MaxPerRule 125)
        $allItems = $result | ForEach-Object { $_ } | ForEach-Object { $_.Name }
        $allItems.Count | Should -Be 200
    }

    It 'Throws when chunk count would exceed 26 (a-z limit)' {
        # 27 chunks of 125 = 3375 classifiers
        $classifiers = 1..3375 | ForEach-Object { @{ Name = "SIT-$_"; Id = [guid]::NewGuid().ToString() } }
        { Split-ClassifierChunks -ClassifierList $classifiers -MaxPerRule 125 } | Should -Throw "*maximum is 26*"
    }

    It 'Allows exactly 26 chunks (3250 classifiers at 125)' {
        $classifiers = 1..3250 | ForEach-Object { @{ Name = "SIT-$_"; Id = [guid]::NewGuid().ToString() } }
        $result = @(Split-ClassifierChunks -ClassifierList $classifiers -MaxPerRule 125)
        $result.Count | Should -Be 26
    }
}

Describe 'Get-ChunkLetter' {
    It 'Returns a for index 1' {
        Get-ChunkLetter -ChunkIndex 1 | Should -Be 'a'
    }

    It 'Returns z for index 26' {
        Get-ChunkLetter -ChunkIndex 26 | Should -Be 'z'
    }

    It 'Throws for index 0' {
        { Get-ChunkLetter -ChunkIndex 0 } | Should -Throw "*out of range*"
    }

    It 'Throws for index 27' {
        { Get-ChunkLetter -ChunkIndex 27 } | Should -Throw "*out of range*"
    }

    It 'Throws for negative index' {
        { Get-ChunkLetter -ChunkIndex -1 } | Should -Throw "*out of range*"
    }
}

Describe 'Resolve-CleanupTargets' {
    BeforeAll {
        $script:cfg = @{ namingPrefix = 'QGISCF'; namingSuffix = 'EXT-ADT'; publisher = 'Queensland Government CSU'; labelPolicyName = 'QGISCF-Label-Policy' }
    }

    It 'matches DLP policies by configured prefix and tags them scoped' {
        $objs = @{ DlpPolicy = @([pscustomobject]@{ Name = 'P01-ECH-QGISCF-EXT-ADT' }) }
        $m = Resolve-CleanupTargets -Config $script:cfg -Objects $objs
        $dlp = @($m | Where-Object { $_.Category -eq 'DlpPolicy' })
        $dlp.Count | Should -Be 1
        $dlp[0].Risk | Should -Be 'scoped'
        $dlp[0].MatchedBy | Should -Match 'QGISCF'
    }

    It 'flags a P0-pattern policy without the prefix as broad, not scoped' {
        $objs = @{ DlpPolicy = @([pscustomobject]@{ Name = 'P09-SomeoneElsesPolicy' }) }
        $m = Resolve-CleanupTargets -Config $script:cfg -Objects $objs
        @($m | Where-Object { $_.Category -eq 'DlpPolicy' -and $_.Risk -eq 'broad' }).Count | Should -Be 1
    }

    It 'never matches Microsoft-published SIT packages' {
        $objs = @{ SitPackage = @(
            [pscustomobject]@{ Identity = 'ms-pkg'; Publisher = 'Microsoft Corporation' },
            [pscustomobject]@{ Identity = 'our-pkg'; Publisher = 'Queensland Government CSU' }
        )}
        $m = Resolve-CleanupTargets -Config $script:cfg -Objects $objs
        $pkgs = @($m | Where-Object { $_.Category -eq 'SitPackage' })
        $pkgs.Count | Should -Be 1
        $pkgs[0].Identity | Should -Be 'our-pkg'
    }

    It 'does not match labels unless IncludeLabels is set' {
        $objs = @{ Label = @([pscustomobject]@{ Name = 'OFFICIAL'; ParentId = $null; Priority = 1 }) }
        (Resolve-CleanupTargets -Config $script:cfg -Objects $objs).Count | Should -Be 0
        @(Resolve-CleanupTargets -Config $script:cfg -Objects $objs -IncludeLabels | Where-Object { $_.Category -eq 'Label' }).Count | Should -Be 1
    }

    It 'returns an empty manifest when nothing matches' {
        $objs = @{ DlpPolicy = @([pscustomobject]@{ Name = 'UnrelatedThing' }) }
        (Resolve-CleanupTargets -Config $script:cfg -Objects $objs).Count | Should -Be 0
    }
}

Describe 'Get-CleanupConfirmationPhrase' {
    It 'builds a DELETE phrase from prefix and tenant' {
        Get-CleanupConfirmationPhrase -Prefix 'QGISCF' -Tenant 'qgov.onmicrosoft.com' |
            Should -Be 'DELETE QGISCF qgov.onmicrosoft.com'
    }
}

Describe 'Show-CleanupPlan' {
    It 'returns a summary object with per-category counts and a broad-match flag' {
        $targets = @(
            [pscustomobject]@{ Identity='P01-QGISCF'; Category='DlpPolicy'; Type='DLP policy'; MatchedBy='prefix'; Risk='scoped' },
            [pscustomobject]@{ Identity='OFFICIAL'; Category='Label'; Type='label'; MatchedBy='regex'; Risk='broad' }
        )
        $s = Show-CleanupPlan -Targets $targets -Tenant 't' -Quiet
        $s.Total | Should -Be 2
        $s.BroadCount | Should -Be 1
        $s.Categories['DlpPolicy'] | Should -Be 1
    }

    It 'reports zero for an empty manifest' {
        (Show-CleanupPlan -Targets @() -Tenant 't' -Quiet).Total | Should -Be 0
    }
}

Describe 'Test-DLPSessionMatch' {
    BeforeAll {
        $script:conn = [pscustomobject]@{
            State             = 'Connected'
            ConnectionUri     = 'https://eur02b.ps.compliance.protection.outlook.com/'
            Organization      = 'qgov.onmicrosoft.com'
            TenantId          = '11111111-2222-3333-4444-555555555555'
            UserPrincipalName = 'admin@qgov.onmicrosoft.com'
        }
    }

    It 'matches any live session when neither UPN nor Tenant given' {
        Test-DLPSessionMatch -Connection $script:conn | Should -BeTrue
    }

    It 'matches on exact tenant GUID' {
        Test-DLPSessionMatch -Connection $script:conn -Tenant '11111111-2222-3333-4444-555555555555' | Should -BeTrue
    }

    It 'matches when tenant is a substring of the organization domain' {
        Test-DLPSessionMatch -Connection $script:conn -Tenant 'qgov' | Should -BeTrue
    }

    It 'matches full onmicrosoft domain against organization' {
        Test-DLPSessionMatch -Connection $script:conn -Tenant 'qgov.onmicrosoft.com' | Should -BeTrue
    }

    It 'does not match a different tenant' {
        Test-DLPSessionMatch -Connection $script:conn -Tenant 'contoso.onmicrosoft.com' | Should -BeFalse
    }

    It 'matches on exact UPN' {
        Test-DLPSessionMatch -Connection $script:conn -UPN 'admin@qgov.onmicrosoft.com' | Should -BeTrue
    }

    It 'matches a different user in the same domain' {
        Test-DLPSessionMatch -Connection $script:conn -UPN 'someoneelse@qgov.onmicrosoft.com' | Should -BeTrue
    }

    It 'does not match a UPN in a different domain' {
        Test-DLPSessionMatch -Connection $script:conn -UPN 'admin@contoso.com' | Should -BeFalse
    }
}

Describe 'Convert-DlpSerializedRulePackageToText' {
    It 'decodes a UTF-16LE BOM byte array' {
        $bytes = [System.Text.Encoding]::Unicode.GetPreamble() + [System.Text.Encoding]::Unicode.GetBytes('<x/>')
        Convert-DlpSerializedRulePackageToText -Raw ([byte[]]$bytes) | Should -Be '<x/>'
    }
    It 'decodes a UTF-8 BOM byte array' {
        $bytes = [System.Text.Encoding]::UTF8.GetPreamble() + [System.Text.Encoding]::UTF8.GetBytes('<x/>')
        Convert-DlpSerializedRulePackageToText -Raw ([byte[]]$bytes) | Should -Be '<x/>'
    }
    It 'returns string input unchanged' {
        Convert-DlpSerializedRulePackageToText -Raw '<x/>' | Should -Be '<x/>'
    }
    It 'returns null for null input' {
        Convert-DlpSerializedRulePackageToText -Raw $null | Should -BeNullOrEmpty
    }
}

Describe 'Get-DlpRulePackageEntityIds' {
    BeforeAll {
        $script:goodXml = @'
<RulePackage>
  <RulePack id="aaaaaaaa-1111-2222-3333-444444444444">
    <Version major="1" minor="0" build="0" revision="0"/>
    <Details>
      <LocalizedDetails languageId="en-us"><Name>Test Pkg</Name></LocalizedDetails>
    </Details>
  </RulePack>
  <Rules>
    <Entity id="dddddddd-1111-2222-3333-444444444444"/>
    <Entity id="eeeeeeee-1111-2222-3333-444444444444"/>
  </Rules>
</RulePackage>
'@
    }

    It 'extracts entity ids and marks the package parsed' {
        $pkg = [pscustomobject]@{ Identity='our-pkg'; Publisher='X'; Name='pkg'; SerializedClassificationRuleCollection=$script:goodXml }
        $r = Get-DlpRulePackageEntityIds -Packages @($pkg)
        $r[0].Parsed | Should -BeTrue
        $r[0].EntityIds.Count | Should -Be 2
        $r[0].EntityIds | Should -Contain 'dddddddd-1111-2222-3333-444444444444'
        $r[0].RulePackId | Should -Be 'aaaaaaaa-1111-2222-3333-444444444444'
    }

    It 'flags an unparseable package with Parsed=false and a ParseError' {
        $pkg = [pscustomobject]@{ Identity='bad-pkg'; Publisher='X'; Name='bad'; SerializedClassificationRuleCollection='<RulePackage><Rules><Entity id=' }
        $r = Get-DlpRulePackageEntityIds -Packages @($pkg)
        $r[0].Parsed | Should -BeFalse
        $r[0].ParseError | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-DlpRulePackageRemovalReferenceGuard' {
    BeforeAll {
        # Stub the tenant cmdlet so the guard runs offline; tests set $global:FakeRules.
        function global:Get-DlpComplianceRule { [CmdletBinding()] param() $global:FakeRules }
        $script:pkgXml = @'
<RulePackage>
  <RulePack id="aaaaaaaa-1111-2222-3333-444444444444">
    <Version major="1" minor="0" build="0" revision="0"/>
    <Details><LocalizedDetails languageId="en-us"><Name>Pkg</Name></LocalizedDetails></Details>
  </RulePack>
  <Rules>
    <Entity id="dddddddd-1111-2222-3333-444444444444"/>
  </Rules>
</RulePackage>
'@
        $script:pkg = [pscustomobject]@{ Identity='our-pkg'; Publisher='X'; Name='pkg'; SerializedClassificationRuleCollection=$script:pkgXml }
    }
    AfterAll { Remove-Item function:global:Get-DlpComplianceRule -ErrorAction SilentlyContinue; Remove-Variable -Scope Global -Name FakeRules -ErrorAction SilentlyContinue }

    It 'blocks removal when a live DLP rule references a package entity id' {
        $global:FakeRules = @([pscustomobject]@{ Name='ReferencingRule'; ParentPolicyName='P01'; AdvancedRule='{"id":"dddddddd-1111-2222-3333-444444444444"}' })
        $r = Test-DlpRulePackageRemovalReferenceGuard -Packages @($script:pkg)
        $r.Safe | Should -BeFalse
        $r.ReferencingRuleCount | Should -Be 1
    }

    It 'permits removal when no live rule references the package' {
        $global:FakeRules = @([pscustomobject]@{ Name='UnrelatedRule'; ParentPolicyName='P02'; AdvancedRule='{"id":"99999999-1111-2222-3333-444444444444"}' })
        $r = Test-DlpRulePackageRemovalReferenceGuard -Packages @($script:pkg)
        $r.Safe | Should -BeTrue
        $r.ReferencingRuleCount | Should -Be 0
    }

    It 'is not safe when a package cannot be parsed (fails closed)' {
        $global:FakeRules = @()
        $bad = [pscustomobject]@{ Identity='bad'; Publisher='X'; Name='bad'; SerializedClassificationRuleCollection='<RulePackage><Rules><Entity id=' }
        (Test-DlpRulePackageRemovalReferenceGuard -Packages @($bad)).Safe | Should -BeFalse
    }
}

Describe 'Get-NormalizedDictionaryTerms' {
    It 'lowercases, trims, and de-duplicates' {
        Get-NormalizedDictionaryTerms -Terms @(' Apple ', 'apple', 'BANANA', 'banana ') | Should -Be @('apple','banana')
    }
    It 'drops empty and whitespace-only terms' {
        Get-NormalizedDictionaryTerms -Terms @('a','', '   ', $null) | Should -Be @('a')
    }
    It 'returns empty array for null input' {
        (Get-NormalizedDictionaryTerms -Terms $null).Count | Should -Be 0
    }
}

Describe 'Get-DictionaryTermCoverage' {
    It 'returns 1.0 when all of our terms are present in existing' {
        Get-DictionaryTermCoverage -OurTerms @('a','b') -ExistingTerms @('a','b','c') | Should -Be 1.0
    }
    It 'returns the fraction of our terms covered' {
        Get-DictionaryTermCoverage -OurTerms @('a','b','c','d') -ExistingTerms @('a','b') | Should -Be 0.5
    }
    It 'is coverage of OUR terms, not symmetric' {
        Get-DictionaryTermCoverage -OurTerms @('a') -ExistingTerms @('a','x','y','z') | Should -Be 1.0
    }
    It 'normalises before comparing' {
        Get-DictionaryTermCoverage -OurTerms @('A',' b ') -ExistingTerms @('a','B') | Should -Be 1.0
    }
    It 'returns 1.0 when our term set is empty' {
        Get-DictionaryTermCoverage -OurTerms @() -ExistingTerms @('a') | Should -Be 1.0
    }
    It 'returns 0.0 when nothing overlaps' {
        Get-DictionaryTermCoverage -OurTerms @('a','b') -ExistingTerms @('x') | Should -Be 0.0
    }
}

Describe 'Get-DictionaryCompressedSize' {
    It 'returns a positive byte count' {
        Get-DictionaryCompressedSize -Terms @('alpha','beta','gamma') | Should -BeGreaterThan 0
    }
    It 'is deterministic for the same normalised input' {
        (Get-DictionaryCompressedSize -Terms @('a','b','c')) | Should -Be (Get-DictionaryCompressedSize -Terms @('C','b','a',' a '))
    }
    It 'grows with more distinct terms' {
        (Get-DictionaryCompressedSize -Terms (1..500 | ForEach-Object { "term-$_" })) | Should -BeGreaterThan (Get-DictionaryCompressedSize -Terms @('a'))
    }
}

Describe 'Get-DictionaryGuidReferences' {
    It 'extracts GUID idRefs and ignores named idRefs and entity ids' {
        $xml = @'
<RulePackage>
  <Rules>
    <Entity id="aaaaaaaa-1111-2222-3333-444444444444">
      <IdMatch idRef="Pattern_au_crn_au-centrelink-crn" />
      <Match idRef="dddddddd-1111-2222-3333-444444444444" />
      <Match idRef="Evidence_welfare_context" />
    </Entity>
  </Rules>
</RulePackage>
'@
        $r = Get-DictionaryGuidReferences -PackageXmlText $xml
        $r | Should -Contain 'dddddddd-1111-2222-3333-444444444444'
        $r | Should -Not -Contain 'aaaaaaaa-1111-2222-3333-444444444444'
        $r.Count | Should -Be 1
    }
    It 'returns empty when no GUID idRefs' {
        (Get-DictionaryGuidReferences -PackageXmlText '<R><Match idRef="Keyword_foo"/></R>').Count | Should -Be 0
    }
    It 'de-duplicates repeated references' {
        (Get-DictionaryGuidReferences -PackageXmlText '<R><Match idRef="dddddddd-1111-2222-3333-444444444444"/><Match idRef="dddddddd-1111-2222-3333-444444444444"/></R>').Count | Should -Be 1
    }
}

Describe 'Resolve-DictionarySyncDecision' {
    It 'CREATE when no existing dictionary matched' {
        (Resolve-DictionarySyncDecision -OurTerms @('a','b') -Existing $null -TenantHeadroomBytes 100000).Action | Should -Be 'Create'
    }
    It 'REUSE when existing covers >= 90% of our terms' {
        $existing = @{ Guid='g1'; Terms=(1..95 | ForEach-Object { "t$_" }) }
        $our = (1..100 | ForEach-Object { "t$_" })
        $d = Resolve-DictionarySyncDecision -OurTerms $our -Existing $existing -TenantHeadroomBytes 100000
        $d.Action | Should -Be 'Reuse'
        $d.Guid | Should -Be 'g1'
    }
    It 'MERGE when coverage < 90% and union fits headroom' {
        $existing = @{ Guid='g1'; Terms=@('a','b') }
        $d = Resolve-DictionarySyncDecision -OurTerms @('a','b','c','d','e') -Existing $existing -TenantHeadroomBytes 1000000
        $d.Action | Should -Be 'Merge'
        $d.MergedTerms | Should -Contain 'c'
    }
    It 'OVER-BUDGET keep when coverage < 90% and union does not fit' {
        $existing = @{ Guid='g1'; Terms=@('a','b') }
        (Resolve-DictionarySyncDecision -OurTerms @('a','b','c','d','e') -Existing $existing -TenantHeadroomBytes 1).Action | Should -Be 'OverBudgetKeep'
    }
    It 'OPAQUE keep when existing terms unknown' {
        $existing = @{ Guid='g1'; Terms=$null }
        (Resolve-DictionarySyncDecision -OurTerms @('a') -Existing $existing -TenantHeadroomBytes 100000).Action | Should -Be 'OpaqueKeep'
    }
}

Describe 'Test-DictionaryBudget' {
    It 'passes under the warn cap' {
        $r = Test-DictionaryBudget -ProjectedBytes 400000
        $r.WithinWarn | Should -BeTrue; $r.WithinHard | Should -BeTrue
    }
    It 'warns between warn and hard caps' {
        $r = Test-DictionaryBudget -ProjectedBytes 600000
        $r.WithinWarn | Should -BeFalse; $r.WithinHard | Should -BeTrue
    }
    It 'fails over the hard cap' {
        (Test-DictionaryBudget -ProjectedBytes 1100000).WithinHard | Should -BeFalse
    }
    It 'honours custom caps' {
        (Test-DictionaryBudget -ProjectedBytes 500 -WarnBytes 100 -HardBytes 1000).WithinWarn | Should -BeFalse
    }
}

Describe 'Test-DictionaryRemovalAllowed' {
    It 'allows removal when ours and unreferenced' {
        (Test-DictionaryRemovalAllowed -IsOurs $true -ReferencedByGuids @() -DictGuid 'g1').Allowed | Should -BeTrue
    }
    It 'blocks removal when still referenced' {
        $r = Test-DictionaryRemovalAllowed -IsOurs $true -ReferencedByGuids @('g1') -DictGuid 'g1'
        $r.Allowed | Should -BeFalse; $r.Reason | Should -Match 'referenced'
    }
    It 'blocks removal when not ours' {
        $r = Test-DictionaryRemovalAllowed -IsOurs $false -ReferencedByGuids @() -DictGuid 'g1'
        $r.Allowed | Should -BeFalse; $r.Reason | Should -Match 'not created by this toolkit'
    }
}

Describe 'ConvertFrom-DlpDictionaryTermProperty' {
    It 'splits a comma-separated string into terms' {
        ConvertFrom-DlpDictionaryTermProperty -Raw 'alpha, beta, gamma' | Should -Be @('alpha','beta','gamma')
    }
    It 'splits a newline-separated string' {
        (ConvertFrom-DlpDictionaryTermProperty -Raw "a`nb`r`nc").Count | Should -Be 3
    }
    It 'handles mixed comma and newline delimiters and trims' {
        ConvertFrom-DlpDictionaryTermProperty -Raw "a, b`n c ,d" | Should -Be @('a','b','c','d')
    }
    It 'passes through a collection, trimming and dropping empties' {
        ConvertFrom-DlpDictionaryTermProperty -Raw @(' a ', 'b', '', $null) | Should -Be @('a','b')
    }
    It 'returns empty for null' {
        (ConvertFrom-DlpDictionaryTermProperty -Raw $null).Count | Should -Be 0
    }
}

Describe 'ConvertFrom-DlpDictionaryTermProperty - comma-in-term (deferred)' {
    # LOGGED 2026-05-21: current parser splits on commas AND newlines, assuming terms never
    # contain a literal comma. Nathan believes comma-in-term is not a valid Purview keyword,
    # so this is parked until we capture a real (Get-DlpKeywordDictionary).KeywordDictionary
    # sample. If terms CAN contain commas, switch to newline-only splitting and update this.
    It 'preserves a term that legitimately contains a comma' -Skip {
        # Replace with the real delimiter behaviour once a tenant sample confirms it.
        ConvertFrom-DlpDictionaryTermProperty -Raw "Smith, John`nplain" | Should -Be @('Smith, John','plain')
    }
}
