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
}
