#Requires -Modules Pester

# Compl8.Model — canonical DLP-rule content hash (DR-1).
#
# The point of Get-DlpRuleContentHash is COMPARABILITY across the assess diff:
#   * DESIRED side: the $baseRuleParams / ContentContainsSensitiveInformation hashtable that
#     Deploy-DLPRules.ps1 (via New-DLPSITCondition) constructs to feed New-DlpComplianceRule.
#   * ACTUAL side: what Get-DlpComplianceRule returns on readback — .ContentContainsSensitiveInformation,
#     .AdvancedRule, .AccessScope, .GenerateIncidentReport, .NotifyUser, .ReportSeverityLevel, .Disabled.
#
# Both map to ONE canonical projection:
#   { sensitiveTypes: SORTED [{ id; mincount; maxcount; confidence }]; advancedRule; accessScope;
#     generateIncidentReport; notifyUser; reportSeverity; disabled }
# and the lowercase-hex SHA-256 of that projection (prefixed 'sha256:') is the hash. Same rule,
# either shape, MUST hash EQUAL; any semantic change MUST change the hash.

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:ModuleDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'Compl8.Model'
    Import-Module $script:ModuleDir -Force

    # --- DESIRED build shape (what Deploy-DLPRules constructs) -----------------------------------
    # Mirrors New-DLPSITCondition's Simple Value + the $baseRuleParams the deploy loop builds.
    function New-DesiredParams {
        param(
            [array]$Sits = @(
                @{ name = 'All Full Names'; id = '50b8b56b-4ef8-44c2-a924-03374f5831ce'; mincount = 1; maxcount = -1; confidencelevel = 'Medium' }
                @{ name = 'IP Address';     id = '1daa4ad5-e2dd-4ca4-a788-54722c09efb2'; mincount = 1; maxcount = -1; confidencelevel = 'High' }
            ),
            [string]$AccessScope = 'NotInOrganization',
            [bool]$Disabled = $false,
            [string]$ReportSeverity = 'Low',
            $GenerateIncidentReport = $null,
            $NotifyUser = $null
        )
        $ccsi = @{
            operator = 'And'
            groups   = @(
                @{ operator = 'Or'; name = 'Default'; sensitivetypes = @($Sits) }
            )
        }
        $p = @{
            Name                                = 'P01-R01-ECH-OFFI-EXT-ADT'
            Policy                              = 'P01-ECH-QGISCF-EXT-ADT'
            Comment                             = 'OFFICIAL (2 classifiers)'
            ContentContainsSensitiveInformation = $ccsi
            ReportSeverityLevel                 = $ReportSeverity
            Disabled                            = $Disabled
        }
        if ($AccessScope) { $p['AccessScope'] = $AccessScope }
        if ($GenerateIncidentReport) { $p['GenerateIncidentReport'] = $GenerateIncidentReport; $p['IncidentReportContent'] = 'All' }
        if ($NotifyUser) { $p['NotifyUser'] = $NotifyUser }
        return $p
    }

    # --- ACTUAL readback shape (what Get-DlpComplianceRule returns) ------------------------------
    # Service-side casing/typing: confidence comes back as numeric Minconfidence, keys PascalCased,
    # sensitivetypes can be a FLAT array on the rule rather than nested under groups. The canonical
    # projection must absorb all of that.
    function New-ActualRule {
        param(
            [array]$Sits = @(
                [pscustomobject]@{ name = 'All Full Names'; id = '50b8b56b-4ef8-44c2-a924-03374f5831ce'; Mincount = 1; Maxcount = -1; Minconfidence = 75 }
                [pscustomobject]@{ name = 'IP Address';     id = '1daa4ad5-e2dd-4ca4-a788-54722c09efb2'; Mincount = 1; Maxcount = -1; Minconfidence = 85 }
            ),
            [string]$AccessScope = 'NotInOrganization',
            [bool]$Disabled = $false,
            [string]$ReportSeverity = 'Low',
            $GenerateIncidentReport = $null,
            $NotifyUser = $null,
            [switch]$FlatSensitiveTypes
        )
        $ccsi = if ($FlatSensitiveTypes) {
            @($Sits)
        } else {
            @(
                [pscustomobject]@{ operator = 'And'; groups = @(
                    [pscustomobject]@{ operator = 'Or'; name = 'Default'; sensitivetypes = @($Sits) }
                ) }
            )
        }
        [pscustomobject]@{
            Name                                = 'P01-R01-ECH-OFFI-EXT-ADT'
            Policy                              = 'P01-ECH-QGISCF-EXT-ADT'
            ContentContainsSensitiveInformation = $ccsi
            AdvancedRule                        = $null
            AccessScope                         = $AccessScope
            GenerateIncidentReport              = $GenerateIncidentReport
            NotifyUser                          = $NotifyUser
            ReportSeverityLevel                 = $ReportSeverity
            Disabled                            = $Disabled
        }
    }
}

Describe 'Get-DlpRuleContentHash — surface + format' {
    It 'is exported by Compl8.Model' {
        (Get-Command -Name Get-DlpRuleContentHash -Module Compl8.Model -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
    It 'returns a sha256 hex string of 64 chars' {
        $h = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams)
        $h | Should -Match '^sha256:[0-9a-f]{64}$'
    }
}

Describe 'Get-DlpRuleContentHash — desired/actual comparability (THE proof)' {
    It 'the SAME rule as a desired-build hashtable and an actual-readback object hashes EQUAL' {
        $desired = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams)
        $actual  = Get-DlpRuleContentHash -ActualRule  (New-ActualRule)
        $actual | Should -Be $desired
    }

    It 'auto-detect (-Rule) yields the same hash for either shape' {
        $desired = Get-DlpRuleContentHash -Rule (New-DesiredParams)
        $actual  = Get-DlpRuleContentHash -Rule (New-ActualRule)
        $actual | Should -Be $desired
    }

    It 'comparable even when the actual side returns a FLAT sensitivetypes array (no groups wrapper)' {
        $desired = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams)
        $flat    = Get-DlpRuleContentHash -ActualRule (New-ActualRule -FlatSensitiveTypes)
        $flat | Should -Be $desired
    }

    It 'string confidence Low/Medium/High maps to the SAME canonical as numeric 65/75/85' {
        $dLow = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -Sits @(
            @{ name = 'X'; id = 'aaaaaaaa-0000-0000-0000-000000000001'; mincount = 1; maxcount = -1; confidencelevel = 'Low' }
        ))
        $aLow = Get-DlpRuleContentHash -ActualRule (New-ActualRule -Sits @(
            [pscustomobject]@{ name = 'X'; id = 'aaaaaaaa-0000-0000-0000-000000000001'; Mincount = 1; Maxcount = -1; Minconfidence = 65 }
        ))
        $aLow | Should -Be $dLow
    }
}

Describe 'Get-DlpRuleContentHash — normalization (incidental differences absorbed)' {
    It 'is sensitivetypes ORDER-insensitive' {
        $a = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -Sits @(
            @{ name = 'A'; id = 'aaaaaaaa-0000-0000-0000-000000000001'; mincount = 1; maxcount = -1; confidencelevel = 'High' }
            @{ name = 'B'; id = 'bbbbbbbb-0000-0000-0000-000000000002'; mincount = 1; maxcount = -1; confidencelevel = 'High' }
        ))
        $b = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -Sits @(
            @{ name = 'B'; id = 'bbbbbbbb-0000-0000-0000-000000000002'; mincount = 1; maxcount = -1; confidencelevel = 'High' }
            @{ name = 'A'; id = 'aaaaaaaa-0000-0000-0000-000000000001'; mincount = 1; maxcount = -1; confidencelevel = 'High' }
        ))
        $a | Should -Be $b
    }

    It 'is case-insensitive on the confidence string (high == High == HIGH)' {
        $a = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -Sits @(
            @{ name = 'X'; id = 'aaaaaaaa-0000-0000-0000-000000000001'; mincount = 1; maxcount = -1; confidencelevel = 'high' }
        ))
        $b = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -Sits @(
            @{ name = 'X'; id = 'aaaaaaaa-0000-0000-0000-000000000001'; mincount = 1; maxcount = -1; confidencelevel = 'HIGH' }
        ))
        $a | Should -Be $b
    }

    It 'treats missing AccessScope as null (missing == explicit null, not "")' {
        $missing = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -AccessScope '')
        $nulled  = Get-DlpRuleContentHash -ActualRule  (New-ActualRule  -AccessScope $null)
        $nulled | Should -Be $missing
    }

    It 'name/displayName of a SIT is NOT part of the canonical (only the GUID identifies it)' {
        $a = Get-DlpRuleContentHash -ActualRule (New-ActualRule -Sits @(
            [pscustomobject]@{ name = 'Friendly Name'; id = 'aaaaaaaa-0000-0000-0000-000000000001'; Mincount = 1; Maxcount = -1; Minconfidence = 85 }
        ))
        $b = Get-DlpRuleContentHash -ActualRule (New-ActualRule -Sits @(
            [pscustomobject]@{ name = 'Totally Different Name'; id = 'aaaaaaaa-0000-0000-0000-000000000001'; Mincount = 1; Maxcount = -1; Minconfidence = 85 }
        ))
        $a | Should -Be $b
    }
}

Describe 'Get-DlpRuleContentHash — semantic changes CHANGE the hash' {
    BeforeAll {
        $script:Baseline = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams)
    }

    It 'a changed confidence changes the hash' {
        $changed = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -Sits @(
            @{ name = 'All Full Names'; id = '50b8b56b-4ef8-44c2-a924-03374f5831ce'; mincount = 1; maxcount = -1; confidencelevel = 'High' }
            @{ name = 'IP Address';     id = '1daa4ad5-e2dd-4ca4-a788-54722c09efb2'; mincount = 1; maxcount = -1; confidencelevel = 'High' }
        ))
        $changed | Should -Not -Be $script:Baseline
    }

    It 'a changed mincount changes the hash' {
        $changed = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -Sits @(
            @{ name = 'All Full Names'; id = '50b8b56b-4ef8-44c2-a924-03374f5831ce'; mincount = 5; maxcount = -1; confidencelevel = 'Medium' }
            @{ name = 'IP Address';     id = '1daa4ad5-e2dd-4ca4-a788-54722c09efb2'; mincount = 1; maxcount = -1; confidencelevel = 'High' }
        ))
        $changed | Should -Not -Be $script:Baseline
    }

    It 'a changed maxcount changes the hash' {
        $changed = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -Sits @(
            @{ name = 'All Full Names'; id = '50b8b56b-4ef8-44c2-a924-03374f5831ce'; mincount = 1; maxcount = 9; confidencelevel = 'Medium' }
            @{ name = 'IP Address';     id = '1daa4ad5-e2dd-4ca4-a788-54722c09efb2'; mincount = 1; maxcount = -1; confidencelevel = 'High' }
        ))
        $changed | Should -Not -Be $script:Baseline
    }

    It 'a changed SIT set (added SIT) changes the hash' {
        $changed = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -Sits @(
            @{ name = 'All Full Names'; id = '50b8b56b-4ef8-44c2-a924-03374f5831ce'; mincount = 1; maxcount = -1; confidencelevel = 'Medium' }
            @{ name = 'IP Address';     id = '1daa4ad5-e2dd-4ca4-a788-54722c09efb2'; mincount = 1; maxcount = -1; confidencelevel = 'High' }
            @{ name = 'Extra';          id = 'cccccccc-0000-0000-0000-000000000003'; mincount = 1; maxcount = -1; confidencelevel = 'High' }
        ))
        $changed | Should -Not -Be $script:Baseline
    }

    It 'a changed action (GenerateIncidentReport on) changes the hash' {
        $changed = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -GenerateIncidentReport 'SiteAdmin')
        $changed | Should -Not -Be $script:Baseline
    }

    It 'a changed NotifyUser changes the hash' {
        $changed = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -NotifyUser 'SiteAdmin,LastModifier,Owner')
        $changed | Should -Not -Be $script:Baseline
    }

    It 'a changed reportSeverity changes the hash' {
        $changed = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -ReportSeverity 'Medium')
        $changed | Should -Not -Be $script:Baseline
    }

    It 'a changed Disabled flag changes the hash' {
        $changed = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -Disabled $true)
        $changed | Should -Not -Be $script:Baseline
    }

    It 'a changed accessScope (scope) changes the hash' {
        $changed = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams -AccessScope 'InOrganization')
        $changed | Should -Not -Be $script:Baseline
    }
}

Describe 'Get-DlpRuleContentHash — AdvancedRule rules' {
    BeforeAll {
        # The AdvancedRule JSON string New-AdvancedRuleJson emits (SIT + TC mix). Numeric Minconfidence.
        $script:AdvJson = (@{
            Version   = '1.0'
            Condition = @{
                Operator      = 'And'
                SubConditions = @(
                    @{ ConditionName = 'ContentContainsSensitiveInformation'; Value = @(
                        @{ Operator = 'And'; Groups = @(
                            @{ Name = 'Default'; Operator = 'Or'; Sensitivetypes = @(
                                @{ Name = 'A Full Names'; Id = '50b8b56b-4ef8-44c2-a924-03374f5831ce'; Mincount = 1; Maxcount = -1; Minconfidence = 75; Maxconfidence = 100 }
                                @{ Name = 'A TC'; Id = '11111111-2222-3333-4444-555555555555'; Classifiertype = 'MLModel' }
                            ) }
                        ) }
                    ) }
                    @{ ConditionName = 'AccessScope'; Value = 'NotInOrganization' }
                )
            }
        } | ConvertTo-Json -Depth 20 -Compress)
    }

    It 'an AdvancedRule rule hashes to a stable sha256 value' {
        $h1 = Get-DlpRuleContentHash -DesiredParams @{ Name = 'R'; Policy = 'P'; AdvancedRule = $script:AdvJson; Disabled = $false; ReportSeverityLevel = 'Low' }
        $h2 = Get-DlpRuleContentHash -DesiredParams @{ Name = 'R'; Policy = 'P'; AdvancedRule = $script:AdvJson; Disabled = $false; ReportSeverityLevel = 'Low' }
        $h1 | Should -Match '^sha256:[0-9a-f]{64}$'
        $h1 | Should -Be $h2
    }

    It 'desired AdvancedRule string == actual AdvancedRule readback (same JSON, whitespace-agnostic)' {
        $desired = Get-DlpRuleContentHash -DesiredParams @{ Name = 'R'; Policy = 'P'; AdvancedRule = $script:AdvJson; Disabled = $false; ReportSeverityLevel = 'Low' }
        # Actual side returns the same logical JSON but the service may pretty-print / reorder whitespace.
        $reserialized = ($script:AdvJson | ConvertFrom-Json | ConvertTo-Json -Depth 20)
        $actual = Get-DlpRuleContentHash -ActualRule ([pscustomobject]@{
            Name = 'R'; Policy = 'P'; AdvancedRule = $reserialized; ContentContainsSensitiveInformation = $null
            AccessScope = $null; GenerateIncidentReport = $null; NotifyUser = $null; ReportSeverityLevel = 'Low'; Disabled = $false
        })
        $actual | Should -Be $desired
    }

    It 'an edit inside the AdvancedRule JSON changes the hash' {
        $base = Get-DlpRuleContentHash -DesiredParams @{ Name = 'R'; Policy = 'P'; AdvancedRule = $script:AdvJson; Disabled = $false; ReportSeverityLevel = 'Low' }
        $editedJson = $script:AdvJson -replace '"Mincount":1', '"Mincount":9'
        $edited = Get-DlpRuleContentHash -DesiredParams @{ Name = 'R'; Policy = 'P'; AdvancedRule = $editedJson; Disabled = $false; ReportSeverityLevel = 'Low' }
        $edited | Should -Not -Be $base
    }
}

Describe 'Get-DlpRuleContentHash — purity / determinism' {
    It 'is deterministic across repeated calls' {
        $a = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams)
        $b = Get-DlpRuleContentHash -DesiredParams (New-DesiredParams)
        $a | Should -Be $b
    }
}
