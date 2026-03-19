#Requires -Modules Pester

<#
.SYNOPSIS
    Pester v5 tests for the AutoLabel-Converter module.
    Tests all pure conversion functions for DLP-to-auto-labeling conversion.
#>

BeforeAll {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'AutoLabel-Converter.psm1'
    Import-Module $ModulePath -Force
}

#region Get-ConditionConvertibility

Describe 'Get-ConditionConvertibility' {
    It 'Returns convertible for ContentContainsSensitiveInformation' {
        $result = Get-ConditionConvertibility -ConditionName 'ContentContainsSensitiveInformation'
        $result.Status | Should -Be 'convertible'
    }

    It 'Returns convertible for AccessScope' {
        $result = Get-ConditionConvertibility -ConditionName 'AccessScope'
        $result.Status | Should -Be 'convertible'
    }

    It 'Returns convertible for ExceptIf conditions' {
        $result = Get-ConditionConvertibility -ConditionName 'ExceptIfAccessScope'
        $result.Status | Should -Be 'convertible'
    }

    It 'Returns convertible for SenderDomainIs' {
        $result = Get-ConditionConvertibility -ConditionName 'SenderDomainIs'
        $result.Status | Should -Be 'convertible'
    }

    It 'Returns droppable with What/Why for FromScope' {
        $result = Get-ConditionConvertibility -ConditionName 'FromScope'
        $result.Status | Should -Be 'droppable'
        $result.What | Should -Not -BeNullOrEmpty
        $result.Why | Should -Not -BeNullOrEmpty
    }

    It 'Returns droppable for SubjectContainsWords' {
        $result = Get-ConditionConvertibility -ConditionName 'SubjectContainsWords'
        $result.Status | Should -Be 'droppable'
        $result.Why | Should -BeLike '*regex*'
    }

    It 'Returns droppable for ContentIsNotLabeled' {
        $result = Get-ConditionConvertibility -ConditionName 'ContentIsNotLabeled'
        $result.Status | Should -Be 'droppable'
        $result.Why | Should -BeLike '*label state*'
    }

    It 'Returns droppable for StopPolicyProcessing' {
        $result = Get-ConditionConvertibility -ConditionName 'StopPolicyProcessing'
        $result.Status | Should -Be 'droppable'
    }

    It 'Returns unknown for non-condition properties' {
        $result = Get-ConditionConvertibility -ConditionName 'Name'
        $result.Status | Should -Be 'unknown'
    }

    It 'Returns unknown for arbitrary string' {
        $result = Get-ConditionConvertibility -ConditionName 'SomeRandomProperty'
        $result.Status | Should -Be 'unknown'
    }
}

#endregion

#region ConvertFrom-DlpRuleConditions

Describe 'ConvertFrom-DlpRuleConditions' {
    It 'Extracts simple format CCSI' {
        $rule = [PSCustomObject]@{
            Name     = 'P01-R01-ECH-OFFI-EXT-ADT'
            Policy   = 'P01-ECH'
            ContentContainsSensitiveInformation = @{
                operator = 'And'
                groups   = @(
                    @{
                        operator       = 'Or'
                        name           = 'Default'
                        sensitivetypes = @(
                            @{ name = 'AU Tax File Number'; id = 'abc-123'; mincount = 1; maxcount = -1; confidencelevel = 'High' }
                        )
                    }
                )
            }
        }

        $result = ConvertFrom-DlpRuleConditions -DlpRule $rule
        $result.HasSIT | Should -Be $true
        $result.HasTrainableClassifier | Should -Be $false
        $result.Converted.Contains('ContentContainsSensitiveInformation') | Should -Be $true
    }

    It 'Detects trainable classifiers in AdvancedRule format' {
        $advancedJson = @{
            Version   = '1.0'
            Condition = @{
                Operator      = 'And'
                SubConditions = @(
                    @{
                        ConditionName = 'ContentContainsSensitiveInformation'
                        Value         = @(
                            @{
                                Groups   = @(
                                    @{
                                        Name           = 'Default'
                                        Operator       = 'Or'
                                        Sensitivetypes = @(
                                            @{ Name = 'Some SIT'; Id = 'abc-123'; Mincount = 1; Maxcount = -1; Minconfidence = 85; Maxconfidence = 100 }
                                            @{ Name = 'TC Model'; Id = 'tc-456'; Classifiertype = 'MLModel' }
                                        )
                                    }
                                )
                                Operator = 'And'
                            }
                        )
                    }
                )
            }
        } | ConvertTo-Json -Depth 20

        $rule = [PSCustomObject]@{
            Name         = 'P01-R01-ECH-OFFI-EXT-ADT'
            Policy       = 'P01-ECH'
            AdvancedRule = $advancedJson
        }

        $result = ConvertFrom-DlpRuleConditions -DlpRule $rule
        $result.HasSIT | Should -Be $true
        $result.HasTrainableClassifier | Should -Be $true
    }

    It 'Records droppable conditions' {
        $rule = [PSCustomObject]@{
            Name      = 'P01-R01-ECH-OFFI-EXT-ADT'
            Policy    = 'P01-ECH'
            ContentContainsSensitiveInformation = @{
                operator = 'And'
                groups   = @(@{ operator = 'Or'; name = 'Default'; sensitivetypes = @(@{ name = 'SIT1'; id = '111'; mincount = 1; maxcount = -1; confidencelevel = 'High' }) })
            }
            FromScope = 'InOrganization'
        }

        $result = ConvertFrom-DlpRuleConditions -DlpRule $rule
        $result.Dropped.Count | Should -Be 1
        $result.Dropped[0].Condition | Should -Be 'FromScope'
        $result.Dropped[0].What | Should -Not -BeNullOrEmpty
        $result.Dropped[0].Why | Should -Not -BeNullOrEmpty
    }

    It 'Returns HasSIT false for rules without SIT conditions' {
        $rule = [PSCustomObject]@{
            Name   = 'NoSIT-Rule'
            Policy = 'P01-ECH'
        }

        $result = ConvertFrom-DlpRuleConditions -DlpRule $rule
        $result.HasSIT | Should -Be $false
        $result.Converted.Count | Should -Be 0
    }

    It 'Extracts ExceptIf conditions separately' {
        $rule = [PSCustomObject]@{
            Name    = 'P01-R01-ECH-OFFI-EXT-ADT'
            Policy  = 'P01-ECH'
            ContentContainsSensitiveInformation = @{
                operator = 'And'
                groups   = @(@{ operator = 'Or'; name = 'Default'; sensitivetypes = @(@{ name = 'SIT1'; id = '111'; mincount = 1; maxcount = -1; confidencelevel = 'High' }) })
            }
            ExceptIfAccessScope = 'InOrganization'
        }

        $result = ConvertFrom-DlpRuleConditions -DlpRule $rule
        $result.ExceptIf.Contains('ExceptIfAccessScope') | Should -Be $true
        $result.ExceptIf['ExceptIfAccessScope'] | Should -Be 'InOrganization'
    }

    It 'Extracts AccessScope from AdvancedRule' {
        $advancedJson = @{
            Version   = '1.0'
            Condition = @{
                Operator      = 'And'
                SubConditions = @(
                    @{
                        ConditionName = 'ContentContainsSensitiveInformation'
                        Value         = @(
                            @{
                                Groups   = @(
                                    @{
                                        Name           = 'Default'
                                        Operator       = 'Or'
                                        Sensitivetypes = @(
                                            @{ Name = 'SIT1'; Id = 'abc-123'; Mincount = 1; Maxcount = -1; Minconfidence = 85; Maxconfidence = 100 }
                                        )
                                    }
                                )
                                Operator = 'And'
                            }
                        )
                    }
                    @{
                        ConditionName = 'AccessScope'
                        Value         = 'NotInOrganization'
                    }
                )
            }
        } | ConvertTo-Json -Depth 20

        $rule = [PSCustomObject]@{
            Name         = 'P01-R01-ECH-OFFI-EXT-ADT'
            Policy       = 'P01-ECH'
            AdvancedRule = $advancedJson
        }

        $result = ConvertFrom-DlpRuleConditions -DlpRule $rule
        $result.HasSIT | Should -Be $true
        $result.Converted.Contains('AccessScope') | Should -Be $true
        $result.Converted['AccessScope'] | Should -Be 'NotInOrganization'
    }
}

#endregion

#region Resolve-LabelAssignment

Describe 'Resolve-LabelAssignment' {
    BeforeAll {
        $script:testLabels = @(
            [PSCustomObject]@{ code = 'OFFI'; name = 'OFFICIALv2'; displayName = 'OFFICIAL'; isGroup = $false }
            [PSCustomObject]@{ code = 'SENS'; name = 'SENSITIVE-Defaultv2'; displayName = 'SENSITIVE'; isGroup = $false }
            [PSCustomObject]@{ code = 'PROT'; name = 'PROTECTED-Defaultv2'; displayName = 'PROTECTED'; isGroup = $false }
            [PSCustomObject]@{ code = 'SENS_Fin'; name = 'SENSITIVE-Financialv2'; displayName = 'SENSITIVE Financial'; isGroup = $false }
        )
    }

    It 'Resolves via naming convention' {
        $result = Resolve-LabelAssignment -RuleName 'P01-R01-ECH-OFFI-EXT-ADT' -Mappings $null -TenantLabels $null -LabelsJson $script:testLabels
        $result.LabelCode | Should -Be 'OFFI'
        $result.Label | Should -Be 'OFFICIAL'
        $result.AssignedBy | Should -Be 'naming-convention'
    }

    It 'Resolves via naming convention with underscore label code' {
        $result = Resolve-LabelAssignment -RuleName 'P01-R05-ECH-SENS_Fin-EXT-ADT' -Mappings $null -TenantLabels $null -LabelsJson $script:testLabels
        $result.LabelCode | Should -Be 'SENS_Fin'
        $result.Label | Should -Be 'SENSITIVE Financial'
        $result.AssignedBy | Should -Be 'naming-convention'
    }

    It 'Resolves via exact mapping' {
        $mappings = @(
            [PSCustomObject]@{ Pattern = 'Custom-Rule-Finance'; LabelCode = 'SENS_Fin' }
        )
        $result = Resolve-LabelAssignment -RuleName 'Custom-Rule-Finance' -Mappings $mappings -TenantLabels $null -LabelsJson $script:testLabels
        $result.LabelCode | Should -Be 'SENS_Fin'
        $result.Label | Should -Be 'SENSITIVE Financial'
        $result.AssignedBy | Should -Be 'mapping-json'
    }

    It 'Resolves via wildcard mapping' {
        $mappings = @(
            [PSCustomObject]@{ Pattern = '*Finance*'; LabelCode = 'SENS_Fin' }
        )
        $result = Resolve-LabelAssignment -RuleName 'Some-Finance-Rule' -Mappings $mappings -TenantLabels $null -LabelsJson $script:testLabels
        $result.LabelCode | Should -Be 'SENS_Fin'
        $result.AssignedBy | Should -Be 'mapping-json'
    }

    It 'First mapping match wins' {
        $mappings = @(
            [PSCustomObject]@{ Pattern = '*Rule*'; LabelCode = 'OFFI' }
            [PSCustomObject]@{ Pattern = '*Finance*'; LabelCode = 'SENS_Fin' }
        )
        $result = Resolve-LabelAssignment -RuleName 'Some-Finance-Rule' -Mappings $mappings -TenantLabels $null -LabelsJson $script:testLabels
        $result.LabelCode | Should -Be 'OFFI'
        $result.AssignedBy | Should -Be 'mapping-json'
    }

    It 'Returns unresolved when nothing matches' {
        $result = Resolve-LabelAssignment -RuleName 'Unknown-Rule-Name' -Mappings $null -TenantLabels $null -LabelsJson $script:testLabels
        $result.LabelCode | Should -BeNullOrEmpty
        $result.Label | Should -BeNullOrEmpty
        $result.AssignedBy | Should -Be 'unresolved'
    }

    It 'Naming convention takes priority over mapping' {
        $mappings = @(
            [PSCustomObject]@{ Pattern = '*OFFI*'; LabelCode = 'PROT' }
        )
        $result = Resolve-LabelAssignment -RuleName 'P01-R01-ECH-OFFI-EXT-ADT' -Mappings $mappings -TenantLabels $null -LabelsJson $script:testLabels
        $result.LabelCode | Should -Be 'OFFI'
        $result.AssignedBy | Should -Be 'naming-convention'
    }
}

#endregion

#region Get-DlpRuleClassification

Describe 'Get-DlpRuleClassification' {
    It 'Returns full when all conditions convert' {
        $conditions = @{
            HasSIT                 = $true
            HasTrainableClassifier = $false
            Converted              = @{ ContentContainsSensitiveInformation = @{} }
            ExceptIf               = @{}
            Dropped                = @()
        }
        Get-DlpRuleClassification -ExtractedConditions $conditions | Should -Be 'full'
    }

    It 'Returns partial when some conditions are dropped' {
        $conditions = @{
            HasSIT                 = $true
            HasTrainableClassifier = $false
            Converted              = @{ ContentContainsSensitiveInformation = @{} }
            ExceptIf               = @{}
            Dropped                = @(
                @{ Condition = 'FromScope'; Value = 'InOrganization'; What = 'test'; Why = 'test' }
            )
        }
        Get-DlpRuleClassification -ExtractedConditions $conditions | Should -Be 'partial'
    }

    It 'Returns unconvertible when no SIT' {
        $conditions = @{
            HasSIT                 = $false
            HasTrainableClassifier = $false
            Converted              = @{}
            ExceptIf               = @{}
            Dropped                = @()
        }
        Get-DlpRuleClassification -ExtractedConditions $conditions | Should -Be 'unconvertible'
    }

    It 'Returns unconvertible when trainable classifier present' {
        $conditions = @{
            HasSIT                 = $true
            HasTrainableClassifier = $true
            Converted              = @{ ContentContainsSensitiveInformation = @{} }
            ExceptIf               = @{}
            Dropped                = @()
        }
        Get-DlpRuleClassification -ExtractedConditions $conditions | Should -Be 'unconvertible'
    }
}

#endregion

#region Get-WorkloadFromPolicy

Describe 'Get-WorkloadFromPolicy' {
    It 'Returns Exchange for ExchangeLocation' {
        $policy = [PSCustomObject]@{ ExchangeLocation = @('All') }
        Get-WorkloadFromPolicy -Policy $policy | Should -Be 'Exchange'
    }

    It 'Returns SharePoint for SharePointLocation' {
        $policy = [PSCustomObject]@{ SharePointLocation = @('All') }
        Get-WorkloadFromPolicy -Policy $policy | Should -Be 'SharePoint'
    }

    It 'Returns OneDriveForBusiness for OneDriveLocation' {
        $policy = [PSCustomObject]@{ OneDriveLocation = @('All') }
        Get-WorkloadFromPolicy -Policy $policy | Should -Be 'OneDriveForBusiness'
    }

    It 'Returns Teams for TeamsLocation' {
        $policy = [PSCustomObject]@{ TeamsLocation = @('All') }
        Get-WorkloadFromPolicy -Policy $policy | Should -Be 'Teams'
    }

    It 'Returns Endpoint for EndpointDlpLocation' {
        $policy = [PSCustomObject]@{ EndpointDlpLocation = @('All') }
        Get-WorkloadFromPolicy -Policy $policy | Should -Be 'Endpoint'
    }

    It 'Returns Unknown when no location is set' {
        $policy = [PSCustomObject]@{ SomeOtherProperty = 'value' }
        Get-WorkloadFromPolicy -Policy $policy | Should -Be 'Unknown'
    }

    It 'Prioritises Exchange when multiple locations exist' {
        $policy = [PSCustomObject]@{
            ExchangeLocation   = @('All')
            SharePointLocation = @('All')
        }
        Get-WorkloadFromPolicy -Policy $policy | Should -Be 'Exchange'
    }
}

#endregion

#region Merge-SITConditions

Describe 'Merge-SITConditions' {
    It 'Returns single source unchanged' {
        $source = [ordered]@{
            operator = 'And'
            groups   = @(
                [ordered]@{
                    operator       = 'Or'
                    name           = 'Default'
                    sensitivetypes = @(
                        [ordered]@{ name = 'SIT1'; id = 'aaa'; mincount = 1; maxcount = -1; confidencelevel = 'High' }
                    )
                }
            )
        }

        $result = Merge-SITConditions -Sources @($source)
        $result.Merged | Should -Be $source
        $result.Notes.Count | Should -Be 0
    }

    It 'Merges unique SITs from multiple sources (union)' {
        $source1 = [ordered]@{
            operator = 'And'
            groups   = @(
                [ordered]@{
                    operator       = 'Or'
                    name           = 'Default'
                    sensitivetypes = @(
                        [ordered]@{ name = 'SIT-A'; id = 'aaa'; mincount = 1; maxcount = -1; confidencelevel = 'High' }
                    )
                }
            )
        }
        $source2 = [ordered]@{
            operator = 'And'
            groups   = @(
                [ordered]@{
                    operator       = 'Or'
                    name           = 'Default'
                    sensitivetypes = @(
                        [ordered]@{ name = 'SIT-B'; id = 'bbb'; mincount = 2; maxcount = -1; confidencelevel = 'Medium' }
                    )
                }
            )
        }

        $result = Merge-SITConditions -Sources @($source1, $source2)
        $merged = $result.Merged
        $sits = $merged['groups'][0]['sensitivetypes']
        $sits.Count | Should -Be 2
        ($sits | Where-Object { $_['id'] -eq 'aaa' }) | Should -Not -BeNullOrEmpty
        ($sits | Where-Object { $_['id'] -eq 'bbb' }) | Should -Not -BeNullOrEmpty
    }

    It 'Resolves duplicate SIT IDs with most permissive values' {
        $source1 = [ordered]@{
            operator = 'And'
            groups   = @(
                [ordered]@{
                    operator       = 'Or'
                    name           = 'Default'
                    sensitivetypes = @(
                        [ordered]@{ name = 'SIT-A'; id = 'aaa'; mincount = 3; maxcount = -1; confidencelevel = 'High' }
                    )
                }
            )
        }
        $source2 = [ordered]@{
            operator = 'And'
            groups   = @(
                [ordered]@{
                    operator       = 'Or'
                    name           = 'Default'
                    sensitivetypes = @(
                        [ordered]@{ name = 'SIT-A'; id = 'aaa'; mincount = 1; maxcount = -1; confidencelevel = 'Low' }
                    )
                }
            )
        }

        $result = Merge-SITConditions -Sources @($source1, $source2)
        $merged = $result.Merged
        $sits = $merged['groups'][0]['sensitivetypes']
        $sits.Count | Should -Be 1
        $sits[0]['mincount'] | Should -Be 1
        $sits[0]['confidencelevel'] | Should -Be 'Low'
        $result.Notes | Should -Not -BeNullOrEmpty
    }

    It 'Returns null merged for empty sources' {
        $result = Merge-SITConditions -Sources @()
        $result.Merged | Should -BeNullOrEmpty
    }
}

#endregion

#region New/Export/Import-ConversionPlan

Describe 'New/Export/Import-ConversionPlan round-trip' {
    BeforeAll {
        $script:tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "AutoLabelTests_$(Get-Random)"
        New-Item -ItemType Directory -Path $script:tempDir -Force | Out-Null
    }

    AfterAll {
        if (Test-Path $script:tempDir) {
            Remove-Item -Path $script:tempDir -Recurse -Force
        }
    }

    It 'Creates a valid plan structure' {
        $plan = New-ConversionPlan -Tenant 'testtenant.onmicrosoft.com' -ScannedBy 'test@user.com' -ExistingPolicies 5
        $plan.Version | Should -Be '1'
        $plan.Tenant | Should -Be 'testtenant.onmicrosoft.com'
        $plan.ScannedBy | Should -Be 'test@user.com'
        $plan.ExistingPolicies | Should -Be 5
        ($null -ne $plan.Entries) | Should -Be $true
        $plan.Entries.Count | Should -Be 0
    }

    It 'Round-trips through export and import' {
        $plan = New-ConversionPlan -Tenant 'roundtrip.onmicrosoft.com' -ScannedBy 'admin@test.com' -ExistingPolicies 10

        $path = Join-Path $script:tempDir 'test-plan.json'
        Export-ConversionPlan -Plan $plan -Path $path

        Test-Path $path | Should -Be $true

        $imported = Import-ConversionPlan -Path $path
        $imported.Version | Should -Be '1'
        $imported.Tenant | Should -Be 'roundtrip.onmicrosoft.com'
        $imported.ScannedBy | Should -Be 'admin@test.com'
        $imported.ExistingPolicies | Should -Be 10
    }

    It 'Creates directory if it does not exist' {
        $nestedDir = Join-Path $script:tempDir 'nested' 'deep'
        $path = Join-Path $nestedDir 'plan.json'

        $plan = New-ConversionPlan -Tenant 'test.com' -ScannedBy 'user'
        Export-ConversionPlan -Plan $plan -Path $path

        Test-Path $path | Should -Be $true
    }
}

#endregion

#region Test-ScalingLimits

Describe 'Test-ScalingLimits' {
    It 'Returns ok when well within limits' {
        $result = Test-ScalingLimits -ExistingPolicies 10 -PlannedPolicies 5
        $result.Status | Should -Be 'ok'
        $result.Total | Should -Be 15
        $result.Message | Should -BeLike '*Within limits*'
    }

    It 'Returns warning when approaching limits' {
        $result = Test-ScalingLimits -ExistingPolicies 75 -PlannedPolicies 10
        $result.Status | Should -Be 'warning'
        $result.Total | Should -Be 85
        $result.Message | Should -BeLike '*Approaching*'
    }

    It 'Returns warning at exact threshold' {
        $result = Test-ScalingLimits -ExistingPolicies 70 -PlannedPolicies 10 -WarnAt 80 -MaxPolicies 100
        $result.Status | Should -Be 'warning'
        $result.Total | Should -Be 80
    }

    It 'Returns blocked when exceeding limits' {
        $result = Test-ScalingLimits -ExistingPolicies 90 -PlannedPolicies 15
        $result.Status | Should -Be 'blocked'
        $result.Total | Should -Be 105
        $result.Message | Should -BeLike '*exceed*'
    }

    It 'Returns ok at exactly max minus one with no warning threshold hit' {
        $result = Test-ScalingLimits -ExistingPolicies 70 -PlannedPolicies 9 -WarnAt 80 -MaxPolicies 100
        $result.Status | Should -Be 'ok'
        $result.Total | Should -Be 79
    }

    It 'Returns blocked at exactly max plus one' {
        $result = Test-ScalingLimits -ExistingPolicies 100 -PlannedPolicies 1
        $result.Status | Should -Be 'blocked'
        $result.Total | Should -Be 101
    }

    It 'Respects custom MaxPolicies' {
        $result = Test-ScalingLimits -ExistingPolicies 40 -PlannedPolicies 15 -MaxPolicies 50
        $result.Status | Should -Be 'blocked'
        $result.Total | Should -Be 55
    }
}

#endregion

#region Convert-PSOToHashtable

Describe 'Convert-PSOToHashtable' {
    It 'Converts a flat PSObject to hashtable' {
        $pso = [PSCustomObject]@{ Name = 'test'; Value = 42 }
        $result = Convert-PSOToHashtable -InputObject $pso
        $result | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
        $result['Name'] | Should -Be 'test'
        $result['Value'] | Should -Be 42
    }

    It 'Handles nested PSObjects' {
        $pso = [PSCustomObject]@{
            Outer = [PSCustomObject]@{ Inner = 'deep' }
        }
        $result = Convert-PSOToHashtable -InputObject $pso
        $result['Outer']['Inner'] | Should -Be 'deep'
    }

    It 'Handles arrays' {
        $pso = @( [PSCustomObject]@{ A = 1 }, [PSCustomObject]@{ A = 2 } )
        $result = Convert-PSOToHashtable -InputObject $pso
        $result.Count | Should -Be 2
        $result[0]['A'] | Should -Be 1
    }

    It 'Returns null for null input' {
        $result = Convert-PSOToHashtable -InputObject ([object]$null)
        $result | Should -BeNullOrEmpty
    }

    It 'Returns primitive values as-is' {
        Convert-PSOToHashtable -InputObject 'hello' | Should -Be 'hello'
        Convert-PSOToHashtable -InputObject 42 | Should -Be 42
    }
}

#endregion
