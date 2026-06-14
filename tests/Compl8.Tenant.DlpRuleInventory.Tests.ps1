#Requires -Modules Pester

# Compl8.Tenant — DR-3: Get-TenantInventory carries DLP rule/policy CONTENT for drift hashing.
#
# The actual-side inventory must expose enough of each DLP rule's readback content that assess
# can hash it via Get-DlpRuleContentHash -ActualRule and compare it against the DESIRED rule's
# content hash (Resolve-DesiredDlpRules / Get-DlpRuleContentHash -DesiredParams). This test:
#   1. Mocks Get-DlpComplianceRule / Get-DlpCompliancePolicy with a REALISTIC readback (the
#      service re-serialises CCSI: PascalCase groups, numeric Minconfidence) plus the action /
#      scope / severity / disabled fields the canonical hash reads.
#   2. Asserts Get-TenantInventory emits the extended dlpRules fields (structured CCSI value,
#      advancedRule, accessScope, generateIncidentReport, notifyUser, reportSeverity, disabled,
#      contentHash) and dlpPolicies fields (mode, locations, comment) WITHOUT dropping the
#      existing back-compat fields.
#   3. Proves the reader<->hash round-trip: the per-rule contentHash the reader stored, AND a
#      fresh Get-DlpRuleContentHash -ActualRule over the emitted record, both EQUAL the hash of
#      the SAME rule's DESIRED build params (the shape Resolve-DesiredDlpRules / Deploy build).

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot  = Split-Path $PSScriptRoot -Parent
    $script:TenantDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Tenant'
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:TenantDir -Force

    $script:Prefix = 'QGISCF'
    $script:SitId  = '50b8b56b-4ef8-44c2-a924-03374f5831ce'

    # The SCC read cmdlets are not installed in CI. Global stubs so the names resolve, then
    # Mock -ModuleName overrides them inside the Compl8.Tenant module scope.
    function global:Get-DlpKeywordDictionary { [CmdletBinding()] param() }
    function global:Get-DlpSensitiveInformationTypeRulePackage { [CmdletBinding()] param() }
    function global:Get-DlpComplianceRule { [CmdletBinding()] param() }
    function global:Get-DlpCompliancePolicy { [CmdletBinding()] param() }
    function global:Get-Label { [CmdletBinding()] param() }
    function global:Get-LabelPolicy { [CmdletBinding()] param() }
    function global:Get-AutoSensitivityLabelPolicy { [CmdletBinding()] param() }
    function global:Get-AutoSensitivityLabelRule { [CmdletBinding()] param() }

    $sitIdLocal = $script:SitId

    Mock -ModuleName Compl8.Tenant Get-DlpKeywordDictionary { @() }
    Mock -ModuleName Compl8.Tenant Get-DlpSensitiveInformationTypeRulePackage { @() }
    Mock -ModuleName Compl8.Tenant Get-Label { @() }
    Mock -ModuleName Compl8.Tenant Get-LabelPolicy { @() }
    Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelPolicy { @() }
    Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelRule { @() }

    # REALISTIC readback: the service re-serialises ContentContainsSensitiveInformation with
    # PascalCase keys, a Minconfidence numeric (75) instead of the build-side confidencelevel
    # string, and the nested Groups/Sensitivetypes wrapper. Plus the content fields the canonical
    # hash reads: AccessScope, ReportSeverityLevel, Disabled (GenerateIncidentReport/NotifyUser
    # are off here so they fold to null on both sides).
    Mock -ModuleName Compl8.Tenant Get-DlpComplianceRule {
        @(
            [pscustomobject]@{
                Name     = 'QGISCF-QLD-Medium-Email-07'
                Identity = 'QGISCF-QLD-Medium-Email-07'
                Policy   = 'P01-MED-QGISCF-EXT'
                Priority = 0
                Disabled = $false
                # codex review P1: DLP-rule ownership is the provenance stamp on the Comment, not the
                # name prefix — carry a real '[[Compl8:...]]' marker so this stays ours under the new
                # discriminator (Test-OursDlp).
                Comment  = "OFFICIAL (1 classifiers)`n[[Compl8:0123456789abcdef]]"
                AccessScope = 'NotInOrganization'
                ReportSeverityLevel = 'Low'
                GenerateIncidentReport = $null
                NotifyUser = $null
                AdvancedRule = $null
                ContentContainsSensitiveInformation = @(
                    [pscustomobject]@{
                        Operator = 'And'
                        Groups   = @(
                            [pscustomobject]@{
                                Operator = 'Or'
                                Name     = 'Default'
                                Sensitivetypes = @(
                                    [pscustomobject]@{
                                        Name         = 'All Full Names'
                                        Id           = $sitIdLocal
                                        Mincount     = 1
                                        Maxcount     = -1
                                        Minconfidence = 75
                                    }
                                )
                            }
                        )
                    }
                )
            }
            # codex review P1: a TEMPLATE-named ours rule ('P01-R01-ECH-OFFI-EXT-ADT' — the real
            # dlpRule template shape, which does NOT start with the prefix) whose Comment carries a
            # provenance stamp => Test-OursDlp must mark it ours=$true via the PRIMARY (stamp) path.
            [pscustomobject]@{
                Name     = 'P01-R01-ECH-OFFI-EXT-ADT'
                Identity = 'P01-R01-ECH-OFFI-EXT-ADT'
                Policy   = 'P01-ECH-QGISCF-EXT-ADT'
                Priority = 1
                Disabled = $false
                Comment  = "OFFICIAL (1 classifiers)`n[[Compl8:fedcba9876543210]]"
                AccessScope = 'NotInOrganization'
                ReportSeverityLevel = 'Low'
                ContentContainsSensitiveInformation = $null
            }
            # A foreign Microsoft rule — opacity-as-safety; never our discriminator. Its name does NOT
            # match the P-numbered template and its Comment carries no Compl8 stamp => ours=$false.
            [pscustomobject]@{
                Name     = 'Default rule'
                Identity = 'Default rule'
                Policy   = 'Microsoft DLP Policy'
                Priority = 0
                Disabled = $false
                Comment  = 'Built-in Microsoft policy rule'
                AccessScope = $null
                ReportSeverityLevel = $null
                ContentContainsSensitiveInformation = $null
            }
        )
    }
    Mock -ModuleName Compl8.Tenant Get-DlpCompliancePolicy {
        @(
            [pscustomobject]@{
                Name     = 'P01-MED-QGISCF-EXT'
                Identity = 'P01-MED-QGISCF-EXT'
                Mode     = 'TestWithoutNotifications'
                # codex review P1: ownership via the provenance stamp on the Comment.
                Comment  = "QGISCF DLP Policy for Exchange Online - External Email - Audit Mode`n[[Compl8:0123456789abcdef]]"
                ExchangeLocation = @('All')
            }
            # codex review P1: a TEMPLATE-named ours policy ('P01-ECH-QGISCF-EXT-ADT' — prefix in the
            # MIDDLE) whose Comment carries a provenance stamp => ours=$true via the PRIMARY path.
            [pscustomobject]@{
                Name     = 'P01-ECH-QGISCF-EXT-ADT'
                Identity = 'P01-ECH-QGISCF-EXT-ADT'
                Mode     = 'TestWithoutNotifications'
                Comment  = "Exchange policy`n[[Compl8:fedcba9876543210]]"
                ExchangeLocation = @('All')
            }
            # A foreign policy — non-matching name, non-Compl8 comment => ours=$false.
            [pscustomobject]@{
                Name     = 'Default DLP policy'
                Identity = 'Default DLP policy'
                Mode     = 'Enable'
                Comment  = 'Built-in Microsoft policy'
                ExchangeLocation = @('All')
            }
        )
    }

    $script:Inv = Get-TenantInventory -Prefix $script:Prefix -GeneratedUtc '2026-06-13T00:00:00Z'
    $script:OursRule = @($script:Inv.objects.dlpRules | Where-Object { $_.name -eq 'QGISCF-QLD-Medium-Email-07' })[0]

    # The DESIRED build params for the SAME rule — the shape Resolve-DesiredDlpRules / Deploy build
    # (build-side: lowercase keys, confidencelevel STRING 'Medium' which folds to 75 numerically).
    $script:DesiredParams = @{
        Name                = 'QGISCF-QLD-Medium-Email-07'
        Policy              = 'P01-MED-QGISCF-EXT'
        ReportSeverityLevel = 'Low'
        Disabled            = $false
        AccessScope         = 'NotInOrganization'
        ContentContainsSensitiveInformation = @{
            operator = 'And'
            groups   = @(
                @{
                    operator       = 'Or'
                    name           = 'Default'
                    sensitivetypes = @(
                        @{
                            name            = 'All Full Names'
                            id              = $script:SitId
                            mincount        = 1
                            maxcount        = -1
                            confidencelevel = 'Medium'
                        }
                    )
                }
            )
        }
    }
}

AfterAll {
    foreach ($fn in 'Get-DlpKeywordDictionary', 'Get-DlpSensitiveInformationTypeRulePackage',
        'Get-DlpComplianceRule', 'Get-DlpCompliancePolicy', 'Get-Label', 'Get-LabelPolicy',
        'Get-AutoSensitivityLabelPolicy', 'Get-AutoSensitivityLabelRule') {
        Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
    }
}

Describe 'Get-TenantInventory — dlpRules carry actual-rule content (DR-3)' {
    It 'keeps the existing back-compat dlpRule fields' {
        foreach ($f in 'name', 'identity', 'ours', 'policy', 'priority', 'disabled', 'contentContainsSensitiveInformation') {
            $script:OursRule.PSObject.Properties.Name | Should -Contain $f -Because "back-compat field '$f' must remain"
        }
        $script:OursRule.policy | Should -Be 'P01-MED-QGISCF-EXT'
        $script:OursRule.ours   | Should -BeTrue
    }

    It 'adds the structured content fields the canonical hash reads' {
        foreach ($f in 'contentCondition', 'advancedRule', 'accessScope', 'generateIncidentReport', 'notifyUser', 'reportSeverity', 'contentHash') {
            $script:OursRule.PSObject.Properties.Name | Should -Contain $f -Because "extended field '$f' must be emitted"
        }
        $script:OursRule.accessScope    | Should -Be 'NotInOrganization'
        $script:OursRule.reportSeverity | Should -Be 'Low'
    }

    It 'carries the STRUCTURED CCSI value (not only the flattened reference text)' {
        # contentCondition is the structured readback object — it must still name the SIT id and
        # the nested group operator, so the hash can re-project it. (The old field was only flat text.)
        $cond = $script:OursRule.contentCondition
        $cond | Should -Not -BeNullOrEmpty
        ($cond | ConvertTo-Json -Depth 12) | Should -Match ([regex]::Escape($script:SitId))
    }

    It 'stores a per-rule contentHash that is a sha256 value' {
        $script:OursRule.contentHash | Should -Match '^sha256:[0-9a-f]{64}$'
    }
}

Describe 'Get-TenantInventory — dlpPolicies carry mode/locations/comment (DR-3)' {
    It 'keeps the existing back-compat dlpPolicy fields and adds locations + comment' {
        $pol = @($script:Inv.objects.dlpPolicies)[0]
        foreach ($f in 'name', 'identity', 'ours', 'mode', 'locations', 'comment') {
            $pol.PSObject.Properties.Name | Should -Contain $f -Because "dlpPolicy field '$f' must be present"
        }
        $pol.mode    | Should -Be 'TestWithoutNotifications'
        $pol.comment | Should -Match 'Exchange'
    }
}

Describe 'Get-TenantInventory — DLP rule/policy ownership via provenance stamp (codex review P1)' {
    It 'marks a TEMPLATE-named rule (no prefix-start) ours=$true when its Comment carries a [[Compl8:...]] stamp' {
        $rule = @($script:Inv.objects.dlpRules | Where-Object { $_.name -eq 'P01-R01-ECH-OFFI-EXT-ADT' })[0]
        $rule        | Should -Not -BeNullOrEmpty -Because 'the template-named ours rule must be in the inventory'
        $rule.ours   | Should -BeTrue -Because 'its Comment carries a Compl8 provenance stamp (the definitive ownership marker)'
    }

    It 'marks a rule with a non-Compl8 comment and a non-matching name ours=$false (foreign)' {
        $rule = @($script:Inv.objects.dlpRules | Where-Object { $_.name -eq 'Default rule' })[0]
        $rule        | Should -Not -BeNullOrEmpty
        $rule.ours   | Should -BeFalse -Because 'no provenance stamp and the name does not match the P-numbered template'
    }

    It 'marks a TEMPLATE-named policy (prefix in the middle) ours=$true when its Comment carries a stamp' {
        $pol = @($script:Inv.objects.dlpPolicies | Where-Object { $_.name -eq 'P01-ECH-QGISCF-EXT-ADT' })[0]
        $pol         | Should -Not -BeNullOrEmpty
        $pol.ours    | Should -BeTrue -Because 'the policy name never starts with the prefix; ownership is the provenance stamp'
    }

    It 'marks a non-Compl8 policy ours=$false (foreign)' {
        $pol = @($script:Inv.objects.dlpPolicies | Where-Object { $_.name -eq 'Default DLP policy' })[0]
        $pol         | Should -Not -BeNullOrEmpty
        $pol.ours    | Should -BeFalse
    }
}

Describe 'Get-TenantInventory — reader-to-hash round-trip is comparable (DR-3)' {
    BeforeAll {
        # The reader-stored contentHash IS the actual-rule hash. To prove the round-trip is
        # re-derivable from the EMITTED record's carried content fields, project the record back
        # into the canonical actual-rule shape (structured CCSI under the name the hash reads) and
        # hash that. This is the carried-content -> hash proof: the record carries enough to hash.
        $rec = $script:OursRule
        $projection = [pscustomobject][ordered]@{
            ContentContainsSensitiveInformation = $rec.contentCondition
            AdvancedRule                        = $rec.advancedRule
            AccessScope                         = $rec.accessScope
            GenerateIncidentReport              = $rec.generateIncidentReport
            NotifyUser                          = $rec.notifyUser
            ReportSeverityLevel                 = $rec.reportSeverity
            Disabled                            = $rec.disabled
        }
        $script:RecordActualHash = Get-DlpRuleContentHash -ActualRule $projection
        $script:DesiredHash      = Get-DlpRuleContentHash -DesiredParams $script:DesiredParams
    }

    It 'the desired build hash equals the actual-readback hash (the canonical convention erases re-serialisation)' {
        $script:RecordActualHash | Should -Be $script:DesiredHash -Because 'PascalCase/Minconfidence re-serialisation must not perturb the canonical hash'
    }

    It 'the contentHash the reader stored equals a fresh actual-rule hash over the carried content fields' {
        $script:OursRule.contentHash | Should -Be $script:RecordActualHash
    }

    It 'the stored contentHash equals the desired build hash (the drift baseline assess compares)' {
        $script:OursRule.contentHash | Should -Be $script:DesiredHash
    }
}
