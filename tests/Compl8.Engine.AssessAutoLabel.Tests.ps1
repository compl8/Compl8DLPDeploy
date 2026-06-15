#Requires -Modules Pester

# Compl8.Engine — Invoke-Compl8Assess buckets AUTO-LABEL POLICY drift (the autoLabelPolicy analogue
# of the DR-4 DLP rule/policy bucketing). Assess gets the DESIRED auto-label policies by calling
# Resolve-DesiredAutoLabel over a config root (-ConfigRoot), diffs them against the ACTUAL
# autoLabelPolicies the inventory carries (mode + applied label + locations, with provenance-stamp
# ownership), and buckets each into exactly one of create/drift/orphan/foreign. This drives all four
# buckets from a self-contained temp workspace:
#   * a hand-edited ours policy (actual mode != desired)      -> drift
#   * an unchanged ours policy (actual content == desired)    -> NO bucket
#   * a desired policy with no actual policy                  -> create
#   * an ours actual policy absent from the desired set       -> orphan
#   * a foreign actual policy                                 -> foreign and NEVER actionable
#   * a DIFFERENT-prefix-stamped policy                       -> foreign (prefix-scoped ownership)
# Ownership flows through the REAL Get-TenantInventory (Test-OursDlp), not a hand-set flag.

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot   = Split-Path $PSScriptRoot -Parent
    $script:EngineDir  = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    $script:ContentDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Content'
    $script:TenantDir  = Join-Path $script:RepoRoot 'modules' 'Compl8.Tenant'
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:ContentDir -Force
    Import-Module $script:TenantDir -Force
    Import-Module $script:EngineDir -Force

    # ---- a self-contained workspace: config + a (rule-free) resolved manifest + injected inventory
    $script:Ws = Join-Path ([System.IO.Path]::GetTempPath()) ("alassess-" + [guid]::NewGuid().ToString('N'))
    $resolvedDir = Join-Path $script:Ws 'desired' 'resolved'
    $script:ConfigDir = Join-Path $script:Ws 'config'
    New-Item -ItemType Directory -Path $resolvedDir -Force | Out-Null
    New-Item -ItemType Directory -Path $script:ConfigDir -Force | Out-Null

    # Empty-package manifest so the SIT/package/dictionary buckets are empty — this test is ONLY
    # about autoLabelPolicy bucketing (other layers are covered elsewhere).
    $manifest = [ordered]@{
        schemaVersion = 'compl8.resolve-manifest/v1'
        generatedUtc  = '2026-06-13T00:00:00Z'
        packing       = [ordered]@{ assignments = [ordered]@{} }
        packages      = @()
        warnings      = @()
    }
    $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $resolvedDir 'resolve-manifest.json') -Encoding UTF8

    # DESIRED config: THREE DLP-eligible labels (OFFI, SENS, PROT) x ECH+ODB workloads => three
    # desired auto-label policies (AL01-OFFI, AL02-SENS, AL03-PROT). Room for unchanged + drift +
    # one create (desired-only). Resolve-DesiredAutoLabel reads this; assess re-reads via -ConfigRoot.
    Set-Content -Path (Join-Path $script:ConfigDir 'settings.json') -Value '{ "namingPrefix":"QGISCF","namingSuffix":"EXT-ADT","auditMode":true,"notifyUser":false,"nameTemplates":{ "label":"{prefix}-{name}","autoLabelPolicy":"AL{policyNumber}-{labelCode}-{prefix}-{suffix}","autoLabelRule":"AL{policyNumber}-R{ruleNumber}{chunkLetter}-{workloadCode}-{labelCode}-{suffix}","dlpPolicy":"P{policyNumber}-{policyCode}-{prefix}-{suffix}","dlpRule":"P{policyNumber}-R{ruleNumber}{chunkLetter}-{policyCode}-{labelCode}-{suffix}" } }'
    Set-Content -Path (Join-Path $script:ConfigDir 'labels.json')   -Value '[ { "code":"OFFI","name":"OFFICIAL","displayName":"OFFICIAL","isGroup":false }, { "code":"SENS","name":"SENSITIVE","displayName":"SENSITIVE","isGroup":false }, { "code":"PROT","name":"PROTECTED","displayName":"PROTECTED","isGroup":false } ]'
    Set-Content -Path (Join-Path $script:ConfigDir 'policies.json') -Value '[ { "number":1,"code":"ECH","comment":"Exchange policy","location":{"ExchangeLocation":"All"},"scopeParam":"AccessScope","scopeValue":"NotInOrganization","optional":false,"enabled":true }, { "number":2,"code":"ODB","comment":"OneDrive policy","location":{"OneDriveLocation":"All"},"scopeParam":"AccessScope","scopeValue":"NotInOrganization","optional":false,"enabled":true } ]'
    Set-Content -Path (Join-Path $script:ConfigDir 'classifiers.json') -Value '{ "OFFI":[ {"name":"All Full Names","id":"50b8b56b-4ef8-44c2-a924-03374f5831ce","confidenceLevel":"Medium","minCount":1,"maxCount":-1} ], "SENS":[ {"name":"Credit Card Number","id":"50842eb7-edc8-4019-85dd-5a5c1f2bb085","confidenceLevel":"High","minCount":1,"maxCount":-1} ], "PROT":[ {"name":"Tax File Number","id":"e29bc95f-cba1-4e3d-bf0a-da7e9b6e6f0d","confidenceLevel":"High","minCount":1,"maxCount":-1} ] }'
    Set-Content -Path (Join-Path $script:ConfigDir 'rule-overrides.json') -Value '{}'

    # The desired set assess will resolve — read it ourselves to build a matching/diverging actual.
    $script:Desired = Resolve-DesiredAutoLabel -ConfigPath $script:ConfigDir
    $desiredPols = @($script:Desired.Policies | Sort-Object policyName)
    if ($desiredPols.Count -lt 3) { throw "fixture precondition: expected >= 3 desired auto-label policies, got $($desiredPols.Count)" }
    $script:UnchangedPol = $desiredPols[0]   # AL01-OFFI — actual matches => NO bucket
    $script:DriftPol     = $desiredPols[1]   # AL02-SENS — actual mode hand-edited => drift
    $script:CreatePol    = $desiredPols[2]   # AL03-PROT — desired-only (not in actual) => create

    # ACTUAL inventory is built by the REAL Get-TenantInventory so ownership flows through the REAL
    # provenance-stamp discriminator (Test-OursDlp). A self-contained long-form stamp bearing
    # prefix=QGISCF resolves inline (no seeded registry) and keeps the policies ours; a CONTOSO stamp
    # resolves to a DIFFERENT prefix and must be foreign (prefix-scoped ownership).
    $stamp        = '[[Compl8DLPDeploy:provenance:v1;prefix=QGISCF;component=AutoLabelPolicy;deploymentId=20260614;environment=nonprod]]'
    $contosoStamp = '[[Compl8DLPDeploy:provenance:v1;prefix=CONTOSO;component=AutoLabelPolicy;deploymentId=20260614;environment=nonprod]]'
    $unchangedName = $script:UnchangedPol.policyName
    $unchangedLbl  = $script:UnchangedPol.label
    $driftName     = $script:DriftPol.policyName
    $driftLbl      = $script:DriftPol.label
    $script:OrphanPolName      = 'AL09-ARCH-QGISCF-EXT-ADT'   # AL-numbered, ours via stamp, not desired
    $script:ForeignPolName     = 'Default Auto Policy'         # no stamp, non-template name => foreign
    $script:CrossPrefixPolName = 'AL05-OFFI-QGISCF-EXT-ADT'    # name carries -QGISCF- but CONTOSO stamp

    function global:Get-DlpKeywordDictionary { [CmdletBinding()] param() }
    function global:Get-DlpSensitiveInformationTypeRulePackage { [CmdletBinding()] param() }
    function global:Get-DlpComplianceRule { [CmdletBinding()] param() }
    function global:Get-DlpCompliancePolicy { [CmdletBinding()] param() }
    function global:Get-Label { [CmdletBinding()] param() }
    function global:Get-LabelPolicy { [CmdletBinding()] param() }
    function global:Get-AutoSensitivityLabelPolicy { [CmdletBinding()] param() }
    function global:Get-AutoSensitivityLabelRule { [CmdletBinding()] param() }

    Mock -ModuleName Compl8.Tenant Get-DlpKeywordDictionary { @() }
    Mock -ModuleName Compl8.Tenant Get-DlpSensitiveInformationTypeRulePackage { @() }
    Mock -ModuleName Compl8.Tenant Get-DlpComplianceRule { @() }
    Mock -ModuleName Compl8.Tenant Get-DlpCompliancePolicy { @() }
    Mock -ModuleName Compl8.Tenant Get-Label { @() }
    Mock -ModuleName Compl8.Tenant Get-LabelPolicy { @() }
    Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelRule { @() }

    Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelPolicy {
        @(
            # UNCHANGED — same mode + label + locations as desired; provenance-stamped => ours.
            [pscustomobject]@{
                Name = $unchangedName; Identity = $unchangedName; Mode = 'TestWithoutNotifications'
                ApplySensitivityLabel = $unchangedLbl; ExchangeLocation = @('All'); OneDriveLocation = @('All')
                Comment = "Auto-label OFFICIAL (OFFI)`n$stamp"
            }
            # DRIFT — mode hand-edited to Enable (desired is TestWithoutNotifications); still ours.
            [pscustomobject]@{
                Name = $driftName; Identity = $driftName; Mode = 'Enable'
                ApplySensitivityLabel = $driftLbl; ExchangeLocation = @('All'); OneDriveLocation = @('All')
                Comment = "Auto-label SENSITIVE (SENS)`n$stamp"
            }
            # ORPHAN — AL-numbered ours policy (stamp) absent from the desired set.
            [pscustomobject]@{
                Name = 'AL09-ARCH-QGISCF-EXT-ADT'; Identity = 'AL09-ARCH-QGISCF-EXT-ADT'; Mode = 'TestWithoutNotifications'
                ApplySensitivityLabel = 'QGISCF-ARCHIVE'; ExchangeLocation = @('All')
                Comment = "Auto-label ARCHIVE (ARCH)`n$stamp"
            }
            # FOREIGN — a built-in policy: no stamp, non-template name => ours=$false.
            [pscustomobject]@{
                Name = 'Default Auto Policy'; Identity = 'Default Auto Policy'; Mode = 'Enable'
                ApplySensitivityLabel = 'Confidential'; ExchangeLocation = @('All')
                Comment = 'Built-in Microsoft auto-label policy'
            }
            # FOREIGN DEPLOYMENT — name carries -QGISCF- (the fallback would claim it) but the stamp
            # resolves to a DIFFERENT prefix (CONTOSO). Prefix-scoped ownership => ours=$false; the
            # resolved stamp's definitive-false must win over the name fallback.
            [pscustomobject]@{
                Name = 'AL05-OFFI-QGISCF-EXT-ADT'; Identity = 'AL05-OFFI-QGISCF-EXT-ADT'; Mode = 'TestWithoutNotifications'
                ApplySensitivityLabel = 'QGISCF-OFFICIAL'; ExchangeLocation = @('All'); OneDriveLocation = @('All')
                Comment = "Auto-label OFFICIAL (OFFI)`n$contosoStamp"
            }
        )
    }

    $script:Inv = Get-TenantInventory -Prefix 'QGISCF' -GeneratedUtc '2026-06-13T00:00:00Z'
    $script:ActualAlPolicies = @($script:Inv.objects.autoLabelPolicies)

    $script:Assessment = Invoke-Compl8Assess -WorkspacePath $script:Ws -Inventory $script:Inv `
        -ConfigRoot $script:ConfigDir -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'

    function Get-ALRefs  { param($Assessment, [string]$Bucket) @($Assessment.buckets.$Bucket | ForEach-Object { $_.ref }) }
    function Get-ALEntry { param($Assessment, [string]$Bucket, [string]$Ref) @($Assessment.buckets.$Bucket | Where-Object { $_.ref -eq $Ref })[0] }
}

AfterAll {
    if ($script:Ws -and (Test-Path -LiteralPath $script:Ws)) {
        Remove-Item -LiteralPath $script:Ws -Recurse -Force -ErrorAction SilentlyContinue
    }
    foreach ($fn in 'Get-DlpKeywordDictionary', 'Get-DlpSensitiveInformationTypeRulePackage',
        'Get-DlpComplianceRule', 'Get-DlpCompliancePolicy', 'Get-Label', 'Get-LabelPolicy',
        'Get-AutoSensitivityLabelPolicy', 'Get-AutoSensitivityLabelRule') {
        Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-Compl8Assess — auto-label ownership flows through the real reader' {
    It 'marks a stamped AL-numbered policy ours and a stamp-less built-in foreign' {
        $unchangedActual = @($script:ActualAlPolicies | Where-Object { $_.name -eq $script:UnchangedPol.policyName })[0]
        $unchangedActual.ours | Should -BeTrue -Because 'ownership came from the real stamp/template discriminator'
        $foreignActual = @($script:ActualAlPolicies | Where-Object { $_.name -eq $script:ForeignPolName })[0]
        $foreignActual.ours | Should -BeFalse -Because 'no stamp + non-template name => foreign'
    }

    It 'carries locations + comment on the auto-label policy record' {
        $unchangedActual = @($script:ActualAlPolicies | Where-Object { $_.name -eq $script:UnchangedPol.policyName })[0]
        $unchangedActual.PSObject.Properties.Name | Should -Contain 'locations'
        $unchangedActual.PSObject.Properties.Name | Should -Contain 'comment'
        @($unchangedActual.locations.PSObject.Properties.Name) | Should -Contain 'ExchangeLocation'
    }
}

Describe 'Invoke-Compl8Assess — auto-label four-bucket logic' {
    It 'still produces a schema-valid assessment with the autoLabelPolicy buckets present' {
        $r = Test-AssessmentSchema -Assessment $script:Assessment
        $r.Valid | Should -BeTrue -Because (@($r.Errors) -join '; ')
    }

    It 'drift: an ours policy whose mode changed out-of-band' {
        $entry = Get-ALEntry $script:Assessment 'drift' $script:DriftPol.policyName
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'autoLabelPolicy'
    }

    It 'no bucket: an unchanged ours policy (actual content == desired) lands in NO bucket' {
        foreach ($bucket in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'foreign', 'drift') {
            Get-ALRefs $script:Assessment $bucket | Should -Not -Contain $script:UnchangedPol.policyName -Because "the unchanged policy must not appear in '$bucket'"
        }
    }

    It 'create: a desired auto-label policy with no actual policy' {
        $entry = Get-ALEntry $script:Assessment 'create' $script:CreatePol.policyName
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'autoLabelPolicy'
    }

    It 'orphan: an ours actual policy absent from the desired set' {
        $entry = Get-ALEntry $script:Assessment 'orphan' $script:OrphanPolName
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'autoLabelPolicy'
    }

    It 'foreign: a not-ours policy lands in foreign' {
        $entry = Get-ALEntry $script:Assessment 'foreign' $script:ForeignPolName
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'autoLabelPolicy'
    }

    It 'foreign is NEVER actionable for an autoLabelPolicy' {
        foreach ($actionable in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'drift') {
            Get-ALRefs $script:Assessment $actionable | Should -Not -Contain $script:ForeignPolName -Because "$($script:ForeignPolName) is foreign and must never appear in '$actionable'"
        }
    }

    It 'a DIFFERENT-prefix-stamped policy is foreign and never actionable (prefix-scoping)' {
        $crossActual = @($script:ActualAlPolicies | Where-Object { $_.name -eq $script:CrossPrefixPolName })[0]
        $crossActual      | Should -Not -BeNullOrEmpty
        $crossActual.ours | Should -BeFalse -Because 'a resolved stamp from a DIFFERENT prefix is a foreign deployment''s object, even though the name carries the prefix token'
        (Get-ALEntry $script:Assessment 'foreign' $script:CrossPrefixPolName) | Should -Not -BeNullOrEmpty
        foreach ($actionable in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'drift') {
            Get-ALRefs $script:Assessment $actionable | Should -Not -Contain $script:CrossPrefixPolName -Because "a foreign-deployment policy must never appear in '$actionable'"
        }
    }
}

Describe 'Invoke-Compl8Assess — auto-label exactly-one bucket + determinism' {
    It 'assigns each object to exactly one bucket' {
        $seen = @{}
        foreach ($prop in $script:Assessment.buckets.PSObject.Properties) {
            foreach ($entry in @($prop.Value)) {
                $key = "$($entry.objectType)|$($entry.ref)"
                $seen.ContainsKey($key) | Should -BeFalse -Because "$key appears in '$($prop.Name)' and '$($seen[$key])'"
                $seen[$key] = $prop.Name
            }
        }
    }

    It 'produces byte-identical assessment JSON on repeated runs' {
        $a = Invoke-Compl8Assess -WorkspacePath $script:Ws -Inventory $script:Inv -ConfigRoot $script:ConfigDir -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z' | ConvertTo-Json -Depth 12
        $b = Invoke-Compl8Assess -WorkspacePath $script:Ws -Inventory $script:Inv -ConfigRoot $script:ConfigDir -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z' | ConvertTo-Json -Depth 12
        $a | Should -Be $b
    }
}

Describe 'Invoke-Compl8Assess — no config => no autoLabelPolicy buckets (back-compat)' {
    It 'emits no autoLabelPolicy buckets when ConfigRoot is absent and no workspace config exists' {
        $bareWs = Join-Path ([System.IO.Path]::GetTempPath()) ("albare-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $bareWs 'desired' 'resolved') -Force | Out-Null
        $m = [ordered]@{ schemaVersion='compl8.resolve-manifest/v1'; generatedUtc='2026-06-13T00:00:00Z'; packing=[ordered]@{ assignments=[ordered]@{} }; packages=@(); warnings=@() }
        $m | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $bareWs 'desired' 'resolved' 'resolve-manifest.json') -Encoding UTF8
        try {
            $a = Invoke-Compl8Assess -WorkspacePath $bareWs -Inventory $script:Inv -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'
            foreach ($prop in $a.buckets.PSObject.Properties) {
                @($prop.Value | Where-Object { $_.objectType -eq 'autoLabelPolicy' }).Count |
                    Should -Be 0 -Because "no config => no autoLabelPolicy buckets (bucket '$($prop.Name)')"
            }
        } finally {
            Remove-Item -LiteralPath $bareWs -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
