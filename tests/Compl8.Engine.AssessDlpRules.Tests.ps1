#Requires -Modules Pester

# Compl8.Engine — DR-4: Invoke-Compl8Assess buckets DLP rule/policy drift (the config bridge).
#
# Assess gets the DESIRED rules/policies by calling Resolve-DesiredDlpRules over a config root
# (-ConfigRoot — the Stage-5 re-point seam; default derives from the workspace). It diffs them
# against the ACTUAL dlpRules/dlpPolicies the inventory carries (DR-3 content + contentHash) and
# buckets each into exactly one of create/drift/orphan/foreign, honouring the foreign-never-
# actionable rule. This test drives ALL FOUR dlpRule buckets from a self-contained temp workspace:
#   * a hand-edited ours rule (actual contentHash != desired)  -> drift
#   * an unchanged ours rule (actual contentHash == desired)   -> NO bucket
#   * a desired rule with no actual rule                        -> create
#   * an ours actual rule absent from the desired set          -> orphan
#   * a foreign actual rule                                     -> foreign and NEVER actionable
# and the dlpPolicy create/drift/orphan/foreign buckets the same way.

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot   = Split-Path $PSScriptRoot -Parent
    $script:EngineDir  = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    $script:ContentDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Content'
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:ContentDir -Force
    Import-Module $script:EngineDir -Force

    # ---- a self-contained workspace: config + a (rule-free) resolved manifest + injected inventory
    $script:Ws = Join-Path ([System.IO.Path]::GetTempPath()) ("dr4-" + [guid]::NewGuid().ToString('N'))
    $resolvedDir = Join-Path $script:Ws 'desired' 'resolved'
    $script:ConfigDir = Join-Path $script:Ws 'config'
    New-Item -ItemType Directory -Path $resolvedDir -Force | Out-Null
    New-Item -ItemType Directory -Path $script:ConfigDir -Force | Out-Null

    # An empty-package resolve manifest so the SIT/package/dictionary buckets are all empty here —
    # this test is ONLY about dlpRule/dlpPolicy bucketing (the SIT path is covered elsewhere).
    $manifest = [ordered]@{
        schemaVersion = 'compl8.resolve-manifest/v1'
        generatedUtc  = '2026-06-13T00:00:00Z'
        packing       = [ordered]@{ assignments = [ordered]@{} }
        packages      = @()
        warnings      = @()
    }
    $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $resolvedDir 'resolve-manifest.json') -Encoding UTF8

    # ---- DESIRED config: TWO policies x TWO DLP-eligible labels (OFFI, SENS) => four desired
    # rules. Resolve-DesiredDlpRules reads this; assess re-reads it via -ConfigRoot. Four rules give
    # room for unchanged + drift + two create (desired-only) cases.
    Set-Content -Path (Join-Path $script:ConfigDir 'settings.json') -Value '{ "namingPrefix":"QGISCF","namingSuffix":"EXT-ADT","auditMode":true,"notifyUser":false,"generateIncidentReport":false,"sitPrefix":"QGISCF","publisher":"QGISCF","nameTemplates":{"dlpPolicy":"P{policyNumber}-{policyCode}-{prefix}-{suffix}","dlpRule":"P{policyNumber}-R{ruleNumber}{chunkLetter}-{policyCode}-{labelCode}-{suffix}"} }'
    Set-Content -Path (Join-Path $script:ConfigDir 'labels.json')   -Value '[ { "code":"OFFI","name":"OFFICIAL","displayName":"OFFICIAL","isGroup":false }, { "code":"SENS","name":"SENSITIVE","displayName":"SENSITIVE","isGroup":false } ]'
    Set-Content -Path (Join-Path $script:ConfigDir 'policies.json') -Value '[ { "number":1,"code":"ECH","comment":"Exchange policy","location":{"ExchangeLocation":"All"},"scopeParam":"AccessScope","scopeValue":"NotInOrganization","optional":false,"enabled":true }, { "number":2,"code":"ODB","comment":"OneDrive policy","location":{"OneDriveLocation":"All"},"scopeParam":"AccessScope","scopeValue":"NotInOrganization","optional":false,"enabled":true } ]'
    Set-Content -Path (Join-Path $script:ConfigDir 'classifiers.json') -Value '{ "OFFI":[ {"name":"All Full Names","id":"50b8b56b-4ef8-44c2-a924-03374f5831ce","confidenceLevel":"Medium","minCount":1,"maxCount":-1} ], "SENS":[ {"name":"Credit Card Number","id":"50842eb7-edc8-4019-85dd-5a5c1f2bb085","confidenceLevel":"High","minCount":1,"maxCount":-1} ] }'
    Set-Content -Path (Join-Path $script:ConfigDir 'rule-overrides.json') -Value '{}'

    # The desired set assess will resolve — we read it ourselves to build a matching/diverging actual.
    $script:Desired = Resolve-DesiredDlpRules -ConfigPath $script:ConfigDir
    $desiredRules = @($script:Desired.Rules | Sort-Object ruleName)
    $desiredPols  = @($script:Desired.Policies)
    if ($desiredRules.Count -le 2) { throw "fixture precondition: expected >= 4 desired rules, got $($desiredRules.Count)" }

    # rule[0] -> UNCHANGED (actual hash == desired => NO bucket); rule[1] -> DRIFT (actual hash
    # mutated => drift). rules[2..] are DESIRED-ONLY (not added to actual) => create.
    $script:UnchangedRule = $desiredRules[0]   # P01-R01-ECH-OFFI-EXT-ADT (OFFI, Medium/75)
    $script:DriftRule     = $desiredRules[1]   # P01-R02-ECH-SENS-EXT-ADT (SENS, High/85)
    $desiredPolByName = @{}
    foreach ($p in $desiredPols) { $desiredPolByName[$p.policyName] = $p }
    $polNames = @($desiredPols | ForEach-Object { $_.policyName } | Sort-Object)

    # codex review P1 (end-to-end): the ACTUAL inventory is built by the REAL Get-TenantInventory so
    # ownership flows through the REAL provenance-stamp discriminator (Test-OursDlp) — NOT a hand-set
    # ours=$true. The mocked SCC readback uses REALISTIC template names + provenance-stamped Comments,
    # so a deployed-and-edited rule lands in 'drift' (proving it is NOT skipped as foreign), and a
    # foreign rule (no stamp, non-template name) lands in 'foreign'. The service re-serialises CCSI
    # (PascalCase Groups/Sensitivetypes, numeric Minconfidence 75/85), so the readback below mirrors it.
    $script:TenantDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Tenant'
    Import-Module $script:TenantDir -Force

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
    Mock -ModuleName Compl8.Tenant Get-Label { @() }
    Mock -ModuleName Compl8.Tenant Get-LabelPolicy { @() }
    Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelPolicy { @() }
    Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelRule { @() }

    # A re-serialised readback CCSI in the SERVICE shape (PascalCase, numeric Minconfidence).
    function global:New-ReadbackCcsi { param([string]$SitId, [int]$MinConfidence)
        @(
            [pscustomobject]@{
                Operator = 'And'
                Groups   = @(
                    [pscustomobject]@{
                        Operator = 'Or'; Name = 'Default'
                        Sensitivetypes = @(
                            [pscustomobject]@{ Name='x'; Id=$SitId; Mincount=1; Maxcount=-1; Minconfidence=$MinConfidence }
                        )
                    }
                )
            }
        )
    }
    $offiSit = '50b8b56b-4ef8-44c2-a924-03374f5831ce'
    $sensSit = '50842eb7-edc8-4019-85dd-5a5c1f2bb085'
    # codex review (prefix-scoping P1): ownership is the provenance stamp on the Comment AND its
    # prefix must equal this inventory's prefix (QGISCF). A bare short marker resolves via a seeded
    # registry and stays Unresolved here, so use a SELF-CONTAINED long-form stamp bearing
    # prefix=QGISCF — it resolves inline (no seeded registry) and keeps these rules/policies ours
    # under the corrected, prefix-validated discriminator. (The orphan/template rule names carry no
    # prefix token, so the stamp is the ONLY thing that can confer ownership on them.)
    $stamp   = '[[Compl8DLPDeploy:provenance:v1;prefix=QGISCF;component=DlpRule;deploymentId=20260614;environment=nonprod]]'
    $unchangedName = $script:UnchangedRule.ruleName
    $driftName     = $script:DriftRule.ruleName
    $script:OrphanRuleName  = 'P09-R09-ECH-OFFI-EXT-ADT'  # template-shaped, ours via stamp, not desired
    $script:ForeignRuleName = 'Default DLP rule'           # no stamp, non-template name => foreign
    # codex review (prefix-scoping P1): a foreign-DEPLOYMENT rule — template-shaped name but its
    # stamp resolves to a DIFFERENT prefix (CONTOSO). Ownership is prefix-scoped, so it must be
    # foreign (NOT claimed as ours) and never land in an actionable bucket.
    $contosoStamp = '[[Compl8DLPDeploy:provenance:v1;prefix=CONTOSO;component=DlpRule;deploymentId=20260614;environment=nonprod]]'
    $script:CrossPrefixRuleName = 'P05-R05-ECH-OFFI-EXT-ADT-CONTOSO'

    Mock -ModuleName Compl8.Tenant Get-DlpComplianceRule {
        @(
            # UNCHANGED — OFFI Medium=75 matches desired; provenance-stamped Comment => ours via stamp.
            [pscustomobject]@{
                Name = $unchangedName; Identity = $unchangedName; Policy = 'P01-ECH-QGISCF-EXT-ADT'
                Priority = 1; Disabled = $false; AccessScope = 'NotInOrganization'; ReportSeverityLevel = 'Low'
                GenerateIncidentReport = $null; NotifyUser = $null; AdvancedRule = $null
                Comment = "OFFICIAL (1 classifiers)`n$stamp"
                ContentContainsSensitiveInformation = (New-ReadbackCcsi -SitId $offiSit -MinConfidence 75)
            }
            # DRIFT — SENS desired is High=85, but the tenant readback was HAND-EDITED to 75 =>
            # contentHash diverges. Still ours (provenance stamp) => must land in 'drift', not foreign.
            [pscustomobject]@{
                Name = $driftName; Identity = $driftName; Policy = 'P01-ECH-QGISCF-EXT-ADT'
                Priority = 2; Disabled = $false; AccessScope = 'NotInOrganization'; ReportSeverityLevel = 'Low'
                GenerateIncidentReport = $null; NotifyUser = $null; AdvancedRule = $null
                Comment = "SENSITIVE (1 classifiers)`n$stamp"
                ContentContainsSensitiveInformation = (New-ReadbackCcsi -SitId $sensSit -MinConfidence 75)
            }
            # ORPHAN — template-shaped ours rule (stamp) absent from the desired set.
            [pscustomobject]@{
                Name = 'P09-R09-ECH-OFFI-EXT-ADT'; Identity = 'P09-R09-ECH-OFFI-EXT-ADT'; Policy = 'P09-ECH-QGISCF-EXT-ADT'
                Priority = 1; Disabled = $false; AccessScope = 'NotInOrganization'; ReportSeverityLevel = 'Low'
                Comment = "OFFICIAL (1 classifiers)`n$stamp"
                ContentContainsSensitiveInformation = (New-ReadbackCcsi -SitId $offiSit -MinConfidence 75)
            }
            # FOREIGN — a Microsoft rule: no stamp, non-template name => ours=$false.
            [pscustomobject]@{
                Name = 'Default DLP rule'; Identity = 'Default DLP rule'; Policy = 'Default DLP policy'
                Priority = 0; Disabled = $false; AccessScope = $null; ReportSeverityLevel = $null
                Comment = 'Built-in Microsoft policy rule'
                ContentContainsSensitiveInformation = $null
            }
            # FOREIGN DEPLOYMENT — template-shaped name, real stamp, but prefix=CONTOSO (not QGISCF).
            # Ownership is prefix-scoped => ours=$false => must land in foreign, never actionable.
            [pscustomobject]@{
                Name = 'P05-R05-ECH-OFFI-EXT-ADT-CONTOSO'; Identity = 'P05-R05-ECH-OFFI-EXT-ADT-CONTOSO'; Policy = 'P05-ECH-CONTOSO-EXT-ADT'
                Priority = 5; Disabled = $false; AccessScope = 'NotInOrganization'; ReportSeverityLevel = 'Low'
                Comment = "OFFICIAL (1 classifiers)`n$contosoStamp"
                ContentContainsSensitiveInformation = (New-ReadbackCcsi -SitId $offiSit -MinConfidence 75)
            }
        )
    }

    # ---- DLP POLICIES (actual, via the real reader) -------------------------------------------
    # policy[0]: present, ours (stamp), SAME mode + locations, but its Comment is the RAW comment
    # WRAPPED WITH THE PROVENANCE STAMP (what Deploy writes) — its ONLY difference from desired.
    # codex review P2: this must NOT bucket as drift (the comment is provenance metadata, not content).
    # policy[1]: present, ours (stamp), DIFFERENT mode (Enable) => drift.
    $p0 = $desiredPolByName[$polNames[0]]
    $p1 = $desiredPolByName[$polNames[1]]
    $p0Comment = "$($p0.comment)`n$stamp"   # raw 'Exchange policy' + stamp — the deploy-time form
    $p1Comment = "$($p1.comment)`n$stamp"
    $p0Loc = if ($p0.locations.ContainsKey('ExchangeLocation')) { @($p0.locations['ExchangeLocation']) } else { @('All') }
    $p1Loc = if ($p1.locations.ContainsKey('OneDriveLocation')) { @($p1.locations['OneDriveLocation']) } else { @('All') }
    $polName0 = $polNames[0]; $polName1 = $polNames[1]
    $script:OrphanPolName  = 'P09-ECH-QGISCF-EXT-ADT'  # template-shaped ours policy, not desired
    $script:ForeignPolName = 'Default DLP policy'

    Mock -ModuleName Compl8.Tenant Get-DlpCompliancePolicy {
        @(
            # UNCHANGED-but-stamped-comment (P2 proof): same mode/locations, comment = raw + stamp.
            [pscustomobject]@{
                Name = $polName0; Identity = $polName0; Mode = 'TestWithoutNotifications'
                Comment = $p0Comment; ExchangeLocation = @($p0Loc)
            }
            # DRIFT: mode hand-edited to Enable (desired is TestWithoutNotifications).
            [pscustomobject]@{
                Name = $polName1; Identity = $polName1; Mode = 'Enable'
                Comment = $p1Comment; OneDriveLocation = @($p1Loc)
            }
            # ORPHAN: template-shaped ours policy (stamp) not in desired.
            [pscustomobject]@{
                Name = 'P09-ECH-QGISCF-EXT-ADT'; Identity = 'P09-ECH-QGISCF-EXT-ADT'; Mode = 'Enable'
                Comment = "Some policy`n$stamp"; ExchangeLocation = @('All')
            }
            # FOREIGN: no stamp, non-template name => ours=$false.
            [pscustomobject]@{
                Name = 'Default DLP policy'; Identity = 'Default DLP policy'; Mode = 'Enable'
                Comment = 'Built-in Microsoft policy'; ExchangeLocation = @('All')
            }
        )
    }

    # Build the ACTUAL inventory through the REAL reader => real ownership discriminator.
    $script:Inv = Get-TenantInventory -Prefix 'QGISCF' -GeneratedUtc '2026-06-13T00:00:00Z'
    $script:ActualDlpRules    = @($script:Inv.objects.dlpRules)
    $script:ActualDlpPolicies = @($script:Inv.objects.dlpPolicies)

    $script:Assessment = Invoke-Compl8Assess -WorkspacePath $script:Ws -Inventory $script:Inv `
        -ConfigRoot $script:ConfigDir -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'

    function Get-DR4Refs { param($Assessment, [string]$Bucket) @($Assessment.buckets.$Bucket | ForEach-Object { $_.ref }) }
    function Get-DR4Entry { param($Assessment, [string]$Bucket, [string]$Ref) @($Assessment.buckets.$Bucket | Where-Object { $_.ref -eq $Ref })[0] }
}

AfterAll {
    if ($script:Ws -and (Test-Path -LiteralPath $script:Ws)) {
        Remove-Item -LiteralPath $script:Ws -Recurse -Force -ErrorAction SilentlyContinue
    }
    foreach ($fn in 'Get-DlpKeywordDictionary', 'Get-DlpSensitiveInformationTypeRulePackage',
        'Get-DlpComplianceRule', 'Get-DlpCompliancePolicy', 'Get-Label', 'Get-LabelPolicy',
        'Get-AutoSensitivityLabelPolicy', 'Get-AutoSensitivityLabelRule', 'New-ReadbackCcsi') {
        Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-Compl8Assess — DR-4 module surface and ConfigRoot seam' {
    It 'exposes a -ConfigRoot parameter (the config-bridge seam)' {
        (Get-Command Invoke-Compl8Assess).Parameters.ContainsKey('ConfigRoot') | Should -BeTrue
    }

    It 'still produces a schema-valid assessment with the dlpRule buckets present' {
        $r = Test-AssessmentSchema -Assessment $script:Assessment
        $r.Valid | Should -BeTrue -Because (@($r.Errors) -join '; ')
    }
}

Describe 'Invoke-Compl8Assess — DR-4 dlpRule four-bucket logic' {
    It 'the actual ownership flows through the REAL provenance-stamp discriminator (codex review P1)' {
        # The deployed-and-edited drift rule is ours because the REAL Get-TenantInventory recognised
        # its provenance-stamped Comment — NOT because the fixture hand-set ours=$true. This is the
        # end-to-end proof of the P1 path: a stamped, template-named rule is ours (not foreign).
        $driftActual = @($script:ActualDlpRules | Where-Object { $_.name -eq $script:DriftRule.ruleName })[0]
        $driftActual.ours | Should -BeTrue -Because 'ownership came from the real stamp discriminator, not a hand-set flag'
        $foreignActual = @($script:ActualDlpRules | Where-Object { $_.name -eq $script:ForeignRuleName })[0]
        $foreignActual.ours | Should -BeFalse -Because 'no provenance stamp + non-template name => foreign'
    }

    It 'drift: an ours rule present in both whose content hash differs (the hand-edit signal)' {
        $entry = Get-DR4Entry $script:Assessment 'drift' $script:DriftRule.ruleName
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'dlpRule'
    }

    It 'no bucket: an unchanged ours rule (actual hash == desired hash) lands in NO bucket' {
        foreach ($bucket in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'foreign', 'drift') {
            Get-DR4Refs $script:Assessment $bucket | Should -Not -Contain $script:UnchangedRule.ruleName -Because "the unchanged rule must not appear in '$bucket'"
        }
    }

    It 'create: a desired rule with no actual rule' {
        # At least one desired rule name has no actual counterpart => create.
        $desiredNames = @($script:Desired.Rules | ForEach-Object { $_.ruleName })
        $actualNames  = @($script:ActualDlpRules | ForEach-Object { $_.name })
        $createNames  = @($desiredNames | Where-Object { $_ -notin $actualNames })
        $createNames.Count | Should -BeGreaterThan 0 -Because 'the fixture must leave a desired rule absent from actual'
        foreach ($cn in $createNames) {
            Get-DR4Refs $script:Assessment 'create' | Should -Contain $cn
            (Get-DR4Entry $script:Assessment 'create' $cn).objectType | Should -Be 'dlpRule'
        }
    }

    It 'orphan: an ours actual rule absent from the desired set' {
        $entry = Get-DR4Entry $script:Assessment 'orphan' $script:OrphanRuleName
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'dlpRule'
    }

    It 'foreign: a not-ours actual rule lands in foreign' {
        $entry = Get-DR4Entry $script:Assessment 'foreign' $script:ForeignRuleName
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'dlpRule'
    }

    It 'foreign is NEVER actionable for a dlpRule' {
        foreach ($actionable in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'drift') {
            Get-DR4Refs $script:Assessment $actionable | Should -Not -Contain $script:ForeignRuleName -Because "$($script:ForeignRuleName) is foreign and must never appear in '$actionable'"
        }
    }

    It 'a DIFFERENT-prefix-stamped rule is foreign and never actionable (prefix-scoping P1)' {
        # The CONTOSO-stamped rule resolves to another deployment's prefix. Ownership is prefix-scoped,
        # so the real reader marks it ours=$false; assess must bucket it foreign and never actionable —
        # otherwise assess/apply could target a DIFFERENT Compl8 deployment's object.
        $crossActual = @($script:ActualDlpRules | Where-Object { $_.name -eq $script:CrossPrefixRuleName })[0]
        $crossActual        | Should -Not -BeNullOrEmpty
        $crossActual.ours   | Should -BeFalse -Because 'a resolved stamp from a DIFFERENT prefix is a foreign deployment''s object'
        (Get-DR4Entry $script:Assessment 'foreign' $script:CrossPrefixRuleName) | Should -Not -BeNullOrEmpty -Because 'it must land in the foreign bucket'
        foreach ($actionable in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'drift') {
            Get-DR4Refs $script:Assessment $actionable | Should -Not -Contain $script:CrossPrefixRuleName -Because "a foreign-deployment rule must never appear in '$actionable'"
        }
    }
}

Describe 'Invoke-Compl8Assess — DR-4 dlpPolicy buckets' {
    It 'drift: an ours policy whose mode changed out-of-band, attributed to driftFields=mode (planner depth #3)' {
        $polNames = @($script:Desired.Policies | ForEach-Object { $_.policyName } | Sort-Object)
        $entry = Get-DR4Entry $script:Assessment 'drift' $polNames[1]
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'dlpPolicy'
        # policy[1] differs only in mode (Enable vs desired) — locations match. assess attributes the
        # drift per aspect so the planner can converge a mode change via update but flag a locations change
        # as needing a recreate.
        $entry.driftFields | Should -Contain 'mode'
        @($entry.driftFields) | Should -Not -Contain 'locations'
    }

    It 'no bucket: an unchanged ours policy lands in NO bucket' {
        $polNames = @($script:Desired.Policies | ForEach-Object { $_.policyName } | Sort-Object)
        foreach ($bucket in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'foreign', 'drift') {
            Get-DR4Refs $script:Assessment $bucket | Should -Not -Contain $polNames[0]
        }
    }

    It 'NOT drift: a deployed policy whose ONLY difference from desired is the provenance-stamped comment (codex review P2)' {
        # policy[0]'s actual Comment is the RAW desired comment WRAPPED WITH THE PROVENANCE STAMP (what
        # Deploy-DLPRules writes), while desired keeps the raw comment — same mode + locations otherwise.
        # Before the P2 fix the policy content hash folded in the comment, so this falsely reported
        # drift. The stamped-comment-only delta must NOT bucket as drift (the comment is provenance
        # metadata, not drift-relevant content).
        $polNames = @($script:Desired.Policies | ForEach-Object { $_.policyName } | Sort-Object)
        $actual0  = @($script:ActualDlpPolicies | Where-Object { $_.name -eq $polNames[0] })[0]
        $desired0 = @($script:Desired.Policies | Where-Object { $_.policyName -eq $polNames[0] })[0]
        $actual0.ours        | Should -BeTrue -Because 'the stamped policy is ours via the real discriminator'
        # The actual comment carries the provenance stamp (long-form prefix-bearing variant, per the
        # prefix-scoping fix); assert it carries a Compl8 provenance marker (short OR long form).
        $actual0.comment     | Should -Match '\[\[Compl8(:[0-9a-f]{16}|DLPDeploy:provenance:v\d+)' -Because 'the actual comment carries the provenance stamp'
        $actual0.comment     | Should -Not -Be $desired0.comment -Because 'the stamped actual comment differs from the raw desired comment'
        Get-DR4Refs $script:Assessment 'drift' | Should -Not -Contain $polNames[0] -Because 'a stamped-comment-only delta is not drift'
    }

    It 'orphan: an ours policy absent from the desired set' {
        $entry = Get-DR4Entry $script:Assessment 'orphan' $script:OrphanPolName
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'dlpPolicy'
    }

    It 'foreign: a not-ours policy, never actionable' {
        (Get-DR4Entry $script:Assessment 'foreign' $script:ForeignPolName) | Should -Not -BeNullOrEmpty
        foreach ($actionable in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'drift') {
            Get-DR4Refs $script:Assessment $actionable | Should -Not -Contain $script:ForeignPolName
        }
    }
}

Describe 'Invoke-Compl8Assess — DR-4 exactly-one bucket + determinism' {
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

Describe 'Invoke-Compl8Assess — DR-4 no config => no dlpRule buckets (back-compat)' {
    It 'emits no dlpRule/dlpPolicy buckets when ConfigRoot is absent and no workspace config exists' {
        # The existing SIT-only fixtures call assess with NO -ConfigRoot and no workspace config dir;
        # assess must not invent dlpRule buckets. Re-run WITHOUT -ConfigRoot against a config-free ws.
        $bareWs = Join-Path ([System.IO.Path]::GetTempPath()) ("dr4bare-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $bareWs 'desired' 'resolved') -Force | Out-Null
        $m = [ordered]@{ schemaVersion='compl8.resolve-manifest/v1'; generatedUtc='2026-06-13T00:00:00Z'; packing=[ordered]@{ assignments=[ordered]@{} }; packages=@(); warnings=@() }
        $m | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $bareWs 'desired' 'resolved' 'resolve-manifest.json') -Encoding UTF8
        try {
            $a = Invoke-Compl8Assess -WorkspacePath $bareWs -Inventory $script:Inv -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'
            foreach ($prop in $a.buckets.PSObject.Properties) {
                @($prop.Value | Where-Object { $_.objectType -in @('dlpRule', 'dlpPolicy') }).Count |
                    Should -Be 0 -Because "no config => no dlpRule/dlpPolicy buckets (bucket '$($prop.Name)')"
            }
        } finally {
            Remove-Item -LiteralPath $bareWs -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
