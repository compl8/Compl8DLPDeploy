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
    $script:UnchangedRule = $desiredRules[0]
    $script:DriftRule     = $desiredRules[1]

    $actualDlpRules = New-Object System.Collections.Generic.List[object]

    # UNCHANGED — same name, ours, contentHash == desired contentHash -> NO bucket.
    $actualDlpRules.Add([pscustomobject]@{
        name = $script:UnchangedRule.ruleName; identity = $script:UnchangedRule.ruleName
        ours = $true; policy = $script:UnchangedRule.policyName; priority = 0; disabled = $false
        contentContainsSensitiveInformation = 'unused-flat-text'
        contentHash = $script:UnchangedRule.contentHash
    }) | Out-Null

    # DRIFT — same name, ours, contentHash DIFFERS (a hand-edit in the tenant) -> drift.
    $actualDlpRules.Add([pscustomobject]@{
        name = $script:DriftRule.ruleName; identity = $script:DriftRule.ruleName
        ours = $true; policy = $script:DriftRule.policyName; priority = 0; disabled = $false
        contentContainsSensitiveInformation = 'unused-flat-text'
        contentHash = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
    }) | Out-Null

    # ORPHAN — an ours actual rule with a QGISCF-prefixed name that is NOT in the desired set.
    $script:OrphanRuleName = 'P09-R09-XXX-OFFI-EXT-ADT'
    $actualDlpRules.Add([pscustomobject]@{
        name = $script:OrphanRuleName; identity = $script:OrphanRuleName
        ours = $true; policy = 'P09-XXX-QGISCF-EXT-ADT'; priority = 0; disabled = $false
        contentContainsSensitiveInformation = 'unused'; contentHash = 'sha256:1111111111111111111111111111111111111111111111111111111111111111'
    }) | Out-Null

    # FOREIGN — a Microsoft rule (ours=false) that must NEVER appear in an actionable bucket.
    $script:ForeignRuleName = 'Default DLP rule'
    $actualDlpRules.Add([pscustomobject]@{
        name = $script:ForeignRuleName; identity = $script:ForeignRuleName
        ours = $false; policy = 'Default DLP policy'; priority = 0; disabled = $false
        contentContainsSensitiveInformation = 'unused'; contentHash = 'sha256:2222222222222222222222222222222222222222222222222222222222222222'
    }) | Out-Null

    # rules[2..] are NOT added to actual => they surface as CREATE (desired, no actual rule).
    $script:CreateRuleNames = @($desiredRules[2..($desiredRules.Count - 1)] | ForEach-Object { $_.ruleName })
    # Materialise to a PLAIN array — a List[object] inside a [pscustomobject]@{} cast trips
    # 'Argument types do not match' in PowerShell, and the inventory shape is a plain array anyway.
    $script:ActualDlpRules = @($actualDlpRules.ToArray())

    # ---- DLP POLICIES (actual) ----------------------------------------------------------------
    # Desired policies: P01-ECH-QGISCF-EXT-ADT, P02-ODB-QGISCF-EXT-ADT (mode TestWithoutNotifications).
    $desiredPolByName = @{}
    foreach ($p in $desiredPols) { $desiredPolByName[$p.policyName] = $p }
    $polNames = @($desiredPols | ForEach-Object { $_.policyName } | Sort-Object)

    $actualDlpPolicies = New-Object System.Collections.Generic.List[object]
    # policy[0]: present, ours, SAME mode -> NO bucket.
    $actualDlpPolicies.Add([pscustomobject]@{
        name = $polNames[0]; identity = $polNames[0]; ours = $true
        mode = $desiredPolByName[$polNames[0]].mode
        locations = $desiredPolByName[$polNames[0]].locations
        comment = $desiredPolByName[$polNames[0]].comment
    }) | Out-Null
    # policy[1]: present, ours, DIFFERENT mode (hand-edited) -> drift.
    $actualDlpPolicies.Add([pscustomobject]@{
        name = $polNames[1]; identity = $polNames[1]; ours = $true
        mode = 'Enable'   # desired is TestWithoutNotifications -> drift
        locations = $desiredPolByName[$polNames[1]].locations
        comment = $desiredPolByName[$polNames[1]].comment
    }) | Out-Null
    # ORPHAN policy — ours, not desired.
    $script:OrphanPolName = 'P09-XXX-QGISCF-EXT-ADT'
    $actualDlpPolicies.Add([pscustomobject]@{ name = $script:OrphanPolName; identity = $script:OrphanPolName; ours = $true; mode = 'Enable'; locations = [pscustomobject]@{}; comment = '' }) | Out-Null
    # FOREIGN policy.
    $script:ForeignPolName = 'Default DLP policy'
    $actualDlpPolicies.Add([pscustomobject]@{ name = $script:ForeignPolName; identity = $script:ForeignPolName; ours = $false; mode = 'Enable'; locations = [pscustomobject]@{}; comment = '' }) | Out-Null
    $script:ActualDlpPolicies = @($actualDlpPolicies.ToArray())

    # ---- inventory object (only the dlp record lists matter here) ------------------------------
    $invObjects = [pscustomobject]@{
        dictionaries = @(); sitPackages = @(); sits = @()
        dlpRules     = @($script:ActualDlpRules)
        dlpPolicies  = @($script:ActualDlpPolicies)
        labels = @(); labelPolicies = @(); autoLabelPolicies = @(); autoLabelRules = @()
    }
    $script:Inv = [pscustomobject]@{
        schemaVersion = 'compl8.inventory/v1'
        prefix        = 'QGISCF'
        generatedUtc  = '2026-06-13T00:00:00Z'
        tenant        = $null
        objects       = $invObjects
    }

    $script:Assessment = Invoke-Compl8Assess -WorkspacePath $script:Ws -Inventory $script:Inv `
        -ConfigRoot $script:ConfigDir -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'

    function Get-DR4Refs { param($Assessment, [string]$Bucket) @($Assessment.buckets.$Bucket | ForEach-Object { $_.ref }) }
    function Get-DR4Entry { param($Assessment, [string]$Bucket, [string]$Ref) @($Assessment.buckets.$Bucket | Where-Object { $_.ref -eq $Ref })[0] }
}

AfterAll {
    if ($script:Ws -and (Test-Path -LiteralPath $script:Ws)) {
        Remove-Item -LiteralPath $script:Ws -Recurse -Force -ErrorAction SilentlyContinue
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
}

Describe 'Invoke-Compl8Assess — DR-4 dlpPolicy buckets' {
    It 'drift: an ours policy whose mode changed out-of-band' {
        $polNames = @($script:Desired.Policies | ForEach-Object { $_.policyName } | Sort-Object)
        $entry = Get-DR4Entry $script:Assessment 'drift' $polNames[1]
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'dlpPolicy'
    }

    It 'no bucket: an unchanged ours policy lands in NO bucket' {
        $polNames = @($script:Desired.Policies | ForEach-Object { $_.policyName } | Sort-Object)
        foreach ($bucket in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'foreign', 'drift') {
            Get-DR4Refs $script:Assessment $bucket | Should -Not -Contain $polNames[0]
        }
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
