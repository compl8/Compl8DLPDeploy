#Requires -Modules Pester

# Task 5A-3 PART 1 — DLP-rule desired source re-points config -> desired/resolved (D7).
#
# Today Invoke-Compl8Assess sources desired DLP rules via Resolve-DesiredDlpRules -ConfigPath
# <ConfigRoot> (the Stage-4 config bridge). This re-point makes the workspace self-contained:
# the desired rule set is PERSISTED into <ws>/desired/resolved/dlp-rules.json (written by the
# Content resolver), and assess reads it from there, falling back to the config bridge only when
# the workspace file is absent (back-compat for the DR-4 fixtures).
#
# These tests prove:
#   (1) Resolve-DesiredContent -ConfigRoot writes desired/resolved/dlp-rules.json with each rule's
#       contentHash, and those hashes match Get-DlpRuleContentHash of the rule content.
#   (2) Assess READS that file (re-point): a rule present ONLY in dlp-rules.json surfaces as a
#       'create' bucket even though the -ConfigRoot config would NOT produce it.
#   (3) A config-only run (no dlp-rules.json) still works via the -ConfigRoot fallback.

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot   = Split-Path $PSScriptRoot -Parent
    $script:EngineDir  = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    $script:ContentDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Content'
    $script:ModelDir   = Join-Path $script:RepoRoot 'modules' 'Compl8.Model'
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:ModelDir -Force
    Import-Module $script:ContentDir -Force
    Import-Module $script:EngineDir -Force

    # Build a minimal but real config root (the same shape the DR-4 fixtures use).
    function New-RepointConfig {
        param([string]$Dir)
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        Set-Content -Path (Join-Path $Dir 'settings.json') -Value '{ "namingPrefix":"QGISCF","namingSuffix":"EXT-ADT","auditMode":true,"notifyUser":false,"generateIncidentReport":false,"sitPrefix":"QGISCF","publisher":"QGISCF","nameTemplates":{"dlpPolicy":"P{policyNumber}-{policyCode}-{prefix}-{suffix}","dlpRule":"P{policyNumber}-R{ruleNumber}{chunkLetter}-{policyCode}-{labelCode}-{suffix}"} }'
        Set-Content -Path (Join-Path $Dir 'labels.json')   -Value '[ { "code":"OFFI","name":"OFFICIAL","displayName":"OFFICIAL","isGroup":false }, { "code":"SENS","name":"SENSITIVE","displayName":"SENSITIVE","isGroup":false } ]'
        Set-Content -Path (Join-Path $Dir 'policies.json') -Value '[ { "number":1,"code":"ECH","comment":"Exchange policy","location":{"ExchangeLocation":"All"},"scopeParam":"AccessScope","scopeValue":"NotInOrganization","optional":false,"enabled":true } ]'
        Set-Content -Path (Join-Path $Dir 'classifiers.json') -Value '{ "OFFI":[ {"name":"All Full Names","id":"50b8b56b-4ef8-44c2-a924-03374f5831ce","confidenceLevel":"Medium","minCount":1,"maxCount":-1} ], "SENS":[ {"name":"Credit Card Number","id":"50842eb7-edc8-4019-85dd-5a5c1f2bb085","confidenceLevel":"High","minCount":1,"maxCount":-1} ] }'
        Set-Content -Path (Join-Path $Dir 'rule-overrides.json') -Value '{}'
    }

    # An empty-package resolve manifest so SIT/package/dictionary buckets are empty — this is only
    # about dlpRule bucketing from the persisted desired set.
    function Write-EmptyManifest {
        param([string]$ResolvedDir)
        New-Item -ItemType Directory -Path $ResolvedDir -Force | Out-Null
        $m = [ordered]@{ schemaVersion='compl8.resolve-manifest/v1'; generatedUtc='2026-06-13T00:00:00Z'; packing=[ordered]@{ assignments=[ordered]@{} }; packages=@(); warnings=@() }
        $m | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $ResolvedDir 'resolve-manifest.json') -Encoding UTF8
    }

    # A bare inventory with no DLP rules so 'create' buckets reflect the desired set directly.
    $script:EmptyInv = [pscustomobject]@{
        schemaVersion = 'compl8.inventory/v1'
        objects = [pscustomobject]@{
            sitPackages = @(); sits = @(); dictionaries = @()
            dlpRules = @(); dlpPolicies = @()
        }
    }
}

Describe 'PART 1 — Resolve-DesiredContent persists desired DLP rules into desired/resolved' {
    BeforeAll {
        $script:Ws = Join-Path $TestDrive 'ws-persist'
        New-Item -ItemType Directory -Path (Join-Path $script:Ws 'desired') -Force | Out-Null
        $fixtureRoot = Join-Path $PSScriptRoot 'fixtures' 'content'
        Copy-Item -LiteralPath (Join-Path $fixtureRoot 'mini-release') -Destination (Join-Path $script:Ws 'desired' 'release') -Recurse
        Copy-Item -LiteralPath (Join-Path $fixtureRoot 'mini-overlay') -Destination (Join-Path $script:Ws 'desired' 'overlay') -Recurse
        $script:ConfigDir = Join-Path $script:Ws 'config'
        New-RepointConfig -Dir $script:ConfigDir

        $script:Manifest = Resolve-DesiredContent -WorkspacePath $script:Ws -Prefix 'P' -Publisher 'Test Pub' -ConfigRoot $script:ConfigDir
        $script:DlpRulesPath = Join-Path $script:Ws 'desired' 'resolved' 'dlp-rules.json'
    }

    It 'writes desired/resolved/dlp-rules.json' {
        Test-Path -LiteralPath $script:DlpRulesPath | Should -BeTrue
    }

    It 'the persisted file carries a stable schemaVersion plus rules and policies' {
        $doc = Get-Content -LiteralPath $script:DlpRulesPath -Raw | ConvertFrom-Json
        $doc.schemaVersion | Should -Be 'compl8.dlp-rules/v1'
        @($doc.rules).Count   | Should -BeGreaterThan 0
        @($doc.policies).Count | Should -BeGreaterThan 0
    }

    It 'each persisted rule hash matches Get-DlpRuleContentHash of its content' {
        $doc = Get-Content -LiteralPath $script:DlpRulesPath -Raw | ConvertFrom-Json
        foreach ($rule in @($doc.rules)) {
            $params = @{}
            foreach ($p in $rule.content.PSObject.Properties) { $params[$p.Name] = $p.Value }
            $recomputed = Get-DlpRuleContentHash -DesiredParams $params
            $rule.contentHash | Should -Be $recomputed -Because "the persisted hash for $($rule.ruleName) must equal Get-DlpRuleContentHash"
        }
    }

    It 'does NOT write dlp-rules.json when no -ConfigRoot is supplied (back-compat)' {
        $ws2 = Join-Path $TestDrive 'ws-noconfig'
        New-Item -ItemType Directory -Path (Join-Path $ws2 'desired') -Force | Out-Null
        $fixtureRoot = Join-Path $PSScriptRoot 'fixtures' 'content'
        Copy-Item -LiteralPath (Join-Path $fixtureRoot 'mini-release') -Destination (Join-Path $ws2 'desired' 'release') -Recurse
        Copy-Item -LiteralPath (Join-Path $fixtureRoot 'mini-overlay') -Destination (Join-Path $ws2 'desired' 'overlay') -Recurse
        Resolve-DesiredContent -WorkspacePath $ws2 -Prefix 'P' -Publisher 'Test Pub' | Out-Null
        Test-Path -LiteralPath (Join-Path $ws2 'desired' 'resolved' 'dlp-rules.json') | Should -BeFalse
    }
}

Describe 'PART 1 — Invoke-Compl8Assess re-points to desired/resolved/dlp-rules.json' {
    It 'reads the desired rule set from the workspace file (a rule only in the file surfaces)' {
        $ws = Join-Path $TestDrive 'ws-read'
        $resolvedDir = Join-Path $ws 'desired' 'resolved'
        Write-EmptyManifest -ResolvedDir $resolvedDir

        # A desired rule set that exists ONLY in dlp-rules.json — NOT derivable from any config root.
        $onlyInFileRule = 'P01-R99-ZZZ-ONLYFILE-EXT-ADT'
        $ruleContent = [ordered]@{
            Name     = $onlyInFileRule
            Policy   = 'P01-ZZZ-QGISCF-EXT-ADT'
            Disabled = $false
            ContentContainsSensitiveInformation = @(
                [ordered]@{ operator = 'And'; groups = @([ordered]@{ operator = 'Or'; name = 'Default'; sensitivetypes = @([ordered]@{ name = 'x'; id = '50b8b56b-4ef8-44c2-a924-03374f5831ce'; mincount = 1; maxcount = -1; confidencelevel = 'High' }) }) }
            )
        }
        $hash = Get-DlpRuleContentHash -DesiredParams (@{} + $ruleContent)
        $doc = [ordered]@{
            schemaVersion = 'compl8.dlp-rules/v1'
            generatedUtc  = '2026-06-13T00:00:00Z'
            rules    = @([ordered]@{ ruleName = $onlyInFileRule; policyName = 'P01-ZZZ-QGISCF-EXT-ADT'; contentHash = $hash; content = $ruleContent })
            policies = @()
        }
        $doc | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $resolvedDir 'dlp-rules.json') -Encoding UTF8

        # Assess with NO -ConfigRoot. If it re-points to the file, the rule surfaces as 'create'
        # (desired, absent from the empty actual). If it ignored the file, no dlpRule bucket appears.
        $a = Invoke-Compl8Assess -WorkspacePath $ws -Inventory $script:EmptyInv -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'
        $createRefs = @($a.buckets.create | Where-Object { $_.objectType -eq 'dlpRule' } | ForEach-Object { $_.ref })
        $createRefs | Should -Contain $onlyInFileRule -Because 'assess must read the desired rule set from desired/resolved/dlp-rules.json'
    }

    It 'prefers the workspace file over -ConfigRoot when BOTH are present' {
        $ws = Join-Path $TestDrive 'ws-prefer'
        $resolvedDir = Join-Path $ws 'desired' 'resolved'
        Write-EmptyManifest -ResolvedDir $resolvedDir
        $cfg = Join-Path $ws 'cfg'
        New-RepointConfig -Dir $cfg   # would produce OFFI/SENS rules under P01-ECH

        $fileOnlyRule = 'P01-R99-ZZZ-ONLYFILE-EXT-ADT'
        $doc = [ordered]@{
            schemaVersion = 'compl8.dlp-rules/v1'
            rules    = @([ordered]@{ ruleName = $fileOnlyRule; policyName = 'P01-ZZZ-QGISCF-EXT-ADT'; contentHash = 'sha256:deadbeef'; content = [ordered]@{ Name = $fileOnlyRule; Disabled = $false } })
            policies = @()
        }
        $doc | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $resolvedDir 'dlp-rules.json') -Encoding UTF8

        $a = Invoke-Compl8Assess -WorkspacePath $ws -Inventory $script:EmptyInv -ConfigRoot $cfg -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'
        $createRefs = @($a.buckets.create | Where-Object { $_.objectType -eq 'dlpRule' } | ForEach-Object { $_.ref })
        $createRefs | Should -Contain $fileOnlyRule -Because 'the workspace file wins over the config bridge'
        # The config-derived rule names (P01-R01-ECH-OFFI-...) must NOT appear — the file was used, not config.
        ($createRefs | Where-Object { $_ -like 'P01-R01-ECH-OFFI-*' }) | Should -BeNullOrEmpty
    }

    It 'falls back to -ConfigRoot when no workspace dlp-rules.json exists (DR-4 back-compat)' {
        $ws = Join-Path $TestDrive 'ws-fallback'
        $resolvedDir = Join-Path $ws 'desired' 'resolved'
        Write-EmptyManifest -ResolvedDir $resolvedDir
        $cfg = Join-Path $ws 'cfg'
        New-RepointConfig -Dir $cfg

        $a = Invoke-Compl8Assess -WorkspacePath $ws -Inventory $script:EmptyInv -ConfigRoot $cfg -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'
        $createRefs = @($a.buckets.create | Where-Object { $_.objectType -eq 'dlpRule' } | ForEach-Object { $_.ref })
        # Config produces OFFI + SENS rules under policy P01-ECH.
        ($createRefs | Where-Object { $_ -like 'P01-R0*-ECH-*-EXT-ADT' }).Count | Should -BeGreaterThan 0 -Because 'the config bridge fallback must still resolve the desired set'
    }
}
