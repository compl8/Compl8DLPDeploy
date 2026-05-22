#Requires -Modules Pester

BeforeAll {
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    $script:DriftScript = Join-Path $script:RepoRoot 'scripts' 'Test-TestPatternDrift.ps1'
    $script:FixtureRoot = Join-Path $script:RepoRoot 'tests/fixtures/testpattern'

    function Invoke-TestPatternDriftScript {
        param([hashtable]$Parameters = @{})

        $splat = @{
            ProjectRoot = $script:RepoRoot
            NoExit = $true
        }
        foreach ($key in $Parameters.Keys) {
            $splat[$key] = $Parameters[$key]
        }

        $result = @(& $script:DriftScript @splat)
        return $result[-1]
    }
}

Describe 'Test-TestPatternDrift.ps1' {
    BeforeEach {
        $script:TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:FixtureRoot 'patterns.json') -Destination (Join-Path $script:TempRoot 'patterns.json')
        Copy-Item -LiteralPath (Join-Path $script:FixtureRoot 'dictionary-manifest.json') -Destination (Join-Path $script:TempRoot 'dictionary-manifest.json')
        Copy-Item -LiteralPath (Join-Path $script:FixtureRoot 'purview-bundle.xml') -Destination (Join-Path $script:TempRoot 'purview-bundle.xml')
    }

    AfterEach {
        Remove-Item -LiteralPath $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'passes with the checked-in offline fixtures' {
        Invoke-TestPatternDriftScript | Should -BeTrue
    }

    It 'fails when the pattern catalogue shape loses slugs' {
        '{"patterns":[{"name":"Missing Slug"}]}' |
            Set-Content -LiteralPath (Join-Path $script:TempRoot 'patterns.json') -Encoding UTF8

        Invoke-TestPatternDriftScript -Parameters @{
            PatternsFixturePath = Join-Path $script:TempRoot 'patterns.json'
            DictionaryManifestFixturePath = Join-Path $script:TempRoot 'dictionary-manifest.json'
            BundleFixturePath = Join-Path $script:TempRoot 'purview-bundle.xml'
        } | Should -BeFalse
    }

    It 'fails when dictionaries=true bundle output loses dictionary placeholders' {
        $xml = Get-Content -Raw -LiteralPath (Join-Path $script:TempRoot 'purview-bundle.xml')
        $xml = $xml -replace '\{\{DICT_NOISE_EXCLUSION\}\}', 'Pattern_local_keyword'
        $xml | Set-Content -LiteralPath (Join-Path $script:TempRoot 'purview-bundle.xml') -Encoding UTF8

        Invoke-TestPatternDriftScript -Parameters @{
            PatternsFixturePath = Join-Path $script:TempRoot 'patterns.json'
            DictionaryManifestFixturePath = Join-Path $script:TempRoot 'dictionary-manifest.json'
            BundleFixturePath = Join-Path $script:TempRoot 'purview-bundle.xml'
        } | Should -BeFalse
    }

    It 'fails when the dictionary manifest shape loses DICT placeholders' {
        '{"dictionaries":[{"placeholder":"NOISE","name":"Noise","terms":["x"]}]}' |
            Set-Content -LiteralPath (Join-Path $script:TempRoot 'dictionary-manifest.json') -Encoding UTF8

        Invoke-TestPatternDriftScript -Parameters @{
            PatternsFixturePath = Join-Path $script:TempRoot 'patterns.json'
            DictionaryManifestFixturePath = Join-Path $script:TempRoot 'dictionary-manifest.json'
            BundleFixturePath = Join-Path $script:TempRoot 'purview-bundle.xml'
        } | Should -BeFalse
    }

    It 'can promote drift warnings to failures for interactive checks' {
        '{"dictionaries":[{"placeholder":"{{DICT_NOISE_EXCLUSION}}","name":"Noise","terms":[]}]}' |
            Set-Content -LiteralPath (Join-Path $script:TempRoot 'dictionary-manifest.json') -Encoding UTF8

        Invoke-TestPatternDriftScript -Parameters @{
            PatternsFixturePath = Join-Path $script:TempRoot 'patterns.json'
            DictionaryManifestFixturePath = Join-Path $script:TempRoot 'dictionary-manifest.json'
            BundleFixturePath = Join-Path $script:TempRoot 'purview-bundle.xml'
            FailOnWarnings = $true
        } | Should -BeFalse
    }
}
