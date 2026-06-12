#Requires -Modules Pester

# Byte-parity harness: ConvertTo-RulePackageXml must reproduce the Python pipeline's
# output (testpattern purview-bundle API + optimise()) EXACTLY, byte for byte, from the
# per-slug fragments recorded by scripts/record-content-fixtures.py.
# Skipped cleanly when the recorded fixtures are absent (they require one network run).

BeforeDiscovery {
    $script:ParityRoot = Join-Path $PSScriptRoot 'fixtures' 'content' 'parity'
    $script:HasParityFixtures = Test-Path -LiteralPath (Join-Path $script:ParityRoot 'inputs.json')
}

BeforeAll {
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $script:RepoRoot 'modules' 'Compl8.Content') -Force
    $script:ParityRoot = Join-Path $PSScriptRoot 'fixtures' 'content' 'parity'
}

Describe 'Python-pipeline byte parity' -Skip:(-not $script:HasParityFixtures) {
    BeforeAll {
        $script:Inputs = Get-Content -LiteralPath (Join-Path $script:ParityRoot 'inputs.json') -Raw |
            ConvertFrom-Json
        $script:Fragments = foreach ($slug in $script:Inputs.slugs) {
            Get-Content -LiteralPath (Join-Path $script:ParityRoot 'fragments' "$slug.json") -Raw |
                ConvertFrom-Json
        }
        $script:Items = @(foreach ($fragment in $script:Fragments) {
            [pscustomobject]@{
                Slug        = $fragment.slug
                EntityId    = $fragment.entityId
                Sections    = [pscustomobject]@{
                    Entity     = $fragment.sections.entity
                    Regexes    = @($fragment.sections.regexes)
                    Keywords   = @($fragment.sections.keywords)
                    Filters    = @($fragment.sections.filters)
                    Validators = @($fragment.sections.validators)
                    Resources  = @($fragment.sections.resources)
                }
                AttrPatches = @{}
            }
        })
        # Identity ledger: parity content binds to its own fragment GUIDs.
        $script:IdentityLedger = [pscustomobject]@{
            Path    = '(in-memory)'
            Entries = @($script:Fragments | ForEach-Object {
                [pscustomobject]@{ slug = $_.slug; entityId = $_.entityId; state = 'active'; source = 'release' }
            })
        }
    }

    It 'composes byte-identically to the recorded pipeline output' {
        $composed = ConvertTo-RulePackageXml -Name $script:Inputs.package -Items $script:Items `
            -Ledger $script:IdentityLedger -Publisher $script:Inputs.publisher `
            -RulePackId $script:Inputs.rulePackId

        $goldenPath = Join-Path $script:ParityRoot 'golden' "$($script:Inputs.package).xml"
        $golden = [System.IO.File]::ReadAllBytes($goldenPath)

        if ($composed.Bytes.Length -ne $golden.Length -or
            (Compare-Object $composed.Bytes $golden -SyncWindow 0)) {
            # Debuggability: persist the actual output and report the first divergence.
            $actualPath = Join-Path $TestDrive 'parity-actual.xml'
            [System.IO.File]::WriteAllBytes($actualPath, $composed.Bytes)
            $limit = [Math]::Min($composed.Bytes.Length, $golden.Length)
            $firstDiff = -1
            for ($i = 0; $i -lt $limit; $i++) {
                if ($composed.Bytes[$i] -ne $golden[$i]) { $firstDiff = $i; break }
            }
            if ($firstDiff -lt 0) { $firstDiff = $limit }
            $context = [System.Text.Encoding]::UTF8.GetString(
                $golden[([Math]::Max(0, $firstDiff - 60))..([Math]::Min($golden.Length - 1, $firstDiff + 60))])
            throw ("Parity mismatch at byte $firstDiff (composed $($composed.Bytes.Length) vs golden $($golden.Length) bytes). " +
                "Golden context: ...$context... Actual output written to $actualPath")
        }
        $composed.Bytes.Length | Should -Be $golden.Length
        $composed.EntityCount | Should -Be $script:Inputs.entities
    }
}
