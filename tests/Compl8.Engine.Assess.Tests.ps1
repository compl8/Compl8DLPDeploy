#Requires -Modules Pester

# Compl8.Engine — Invoke-Compl8Assess: the read-only desired/actual reference-graph diff
# (Stage 4 PHASE 4A, Task 3). Every tenant object lands in exactly ONE of seven buckets:
# create / update-in-place / repack-move / remove / orphan / foreign / drift.
#
# Fixture (tests/fixtures/engine/assess/): the DESIRED side is a real Stage-3 resolve
# (Resolve-DesiredContent, -Prefix QGISCF) committed under desired/resolved/ plus its
# entity-ledger.json; the ACTUAL side is a hand-authored actual/inventory.json built to
# share the QGISCF namespace so the diff is meaningful and exercises all seven buckets.
# See the fixture README block at the foot of this file for the per-object bucket map.

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot   = Split-Path $PSScriptRoot -Parent
    $script:EngineDir  = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    # DLP-Deploy's facade dot-source can claim these function names; remove it so the
    # Compl8.Engine module attribution is clean (same pattern as the Tenant tests).
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:EngineDir -Force

    $script:FixtureRoot = Join-Path $script:RepoRoot 'tests' 'fixtures' 'engine' 'assess'
    $script:InventoryPath = Join-Path $script:FixtureRoot 'actual' 'inventory.json'
    $script:ExpectedRoot = Join-Path $script:RepoRoot 'tests' 'fixtures' 'engine' 'expected'

    # Helpers for navigating an assessment's buckets in assertions.
    function Get-BucketRefs {
        param($Assessment, [string]$Bucket)
        @($Assessment.buckets.$Bucket | ForEach-Object { $_.ref })
    }
    function Find-Entry {
        param($Assessment, [string]$Bucket, [string]$Ref)
        @($Assessment.buckets.$Bucket | Where-Object { $_.ref -eq $Ref })[0]
    }

    # Golden robustness: assess hashes the RAW BYTES of its input fixtures (inputs.inventory /
    # inputs.resolveManifest + the package XML), so the pinned golden is sensitive to the fixtures'
    # on-disk line endings. A fresh Windows clone (core.autocrlf=true) renders the LF-committed
    # fixtures as CRLF, changing those hashes. This returns a temp copy of a fixture tree with CR
    # bytes stripped from json/xml (byte-exact LF), so a golden run reads checkout-independent inputs
    # (the golden was pinned from LF). Caller deletes it.
    function New-LfFixtureRoot {
        param([Parameter(Mandatory)][string]$Src)
        $dest = Join-Path ([System.IO.Path]::GetTempPath()) ("lf-fixture-" + [guid]::NewGuid().ToString('N'))
        Copy-Item -LiteralPath $Src -Destination $dest -Recurse -Force
        foreach ($f in @(Get-ChildItem -LiteralPath $dest -Recurse -File | Where-Object { $_.Extension -in '.json', '.xml' })) {
            $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
            [System.IO.File]::WriteAllBytes($f.FullName, ($bytes -ne [byte]0x0D))
        }
        $dest
    }

    # Single assess run reused across the read-only assertions. The inventory is supplied
    # from the fixture (no live tenant call); workspace path points at the committed desired/.
    $script:Assessment = Invoke-Compl8Assess `
        -WorkspacePath $script:FixtureRoot `
        -InventoryPath $script:InventoryPath `
        -Workspace 'nonprod' `
        -GeneratedUtc '2026-06-13T00:00:00Z'
}

Describe 'Invoke-Compl8Assess — module surface' {
    It 'exports Invoke-Compl8Assess and Get-Compl8AssessmentReport from Compl8.Engine' {
        (Get-Command -Name Invoke-Compl8Assess -Module Compl8.Engine -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
        (Get-Command -Name Get-Compl8AssessmentReport -Module Compl8.Engine -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-Compl8Assess — assessment object shape' {
    It 'produces a compl8.assessment/v1 object that passes Test-AssessmentSchema' {
        $script:Assessment.schemaVersion | Should -Be 'compl8.assessment/v1'
        $script:Assessment.workspace     | Should -Be 'nonprod'
        $r = Test-AssessmentSchema -Assessment $script:Assessment
        $r.Valid | Should -BeTrue -Because (@($r.Errors) -join '; ')
    }

    It 'records the resolve-manifest and inventory input hashes' {
        $script:Assessment.inputs.resolveManifest | Should -Match '^sha256:'
        $script:Assessment.inputs.inventory       | Should -Match '^sha256:'
    }
}

Describe 'Invoke-Compl8Assess — seven-bucket placement' {
    It 'places every one of the seven buckets with at least one object' {
        foreach ($bucket in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'foreign', 'drift') {
            @($script:Assessment.buckets.$bucket).Count |
                Should -BeGreaterThan 0 -Because "bucket '$bucket' must have at least one fixture object"
        }
    }

    It 'assigns each object to exactly one bucket (the schema exactly-one invariant)' {
        $seen = @{}
        foreach ($prop in $script:Assessment.buckets.PSObject.Properties) {
            foreach ($entry in @($prop.Value)) {
                $key = "$($entry.objectType)|$($entry.ref)"
                $seen.ContainsKey($key) | Should -BeFalse -Because "$key appears in '$($prop.Name)' and '$($seen[$key])'"
                $seen[$key] = $prop.Name
            }
        }
    }

    It 'create: a desired dictionary and a desired sit absent from actual' {
        Get-BucketRefs $script:Assessment 'create' | Should -Contain '{{DICT_AU_FORENAMES}}'
        Get-BucketRefs $script:Assessment 'create' | Should -Contain 'custom-incident-ref'
    }

    It 'update-in-place: the rule package present in both, ours, with a changed sha256 (a refit)' {
        $entry = Find-Entry $script:Assessment 'update-in-place' 'QGISCF-test-01'
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'rulePackage'
    }

    It 'repack-move: a sit whose package assignment changed between actual and desired' {
        $entry = Find-Entry $script:Assessment 'repack-move' 'bail-note'
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'sit'
        $entry.from | Should -Be 'QGISCF-test-02'
        $entry.to   | Should -Be 'QGISCF-test-01'
    }

    It 'remove: a desired (ledger-disabled) removal of an actual ours object' {
        $entry = Find-Entry $script:Assessment 'remove' 'shared-b'
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'sit'
    }

    It 'orphan: an actual ours object with no desired record (not a planned removal)' {
        $entry = Find-Entry $script:Assessment 'orphan' 'QGISCF-orphan-keywords'
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'dictionary'
    }

    It 'drift: an actual ours object whose content changed out-of-band vs desired/resolved' {
        $entry = Find-Entry $script:Assessment 'drift' 'name-dict'
        $entry | Should -Not -BeNullOrEmpty
        $entry.objectType | Should -Be 'sit'
    }
}

Describe 'Invoke-Compl8Assess — foreign objects are never actionable (opacity-as-safety)' {
    It 'places the foreign Microsoft rule package in foreign' {
        Get-BucketRefs $script:Assessment 'foreign' | Should -Contain 'Microsoft Rule Package'
    }

    It 'never lists a foreign object in any actionable bucket' {
        foreach ($foreignRef in 'Microsoft Rule Package', 'Microsoft.SSN', 'Diseases') {
            foreach ($actionable in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'drift') {
                Get-BucketRefs $script:Assessment $actionable |
                    Should -Not -Contain $foreignRef -Because "$foreignRef is foreign and must NEVER appear in '$actionable'"
            }
        }
    }
}

Describe 'Invoke-Compl8Assess — upgrade conflicts and impact' {
    It 'carries the resolve-manifest override warning into upgradeConflicts' {
        @($script:Assessment.upgradeConflicts).Count | Should -BeGreaterThan 0
        $c = @($script:Assessment.upgradeConflicts | Where-Object { $_.slug -eq 'bail-note' })[0]
        $c | Should -Not -BeNullOrEmpty
        $c.kind | Should -Be 'override-base-changed'
    }

    It 'derives impact for a changed classifier from sitReferencedByRule edges' {
        $impact = @($script:Assessment.impact | Where-Object { $_.objectRef -eq 'name-dict' })[0]
        $impact | Should -Not -BeNullOrEmpty
        @($impact.affects) -join '; ' | Should -Match 'QGISCF-QLD-Medium-Email-07'
    }

    It 'does not raise impact for a foreign classifier' {
        @($script:Assessment.impact | Where-Object { $_.objectRef -eq 'Microsoft.SSN' }).Count | Should -Be 0
    }
}

Describe 'Invoke-Compl8Assess — determinism' {
    It 'produces byte-identical assessment JSON on repeated runs (same inputs)' {
        $a = Invoke-Compl8Assess -WorkspacePath $script:FixtureRoot -InventoryPath $script:InventoryPath `
            -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z' | ConvertTo-Json -Depth 12
        $b = Invoke-Compl8Assess -WorkspacePath $script:FixtureRoot -InventoryPath $script:InventoryPath `
            -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z' | ConvertTo-Json -Depth 12
        $a | Should -Be $b
    }
}

Describe 'Invoke-Compl8Assess — golden assessment' {
    It 'matches the pinned golden assessment JSON (line-ending insensitive)' {
        $goldenPath = Join-Path $script:ExpectedRoot 'assessment-nonprod.json'
        # Run against a CR-stripped (LF) copy of the fixtures so the embedded raw-byte input hashes are
        # checkout-independent (the golden was pinned from LF); compare with line endings normalised on
        # both sides (the engine's ConvertTo-Json emits platform newlines).
        $lfRoot = New-LfFixtureRoot -Src $script:FixtureRoot
        try {
            $actual = Invoke-Compl8Assess -WorkspacePath $lfRoot -InventoryPath (Join-Path $lfRoot 'actual' 'inventory.json') `
                -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z' | ConvertTo-Json -Depth 12
        } finally {
            if (Test-Path -LiteralPath $lfRoot) { Remove-Item -LiteralPath $lfRoot -Recurse -Force -ErrorAction SilentlyContinue }
        }

        if (-not (Test-Path -LiteralPath $goldenPath)) {
            # First green run records the golden file; thereafter it is asserted (LF-normalised).
            Set-Content -LiteralPath $goldenPath -Value $actual -Encoding UTF8 -NoNewline
        }
        $expected = Get-Content -LiteralPath $goldenPath -Raw
        ($actual -replace "`r`n", "`n") | Should -Be (($expected -replace "`r`n", "`n").TrimEnd("`n"))
    }
}

Describe 'Invoke-Compl8Assess — read-only contract' {
    It 'makes no mutating SCC cmdlet call (the inventory is supplied, never read live)' {
        # Every mutating SCC verb is stubbed and asserted untouched. The inventory comes from
        # a fixture path, so even the read cmdlets are not invoked.
        foreach ($fn in 'New-DlpKeywordDictionary', 'Set-DlpKeywordDictionary', 'Remove-DlpKeywordDictionary',
            'New-DlpSensitiveInformationTypeRulePackage', 'Set-DlpSensitiveInformationTypeRulePackage',
            'Remove-DlpSensitiveInformationTypeRulePackage', 'New-DlpComplianceRule', 'Set-DlpComplianceRule',
            'Remove-DlpComplianceRule', 'Get-DlpKeywordDictionary', 'Get-DlpSensitiveInformationTypeRulePackage') {
            Set-Item -Path "function:global:$fn" -Value { throw "MUTATION: $fn was called by assess" } -Force
        }
        try {
            { Invoke-Compl8Assess -WorkspacePath $script:FixtureRoot -InventoryPath $script:InventoryPath `
                -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z' } | Should -Not -Throw
        } finally {
            foreach ($fn in 'New-DlpKeywordDictionary', 'Set-DlpKeywordDictionary', 'Remove-DlpKeywordDictionary',
                'New-DlpSensitiveInformationTypeRulePackage', 'Set-DlpSensitiveInformationTypeRulePackage',
                'Remove-DlpSensitiveInformationTypeRulePackage', 'New-DlpComplianceRule', 'Set-DlpComplianceRule',
                'Remove-DlpComplianceRule', 'Get-DlpKeywordDictionary', 'Get-DlpSensitiveInformationTypeRulePackage') {
                Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe 'Get-Compl8AssessmentReport — human-readable render' {
    BeforeAll {
        $script:Report = Get-Compl8AssessmentReport -Assessment $script:Assessment
    }

    It 'returns a non-empty text render' {
        $script:Report | Should -Not -BeNullOrEmpty
    }

    It 'shows a count line for every bucket' {
        foreach ($bucket in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'foreign', 'drift') {
            $script:Report | Should -Match ([regex]::Escape($bucket))
        }
    }

    It 'calls out the foreign never-touch objects' {
        $script:Report | Should -Match 'never'
        $script:Report | Should -Match 'Microsoft Rule Package'
    }

    It 'calls out the upgrade conflicts' {
        $script:Report | Should -Match 'override-base-changed'
    }
}
