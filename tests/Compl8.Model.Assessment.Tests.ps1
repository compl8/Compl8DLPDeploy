#Requires -Modules Pester

BeforeAll {
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    $script:ModelDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Model'
    Import-Module $script:ModelDir -Force
}

Describe 'Get-Compl8EngineSchemaEnums' {
    It 'single-sources the seven assessment bucket names' {
        $enums = Get-Compl8EngineSchemaEnums
        @($enums.Buckets) | Should -Be @(
            'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'foreign', 'drift'
        )
    }

    It 'exposes the plan action, objectType and gate-type enums' {
        $enums = Get-Compl8EngineSchemaEnums
        @($enums.Actions) | Should -Contain 'create'
        @($enums.Actions) | Should -Contain 'dereference'
        @($enums.Actions) | Should -Contain 'snapshot'
        @($enums.ObjectTypes) | Should -Contain 'dictionary'
        @($enums.ObjectTypes) | Should -Contain 'autoLabelPolicy'
        @($enums.ObjectTypes) | Should -Contain 'tenant'
        @($enums.GateTypes) | Should -Contain 'propagation'
        @($enums.GateTypes) | Should -Contain 'externalRefs'
        @($enums.GateTypes) | Should -Contain 'snapshotBeforeDestroy'
    }
}

Describe 'New-AssessmentObject' {
    It 'returns a compl8.assessment/v1 object with all seven empty buckets' {
        $a = New-AssessmentObject -Workspace 'nonprod'
        $a.schemaVersion | Should -Be 'compl8.assessment/v1'
        $a.workspace | Should -Be 'nonprod'
        foreach ($bucket in 'create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'foreign', 'drift') {
            @($a.buckets.$bucket).Count | Should -Be 0
        }
        @($a.upgradeConflicts).Count | Should -Be 0
        @($a.impact).Count | Should -Be 0
    }

    It 'carries the generated UTC timestamp and input hashes' {
        $a = New-AssessmentObject -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z' `
            -ResolveManifestHash 'sha256:aaa' -InventoryHash 'sha256:bbb'
        $a.generatedUtc | Should -Be '2026-06-13T00:00:00Z'
        $a.inputs.resolveManifest | Should -Be 'sha256:aaa'
        $a.inputs.inventory | Should -Be 'sha256:bbb'
    }

    It 'is round-trippable: the constructed object passes Test-AssessmentSchema' {
        $a = New-AssessmentObject -Workspace 'nonprod'
        (Test-AssessmentSchema -Assessment $a).Valid | Should -BeTrue
    }
}

Describe 'Test-AssessmentSchema' {
    BeforeEach {
        $script:Good = New-AssessmentObject -Workspace 'nonprod'
        $script:Good.buckets.create = @(
            [pscustomobject]@{ objectType = 'rulePackage'; ref = 'QGISCF-medium-09'; reason = 'desired, absent' }
        )
    }

    It 'accepts a well-formed assessment' {
        $r = Test-AssessmentSchema -Assessment $script:Good
        $r.Valid | Should -BeTrue
        @($r.Errors).Count | Should -Be 0
    }

    It 'rejects a bad schemaVersion' {
        $script:Good.schemaVersion = 'compl8.assessment/v999'
        $r = Test-AssessmentSchema -Assessment $script:Good
        $r.Valid | Should -BeFalse
        @($r.Errors) -join '; ' | Should -Match 'schemaVersion'
    }

    It 'rejects an object appearing in two buckets (the exactly-one invariant)' {
        $script:Good.buckets.orphan = @(
            [pscustomobject]@{ objectType = 'rulePackage'; ref = 'QGISCF-medium-09'; reason = 'also here' }
        )
        $r = Test-AssessmentSchema -Assessment $script:Good
        $r.Valid | Should -BeFalse
        @($r.Errors) -join '; ' | Should -Match 'QGISCF-medium-09'
    }

    It 'rejects an unknown objectType' {
        $script:Good.buckets.create[0].objectType = 'wormhole'
        $r = Test-AssessmentSchema -Assessment $script:Good
        $r.Valid | Should -BeFalse
        @($r.Errors) -join '; ' | Should -Match 'wormhole'
    }

    It 'rejects an unknown bucket name' {
        $script:Good.buckets | Add-Member -NotePropertyName 'teleport' -NotePropertyValue @(
            [pscustomobject]@{ objectType = 'sit'; ref = 'x'; reason = 'y' }
        )
        $r = Test-AssessmentSchema -Assessment $script:Good
        $r.Valid | Should -BeFalse
        @($r.Errors) -join '; ' | Should -Match 'teleport'
    }

    It 'rejects an assessment that omits a required bucket (total-partition contract)' {
        # Rebuild the buckets object without 'foreign' — an incomplete partition must fail,
        # not silently pass (codex 4A P2).
        $partial = [ordered]@{}
        foreach ($b in (Get-Compl8EngineSchemaEnums).Buckets) {
            if ($b -ne 'foreign') { $partial[$b] = @() }
        }
        $script:Good.buckets = [pscustomobject]$partial
        $r = Test-AssessmentSchema -Assessment $script:Good
        $r.Valid | Should -BeFalse
        @($r.Errors) -join '; ' | Should -Match "missing the required 'foreign' bucket"
    }
}
