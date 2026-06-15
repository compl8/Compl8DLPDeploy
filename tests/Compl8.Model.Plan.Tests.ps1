#Requires -Modules Pester

BeforeAll {
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    $script:ModelDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Model'
    Import-Module $script:ModelDir -Force
}

Describe 'New-PlanObject' {
    It 'returns a compl8.plan/v1 object with no steps and graph-derived ordering' {
        $p = New-PlanObject -Workspace 'nonprod' -Id 'plan-20260613-test'
        $p.schemaVersion | Should -Be 'compl8.plan/v1'
        $p.id | Should -Be 'plan-20260613-test'
        $p.workspace | Should -Be 'nonprod'
        @($p.steps).Count | Should -Be 0
        $p.ordering | Should -Be 'graph-derived'
        @($p.warnings).Count | Should -Be 0
    }

    It 'carries the input hashes including the assessment hash' {
        $p = New-PlanObject -Workspace 'nonprod' -Id 'plan-x' `
            -ResolveManifestHash 'sha256:aaa' -InventoryHash 'sha256:bbb' -AssessmentHash 'sha256:ccc'
        $p.inputs.resolveManifest | Should -Be 'sha256:aaa'
        $p.inputs.inventory | Should -Be 'sha256:bbb'
        $p.inputs.assessment | Should -Be 'sha256:ccc'
    }
}

Describe 'Add-PlanStep' {
    It 'appends a step with defaults for dependsOn/impact/gate' {
        $p = New-PlanObject -Workspace 'nonprod' -Id 'plan-x'
        $p = Add-PlanStep -Plan $p -Id 's01' -Action 'create' -ObjectType 'dictionary' -ObjectRef '{{DICT_X}}'
        @($p.steps).Count | Should -Be 1
        $step = $p.steps[0]
        $step.id | Should -Be 's01'
        $step.action | Should -Be 'create'
        $step.objectType | Should -Be 'dictionary'
        $step.objectRef | Should -Be '{{DICT_X}}'
        @($step.dependsOn).Count | Should -Be 0
        @($step.impact).Count | Should -Be 0
        $step.gate | Should -Be $null
    }

    It 'records dependsOn, impact and a gate object when provided' {
        $p = New-PlanObject -Workspace 'nonprod' -Id 'plan-x'
        $p = Add-PlanStep -Plan $p -Id 's01' -Action 'create' -ObjectType 'dictionary' -ObjectRef '{{DICT_X}}'
        $p = Add-PlanStep -Plan $p -Id 's04' -Action 'update' -ObjectType 'rulePackage' `
            -ObjectRef 'QGISCF-medium-03' -DependsOn 's01' -Impact 'dlp-rule: QLD-Medium-Email-07' `
            -Gate ([pscustomobject]@{ type = 'propagation'; notBeforeOffsetHours = 4 })
        @($p.steps).Count | Should -Be 2
        $step = $p.steps[1]
        @($step.dependsOn) | Should -Be @('s01')
        @($step.impact) | Should -Be @('dlp-rule: QLD-Medium-Email-07')
        $step.gate.type | Should -Be 'propagation'
        $step.gate.notBeforeOffsetHours | Should -Be 4
    }

    It 'rejects a duplicate step id' {
        $p = New-PlanObject -Workspace 'nonprod' -Id 'plan-x'
        $p = Add-PlanStep -Plan $p -Id 's01' -Action 'create' -ObjectType 'dictionary' -ObjectRef 'a'
        { Add-PlanStep -Plan $p -Id 's01' -Action 'create' -ObjectType 'dictionary' -ObjectRef 'b' } |
            Should -Throw '*s01*'
    }

    It 'builds a plan that passes Test-PlanSchema' {
        $p = New-PlanObject -Workspace 'nonprod' -Id 'plan-x'
        $p = Add-PlanStep -Plan $p -Id 's01' -Action 'create' -ObjectType 'dictionary' -ObjectRef '{{DICT_X}}'
        $p = Add-PlanStep -Plan $p -Id 's04' -Action 'update' -ObjectType 'rulePackage' `
            -ObjectRef 'QGISCF-medium-03' -DependsOn 's01' `
            -Gate ([pscustomobject]@{ type = 'propagation'; notBeforeOffsetHours = 4 })
        (Test-PlanSchema -Plan $p).Valid | Should -BeTrue
    }
}

Describe 'Test-PlanSchema' {
    BeforeEach {
        $p = New-PlanObject -Workspace 'nonprod' -Id 'plan-x'
        $p = Add-PlanStep -Plan $p -Id 's01' -Action 'create' -ObjectType 'dictionary' -ObjectRef '{{DICT_X}}'
        $p = Add-PlanStep -Plan $p -Id 's04' -Action 'update' -ObjectType 'rulePackage' `
            -ObjectRef 'QGISCF-medium-03' -DependsOn 's01'
        $script:Good = $p
    }

    It 'accepts a well-formed plan' {
        $r = Test-PlanSchema -Plan $script:Good
        $r.Valid | Should -BeTrue
        @($r.Errors).Count | Should -Be 0
    }

    It 'rejects a bad schemaVersion' {
        $script:Good.schemaVersion = 'compl8.plan/v999'
        $r = Test-PlanSchema -Plan $script:Good
        $r.Valid | Should -BeFalse
        @($r.Errors) -join '; ' | Should -Match 'schemaVersion'
    }

    It 'rejects a step whose dependsOn names a missing step id' {
        $script:Good.steps[1].dependsOn = @('s99')
        $r = Test-PlanSchema -Plan $script:Good
        $r.Valid | Should -BeFalse
        @($r.Errors) -join '; ' | Should -Match 's99'
    }

    It 'rejects an unknown action' {
        $script:Good.steps[0].action = 'detonate'
        $r = Test-PlanSchema -Plan $script:Good
        $r.Valid | Should -BeFalse
        @($r.Errors) -join '; ' | Should -Match 'detonate'
    }

    It 'rejects an unknown objectType' {
        $script:Good.steps[0].objectType = 'wormhole'
        $r = Test-PlanSchema -Plan $script:Good
        $r.Valid | Should -BeFalse
        @($r.Errors) -join '; ' | Should -Match 'wormhole'
    }

    It 'rejects an unknown gate.type' {
        $script:Good.steps[1].gate = [pscustomobject]@{ type = 'forcefield' }
        $r = Test-PlanSchema -Plan $script:Good
        $r.Valid | Should -BeFalse
        @($r.Errors) -join '; ' | Should -Match 'forcefield'
    }

    It 'rejects a duplicate step id' {
        $script:Good.steps[1].id = 's01'
        $r = Test-PlanSchema -Plan $script:Good
        $r.Valid | Should -BeFalse
        @($r.Errors) -join '; ' | Should -Match 's01'
    }
}
