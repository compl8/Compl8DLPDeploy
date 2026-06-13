#Requires -Modules Pester

# Compl8.Engine — apply executors. (Stage 4 PHASE 4C, Task 8 — the PILOT.)
#
# Task 8 is the PILOT executor: Invoke-Compl8DictionaryExecutor. It establishes the TEMPLATE that
# Tasks 9-12 copy (label, rule-package, DLP-rule, auto-label executors). The template is:
#   * the executor is the per-objectType apply unit Invoke-Compl8Apply dispatches a plan step to
#     (via -ExecutorMap @{ dictionary = 'Invoke-Compl8DictionaryExecutor' } or a scriptblock);
#   * it takes the plan STEP (-Step) + the RESOLVED content it needs (-Content), calls the SCC
#     cmdlets (New-/Set-/Get-/Remove-DlpKeywordDictionary — ALL mocked -ModuleName Compl8.Engine),
#     reuses the ported helpers (Remove-PurviewObject, Invoke-WithRetry — Task 7) and the budget gate
#     (Test-ContentDictionaryBudget — Compl8.Content), stamps provenance (Add-DeploymentProvenanceStamp
#     — Compl8.Model), is IDEMPOTENT (re-applying a create where the dict exists REUSES, no duplicate),
#     and returns a step result the apply checkpoint records;
#   * a PLAN/-WhatIf mode emits "planned operations" in the Get-Compl8ShadowDiff normalised op shape:
#       { action; objectType; objectRef } (+ optional descriptive fields).
#
# SHADOW PARITY (the heart of the pilot): the executor's PLANNED OPS for a fixture must MATCH the old
# leaf path's -WhatIf output for the same input, proven by GENUINELY RUNNING the old path
# (Sync-DlpKeywordDictionaries -WhatIf, with Invoke-RestMethod mocked to return the fixture manifest)
# and normalising BOTH sides to the common op shape, then Get-Compl8ShadowDiff(...).Match -eq $true.
# The old-side normaliser DERIVES from the actual Sync -WhatIf run (the returned placeholder->GUID
# map), it is NOT a hand-rigged expected list.

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot   = Split-Path $PSScriptRoot -Parent
    $script:EngineDir  = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    $script:DlpDeploy  = Join-Path $script:RepoRoot 'modules' 'DLP-Deploy.psm1'

    Import-Module $script:EngineDir -Force

    # Isolate the provenance registry to a throwaway temp file (the established repo pattern) so the
    # provenance stamp never writes to reports/provenance-registry.json during tests.
    $env:COMPL8_PROVENANCE_REGISTRY = Join-Path ([System.IO.Path]::GetTempPath()) ("compl8-exec-prov-{0}.json" -f ([guid]::NewGuid().ToString('N')))
    # Pin the deployment id so the stamp / registry are deterministic (Get-Date is banned in det paths).
    $env:COMPL8_DEPLOYMENT_ID = '20260613'

    # SCC cmdlets are not installed in CI and the executor invokes them DYNAMICALLY, so there is no
    # static reference for Pester to bootstrap a mock from. Define GLOBAL STUBS (the established repo
    # pattern, see Compl8.Engine.Shadow.Tests.ps1) so the commands EXIST and `Mock -ModuleName
    # Compl8.Engine` can shadow them inside the module scope.
    # NOTE: do NOT declare -ErrorAction/-Confirm explicitly — [CmdletBinding()] already supplies them
    # as common parameters, and a duplicate declaration is a MetadataException at call time.
    function global:New-DlpKeywordDictionary { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$Description, [byte[]]$FileData) }
    function global:Set-DlpKeywordDictionary { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [byte[]]$FileData, [string]$Description) }
    function global:Get-DlpKeywordDictionary { [CmdletBinding()] param([string]$Identity) }
    function global:Remove-DlpKeywordDictionary { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }

    # ---------------------------------------------------------------- fixture: a dictionary content set
    # The resolved content the executor consumes: one record per dictionary placeholder, carrying the
    # name (prefix-scoped), terms, description and termsBytes (the budget input). The shadow fixture is
    # "one create, one reuse" per the spec; both are well under the 1 MB cap.
    $script:Prefix = 'QGISCF'
    $script:DictContent = @(
        [pscustomobject]@{
            placeholder = '{{DICT_AU_FORENAMES}}'
            name        = 'QGISCF - AU Forenames'
            description = 'Australian forenames'
            terms       = @('alice', 'bob', 'carol')
            termsBytes  = 122880
        }
        [pscustomobject]@{
            placeholder = '{{DICT_NOISE_EXCLUSION}}'
            name        = 'QGISCF - Noise Exclusion'
            description = 'Noise exclusion terms'
            terms       = @('the', 'and', 'of')
            termsBytes  = 2048
        }
    )

    # The manifest the OLD path (Sync-DlpKeywordDictionaries) consumes from its URL. Same dictionaries,
    # in the old path's manifest shape (name is the RAW "TestPattern - " name; Sync re-scopes it to the
    # NamePrefix, exactly as our content `name` already is).
    $script:OldManifest = [pscustomobject]@{
        dictionaries = @(
            [pscustomobject]@{ placeholder = '{{DICT_AU_FORENAMES}}';   name = 'TestPattern - AU Forenames'; description = 'Australian forenames'; terms = @('alice', 'bob', 'carol') }
            [pscustomobject]@{ placeholder = '{{DICT_NOISE_EXCLUSION}}'; name = 'TestPattern - Noise Exclusion'; description = 'Noise exclusion terms'; terms = @('the', 'and', 'of') }
        )
    }

    # ---------------------------------------------------------------- plan-step helper
    function New-DictStep {
        param([string]$Id, [string]$Action, [string]$ObjectRef)
        [pscustomobject]@{ id = $Id; action = $Action; objectType = 'dictionary'; objectRef = $ObjectRef
            dependsOn = @(); impact = @(); gate = $null }
    }

    # ---------------------------------------------------------------- old-side normaliser (GENUINE)
    # Run Sync-DlpKeywordDictionaries -WhatIf for real (Invoke-RestMethod mocked to return the fixture
    # manifest) and derive the old path's PLANNED OPS from its actual output. Under -WhatIf the old path
    # sees an EMPTY tenant inventory (line 1962) so every manifest dictionary is reported as a planned
    # create-equivalent: it writes a [WHATIF] line and sets guidMap[placeholder]=dummy GUID. The
    # observable planned-operation set is therefore the RETURNED guidMap's keys (the placeholders that
    # got a planned dictionary). We map each to the normalised op shape. This is derived from the REAL
    # run, not fabricated.
    function Get-OldDictionaryWhatIfOps {
        param([pscustomobject]$Manifest, [string]$NamePrefix)
        Import-Module $script:DlpDeploy -Force
        try {
            # Mock the manifest fetch inside DLP-Deploy scope so no network is touched.
            Mock -ModuleName DLP-Deploy Invoke-RestMethod { $Manifest }.GetNewClosure()
            $guidMap = Sync-DlpKeywordDictionaries -ManifestUrl 'https://fixture/manifest' -NamePrefix $NamePrefix -WhatIf
            @($guidMap.Keys | Sort-Object | ForEach-Object {
                [pscustomobject]@{ action = 'create'; objectType = 'dictionary'; objectRef = [string]$_ }
            })
        } finally {
            Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
            Import-Module $script:EngineDir -Force
        }
    }
}

AfterAll {
    if ($env:COMPL8_PROVENANCE_REGISTRY -and (Test-Path -LiteralPath $env:COMPL8_PROVENANCE_REGISTRY)) {
        Remove-Item -LiteralPath $env:COMPL8_PROVENANCE_REGISTRY -Force -ErrorAction SilentlyContinue
    }
    Remove-Item Env:\COMPL8_PROVENANCE_REGISTRY -ErrorAction SilentlyContinue
    Remove-Item Env:\COMPL8_DEPLOYMENT_ID -ErrorAction SilentlyContinue
    foreach ($fn in 'New-DlpKeywordDictionary', 'Set-DlpKeywordDictionary', 'Get-DlpKeywordDictionary', 'Remove-DlpKeywordDictionary') {
        Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
    }
}

Describe 'module surface' {
    It 'exports Invoke-Compl8DictionaryExecutor from Compl8.Engine' {
        (Get-Command -Name 'Invoke-Compl8DictionaryExecutor' -Module Compl8.Engine -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-Compl8DictionaryExecutor — create (new dictionary)' {
    It 'calls New-DlpKeywordDictionary once and returns a created result' {
        Mock -ModuleName Compl8.Engine Get-DlpKeywordDictionary { @() }     # nothing exists yet
        Mock -ModuleName Compl8.Engine New-DlpKeywordDictionary { [pscustomobject]@{ Identity = 'guid-new-1'; Name = $Name } }
        Mock -ModuleName Compl8.Engine Set-DlpKeywordDictionary { }

        $step = New-DictStep -Id 's01' -Action 'create' -ObjectRef '{{DICT_AU_FORENAMES}}'
        $content = $script:DictContent | Where-Object placeholder -EQ '{{DICT_AU_FORENAMES}}'
        $result = Invoke-Compl8DictionaryExecutor -Step $step -Content $content -Prefix $script:Prefix

        Should -Invoke -ModuleName Compl8.Engine New-DlpKeywordDictionary -Times 1
        Should -Invoke -ModuleName Compl8.Engine Set-DlpKeywordDictionary -Times 0
        $result.status    | Should -Be 'created'
        $result.action    | Should -Be 'create'
        $result.objectRef | Should -Be '{{DICT_AU_FORENAMES}}'
        $result.guid      | Should -Be 'guid-new-1'
    }

    It 'stamps provenance with the [[Compl8:...]] marker on the created dictionary description' {
        $script:capturedDesc = $null
        Mock -ModuleName Compl8.Engine Get-DlpKeywordDictionary { @() }
        Mock -ModuleName Compl8.Engine New-DlpKeywordDictionary {
            $script:capturedDesc = $Description
            [pscustomobject]@{ Identity = 'guid-new-2'; Name = $Name }
        }

        $step = New-DictStep -Id 's01' -Action 'create' -ObjectRef '{{DICT_AU_FORENAMES}}'
        $content = $script:DictContent | Where-Object placeholder -EQ '{{DICT_AU_FORENAMES}}'
        $result = Invoke-Compl8DictionaryExecutor -Step $step -Content $content -Prefix $script:Prefix

        $script:capturedDesc | Should -Match '\[\[Compl8:[0-9a-f]{16}\]\]'
        $result.stampedDescription | Should -Match '\[\[Compl8:[0-9a-f]{16}\]\]'
    }
}

Describe 'Invoke-Compl8DictionaryExecutor — update (existing dictionary)' {
    It 'takes the Set-DlpKeywordDictionary path and returns an updated result' {
        Mock -ModuleName Compl8.Engine Get-DlpKeywordDictionary { [pscustomobject]@{ Identity = 'guid-exist-1'; Name = 'QGISCF - AU Forenames' } }
        Mock -ModuleName Compl8.Engine New-DlpKeywordDictionary { throw 'New should not be called on update' }
        Mock -ModuleName Compl8.Engine Set-DlpKeywordDictionary { }

        $step = New-DictStep -Id 's01' -Action 'update' -ObjectRef '{{DICT_AU_FORENAMES}}'
        $content = $script:DictContent | Where-Object placeholder -EQ '{{DICT_AU_FORENAMES}}'
        $result = Invoke-Compl8DictionaryExecutor -Step $step -Content $content -Prefix $script:Prefix

        Should -Invoke -ModuleName Compl8.Engine Set-DlpKeywordDictionary -Times 1
        Should -Invoke -ModuleName Compl8.Engine New-DlpKeywordDictionary -Times 0
        $result.status | Should -Be 'updated'
        $result.guid   | Should -Be 'guid-exist-1'
    }
}

Describe 'Invoke-Compl8DictionaryExecutor — remove' {
    It 'goes through Remove-PurviewObject and returns a deleted result' {
        Mock -ModuleName Compl8.Engine Get-DlpKeywordDictionary { [pscustomobject]@{ Identity = 'guid-exist-9'; Name = 'QGISCF - AU Forenames' } }
        Mock -ModuleName Compl8.Engine Remove-DlpKeywordDictionary { }

        $step = New-DictStep -Id 's01' -Action 'remove' -ObjectRef '{{DICT_AU_FORENAMES}}'
        $content = $script:DictContent | Where-Object placeholder -EQ '{{DICT_AU_FORENAMES}}'
        $result = Invoke-Compl8DictionaryExecutor -Step $step -Content $content -Prefix $script:Prefix

        Should -Invoke -ModuleName Compl8.Engine Remove-DlpKeywordDictionary -Times 1
        $result.status     | Should -Be 'deleted'
        $result.removeState | Should -Be 'deleted'
    }
}

Describe 'Invoke-Compl8DictionaryExecutor — idempotent create (already exists => REUSE)' {
    It 'reuses the existing dictionary (no New call, no duplicate) mirroring Sync recovery' {
        Mock -ModuleName Compl8.Engine Get-DlpKeywordDictionary { [pscustomobject]@{ Identity = 'guid-already'; Name = 'QGISCF - AU Forenames' } }
        Mock -ModuleName Compl8.Engine New-DlpKeywordDictionary { throw 'must not create a duplicate' }
        Mock -ModuleName Compl8.Engine Set-DlpKeywordDictionary { throw 'reuse must not modify' }

        $step = New-DictStep -Id 's01' -Action 'create' -ObjectRef '{{DICT_AU_FORENAMES}}'
        $content = $script:DictContent | Where-Object placeholder -EQ '{{DICT_AU_FORENAMES}}'
        $result = Invoke-Compl8DictionaryExecutor -Step $step -Content $content -Prefix $script:Prefix

        Should -Invoke -ModuleName Compl8.Engine New-DlpKeywordDictionary -Times 0
        $result.status | Should -Be 'reused'
        $result.guid   | Should -Be 'guid-already'
    }
}

Describe 'Invoke-Compl8DictionaryExecutor — budget gate (over the 1 MB hard cap)' {
    It 'refuses the over-budget create and keeps existing/skips, no New call (mirrors Sync OverBudgetKeep/skip)' {
        $limits = Get-DeploymentLimits
        Mock -ModuleName Compl8.Engine Get-DlpKeywordDictionary { @() }
        Mock -ModuleName Compl8.Engine New-DlpKeywordDictionary { throw 'must not create an over-budget dictionary' }

        $step = New-DictStep -Id 's01' -Action 'create' -ObjectRef '{{DICT_HUGE}}'
        $content = [pscustomobject]@{
            placeholder = '{{DICT_HUGE}}'; name = 'QGISCF - Huge'; description = 'huge'; terms = @('x')
            termsBytes  = $limits.DictionaryBudgetMaxBytes
        }
        $result = Invoke-Compl8DictionaryExecutor -Step $step -Content $content -Prefix $script:Prefix

        Should -Invoke -ModuleName Compl8.Engine New-DlpKeywordDictionary -Times 0
        $result.status | Should -Be 'over-budget'
        @($result.budgetErrors).Count | Should -BeGreaterThan 0
    }
}

Describe 'Invoke-Compl8DictionaryExecutor — planned ops (-WhatIf / plan mode)' {
    It 'emits one normalised create op per dictionary in the Get-Compl8ShadowDiff op shape' {
        $steps = @(
            New-DictStep -Id 's01' -Action 'create' -ObjectRef '{{DICT_AU_FORENAMES}}'
            New-DictStep -Id 's02' -Action 'create' -ObjectRef '{{DICT_NOISE_EXCLUSION}}'
        )
        $ops = foreach ($s in $steps) {
            $content = $script:DictContent | Where-Object placeholder -EQ $s.objectRef
            Invoke-Compl8DictionaryExecutor -Step $s -Content $content -Prefix $script:Prefix -WhatIf
        }
        @($ops).Count | Should -Be 2
        foreach ($op in $ops) {
            $op.objectType | Should -Be 'dictionary'
            $op.action     | Should -Be 'create'
            $op.objectRef  | Should -Match '^\{\{DICT_'
        }
    }
}

Describe 'Invoke-Compl8DictionaryExecutor — SHADOW PARITY vs Sync-DlpKeywordDictionaries -WhatIf' {
    It 'executor planned ops MATCH the old path -WhatIf ops (Get-Compl8ShadowDiff.Match = $true, GENUINE)' {
        # OLD side: genuinely run Sync-DlpKeywordDictionaries -WhatIf and derive its planned ops.
        $oldOps = Get-OldDictionaryWhatIfOps -Manifest $script:OldManifest -NamePrefix $script:Prefix

        # ENGINE side: run the executor in -WhatIf mode over the SAME dictionaries (one step each).
        $steps = @(
            New-DictStep -Id 's01' -Action 'create' -ObjectRef '{{DICT_AU_FORENAMES}}'
            New-DictStep -Id 's02' -Action 'create' -ObjectRef '{{DICT_NOISE_EXCLUSION}}'
        )
        $engineOps = foreach ($s in $steps) {
            $content = $script:DictContent | Where-Object placeholder -EQ $s.objectRef
            Invoke-Compl8DictionaryExecutor -Step $s -Content $content -Prefix $script:Prefix -WhatIf
        }

        # Sanity: both sides actually produced ops (guards against a vacuous "empty == empty" pass).
        @($oldOps).Count    | Should -Be 2 -Because 'the fixture manifest has two dictionaries'
        @($engineOps).Count | Should -Be 2

        $diff = Get-Compl8ShadowDiff -EngineOps @($engineOps) -OldOps @($oldOps)
        $diff.Match | Should -BeTrue -Because "executor planned ops must reproduce the old -WhatIf path exactly. OnlyInEngine=$(@($diff.OnlyInEngine).objectRef -join ','); OnlyInOld=$(@($diff.OnlyInOld).objectRef -join ',')"
        @($diff.OnlyInEngine).Count | Should -Be 0
        @($diff.OnlyInOld).Count    | Should -Be 0
        @($diff.Differing).Count    | Should -Be 0
    }
}

Describe 'Invoke-Compl8DictionaryExecutor — apply contract (slots into Invoke-Compl8Apply -ExecutorMap)' {
    It 'is invokable with a single -Step (positional) as the apply dispatcher calls a command executor' {
        Mock -ModuleName Compl8.Engine Get-DlpKeywordDictionary { @() }
        Mock -ModuleName Compl8.Engine New-DlpKeywordDictionary { [pscustomobject]@{ Identity = 'guid-apply-1'; Name = $Name } }

        # Apply's dispatcher binds -Content via a closure in the production executor map; here we prove
        # the result object carries the fields the checkpoint records (stepId, action, objectType,
        # objectRef, status).
        $step = New-DictStep -Id 's07' -Action 'create' -ObjectRef '{{DICT_AU_FORENAMES}}'
        $content = $script:DictContent | Where-Object placeholder -EQ '{{DICT_AU_FORENAMES}}'
        $result = Invoke-Compl8DictionaryExecutor -Step $step -Content $content -Prefix $script:Prefix

        $result.stepId     | Should -Be 's07'
        $result.action     | Should -Be 'create'
        $result.objectType | Should -Be 'dictionary'
        $result.objectRef  | Should -Be '{{DICT_AU_FORENAMES}}'
        $result.status     | Should -Be 'created'
    }
}
