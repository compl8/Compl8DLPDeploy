#Requires -Modules Pester

# =====================================================================================
# Compl8.Engine — Invoke-Compl8Deploy: the holistic deploy workflow.
# (Stage 5 PHASE 5B, Task 5B-1.)
#
# Invoke-Compl8Deploy runs the WHOLE lifecycle behind ONE verb:
#     New-Compl8Context  ->  Invoke-Compl8Assess  ->  New-Compl8Plan  ->  render
#                        ->  confirm callback      ->  Invoke-Compl8Apply
# honouring Context.EngineRoutes (D4, D6): the engine PLANS + APPLIES only the object
# types whose route is ON; every other actionable type is DEFERRED to the still-live leaf
# path (reported, never mutated). ALL routes default to FALSE (leaf), so wiring this in
# changes NO live behaviour until an operator flips a route after its nonprod shadow trial.
#
# These tests reuse the committed e2e fixture workspace (tests/fixtures/engine/e2e/) — a
# QGISCF desired/resolved + entity-ledger + actual/inventory that diffs to one of each
# actionable kind — COPIED into a writable temp workspace per Describe (the engine writes
# history/plans/ + history/applies/ under the context's workspace, never the fixture).
# SCC cmdlets are mocked -ModuleName Compl8.Engine (the repo global-stub pattern).
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot  = Split-Path $PSScriptRoot -Parent
    $script:EngineDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:EngineDir -Force

    # Provenance registry isolated to a throwaway temp file + pinned deployment id (determinism).
    $env:COMPL8_PROVENANCE_REGISTRY = Join-Path ([System.IO.Path]::GetTempPath()) ("compl8-deploy-prov-{0}.json" -f ([guid]::NewGuid().ToString('N')))
    $env:COMPL8_DEPLOYMENT_ID = '20260615'

    $script:FixtureRoot   = Join-Path $script:RepoRoot 'tests' 'fixtures' 'engine' 'e2e'

    # ---- GLOBAL SCC cmdlet stubs (so `Mock -ModuleName Compl8.Engine` can shadow them) --------
    function global:New-DlpKeywordDictionary { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$Description, [byte[]]$FileData) }
    function global:Set-DlpKeywordDictionary { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [byte[]]$FileData, [string]$Description) }
    function global:Get-DlpKeywordDictionary { [CmdletBinding()] param([string]$Identity) }
    function global:Remove-DlpKeywordDictionary { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }

    function global:New-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([byte[]]$FileData) }
    function global:Set-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([byte[]]$FileData) }
    function global:Remove-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }
    function global:Get-DlpSensitiveInformationTypeRulePackage { [CmdletBinding()] param([string]$Identity) }
    function global:Get-DlpSensitiveInformationType { [CmdletBinding()] param([string]$Identity) }

    function global:Get-DlpComplianceRule { [CmdletBinding()] param([string]$Identity, [string]$Policy) }
    function global:New-DlpComplianceRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$Policy, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled) }
    function global:Set-DlpComplianceRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled) }
    function global:Remove-DlpComplianceRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }
    function global:Get-DlpCompliancePolicy { [CmdletBinding()] param([string]$Identity) }
    function global:New-DlpCompliancePolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$Comment, [string]$Mode) }
    function global:Set-DlpCompliancePolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [string]$Comment, [string]$Mode) }
    function global:Remove-DlpCompliancePolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }

    $script:NoSleep = { param($s) }

    # A New-Compl8Context-SHAPED context object pointed at a writable workspace, with the routes
    # under test. (Decouples the deploy-verb unit tests from New-Compl8Context's file resolution;
    # the shape matches modules/Compl8.Tenant/Public/New-Compl8Context.ps1 exactly.)
    function New-DeployTestContext {
        param([hashtable]$Routes = @{}, [Parameter(Mandatory)][string]$WorkspacePath)
        $r = [ordered]@{ dictionary = $false; label = $false; rulePackage = $false; dlpRule = $false; autoLabel = $false }
        foreach ($k in $Routes.Keys) { $r[$k] = [bool]$Routes[$k] }
        [pscustomobject]@{
            Environment            = 'nonprod'
            WorkspacePath          = $WorkspacePath
            TenantId               = '11111111-1111-1111-1111-111111111111'
            Prefix                 = 'QGISCF'
            FingerprintMode        = 'warn'
            UPN                    = $null
            Delegated              = $false
            DesiredRoot            = (Join-Path $WorkspacePath 'desired' 'resolved')
            ProvenanceRegistryPath = (Join-Path $WorkspacePath 'history' 'applies' 'provenance.json')
            EngineRoutes           = [pscustomobject]$r
        }
    }

    # Copy the committed fixture (desired/, entity-ledger.json, actual/) into a fresh writable
    # workspace so the engine may write history/ without touching the fixture.
    function New-DeployWorkspace {
        $ws = Join-Path ([System.IO.Path]::GetTempPath()) ("compl8deploy-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $ws -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:FixtureRoot 'desired') -Destination (Join-Path $ws 'desired') -Recurse -Force
        Copy-Item -LiteralPath (Join-Path $script:FixtureRoot 'actual')  -Destination (Join-Path $ws 'actual')  -Recurse -Force
        $ledger = Join-Path $script:FixtureRoot 'entity-ledger.json'
        if (Test-Path -LiteralPath $ledger) { Copy-Item -LiteralPath $ledger -Destination (Join-Path $ws 'entity-ledger.json') -Force }
        $ws
    }

    # The resolved desired content the dictionary create step needs, keyed by 'objectType|objectRef'
    # (the caller-knowable key Invoke-Compl8Deploy re-maps to step ids after planning).
    function New-DictDesiredContent {
        @{
            'dictionary|{{DICT_AU_FORENAMES}}' = [pscustomobject]@{
                placeholder = '{{DICT_AU_FORENAMES}}'; name = 'QGISCF - AU Forenames'
                description = 'Australian forenames'; terms = @('alice', 'bob', 'carol'); termsBytes = 122880
            }
        }
    }

    function Set-DeploySccMocks {
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }
        # Dictionary create: nothing exists yet -> New path.
        Mock -ModuleName Compl8.Engine Get-DlpKeywordDictionary { @() }
        Mock -ModuleName Compl8.Engine New-DlpKeywordDictionary { [pscustomobject]@{ Identity = 'guid-dict-new'; Name = $Name } }
        Mock -ModuleName Compl8.Engine Set-DlpKeywordDictionary { }
        # Rule-package / dlp-rule mutations (must be available so a leak is detectable as an invoke).
        Mock -ModuleName Compl8.Engine Set-DlpSensitiveInformationTypeRulePackage { }
        Mock -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage { }
        Mock -ModuleName Compl8.Engine Set-DlpComplianceRule { }
        Mock -ModuleName Compl8.Engine New-DlpComplianceRule { }
        Mock -ModuleName Compl8.Engine Get-DlpComplianceRule { $null }
    }
}

AfterAll {
    foreach ($fn in 'New-DlpKeywordDictionary', 'Set-DlpKeywordDictionary', 'Get-DlpKeywordDictionary', 'Remove-DlpKeywordDictionary',
        'New-DlpSensitiveInformationTypeRulePackage', 'Set-DlpSensitiveInformationTypeRulePackage', 'Remove-DlpSensitiveInformationTypeRulePackage',
        'Get-DlpSensitiveInformationTypeRulePackage', 'Get-DlpSensitiveInformationType',
        'Get-DlpComplianceRule', 'New-DlpComplianceRule', 'Set-DlpComplianceRule', 'Remove-DlpComplianceRule',
        'Get-DlpCompliancePolicy', 'New-DlpCompliancePolicy', 'Set-DlpCompliancePolicy', 'Remove-DlpCompliancePolicy') {
        Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-Compl8Deploy — module surface' {
    It 'is exported from Compl8.Engine' {
        (Get-Command -Name 'Invoke-Compl8Deploy' -Module Compl8.Engine -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-Compl8Deploy — routes ALL FALSE: assess + plan only, NO apply (default leaf)' {
    BeforeAll {
        $script:ws = New-DeployWorkspace
        $script:ctx = New-DeployTestContext -WorkspacePath $script:ws    # every route false
        Set-DeploySccMocks
        $script:result = Invoke-Compl8Deploy -Context $script:ctx -PlanId 'plan-deploy-allfalse' `
            -GeneratedUtc '2026-06-13T00:00:00Z' -ProjectRoot $script:RepoRoot -SleepAction $script:NoSleep -Now ([datetime]'2026-06-14T00:00:00Z')
    }
    AfterAll {
        if ($script:ws -and (Test-Path -LiteralPath $script:ws)) { Remove-Item -LiteralPath $script:ws -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'returns phase=planned and applies NOTHING' {
        $script:result.phase | Should -Be 'planned'
        $script:result.apply | Should -BeNullOrEmpty
    }
    It 'still produces the FULL assessment (the operator sees everything, routed or not)' {
        $script:result.assessment | Should -Not -BeNullOrEmpty
        $script:result.assessment.schemaVersion | Should -Be 'compl8.assessment/v1'
        # The fixture diffs to a non-empty create bucket.
        @($script:result.assessment.buckets.create).Count | Should -BeGreaterThan 0
    }
    It 'the ROUTED plan has ZERO steps (nothing routed through the engine)' {
        @($script:result.plan.steps).Count | Should -Be 0
    }
    It 'invokes NO mutating SCC cmdlet (every type deferred to the leaf)' {
        Should -Invoke -ModuleName Compl8.Engine New-DlpKeywordDictionary -Scope Describe -Times 0
        Should -Invoke -ModuleName Compl8.Engine Set-DlpSensitiveInformationTypeRulePackage -Scope Describe -Times 0
        Should -Invoke -ModuleName Compl8.Engine Set-DlpComplianceRule -Scope Describe -Times 0
    }
    It 'reports the actionable items as deferred to the leaf path' {
        @($script:result.deferredTypes) | Should -Contain 'dictionary'
        @($script:result.deferred).Count | Should -BeGreaterThan 0
    }
}

Describe 'Invoke-Compl8Deploy — routes {dictionary:true}: ONLY dictionary steps apply' {
    BeforeAll {
        $script:ws = New-DeployWorkspace
        $script:ctx = New-DeployTestContext -Routes @{ dictionary = $true } -WorkspacePath $script:ws
        Set-DeploySccMocks
        $script:result = Invoke-Compl8Deploy -Context $script:ctx -PlanId 'plan-deploy-dict' `
            -GeneratedUtc '2026-06-13T00:00:00Z' -DesiredContent (New-DictDesiredContent) `
            -ProjectRoot $script:RepoRoot -SleepAction $script:NoSleep -Now ([datetime]'2026-06-14T00:00:00Z')
    }
    AfterAll {
        if ($script:ws -and (Test-Path -LiteralPath $script:ws)) { Remove-Item -LiteralPath $script:ws -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'applied the deploy (phase=applied)' {
        $script:result.phase | Should -Be 'applied'
        $script:result.apply | Should -Not -BeNullOrEmpty
    }
    It 'the routed plan contains the dictionary create step (and only routed types)' {
        @($script:result.plan.steps).Count | Should -BeGreaterThan 0
        @($script:result.plan.steps | ForEach-Object objectType | Sort-Object -Unique) | Should -Be @('dictionary')
        $script:result.routedTypes | Should -Contain 'dictionary'
    }
    It 'created the dictionary via the REAL dictionary executor' {
        $dict = @($script:result.apply.steps | Where-Object { $_.objectType -eq 'dictionary' -and $_.action -eq 'create' })[0]
        $dict | Should -Not -BeNullOrEmpty
        $dict.status | Should -Be 'applied'
        Should -Invoke -ModuleName Compl8.Engine New-DlpKeywordDictionary -Scope Describe -Times 1
    }
    It 'mutated NO other object type (rule packages + dlp rules stay on the leaf)' {
        Should -Invoke -ModuleName Compl8.Engine Set-DlpSensitiveInformationTypeRulePackage -Scope Describe -Times 0
        Should -Invoke -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage -Scope Describe -Times 0
        Should -Invoke -ModuleName Compl8.Engine Set-DlpComplianceRule -Scope Describe -Times 0
    }
    It 'still reports the un-routed actionable types as deferred' {
        @($script:result.deferredTypes) | Should -Contain 'rulePackage'
    }
}

Describe 'Invoke-Compl8Deploy — confirm callback gates the apply' {
    AfterEach {
        if ($script:ws -and (Test-Path -LiteralPath $script:ws)) { Remove-Item -LiteralPath $script:ws -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'a callback returning $false DEFERS the apply (phase=planned, nothing mutated)' {
        $script:ws = New-DeployWorkspace
        $ctx = New-DeployTestContext -Routes @{ dictionary = $true } -WorkspacePath $script:ws
        Set-DeploySccMocks
        $seen = @{}
        $cb = { param($Assessment, $Plan, $Render) $seen.Assessment = $Assessment; $seen.Plan = $Plan; $seen.Render = $Render; $false }
        $result = Invoke-Compl8Deploy -Context $ctx -PlanId 'plan-deploy-deny' -GeneratedUtc '2026-06-13T00:00:00Z' `
            -DesiredContent (New-DictDesiredContent) -ConfirmCallback $cb -ProjectRoot $script:RepoRoot -SleepAction $script:NoSleep -Now ([datetime]'2026-06-14T00:00:00Z')

        $result.phase     | Should -Be 'planned'
        $result.confirmed | Should -BeFalse
        $result.apply     | Should -BeNullOrEmpty
        Should -Invoke -ModuleName Compl8.Engine New-DlpKeywordDictionary -Times 0
        # The callback received the assessment + plan + render so the surface can drive confirmation.
        $seen.Assessment.schemaVersion | Should -Be 'compl8.assessment/v1'
        $seen.Plan.schemaVersion       | Should -Be 'compl8.plan/v1'
        $seen.Render                   | Should -Not -BeNullOrEmpty
    }

    It 'a callback returning $true PROCEEDS to apply' {
        $script:ws = New-DeployWorkspace
        $ctx = New-DeployTestContext -Routes @{ dictionary = $true } -WorkspacePath $script:ws
        Set-DeploySccMocks
        $result = Invoke-Compl8Deploy -Context $ctx -PlanId 'plan-deploy-allow' -GeneratedUtc '2026-06-13T00:00:00Z' `
            -DesiredContent (New-DictDesiredContent) -ConfirmCallback { param($a, $p, $r) $true } `
            -ProjectRoot $script:RepoRoot -SleepAction $script:NoSleep -Now ([datetime]'2026-06-14T00:00:00Z')

        $result.phase     | Should -Be 'applied'
        $result.confirmed | Should -BeTrue
        Should -Invoke -ModuleName Compl8.Engine New-DlpKeywordDictionary -Times 1
    }
}

Describe 'Invoke-Compl8Deploy — -WhatIf is plan-only' {
    BeforeAll {
        $script:ws = New-DeployWorkspace
        $script:ctx = New-DeployTestContext -Routes @{ dictionary = $true } -WorkspacePath $script:ws
        Set-DeploySccMocks
        $script:result = Invoke-Compl8Deploy -Context $script:ctx -PlanId 'plan-deploy-whatif' `
            -GeneratedUtc '2026-06-13T00:00:00Z' -DesiredContent (New-DictDesiredContent) `
            -ProjectRoot $script:RepoRoot -SleepAction $script:NoSleep -Now ([datetime]'2026-06-14T00:00:00Z') -WhatIf
    }
    AfterAll {
        if ($script:ws -and (Test-Path -LiteralPath $script:ws)) { Remove-Item -LiteralPath $script:ws -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'plans without applying (phase=planned) even with a route ON' {
        $script:result.phase | Should -Be 'planned'
        $script:result.apply | Should -BeNullOrEmpty
    }
    It 'still produces the routed plan + render (so the operator can preview)' {
        @($script:result.plan.steps).Count | Should -BeGreaterThan 0
        $script:result.render | Should -Not -BeNullOrEmpty
    }
    It 'mutates nothing' {
        Should -Invoke -ModuleName Compl8.Engine New-DlpKeywordDictionary -Scope Describe -Times 0
    }
}

Describe 'Invoke-Compl8Deploy — render output shape' {
    BeforeAll {
        $script:ws = New-DeployWorkspace
        $script:ctx = New-DeployTestContext -Routes @{ dictionary = $true } -WorkspacePath $script:ws
        Set-DeploySccMocks
        $script:result = Invoke-Compl8Deploy -Context $script:ctx -PlanId 'plan-deploy-render' `
            -GeneratedUtc '2026-06-13T00:00:00Z' -DesiredContent (New-DictDesiredContent) `
            -ProjectRoot $script:RepoRoot -SleepAction $script:NoSleep -Now ([datetime]'2026-06-14T00:00:00Z') -WhatIf
    }
    AfterAll {
        if ($script:ws -and (Test-Path -LiteralPath $script:ws)) { Remove-Item -LiteralPath $script:ws -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'includes the assessment report' {
        $script:result.render | Should -Match 'Assessment \(compl8\.assessment/v1\)'
    }
    It 'includes an engine-routes summary naming what routes vs defers' {
        $script:result.render | Should -Match 'Engine routes'
        $script:result.render | Should -Match 'dictionary'
    }
}

Describe 'Invoke-Compl8Deploy — reference-existence pre-flight (planner depth #2 reframed)' {
    BeforeEach {
        $script:ws = New-DeployWorkspace
        # A DESIRED dlp rule (a CREATE — not in the fixture actual) referencing a tenant identity.
        $dlp = [pscustomobject]@{ schemaVersion = 'compl8.dlp-rules/v1'; policies = @(); rules = @(
            [pscustomobject]@{ ruleName = 'P99-R99-REFTEST-OFFI'; contentHash = 'sha256:ref'; content = [pscustomobject]@{
                Name = 'P99-R99-REFTEST-OFFI'; Policy = 'P99'; GenerateIncidentReport = 'Ghost-Group' } }
        ) }
        $dlp | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $script:ws 'desired' 'resolved' 'dlp-rules.json') -Encoding UTF8
        Set-DeploySccMocks
    }
    AfterEach {
        if ($script:ws -and (Test-Path -LiteralPath $script:ws)) { Remove-Item -LiteralPath $script:ws -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'HALTS before apply when a DEPLOYED rule references a missing identity (no mutation)' {
        $ctx = New-DeployTestContext -Routes @{ dlpRule = $true } -WorkspacePath $script:ws
        $missingResolver = { param($v) if ($v -eq 'Ghost-Group') { 'missing' } else { 'unverified' } }
        $r = Invoke-Compl8Deploy -Context $ctx -PlanId 'plan-deploy-refblock' -GeneratedUtc '2026-06-13T00:00:00Z' `
            -ProjectRoot $script:RepoRoot -SleepAction $script:NoSleep -Now ([datetime]'2026-06-14T00:00:00Z') `
            -ReferenceResolver $missingResolver
        $r.phase | Should -Be 'blocked-references'
        $r.apply | Should -BeNullOrEmpty
        @($r.referenceReadiness.blocking | Where-Object { $_.value -eq 'Ghost-Group' }).Count | Should -Be 1
        $r.render | Should -Match 'REFERENCE CHECK FAILED'
        Should -Invoke -ModuleName Compl8.Engine New-DlpComplianceRule -Times 0
    }

    It 'uses the SAME desired-rule source as assess — config fallback, not just dlp-rules.json (codex)' {
        # A config-fallback workspace (no desired/resolved/dlp-rules.json) still plans dlpRule changes from
        # config; the pre-flight must collect those rules' references too, or it silently skips the check.
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'modules' 'Compl8.Engine' 'Public' 'Invoke-Compl8Deploy.ps1') -Raw
        ($src -match 'dlp-rules\.json')           | Should -BeTrue
        ($src -match 'Resolve-DesiredDlpRules')   | Should -BeTrue   # the config fallback
    }
    It 'does NOT block a dictionary-only deploy on an UNRELATED rule''s missing reference (codex scoping)' {
        # dlpRule routing is OFF — the P99 rule is present in dlp-rules.json but NOT being deployed, so its
        # missing recipient must not block the dictionary deploy.
        $ctx = New-DeployTestContext -Routes @{ dictionary = $true } -WorkspacePath $script:ws
        $blockEverything = { param($v) 'missing' }   # would block the rule IF it were checked
        $r = Invoke-Compl8Deploy -Context $ctx -PlanId 'plan-deploy-dictok' -GeneratedUtc '2026-06-13T00:00:00Z' `
            -DesiredContent (New-DictDesiredContent) -ProjectRoot $script:RepoRoot -SleepAction $script:NoSleep `
            -Now ([datetime]'2026-06-14T00:00:00Z') -ReferenceResolver $blockEverything
        $r.phase | Should -Be 'applied'
        Should -Invoke -ModuleName Compl8.Engine New-DlpKeywordDictionary -Times 1
    }
}
