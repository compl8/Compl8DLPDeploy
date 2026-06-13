#Requires -Modules Pester

# =====================================================================================
# Compl8.Engine — END-TO-END assess -> plan -> apply on a fixture workspace.
# (Stage 4 PHASE 4D, Task 13 — the CAPSTONE integration test.)
#
# This wires the WHOLE Engine together and proves the cross-cutting behaviours actually
# COMPOSE through the real verbs and the REAL per-type executors:
#       Invoke-Compl8Assess  ->  New-Compl8Plan  ->  Invoke-Compl8Apply
# with ALL SCC cmdlets mocked -ModuleName Compl8.Engine. The executor map is assembled by
# the production helper Get-Compl8ExecutorMap, binding the real executors
# (Invoke-Compl8DictionaryExecutor / RulePackageExecutor / DlpRuleExecutor / ...) with
# their -Content via closures. The five behaviours asserted (the Task-13 acceptance set):
#
#   1. snapshotBeforeDestroy Step 0.5 runs BEFORE any destructive step.
#   2. A removal of a classifier referenced by a LIVE DLP rule generates dereference step(s)
#      applied BEFORE the removal.
#   3. The propagation gate HALTS a dependent rule step until its offset elapses (injected
#      clock): blocked with an early clock, proceeds with a later clock.
#   4. CHECKPOINT/RESUME: a mid-plan kill (a wrapped executor that throws on a chosen step)
#      checkpoints the prior steps; a re-run SKIPS completed steps and resumes.
#   5. The final history/applies/<planId>/result.json records EVERY step exactly once.
#
# ------------------------------------------------------------------------------------------
# FIXTURE SCENARIO (tests/fixtures/engine/e2e/) — a single QGISCF workspace whose DESIRED
# side (a Stage-3-shaped desired/resolved + entity-ledger) diffed against a hand-authored
# ACTUAL inventory exercises one of EACH actionable kind plus a propagation-gated rule:
#
#   * CREATE      : dictionary '{{DICT_AU_FORENAMES}}' and sit 'custom-incident-ref'
#                   (both desired, absent from actual).
#   * UPDATE      : rule package 'QGISCF-test-01' (present + ours, canonical content hash
#                   differs => a refit / update-in-place).
#   * REMOVE      : sit 'shared-b' (ours, ledger-DISABLED, unassigned in desired => a planned
#                   removal). Its entity (GUID 4444...) lives in the desired QGISCF-test-01 XML
#                   so the reference graph can see who points at it.
#   * DEREFERENCE : the live DLP rule 'QGISCF-Bravo-Deref-09' references shared-b (GUID 4444...).
#                   The planner GENERATES a dereference step for that rule, ordered BEFORE the
#                   shared-b removal (D5). The rule also references shared-a, so dereferencing
#                   shared-b leaves shared-a => the rule is trimmed, not deleted.
#   * PROPAGATION : the e2e ADDS a drift dlpRule 'QGISCF-QLD-Medium-Email-07' (it references
#                   name-dict in the updated QGISCF-test-01) to the assessment's drift bucket —
#                   modelling a rule edited out-of-band that must be re-applied. Because it
#                   depends on a package UPDATED this plan, Get-Compl8PlanOrder attaches a
#                   { type='propagation'; notBeforeOffsetHours=4 } gate, so the rule step waits
#                   for classifier propagation after the package step's apply time.
#
# NOTE on the drift dlpRule: Invoke-Compl8Assess does not yet detect out-of-band dlpRule drift
# (it buckets packages/sits/dictionaries), but the plan + apply machinery already supports a
# `drift` dlpRule step (Get-Compl8PlanOrder turns it into a re-apply step and attaches the
# propagation gate). The e2e injects that one drift entry into the real assessment so the
# propagation behaviour is reachable end to end through the REAL planner + REAL gate evaluator;
# it does not hand-author the plan. Everything else flows from the real assess output.
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot  = Split-Path $PSScriptRoot -Parent
    $script:EngineDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    $script:TenantDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Tenant'
    # DLP-Deploy's facade dot-source can claim these function names; drop it so the
    # Compl8.Engine module attribution is clean (same pattern as the other Engine tests).
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:EngineDir -Force

    # Provenance registry isolated to a throwaway temp file (repo pattern) + a pinned deployment
    # id so stamps are deterministic and never touch reports/provenance-registry.json.
    $env:COMPL8_PROVENANCE_REGISTRY = Join-Path ([System.IO.Path]::GetTempPath()) ("compl8-e2e-prov-{0}.json" -f ([guid]::NewGuid().ToString('N')))
    $env:COMPL8_DEPLOYMENT_ID = '20260613'

    $script:FixtureRoot   = Join-Path $script:RepoRoot 'tests' 'fixtures' 'engine' 'e2e'
    $script:InventoryPath = Join-Path $script:FixtureRoot 'actual' 'inventory.json'

    # ---- GLOBAL SCC cmdlet stubs (repo pattern) ----------------------------------------------
    # The executors invoke these DYNAMICALLY, so they must EXIST for `Mock -ModuleName Compl8.Engine`
    # to shadow them in the module scope. (No -ErrorAction/-Confirm redeclared — common params.)
    function global:New-DlpKeywordDictionary { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$Description, [byte[]]$FileData) }
    function global:Set-DlpKeywordDictionary { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [byte[]]$FileData, [string]$Description) }
    function global:Get-DlpKeywordDictionary { [CmdletBinding()] param([string]$Identity) }
    function global:Remove-DlpKeywordDictionary { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }

    function global:New-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([byte[]]$FileData) }
    function global:Set-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([byte[]]$FileData) }
    function global:Remove-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }
    function global:Get-DlpSensitiveInformationTypeRulePackage { [CmdletBinding()] param([string]$Identity) }
    function global:Get-DlpSensitiveInformationType { [CmdletBinding()] param([string]$Identity) }

    function global:Get-DlpCompliancePolicy { [CmdletBinding()] param([string]$Identity) }
    function global:New-DlpCompliancePolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$Comment, [string]$Mode) }
    function global:Set-DlpCompliancePolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [string]$Comment, [string]$Mode) }
    function global:Remove-DlpCompliancePolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }
    function global:Get-DlpComplianceRule { [CmdletBinding()] param([string]$Identity, [string]$Policy) }
    function global:New-DlpComplianceRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$Policy, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled) }
    function global:Set-DlpComplianceRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled) }
    function global:Remove-DlpComplianceRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }

    # Sensitivity-label cmdlets the label executor invokes (needed so `Mock -ModuleName Compl8.Engine`
    # can shadow them; the e2e plan exercises no labels itself, but the Get-Compl8ExecutorMap Describe
    # runs the label closures directly — see the shared parent-guid cache test).
    function global:Get-Label { [CmdletBinding()] param([string]$Identity) }
    function global:New-Label {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [string]$Name, [string]$DisplayName, [string]$Tooltip, [string]$Comment, [string]$ContentType,
            [switch]$IsLabelGroup, [string]$ParentId,
            [switch]$ApplyContentMarkingHeaderEnabled, [string]$ApplyContentMarkingHeaderText,
            [int]$ApplyContentMarkingHeaderFontSize, [string]$ApplyContentMarkingHeaderAlignment, [string]$ApplyContentMarkingHeaderFontColor,
            [switch]$ApplyContentMarkingFooterEnabled, [string]$ApplyContentMarkingFooterText,
            [int]$ApplyContentMarkingFooterFontSize, [string]$ApplyContentMarkingFooterAlignment, [string]$ApplyContentMarkingFooterFontColor,
            [hashtable]$AdvancedSettings)
    }
    function global:Set-Label {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [string]$Identity, [string]$DisplayName, [string]$Tooltip, [string]$Comment,
            [switch]$ApplyContentMarkingHeaderEnabled, [string]$ApplyContentMarkingHeaderText,
            [int]$ApplyContentMarkingHeaderFontSize, [string]$ApplyContentMarkingHeaderAlignment, [string]$ApplyContentMarkingHeaderFontColor,
            [switch]$ApplyContentMarkingFooterEnabled, [string]$ApplyContentMarkingFooterText,
            [int]$ApplyContentMarkingFooterFontSize, [string]$ApplyContentMarkingFooterAlignment, [string]$ApplyContentMarkingFooterFontColor,
            [hashtable]$AdvancedSettings)
    }
    function global:Remove-Label { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }
    function global:Get-LabelPolicy { [CmdletBinding()] param([string]$Identity) }
    function global:New-LabelPolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string[]]$Labels, [string]$ExchangeLocation, [string]$Comment) }
    function global:Set-LabelPolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [string[]]$AddLabels, [string]$Comment) }
    function global:Remove-LabelPolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }

    # ---- the desired/actual diff + graph the planner consumes (built ONCE, real assess) -------
    function New-E2EAssessment {
        Invoke-Compl8Assess -WorkspacePath $script:FixtureRoot -InventoryPath $script:InventoryPath `
            -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'
    }

    function New-E2EGraph {
        param([pscustomobject]$Inventory)
        $resolvedDir = Join-Path $script:FixtureRoot 'desired' 'resolved'
        $manifest = Get-Content -LiteralPath (Join-Path $resolvedDir 'resolve-manifest.json') -Raw | ConvertFrom-Json
        $graphPackages = @(foreach ($pkg in @($manifest.packages)) {
            $pkgFile = Join-Path $resolvedDir ([string]$pkg.file)
            if (-not $pkg.file -or -not (Test-Path -LiteralPath $pkgFile)) { continue }
            [pscustomobject]@{
                Identity = [string]$pkg.name; Name = [string]$pkg.name; Publisher = 'Compl8'
                SerializedClassificationRuleCollection = (Get-Content -LiteralPath $pkgFile -Raw)
            }
        })
        $graphRules = @(foreach ($rule in @($Inventory.objects.dlpRules)) {
            [pscustomobject]@{
                Name = [string]$rule.name; Identity = [string]$rule.identity; Policy = [string]$rule.policy
                ContentContainsSensitiveInformation = $rule.contentContainsSensitiveInformation
            }
        })
        Get-DeploymentReferenceGraph -SitPackages $graphPackages -DlpRules $graphRules
    }

    # Build the full e2e plan into a scratch workspace. The drift dlpRule (the propagation carrier,
    # see the header NOTE) is injected into the real assessment's drift bucket before planning.
    function New-E2EPlanFile {
        param([string]$Id = 'plan-e2e')
        $assessment = New-E2EAssessment
        $assessment.buckets.drift = @(@($assessment.buckets.drift) + [pscustomobject]@{
            objectType = 'dlpRule'; ref = 'QGISCF-QLD-Medium-Email-07'
            reason = 'ours — rule edited out-of-band, re-apply (propagation carrier)'
        })
        $inventory = Get-Content -LiteralPath $script:InventoryPath -Raw | ConvertFrom-Json
        $graph = New-E2EGraph -Inventory $inventory

        $workRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("compl8e2e-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
        $plan = New-Compl8Plan -Assessment $assessment -Graph $graph -Inventory $inventory `
            -Workspace 'nonprod' -Id $Id -GeneratedUtc '2026-06-13T00:00:00Z' -WorkspacePath $workRoot
        $planPath = Join-Path $workRoot 'history' 'plans' "$Id.json"
        [pscustomobject]@{ WorkRoot = $workRoot; PlanPath = $planPath; Plan = $plan; Inventory = $inventory }
    }

    # ---- per-step resolved content the real executors consume --------------------------------
    # Keyed by stepId; Get-Compl8ExecutorMap threads each into its executor's -Content via closure.
    # The dereference / remove / snapshot / sit steps carry no content (the dereference reads the
    # removed-sit refs from the step's impact; remove/sit are subsumed; snapshot is the snapshot).
    function New-E2EStepContent {
        param([pscustomobject]$Plan)
        $byRef = @{}
        foreach ($s in $Plan.steps) { $byRef["$($s.objectType)|$($s.objectRef)"] = $s.id }
        $content = @{}
        # s01: dictionary create.
        if ($byRef.ContainsKey('dictionary|{{DICT_AU_FORENAMES}}')) {
            $content[$byRef['dictionary|{{DICT_AU_FORENAMES}}']] = [pscustomobject]@{
                placeholder = '{{DICT_AU_FORENAMES}}'; name = 'QGISCF - AU Forenames'
                description = 'Australian forenames'; terms = @('alice', 'bob', 'carol'); termsBytes = 122880
            }
        }
        # rule-package update: payloadXml + no localSitIds (skip the verify poll deterministically).
        if ($byRef.ContainsKey('rulePackage|QGISCF-test-01')) {
            $pkgXml = Get-Content -LiteralPath (Join-Path $script:FixtureRoot 'desired' 'resolved' 'QGISCF-test-01.xml') -Raw
            $content[$byRef['rulePackage|QGISCF-test-01']] = [pscustomobject]@{
                name = 'QGISCF-test-01'; payloadXml = $pkgXml; localSitIds = @()
            }
        }
        # drift rule update: the re-applied rule's desired condition + policy.
        if ($byRef.ContainsKey('dlpRule|QGISCF-QLD-Medium-Email-07')) {
            $content[$byRef['dlpRule|QGISCF-QLD-Medium-Email-07']] = [pscustomobject]@{
                name = 'QGISCF-QLD-Medium-Email-07'; policy = 'P01-MED-QGISCF-EXT'; comment = 'medium email rule'
                condition = [pscustomobject]@{ Format = 'Simple'; Value = @{ operator = 'And'; groups = @() } }
            }
        }
        $content
    }

    # ---- the SCC mocks the real executors hit in apply mode (mocked -ModuleName Compl8.Engine) -
    # A no-op sleep so the retry/verify paths never wait on the wall clock.
    $script:NoSleep = { param($s) }
    function Set-E2ESccMocks {
        Mock -ModuleName Compl8.Engine Test-Compl8PlanCurrent { $true }
        Mock -ModuleName Compl8.Engine Test-DeploymentTenantFingerprint { [pscustomobject]@{ passed = $true } }

        # Dictionary create: nothing exists yet -> New path.
        Mock -ModuleName Compl8.Engine Get-DlpKeywordDictionary { @() }
        Mock -ModuleName Compl8.Engine New-DlpKeywordDictionary { [pscustomobject]@{ Identity = 'guid-dict-new'; Name = $Name } }
        Mock -ModuleName Compl8.Engine Set-DlpKeywordDictionary { }
        Mock -ModuleName Compl8.Engine Remove-DlpKeywordDictionary { }

        # Rule-package update.
        Mock -ModuleName Compl8.Engine Set-DlpSensitiveInformationTypeRulePackage { }
        Mock -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage { }

        # DLP rule probes/mutations. The DEREFERENCE rule (QGISCF-Bravo-Deref-09) returns a live
        # CCSI carrying BOTH shared-b (to be stripped) and shared-a (to remain). The UPDATE rule
        # (QGISCF-QLD-Medium-Email-07) returns an existing object so the executor takes the Set path.
        Mock -ModuleName Compl8.Engine Get-DlpComplianceRule {
            if ($Identity -eq 'QGISCF-Bravo-Deref-09') {
                return [pscustomobject]@{
                    Identity = 'QGISCF-Bravo-Deref-09'; Name = 'QGISCF-Bravo-Deref-09'
                    ContentContainsSensitiveInformation = [pscustomobject]@{
                        operator = 'And'
                        groups = @([pscustomobject]@{
                            operator = 'Or'; name = 'Default'
                            sensitivetypes = @(
                                [pscustomobject]@{ id = '44444444-aaaa-4bbb-8ccc-000000000004'; name = 'shared-b' }
                                [pscustomobject]@{ id = '33333333-aaaa-4bbb-8ccc-000000000003'; name = 'shared-a' }
                            )
                        })
                    }
                }
            }
            if ($Identity -eq 'QGISCF-QLD-Medium-Email-07') {
                return [pscustomobject]@{ Identity = 'QGISCF-QLD-Medium-Email-07'; Name = 'QGISCF-QLD-Medium-Email-07'; Mode = 'Enable' }
            }
            return $null
        }
        Mock -ModuleName Compl8.Engine Set-DlpComplianceRule { }
        Mock -ModuleName Compl8.Engine New-DlpComplianceRule { }
        Mock -ModuleName Compl8.Engine Remove-DlpComplianceRule { }
    }

    # Build the production executor map for the e2e plan (real executors, no-op sleep, captured
    # snapshot inventory written into the workspace actual/ via the Tenant reader).
    function New-E2EExecutorMap {
        param([pscustomobject]$Plan, [string]$WorkRoot, [pscustomobject]$Inventory, [hashtable]$ExtraStepContent)
        $stepContent = New-E2EStepContent -Plan $Plan
        if ($ExtraStepContent) { foreach ($k in $ExtraStepContent.Keys) { $stepContent[$k] = $ExtraStepContent[$k] } }
        Get-Compl8ExecutorMap -StepContent $stepContent -Prefix 'QGISCF' `
            -SleepAction $script:NoSleep `
            -SnapshotInventory $Inventory -SnapshotWorkspacePath $WorkRoot -SnapshotTimestamp '20260613_000000'
    }
}

AfterAll {
    foreach ($fn in 'New-DlpKeywordDictionary', 'Set-DlpKeywordDictionary', 'Get-DlpKeywordDictionary', 'Remove-DlpKeywordDictionary',
        'New-DlpSensitiveInformationTypeRulePackage', 'Set-DlpSensitiveInformationTypeRulePackage', 'Remove-DlpSensitiveInformationTypeRulePackage',
        'Get-DlpSensitiveInformationTypeRulePackage', 'Get-DlpSensitiveInformationType',
        'Get-DlpCompliancePolicy', 'New-DlpCompliancePolicy', 'Set-DlpCompliancePolicy', 'Remove-DlpCompliancePolicy',
        'Get-DlpComplianceRule', 'New-DlpComplianceRule', 'Set-DlpComplianceRule', 'Remove-DlpComplianceRule',
        'Get-Label', 'New-Label', 'Set-Label', 'Remove-Label',
        'Get-LabelPolicy', 'New-LabelPolicy', 'Set-LabelPolicy', 'Remove-LabelPolicy') {
        Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
    }
}

Describe 'E2E — module surface' {
    It 'exports Get-Compl8ExecutorMap from Compl8.Engine' {
        (Get-Command -Name 'Get-Compl8ExecutorMap' -Module Compl8.Engine -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-Compl8ExecutorMap — assembles the production map (objectType -> real executor closure)' {
    It 'registers a closure for every apply objectType (fails closed for none in the enum)' {
        $map = Get-Compl8ExecutorMap -StepContent @{}
        foreach ($type in 'dictionary', 'rulePackage', 'sit', 'label', 'labelPolicy', 'dlpRule', 'dlpPolicy', 'autoLabelPolicy', 'tenant') {
            $map.ContainsKey($type) | Should -BeTrue -Because "objectType '$type' must have an executor"
            $map[$type] | Should -BeOfType [scriptblock]
        }
    }

    It 'binds the per-step resolved -Content from -StepContent (the closure threads it to the executor)' {
        # A dictionary create step + its content; the closure must resolve content by $Step.id and
        # call the real dictionary executor against the mocked SCC cmdlets.
        Mock -ModuleName Compl8.Engine Get-DlpKeywordDictionary { @() }
        Mock -ModuleName Compl8.Engine New-DlpKeywordDictionary { [pscustomobject]@{ Identity = 'g-map'; Name = $Name } }
        $step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'dictionary'; objectRef = '{{DICT_MAP}}'; dependsOn = @(); impact = @(); gate = $null }
        $content = @{ s01 = [pscustomobject]@{ placeholder = '{{DICT_MAP}}'; name = 'QGISCF - Map'; description = 'd'; terms = @('a'); termsBytes = 100 } }
        $map = Get-Compl8ExecutorMap -StepContent $content -Prefix 'QGISCF' -SleepAction { param($s) }

        $result = & $map['dictionary'] $step
        $result.status | Should -Be 'created'
        $result.guid   | Should -Be 'g-map'
        $result.stampedDescription | Should -Match '\[\[Compl8:[0-9a-f]{16}\]\]'
        Should -Invoke -ModuleName Compl8.Engine New-DlpKeywordDictionary -Times 1
    }

    It 'the default tenant snapshot executor writes actual/ via the Tenant reader' {
        $wr = Join-Path ([System.IO.Path]::GetTempPath()) ("compl8map-snap-" + [guid]::NewGuid())
        try {
            $inv = [pscustomobject]@{ schemaVersion = 'compl8.inventory/v1'; objects = [pscustomobject]@{} }
            $map = Get-Compl8ExecutorMap -StepContent @{} -SnapshotInventory $inv -SnapshotWorkspacePath $wr -SnapshotTimestamp '20260613_000000'
            $step = [pscustomobject]@{ id = 's00'; action = 'snapshot'; objectType = 'tenant'; objectRef = '*'; dependsOn = @(); impact = @(); gate = $null }
            $r = & $map['tenant'] $step
            $r.status | Should -Be 'snapshotted'
            Test-Path -LiteralPath (Join-Path $wr 'actual' 'snapshots' '20260613_000000' 'inventory.json') | Should -BeTrue
        } finally {
            if (Test-Path -LiteralPath $wr) { Remove-Item -LiteralPath $wr -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'an injected -SnapshotExecutor overrides the default tenant executor' {
        $map = Get-Compl8ExecutorMap -StepContent @{} -SnapshotExecutor { param($Step) [pscustomobject]@{ status = 'custom-snap'; stepId = $Step.id } }
        $step = [pscustomobject]@{ id = 's00'; action = 'snapshot'; objectType = 'tenant'; objectRef = '*'; dependsOn = @(); impact = @(); gate = $null }
        (& $map['tenant'] $step).status | Should -Be 'custom-snap'
    }

    It '[P2-1] threads rule-package SLOT ACCOUNTING from -Inventory/-Plan so a near-full tenant refuses an over-cap create' {
        # The tenant already holds (MaxRulePackagesPerTenant - 1) = 9 of OUR rule packages, plus a
        # Microsoft package that is NOT ours (must not count toward our slots). The plan creates 2 new
        # packages and frees 0. The capacity gate must allow exactly ONE create (filling the 10th slot)
        # and REFUSE the second (over-cap) — NO New call for the over-cap one.
        Mock -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage { }
        $cap = (Get-DeploymentLimits).MaxRulePackagesPerTenant

        $ourPackages = @(1..($cap - 1) | ForEach-Object { [pscustomobject]@{ name = "QGISCF-existing-$_"; ours = $true } })
        $inventory = [pscustomobject]@{
            schemaVersion = 'compl8.inventory/v1'
            objects = [pscustomobject]@{
                sitPackages = @($ourPackages + [pscustomobject]@{ name = 'Microsoft Rule Package'; ours = $false })
            }
        }

        $stepA = [pscustomobject]@{ id = 'pA'; action = 'create'; objectType = 'rulePackage'; objectRef = 'QGISCF-new-A'; dependsOn = @(); impact = @(); gate = $null }
        $stepB = [pscustomobject]@{ id = 'pB'; action = 'create'; objectType = 'rulePackage'; objectRef = 'QGISCF-new-B'; dependsOn = @(); impact = @(); gate = $null }
        $plan = [pscustomobject]@{ steps = @($stepA, $stepB) }   # 2 creates, 0 rulePackage removals
        # payloadXml referencing no dictionary GUID + empty localSitIds => dict-ref + verify gates pass trivially.
        $content = @{
            pA = [pscustomobject]@{ name = 'QGISCF-new-A'; payloadXml = '<RulePackage/>'; localSitIds = @() }
            pB = [pscustomobject]@{ name = 'QGISCF-new-B'; payloadXml = '<RulePackage/>'; localSitIds = @() }
        }

        $map = Get-Compl8ExecutorMap -StepContent $content -Prefix 'QGISCF' -SleepAction { param($s) } `
            -Inventory $inventory -Plan $plan

        # First create fills the last free slot (9 used + 1 = 10 <= cap) -> created.
        $rA = & $map['rulePackage'] $stepA
        $rA.status | Should -Be 'created'
        # Second create would make 11 > cap -> REFUSED before mutation.
        $rB = & $map['rulePackage'] $stepB
        $rB.status | Should -Be 'capacity-blocked'

        # Exactly ONE New call total (the over-cap one never reaches the SCC cmdlet).
        Should -Invoke -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage -Times 1
    }

    It '[P2-A] credits ONLY removals that have actually COMPLETED, not all planned removals (early create at capacity is refused)' {
        # FULL tenant: baselineUsed = MaxRulePackagesPerTenant. The plan REMOVES one package and CREATES
        # one, BUT the create step dispatches BEFORE the remove step (construct a step order where the
        # create id precedes the remove id). The freed-slot credit a create sees must equal the removals
        # that have SUCCEEDED so far — which, when the create runs first, is ZERO. So the early create is
        # REFUSED (no New call). After the remove COMPLETES (freed=1), a subsequent create IS allowed.
        # Before the fix the static SlotsFreed-from-plan (=1) wrongly credited the early create.
        Mock -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage { }
        Mock -ModuleName Compl8.Engine Remove-DlpSensitiveInformationTypeRulePackage { }
        Mock -ModuleName Compl8.Engine Get-DlpSensitiveInformationTypeRulePackage { [pscustomobject]@{ Identity = 'QGISCF-old-1'; Name = 'QGISCF-old-1' } }
        $cap = (Get-DeploymentLimits).MaxRulePackagesPerTenant

        # Tenant is FULL: all `cap` slots are OUR packages.
        $ourPackages = @(1..$cap | ForEach-Object { [pscustomobject]@{ name = "QGISCF-existing-$_"; ours = $true } })
        $inventory = [pscustomobject]@{
            schemaVersion = 'compl8.inventory/v1'
            objects = [pscustomobject]@{ sitPackages = @($ourPackages) }
        }

        # The plan: a create (pA) and a remove (rmOld). The map closure must NOT pre-credit the planned
        # remove to the create — only completed removes count.
        $createStep = [pscustomobject]@{ id = 'pA'; action = 'create'; objectType = 'rulePackage'; objectRef = 'QGISCF-new-A'; dependsOn = @(); impact = @(); gate = $null }
        $removeStep = [pscustomobject]@{ id = 'rmOld'; action = 'remove'; objectType = 'rulePackage'; objectRef = 'QGISCF-old-1'; dependsOn = @(); impact = @(); gate = $null }
        $createStepB = [pscustomobject]@{ id = 'pB'; action = 'create'; objectType = 'rulePackage'; objectRef = 'QGISCF-new-B'; dependsOn = @(); impact = @(); gate = $null }
        $plan = [pscustomobject]@{ steps = @($createStep, $removeStep, $createStepB) }
        $content = @{
            pA    = [pscustomobject]@{ name = 'QGISCF-new-A'; payloadXml = '<RulePackage/>'; localSitIds = @() }
            pB    = [pscustomobject]@{ name = 'QGISCF-new-B'; payloadXml = '<RulePackage/>'; localSitIds = @() }
            rmOld = [pscustomobject]@{ name = 'QGISCF-old-1'; identity = 'QGISCF-old-1' }
        }

        $map = Get-Compl8ExecutorMap -StepContent $content -Prefix 'QGISCF' -SleepAction { param($s) } `
            -Inventory $inventory -Plan $plan

        # 1) The create dispatches FIRST, while the tenant is still full and NO removal has completed.
        #    available = cap - (cap + 0) + 0 = 0 < 1 -> REFUSED.
        $rEarly = & $map['rulePackage'] $createStep
        $rEarly.status | Should -Be 'capacity-blocked'

        # 2) Now the removal runs and ACTUALLY completes -> frees one slot.
        $rRemove = & $map['rulePackage'] $removeStep
        $rRemove.status | Should -Be 'deleted'

        # 3) A subsequent create now fits: available = cap - (cap + 0) + 1 = 1 >= 1 -> created.
        $rLate = & $map['rulePackage'] $createStepB
        $rLate.status | Should -Be 'created'

        # Exactly ONE New call (the late create); the early over-cap create never reached the SCC cmdlet.
        Should -Invoke -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage -Times 1
    }

    It '[P2-B] a verify-failed create STILL consumed a tenant slot, so the next create is refused' {
        # NEAR-FULL tenant: baselineUsed = MaxRulePackagesPerTenant - 1 (one free slot). Two creates run.
        # The FIRST upload SUCCEEDS but post-upload verification times out (Get-DlpSensitiveInformationType
        # never shows the declared SIT) -> status 'verify-failed'. That create CONSUMED the last slot. So
        # the SECOND create must be REFUSED. Before the fix the consumed counter advanced only on 'created',
        # so the verify-failed first create left stale headroom and the second was wrongly allowed.
        Mock -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage { }
        Mock -ModuleName Compl8.Engine Get-DlpSensitiveInformationType { @() }   # entity never surfaces -> verify times out
        $cap = (Get-DeploymentLimits).MaxRulePackagesPerTenant

        $ourPackages = @(1..($cap - 1) | ForEach-Object { [pscustomobject]@{ name = "QGISCF-existing-$_"; ours = $true } })
        $inventory = [pscustomobject]@{
            schemaVersion = 'compl8.inventory/v1'
            objects = [pscustomobject]@{ sitPackages = @($ourPackages) }
        }

        $stepA = [pscustomobject]@{ id = 'pA'; action = 'create'; objectType = 'rulePackage'; objectRef = 'QGISCF-new-A'; dependsOn = @(); impact = @(); gate = $null }
        $stepB = [pscustomobject]@{ id = 'pB'; action = 'create'; objectType = 'rulePackage'; objectRef = 'QGISCF-new-B'; dependsOn = @(); impact = @(); gate = $null }
        $plan = [pscustomobject]@{ steps = @($stepA, $stepB) }   # 2 creates, 0 removals
        # First create declares a local SIT id (so the verify poll runs and times out); second is irrelevant
        # because it must be refused before any upload.
        $content = @{
            pA = [pscustomobject]@{ name = 'QGISCF-new-A'; payloadXml = '<RulePackage/>'; localSitIds = @('sit-never-surfaces') }
            pB = [pscustomobject]@{ name = 'QGISCF-new-B'; payloadXml = '<RulePackage/>'; localSitIds = @() }
        }

        $map = Get-Compl8ExecutorMap -StepContent $content -Prefix 'QGISCF' -SleepAction { param($s) } `
            -Inventory $inventory -Plan $plan

        # First create: upload happens (the slot is consumed) but verification fails.
        $rA = & $map['rulePackage'] $stepA
        $rA.status | Should -Be 'verify-failed'

        # Second create: the verify-failed first create consumed the last slot -> over cap -> REFUSED.
        $rB = & $map['rulePackage'] $stepB
        $rB.status | Should -Be 'capacity-blocked'

        # Exactly ONE New call (the first create's upload); the second never reached the SCC cmdlet.
        Should -Invoke -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage -Times 1
    }

    It '[P2-2] threads a SHARED parent-guid cache so a sublabel reuses a parent group created earlier in the same apply' {
        # A label GROUP create step seeds the shared cache with its just-created GUID; a later SUBLABEL
        # create step (same map) must resolve the parent from THAT cache even though Get-Label returns
        # NOTHING for the parent (Purview has not yet surfaced the new group). Before the fix (no shared
        # cache) the sublabel falls to Get-Label, finds nothing, and is skipped as parent-not-found.
        $parentGuid = '99999999-aaaa-4bbb-8ccc-000000000099'
        # Get-Label returns nothing for ANY identity (neither the new group nor the parent lookup).
        Mock -ModuleName Compl8.Engine Get-Label { $null }
        Mock -ModuleName Compl8.Engine New-Label {
            if ($Name -eq 'QGISCF - Group') { [pscustomobject]@{ Guid = $parentGuid; Name = $Name } }
            else { [pscustomobject]@{ Guid = 'sublabel-guid'; Name = $Name } }
        }
        Mock -ModuleName Compl8.Engine Set-Label { }

        $groupStep = [pscustomobject]@{ id = 'lg'; action = 'create'; objectType = 'label'; objectRef = 'QGISCF - Group'; dependsOn = @(); impact = @(); gate = $null }
        $subStep   = [pscustomobject]@{ id = 'ls'; action = 'create'; objectType = 'label'; objectRef = 'QGISCF - Group - Child'; dependsOn = @(); impact = @(); gate = $null }
        $content = @{
            lg = [pscustomobject]@{ name = 'QGISCF - Group'; displayName = 'Group'; isGroup = $true }
            ls = [pscustomobject]@{ name = 'QGISCF - Group - Child'; displayName = 'Child'; isGroup = $false; parentGroup = 'QGISCF - Group'; parentLabelName = 'QGISCF - Group' }
        }

        $map = Get-Compl8ExecutorMap -StepContent $content -Prefix 'QGISCF' -SleepAction { param($s) }

        # Group create seeds the shared cache.
        $rg = & $map['label'] $groupStep
        $rg.status | Should -Be 'created'
        $rg.guid   | Should -Be $parentGuid

        # Sublabel must be CREATED using the cached parent GUID, NOT skipped as parent-not-found.
        $rs = & $map['label'] $subStep
        $rs.status   | Should -Be 'created'
        $rs.parentId | Should -Be $parentGuid

        Should -Invoke -ModuleName Compl8.Engine New-Label -Times 2
    }
}

Describe 'E2E — the plan from real assess+plan exercises every actionable kind + a propagation gate' {
    BeforeAll {
        $script:fx = New-E2EPlanFile -Id 'plan-e2e-shape'
        $script:plan = $script:fx.Plan
    }
    AfterAll {
        if ($script:fx.WorkRoot -and (Test-Path -LiteralPath $script:fx.WorkRoot)) {
            Remove-Item -LiteralPath $script:fx.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'contains a create, an update-in-place, a remove and a generated dereference step' {
        @($script:plan.steps | Where-Object { $_.action -eq 'create' }).Count       | Should -BeGreaterThan 0
        @($script:plan.steps | Where-Object { $_.action -eq 'update' -and $_.objectType -eq 'rulePackage' }).Count | Should -BeGreaterThan 0
        @($script:plan.steps | Where-Object { $_.action -eq 'remove' }).Count        | Should -BeGreaterThan 0
        @($script:plan.steps | Where-Object { $_.action -eq 'dereference' }).Count   | Should -BeGreaterThan 0
    }

    It 'attaches a propagation gate to the drift rule step that depends on the updated package' {
        $ruleStep = @($script:plan.steps | Where-Object { $_.objectType -eq 'dlpRule' -and $_.action -eq 'update' -and $_.objectRef -eq 'QGISCF-QLD-Medium-Email-07' })[0]
        $ruleStep            | Should -Not -BeNullOrEmpty
        $ruleStep.gate.type  | Should -Be 'propagation'
        $ruleStep.gate.notBeforeOffsetHours | Should -Be 4
    }
}

Describe 'E2E [1] snapshotBeforeDestroy runs BEFORE any destructive step' {
    BeforeAll {
        $script:fx = New-E2EPlanFile -Id 'plan-e2e-snap'
        Set-E2ESccMocks
        # Clock AFTER the propagation window so the gated rule also applies in this single pass.
        $script:map = New-E2EExecutorMap -Plan $script:fx.Plan -WorkRoot $script:fx.WorkRoot -Inventory $script:fx.Inventory
        $script:result = Invoke-Compl8Apply -PlanPath $script:fx.PlanPath `
            -ResolveManifestHash $script:fx.Plan.inputs.resolveManifest -InventoryHash $script:fx.Plan.inputs.inventory `
            -ProjectRoot $script:RepoRoot -ExecutorMap $script:map -ConfirmExternalRefs `
            -Now ([datetime]'2026-06-14T00:00:00Z')
        $script:appliesDir = Join-Path $script:fx.WorkRoot 'history' 'applies' 'plan-e2e-snap'
    }
    AfterAll {
        if ($script:fx.WorkRoot -and (Test-Path -LiteralPath $script:fx.WorkRoot)) {
            Remove-Item -LiteralPath $script:fx.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'applies the snapshot step (action=snapshot) and records its result' {
        $snap = @($script:result.steps | Where-Object { $_.action -eq 'snapshot' })[0]
        $snap        | Should -Not -BeNullOrEmpty
        $snap.status | Should -Be 'applied'
        # The snapshot executor wrote actual/snapshots/<ts>/ (the Tenant reader owns actual/, D8).
        Test-Path -LiteralPath (Join-Path $script:fx.WorkRoot 'actual' 'snapshots' '20260613_000000' 'inventory.json') | Should -BeTrue
    }

    It 'checkpoints the snapshot step BEFORE any destructive (remove/dereference) step' {
        # Every destructive step depends on the snapshot, and apply walks dependency order, so the
        # snapshot checkpoint exists and each destructive step applied AFTER it.
        $snapId = @($script:fx.Plan.steps | Where-Object { $_.action -eq 'snapshot' })[0].id
        Test-Path -LiteralPath (Join-Path $script:appliesDir "$snapId.json") | Should -BeTrue

        $ids = @($script:result.steps | ForEach-Object stepId)
        $snapIdx = [array]::IndexOf($ids, $snapId)
        $snapIdx | Should -BeGreaterOrEqual 0
        foreach ($d in @($script:result.steps | Where-Object { $_.action -in 'remove', 'dereference' })) {
            $dIdx = [array]::IndexOf($ids, $d.stepId)
            $dIdx | Should -BeGreaterThan $snapIdx -Because "destructive step '$($d.stepId)' must apply after the snapshot"
            # And every destructive step declares the snapshot as a dependency in the plan.
            $planStep = @($script:fx.Plan.steps | Where-Object { $_.id -eq $d.stepId })[0]
            @($planStep.dependsOn) | Should -Contain $snapId
        }
    }
}

Describe 'E2E [2] a removal of a referenced classifier generates+applies dereference BEFORE the removal' {
    BeforeAll {
        $script:fx = New-E2EPlanFile -Id 'plan-e2e-deref'
        Set-E2ESccMocks
        $script:map = New-E2EExecutorMap -Plan $script:fx.Plan -WorkRoot $script:fx.WorkRoot -Inventory $script:fx.Inventory
        $script:result = Invoke-Compl8Apply -PlanPath $script:fx.PlanPath `
            -ResolveManifestHash $script:fx.Plan.inputs.resolveManifest -InventoryHash $script:fx.Plan.inputs.inventory `
            -ProjectRoot $script:RepoRoot -ExecutorMap $script:map -ConfirmExternalRefs `
            -Now ([datetime]'2026-06-14T00:00:00Z')
    }
    AfterAll {
        if ($script:fx.WorkRoot -and (Test-Path -LiteralPath $script:fx.WorkRoot)) {
            Remove-Item -LiteralPath $script:fx.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'generated a dereference step for the rule that references the removed classifier (shared-b)' {
        $deref = @($script:fx.Plan.steps | Where-Object { $_.action -eq 'dereference' -and $_.objectRef -eq 'QGISCF-Bravo-Deref-09' })[0]
        $deref | Should -Not -BeNullOrEmpty
        @($deref.impact) | Should -Contain 'shared-b'
    }

    It 'applied the dereference step via the real DLP-rule executor (Set-DlpComplianceRule, shared-a remains)' {
        $deref = @($script:result.steps | Where-Object { $_.action -eq 'dereference' })[0]
        $deref.status | Should -Be 'applied'
        # The executor stripped shared-b but kept shared-a -> a trimmed Set, not a rule delete.
        $deref.result.status        | Should -Be 'dereferenced'
        @($deref.result.strippedSits) | Should -Contain '44444444-aaaa-4bbb-8ccc-000000000004'
        @($deref.result.remainingSits)| Should -Contain '33333333-aaaa-4bbb-8ccc-000000000003'
        # The apply ran in BeforeAll, so assert the mutation at the Describe scope.
        Should -Invoke -ModuleName Compl8.Engine Set-DlpComplianceRule -Scope Describe -Times 1 -Exactly -ParameterFilter { $Identity -eq 'QGISCF-Bravo-Deref-09' }
    }

    It 'ordered the dereference step BEFORE the shared-b removal (and the removal depends on it)' {
        $ids = @($script:result.steps | ForEach-Object stepId)
        $derefStep  = @($script:fx.Plan.steps | Where-Object { $_.action -eq 'dereference' -and $_.objectRef -eq 'QGISCF-Bravo-Deref-09' })[0]
        $removeStep = @($script:fx.Plan.steps | Where-Object { $_.action -eq 'remove' -and $_.objectRef -eq 'shared-b' })[0]
        ([array]::IndexOf($ids, $derefStep.id)) | Should -BeLessThan ([array]::IndexOf($ids, $removeStep.id))
        @($removeStep.dependsOn) | Should -Contain $derefStep.id
        # Both applied (the removal was not blocked because the dereference ran first).
        (@($script:result.steps | Where-Object { $_.stepId -eq $removeStep.id })[0]).status | Should -Be 'applied'
    }
}

Describe 'E2E [3] the propagation gate HALTS the dependent rule until the offset elapses' {
    BeforeAll {
        $script:fx = New-E2EPlanFile -Id 'plan-e2e-prop'
        $script:appliesDir = Join-Path $script:fx.WorkRoot 'history' 'applies' 'plan-e2e-prop'
        Set-E2ESccMocks
        $script:map = New-E2EExecutorMap -Plan $script:fx.Plan -WorkRoot $script:fx.WorkRoot -Inventory $script:fx.Inventory

        $script:ruleStep = @($script:fx.Plan.steps | Where-Object { $_.objectType -eq 'dlpRule' -and $_.action -eq 'update' -and $_.objectRef -eq 'QGISCF-QLD-Medium-Email-07' })[0]

        # FIRST run: clock is EARLY (well before the package-apply + 4h window) — the gated rule step
        # is BLOCKED. -ContinueOnBlock so the independent rest of the plan still applies.
        $script:early = Invoke-Compl8Apply -PlanPath $script:fx.PlanPath `
            -ResolveManifestHash $script:fx.Plan.inputs.resolveManifest -InventoryHash $script:fx.Plan.inputs.inventory `
            -ProjectRoot $script:RepoRoot -ExecutorMap $script:map -ConfirmExternalRefs -ContinueOnBlock `
            -Now ([datetime]'2026-06-13T00:00:01Z')
    }
    AfterAll {
        if ($script:fx.WorkRoot -and (Test-Path -LiteralPath $script:fx.WorkRoot)) {
            Remove-Item -LiteralPath $script:fx.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'BLOCKS the propagation-gated rule step with an early clock (no Set on that rule, no checkpoint)' {
        $blocked = @($script:early.steps | Where-Object { $_.stepId -eq $script:ruleStep.id })[0]
        $blocked.status | Should -Be 'blocked'
        $blocked.reason | Should -Match 'propagation'
        # A blocked step writes NO checkpoint (so the next run re-evaluates the gate) — the direct
        # proof the rule was not applied (its executor / Set-DlpComplianceRule never ran).
        Test-Path -LiteralPath (Join-Path $script:appliesDir "$($script:ruleStep.id).json") | Should -BeFalse
    }

    It 'PROCEEDS on a later clock (after the offset): the gated rule applies and checkpoints' {
        # The package step (s03) checkpointed in the early run at 2026-06-13T00:00:01Z; the gate is
        # depApply + 4h. A clock past that lets the rule through on resume.
        $late = Invoke-Compl8Apply -PlanPath $script:fx.PlanPath `
            -ResolveManifestHash $script:fx.Plan.inputs.resolveManifest -InventoryHash $script:fx.Plan.inputs.inventory `
            -ProjectRoot $script:RepoRoot -ExecutorMap $script:map -ConfirmExternalRefs `
            -Now ([datetime]'2026-06-13T12:00:00Z')
        $applied = @($late.steps | Where-Object { $_.stepId -eq $script:ruleStep.id })[0]
        $applied.status | Should -Be 'applied'
        Test-Path -LiteralPath (Join-Path $script:appliesDir "$($script:ruleStep.id).json") | Should -BeTrue
        Should -Invoke -ModuleName Compl8.Engine Set-DlpComplianceRule -Times 1 -Exactly -ParameterFilter { $Identity -eq 'QGISCF-QLD-Medium-Email-07' }
    }
}

Describe 'E2E [4] checkpoint/resume: kill mid-plan, re-run SKIPS completed steps' {
    BeforeAll {
        $script:fx = New-E2EPlanFile -Id 'plan-e2e-resume'
        $script:appliesDir = Join-Path $script:fx.WorkRoot 'history' 'applies' 'plan-e2e-resume'
        Set-E2ESccMocks
        $script:baseMap = New-E2EExecutorMap -Plan $script:fx.Plan -WorkRoot $script:fx.WorkRoot -Inventory $script:fx.Inventory

        # Wrap the rule-package executor so it THROWS on the FIRST run (mid-plan kill at the package
        # step) — but counts invocations so the resume can be measured. A later clock so propagation
        # is not what stops us; the THROW is.
        #
        # The wrapper state lives in a HASHTABLE captured by .GetNewClosure(): the apply dispatcher
        # invokes the executor in the Compl8.Engine MODULE scope, where a `$script:` variable would
        # resolve to the MODULE's script scope (NOT this test file's) — so the throw toggle / counter
        # must be a closed-over object reference the closure mutates regardless of execution scope.
        $script:killState = @{ FailPackage = $true; PackageCalls = 0 }
        $killState = $script:killState
        $innerRp = $script:baseMap['rulePackage']
        $script:killMap = @{} + $script:baseMap
        $script:killMap['rulePackage'] = {
            param($Step)
            $killState.PackageCalls++
            if ($killState.FailPackage) { throw "INJECTED mid-plan kill at $($Step.id) ($($Step.objectRef))" }
            & $innerRp $Step
        }.GetNewClosure()

        # FIRST run: the package step throws -> apply halts; steps before it are checkpointed.
        $script:firstError = $null
        try {
            Invoke-Compl8Apply -PlanPath $script:fx.PlanPath `
                -ResolveManifestHash $script:fx.Plan.inputs.resolveManifest -InventoryHash $script:fx.Plan.inputs.inventory `
                -ProjectRoot $script:RepoRoot -ExecutorMap $script:killMap -ConfirmExternalRefs `
                -Now ([datetime]'2026-06-14T00:00:00Z') | Out-Null
        } catch { $script:firstError = $_ }

        $script:pkgStepId  = @($script:fx.Plan.steps | Where-Object { $_.objectType -eq 'rulePackage' -and $_.action -eq 'update' })[0].id
        $script:snapStepId = @($script:fx.Plan.steps | Where-Object { $_.action -eq 'snapshot' })[0].id
        $script:dictStepId = @($script:fx.Plan.steps | Where-Object { $_.objectType -eq 'dictionary' })[0].id
    }
    AfterAll {
        if ($script:fx.WorkRoot -and (Test-Path -LiteralPath $script:fx.WorkRoot)) {
            Remove-Item -LiteralPath $script:fx.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'the first run fails at the injected package step' {
        $script:firstError | Should -Not -BeNullOrEmpty
        $script:firstError.Exception.Message | Should -Match 'INJECTED mid-plan kill'
    }

    It 'checkpoints the steps BEFORE the kill (snapshot + dictionary) but NOT the failed package step' {
        Test-Path -LiteralPath (Join-Path $script:appliesDir "$($script:snapStepId).json") | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:appliesDir "$($script:dictStepId).json") | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:appliesDir "$($script:pkgStepId).json")  | Should -BeFalse
    }

    It 're-running SKIPS the already-checkpointed steps and RESUMES (package retried, plan completes)' {
        # Let the package step succeed this time; the resume must NOT re-run snapshot/dictionary.
        # Mutating the closed-over hashtable flips the wrapper to the success path on the same map.
        $script:killState.FailPackage = $false
        $script:killState.PackageCalls = 0
        Set-E2ESccMocks   # re-arm mocks for the fresh Pester run scope

        # RESUME pass (early clock): the package retries and applies; the propagation-gated rule
        # correctly blocks (its package just applied — the 4h window has not elapsed). -ContinueOnBlock
        # so the resume completes the rest. Snapshot + dictionary are SKIPPED (already checkpointed).
        $resume = Invoke-Compl8Apply -PlanPath $script:fx.PlanPath `
            -ResolveManifestHash $script:fx.Plan.inputs.resolveManifest -InventoryHash $script:fx.Plan.inputs.inventory `
            -ProjectRoot $script:RepoRoot -ExecutorMap $script:killMap -ConfirmExternalRefs -ContinueOnBlock `
            -Now ([datetime]'2026-06-13T00:00:00Z')

        # The package executor ran exactly once now (the retry); snapshot + dictionary were skipped.
        $script:killState.PackageCalls | Should -Be 1
        $snap = @($resume.steps | Where-Object { $_.stepId -eq $script:snapStepId })[0]
        $dict = @($resume.steps | Where-Object { $_.stepId -eq $script:dictStepId })[0]
        $pkg  = @($resume.steps | Where-Object { $_.stepId -eq $script:pkgStepId })[0]
        $snap.status | Should -Be 'skipped'
        $dict.status | Should -Be 'skipped'
        $pkg.status  | Should -Be 'applied'

        # FINAL pass (clock past the propagation offset): the already-applied steps are skipped and
        # the previously-gated rule now lands — every step ends with a checkpoint.
        $final = Invoke-Compl8Apply -PlanPath $script:fx.PlanPath `
            -ResolveManifestHash $script:fx.Plan.inputs.resolveManifest -InventoryHash $script:fx.Plan.inputs.inventory `
            -ProjectRoot $script:RepoRoot -ExecutorMap $script:killMap -ConfirmExternalRefs `
            -Now ([datetime]'2026-06-13T12:00:00Z')
        $script:killState.PackageCalls | Should -Be 1 -Because 'the package was already checkpointed on resume; the final pass must not re-run it'
        @($final.steps | Where-Object { $_.status -eq 'blocked' }) | Should -BeNullOrEmpty
        foreach ($s in $script:fx.Plan.steps) {
            Test-Path -LiteralPath (Join-Path $script:appliesDir "$($s.id).json") | Should -BeTrue -Because "checkpoint for $($s.id)"
        }
    }
}

Describe 'E2E [5] result.json records EVERY step exactly once' {
    BeforeAll {
        $script:fx = New-E2EPlanFile -Id 'plan-e2e-result'
        Set-E2ESccMocks
        $script:map = New-E2EExecutorMap -Plan $script:fx.Plan -WorkRoot $script:fx.WorkRoot -Inventory $script:fx.Inventory

        # PASS 1 (early clock): everything applies EXCEPT the propagation-gated rule, which correctly
        # blocks (its package was just uploaded — the 4h window has not elapsed). -ContinueOnBlock so
        # the rest of the plan still lands and a checkpoint exists for every non-gated step.
        $script:pass1 = Invoke-Compl8Apply -PlanPath $script:fx.PlanPath `
            -ResolveManifestHash $script:fx.Plan.inputs.resolveManifest -InventoryHash $script:fx.Plan.inputs.inventory `
            -ProjectRoot $script:RepoRoot -ExecutorMap $script:map -ConfirmExternalRefs -ContinueOnBlock `
            -Now ([datetime]'2026-06-13T00:00:00Z')

        # PASS 2 (clock advanced PAST the propagation offset): the already-applied steps are skipped
        # and the gated rule now PROCEEDS — the plan resumes to completion.
        $script:pass2 = Invoke-Compl8Apply -PlanPath $script:fx.PlanPath `
            -ResolveManifestHash $script:fx.Plan.inputs.resolveManifest -InventoryHash $script:fx.Plan.inputs.inventory `
            -ProjectRoot $script:RepoRoot -ExecutorMap $script:map -ConfirmExternalRefs `
            -Now ([datetime]'2026-06-13T12:00:00Z')
        $script:resultPath = Join-Path $script:fx.WorkRoot 'history' 'applies' 'plan-e2e-result' 'result.json'
    }
    AfterAll {
        if ($script:fx.WorkRoot -and (Test-Path -LiteralPath $script:fx.WorkRoot)) {
            Remove-Item -LiteralPath $script:fx.WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'writes history/applies/<planId>/result.json' {
        Test-Path -LiteralPath $script:resultPath | Should -BeTrue
    }

    It 'the final result.json records every plan step EXACTLY once (no missing, no duplicate)' {
        $persisted = Get-Content -LiteralPath $script:resultPath -Raw | ConvertFrom-Json
        $planIds   = @($script:fx.Plan.steps | ForEach-Object id | Sort-Object)
        $resultIds = @($persisted.steps | ForEach-Object stepId | Sort-Object)
        $resultIds | Should -Be $planIds
        (@($persisted.steps | Group-Object stepId | Where-Object { $_.Count -gt 1 })) | Should -BeNullOrEmpty
    }

    It 'every step lands once the propagation window has elapsed (pass 2 completes the plan)' {
        # Pass 1: every step applied except the gated rule, which is correctly blocked.
        $p1Blocked = @($script:pass1.steps | Where-Object { $_.status -eq 'blocked' })
        $p1Blocked.Count | Should -Be 1
        $p1Blocked[0].action | Should -Be 'update'
        $p1Blocked[0].objectType | Should -Be 'dlpRule'
        # Pass 2: the gated rule is now applied; every step has a checkpoint (the plan is complete).
        $persisted = Get-Content -LiteralPath $script:resultPath -Raw | ConvertFrom-Json
        @($persisted.steps | Where-Object { $_.status -eq 'blocked' }) | Should -BeNullOrEmpty -Because 'pass 2 clears the propagation gate'
        $appliesDir = Join-Path $script:fx.WorkRoot 'history' 'applies' 'plan-e2e-result'
        foreach ($s in $script:fx.Plan.steps) {
            Test-Path -LiteralPath (Join-Path $appliesDir "$($s.id).json") | Should -BeTrue -Because "checkpoint for $($s.id)"
        }
    }
}
