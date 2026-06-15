#Requires -Modules Pester

# Compl8.Engine — Get-Compl8PlanOrder: the PURE graph-derived plan ordering + de-reference
# step generation (Stage 4 PHASE 4B, Task 4). Given an assessment (Invoke-Compl8Assess
# output) and a reference graph (Get-DeploymentReferenceGraph), it returns an ORDERED list
# of plan steps:
#   - creates/updates walk the dependency graph FORWARD
#     (dictionaries -> rule packages -> [propagation gate] -> labels -> DLP/auto-label rules);
#   - removals walk the graph BACKWARD;
#   - a `remove` of a classifier/SIT still referenced by live DLP rules GENERATES one
#     `dereference` step per referencing rule, ordered BEFORE the removal step (D5);
#   - a `propagation` gate is attached to a rule/auto-label step ONLY when that step depends
#     on a rule package created/updated IN THIS SAME PLAN;
#   - a dependency cycle throws a clear error.
#
# The function is PURE — no tenant call. Referencing rules for de-reference are derived from
# the GRAPH's sitReferencedByRule edges (the same shape the reference guard's References
# output carries), NOT by calling Test-DlpRulePackageRemovalReferenceGuard (which reads the
# tenant). Step ids are deterministic (derived from object refs/sequence, never time/random).

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot  = Split-Path $PSScriptRoot -Parent
    $script:EngineDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:EngineDir -Force

    # ----------------------------------------------------------------- assessment factory
    # Build a minimal compl8.assessment/v1 object from bucket hashtables. Mirrors the
    # New-AssessmentObject shape; we hand-roll it here so the Plan tests do not depend on a
    # specific assessment fixture and can target each ordering rule precisely.
    function New-TestAssessment {
        param([hashtable]$Buckets = @{}, [object[]]$Impact = @())
        $enums = Get-Compl8EngineSchemaEnums
        $b = [ordered]@{}
        foreach ($name in $enums.Buckets) {
            $b[$name] = @(if ($Buckets.ContainsKey($name)) { $Buckets[$name] } else { @() })
        }
        [pscustomobject]@{
            schemaVersion    = 'compl8.assessment/v1'
            workspace        = 'nonprod'
            generatedUtc     = '2026-06-13T00:00:00Z'
            inputs           = [pscustomobject]@{ resolveManifest = 'sha256:aa'; inventory = 'sha256:bb' }
            buckets          = [pscustomobject]$b
            upgradeConflicts = @()
            impact           = @($Impact)
        }
    }

    function New-BucketEntry {
        param([string]$ObjectType, [string]$Ref, [hashtable]$Extra = @{})
        $rec = [ordered]@{ objectType = $ObjectType; ref = $Ref }
        foreach ($k in (@($Extra.Keys) | Sort-Object)) { $rec[$k] = $Extra[$k] }
        [pscustomobject]$rec
    }

    # A rule-package XML carrying one entity (so the graph extracts a sit node + edges).
    function New-PkgXml {
        param([string]$EntityId, [string]$DictGuid)
        $dictRef = if ($DictGuid) { "<Group matchStyle='word'><Term id='$DictGuid' /></Group>" } else { '' }
        @"
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="00000000-0000-4000-8000-000000000000"><Version major="1" minor="0" build="0" revision="0" /></RulePack>
  <Rules>
    <Entity id="$EntityId" patternsProximity="300" recommendedConfidence="85">
      <Pattern confidenceLevel="85"><IdMatch idRef="kw" />$dictRef</Pattern>
    </Entity>
    <Keyword id="kw"><Group matchStyle="word"><Term>alpha</Term></Group></Keyword>
  </Rules>
</RulePackage>
"@
    }

    # A graph built from desired packages + actual dlp rules — the same call Assess makes.
    function New-TestGraph {
        param([object[]]$SitPackages = @(), [object[]]$DlpRules = @(), [object[]]$Dictionaries = @())
        Get-DeploymentReferenceGraph -SitPackages $SitPackages -DlpRules $DlpRules -Dictionaries $Dictionaries
    }
}

Describe 'Get-Compl8PlanOrder — module surface' {
    It 'exports Get-Compl8PlanOrder from Compl8.Engine' {
        (Get-Command -Name Get-Compl8PlanOrder -Module Compl8.Engine -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-Compl8PlanOrder — forward order (dictionary -> rule package -> rule)' {
    BeforeAll {
        $sitGuid = '22222222-aaaa-4bbb-8ccc-000000000002'
        $dictGuid = 'dddddddd-aaaa-4bbb-8ccc-00000000000d'
        $pkg = [pscustomobject]@{
            Identity = 'QGISCF-test-01'; Name = 'QGISCF-test-01'; Publisher = 'Compl8'
            SerializedClassificationRuleCollection = (New-PkgXml -EntityId $sitGuid -DictGuid $dictGuid)
        }
        $rule = [pscustomobject]@{
            Name = 'QGISCF-QLD-Medium-Email-07'; Identity = 'QGISCF-QLD-Medium-Email-07'; Policy = 'P01'
            ContentContainsSensitiveInformation = "[{`"id`":`"$sitGuid`"}]"
        }
        $script:fwGraph = New-TestGraph -SitPackages @($pkg) -DlpRules @($rule)
        $script:fwAssessment = New-TestAssessment -Buckets @{
            'create'          = @(New-BucketEntry -ObjectType 'dictionary' -Ref '{{DICT_X}}')
            'update-in-place' = @(New-BucketEntry -ObjectType 'rulePackage' -Ref 'QGISCF-test-01' -Extra @{ entityId = 'cafebabe-cafe-4abe-8abe-cafebabecafe' })
            'drift'           = @(New-BucketEntry -ObjectType 'dlpRule' -Ref 'QGISCF-QLD-Medium-Email-07')
        }
        $script:fwSteps = @(Get-Compl8PlanOrder -Assessment $script:fwAssessment -Graph $script:fwGraph)
        function Get-StepIndex { param([string]$ObjectType, [string]$Ref)
            for ($i = 0; $i -lt $script:fwSteps.Count; $i++) {
                if ($script:fwSteps[$i].objectType -eq $ObjectType -and $script:fwSteps[$i].objectRef -eq $Ref) { return $i }
            }
            return -1
        }
    }

    It 'orders the dictionary step before the rule-package step before the rule step' {
        $dictIdx = Get-StepIndex -ObjectType 'dictionary' -Ref '{{DICT_X}}'
        $pkgIdx  = Get-StepIndex -ObjectType 'rulePackage' -Ref 'QGISCF-test-01'
        $ruleIdx = Get-StepIndex -ObjectType 'dlpRule' -Ref 'QGISCF-QLD-Medium-Email-07'
        $dictIdx | Should -BeGreaterOrEqual 0
        $pkgIdx  | Should -BeGreaterThan $dictIdx
        $ruleIdx | Should -BeGreaterThan $pkgIdx
    }

    It 'expresses the order in dependsOn (rule depends on the package step)' {
        $pkgStep  = @($script:fwSteps | Where-Object { $_.objectType -eq 'rulePackage' -and $_.objectRef -eq 'QGISCF-test-01' })[0]
        $ruleStep = @($script:fwSteps | Where-Object { $_.objectType -eq 'dlpRule' -and $_.objectRef -eq 'QGISCF-QLD-Medium-Email-07' })[0]
        @($ruleStep.dependsOn) | Should -Contain $pkgStep.id
    }

    It 'produces steps that pass Test-PlanSchema (referential dependsOn + known enums)' {
        $plan = New-PlanObject -Workspace 'nonprod' -Id 'plan-fw'
        $plan.steps = @($script:fwSteps)
        $r = Test-PlanSchema -Plan $plan
        $r.Valid | Should -BeTrue -Because (@($r.Errors) -join '; ')
    }
}

Describe 'Get-Compl8PlanOrder — de-reference generation (D5)' {
    BeforeAll {
        # A classifier (sit) removal where the entity is referenced by TWO live DLP rules.
        $sitGuid = '11111111-aaaa-4bbb-8ccc-000000000001'
        $pkg = [pscustomobject]@{
            Identity = 'QGISCF-test-02'; Name = 'QGISCF-test-02'; Publisher = 'Compl8'
            SerializedClassificationRuleCollection = (New-PkgXml -EntityId $sitGuid -DictGuid $null)
        }
        $ruleA = [pscustomobject]@{ Name = 'QGISCF-RuleA'; Identity = 'QGISCF-RuleA'; Policy = 'P01'
            ContentContainsSensitiveInformation = "[{`"id`":`"$sitGuid`"}]" }
        $ruleB = [pscustomobject]@{ Name = 'QGISCF-RuleB'; Identity = 'QGISCF-RuleB'; Policy = 'P02'
            ContentContainsSensitiveInformation = "[{`"id`":`"$sitGuid`"}]" }
        $script:drGraph = New-TestGraph -SitPackages @($pkg) -DlpRules @($ruleA, $ruleB)
        $script:drAssessment = New-TestAssessment -Buckets @{
            'remove' = @(New-BucketEntry -ObjectType 'sit' -Ref 'bail-note' -Extra @{ identity = $sitGuid })
        } -Impact @(
            [pscustomobject]@{ objectRef = 'bail-note'; affects = @('dlp-rule: QGISCF-RuleA', 'dlp-rule: QGISCF-RuleB') }
        )
        $script:drSteps = @(Get-Compl8PlanOrder -Assessment $script:drAssessment -Graph $script:drGraph)
    }

    It 'generates one dereference step per referencing rule (two rules -> two dereference steps)' {
        $deref = @($script:drSteps | Where-Object { $_.action -eq 'dereference' })
        $deref.Count | Should -Be 2
        @($deref | ForEach-Object objectRef) | Should -Contain 'QGISCF-RuleA'
        @($deref | ForEach-Object objectRef) | Should -Contain 'QGISCF-RuleB'
    }

    It 'orders BOTH dereference steps before the remove step' {
        $removeIdx = -1
        for ($i = 0; $i -lt $script:drSteps.Count; $i++) {
            if ($script:drSteps[$i].action -eq 'remove' -and $script:drSteps[$i].objectRef -eq 'bail-note') { $removeIdx = $i }
        }
        $removeIdx | Should -BeGreaterThan -1
        foreach ($d in @($script:drSteps | Where-Object { $_.action -eq 'dereference' })) {
            $dIdx = [array]::IndexOf($script:drSteps, $d)
            $dIdx | Should -BeLessThan $removeIdx -Because "dereference '$($d.objectRef)' must precede the remove"
        }
    }

    It 'makes the remove step depend on every generated dereference step' {
        $removeStep = @($script:drSteps | Where-Object { $_.action -eq 'remove' -and $_.objectRef -eq 'bail-note' })[0]
        foreach ($d in @($script:drSteps | Where-Object { $_.action -eq 'dereference' })) {
            @($removeStep.dependsOn) | Should -Contain $d.id
        }
    }

    It 'produces steps that pass Test-PlanSchema' {
        $plan = New-PlanObject -Workspace 'nonprod' -Id 'plan-dr'
        $plan.steps = @($script:drSteps)
        $r = Test-PlanSchema -Plan $plan
        $r.Valid | Should -BeTrue -Because (@($r.Errors) -join '; ')
    }
}

Describe 'Get-Compl8PlanOrder — propagation gate placement' {
    It 'attaches a propagation gate to a rule step whose dependency package is changed in this plan' {
        $sitGuid = '22222222-aaaa-4bbb-8ccc-000000000002'
        $pkg = [pscustomobject]@{ Identity = 'QGISCF-test-01'; Name = 'QGISCF-test-01'; Publisher = 'Compl8'
            SerializedClassificationRuleCollection = (New-PkgXml -EntityId $sitGuid -DictGuid $null) }
        $rule = [pscustomobject]@{ Name = 'QGISCF-Rule-Changed'; Identity = 'QGISCF-Rule-Changed'; Policy = 'P01'
            ContentContainsSensitiveInformation = "[{`"id`":`"$sitGuid`"}]" }
        $graph = New-TestGraph -SitPackages @($pkg) -DlpRules @($rule)
        $assessment = New-TestAssessment -Buckets @{
            'update-in-place' = @(New-BucketEntry -ObjectType 'rulePackage' -Ref 'QGISCF-test-01')
            'drift'           = @(New-BucketEntry -ObjectType 'dlpRule' -Ref 'QGISCF-Rule-Changed')
        }
        $steps = @(Get-Compl8PlanOrder -Assessment $assessment -Graph $graph)
        $ruleStep = @($steps | Where-Object { $_.objectType -eq 'dlpRule' -and $_.objectRef -eq 'QGISCF-Rule-Changed' })[0]
        $ruleStep.gate | Should -Not -BeNullOrEmpty
        $ruleStep.gate.type | Should -Be 'propagation'
        $ruleStep.gate.notBeforeOffsetHours | Should -Be 4
    }

    It 'does NOT attach a propagation gate to a rule depending on an UNCHANGED package' {
        # The package is present in the graph (so the dependency edge exists) but is NOT in any
        # actionable bucket — it is not created/updated this plan, so no propagation is needed.
        $sitGuid = '33333333-aaaa-4bbb-8ccc-000000000003'
        $pkg = [pscustomobject]@{ Identity = 'QGISCF-unchanged'; Name = 'QGISCF-unchanged'; Publisher = 'Compl8'
            SerializedClassificationRuleCollection = (New-PkgXml -EntityId $sitGuid -DictGuid $null) }
        $rule = [pscustomobject]@{ Name = 'QGISCF-Rule-Unchanged'; Identity = 'QGISCF-Rule-Unchanged'; Policy = 'P01'
            ContentContainsSensitiveInformation = "[{`"id`":`"$sitGuid`"}]" }
        $graph = New-TestGraph -SitPackages @($pkg) -DlpRules @($rule)
        $assessment = New-TestAssessment -Buckets @{
            'drift' = @(New-BucketEntry -ObjectType 'dlpRule' -Ref 'QGISCF-Rule-Unchanged')
        }
        $steps = @(Get-Compl8PlanOrder -Assessment $assessment -Graph $graph)
        $ruleStep = @($steps | Where-Object { $_.objectType -eq 'dlpRule' -and $_.objectRef -eq 'QGISCF-Rule-Unchanged' })[0]
        $ruleStep | Should -Not -BeNullOrEmpty
        $ruleStep.gate | Should -BeNullOrEmpty
    }
}

Describe 'Get-Compl8PlanOrder — drift of updatable policy types is stepped (codex R4 P2)' {
    # The executor map can update dlpPolicy / autoLabelPolicy, and assess emits drift for them, so the
    # planner must turn that drift into an `update` step (previously only dlpRule drift was stepped).
    It 'turns a drifted dlpPolicy into an update step (no package dependency)' {
        $graph = New-TestGraph
        $assessment = New-TestAssessment -Buckets @{ 'drift' = @(New-BucketEntry -ObjectType 'dlpPolicy' -Ref 'P01-ECH-QGISCF-EXT-ADT') }
        $steps = @(Get-Compl8PlanOrder -Assessment $assessment -Graph $graph)
        $polStep = @($steps | Where-Object { $_.objectType -eq 'dlpPolicy' -and $_.objectRef -eq 'P01-ECH-QGISCF-EXT-ADT' })
        $polStep.Count        | Should -Be 1
        $polStep[0].action    | Should -Be 'update'
        $polStep[0].gate      | Should -BeNullOrEmpty
    }
    It 'turns a drifted autoLabelPolicy into an update step' {
        $graph = New-TestGraph
        $assessment = New-TestAssessment -Buckets @{ 'drift' = @(New-BucketEntry -ObjectType 'autoLabelPolicy' -Ref 'QGISCF-AL-01') }
        $steps = @(Get-Compl8PlanOrder -Assessment $assessment -Graph $graph)
        @($steps | Where-Object { $_.objectType -eq 'autoLabelPolicy' -and $_.action -eq 'update' }).Count | Should -Be 1
    }
    It 'does NOT step a drifted sit (its content lives in its rule package)' {
        $graph = New-TestGraph
        $assessment = New-TestAssessment -Buckets @{ 'drift' = @(New-BucketEntry -ObjectType 'sit' -Ref 'QGISCF-sit-01') }
        $steps = @(Get-Compl8PlanOrder -Assessment $assessment -Graph $graph)
        @($steps | Where-Object { $_.objectType -eq 'sit' }).Count | Should -Be 0
    }
}

Describe 'Get-Compl8PlanOrder — cycle detection' {
    It 'throws a clear error on a dependency cycle' {
        # Construct a graph whose dependency wiring (a package depends on the dictionaries that
        # feed its sits) is cyclic: package A's sit is fed by a "dictionary" whose identity is
        # 'B', and package B's sit is fed by a "dictionary" whose identity is 'A'. Both A and B
        # are changed rule packages this plan, so each becomes a step that depends on the other —
        # an unbreakable cycle the topological sort must reject with a clear error.
        $sitA = 'aaaaaaaa-aaaa-4bbb-8ccc-00000000000a'
        $sitB = 'bbbbbbbb-aaaa-4bbb-8ccc-00000000000b'
        $cycleGraph = [pscustomobject]@{
            Nodes = @(
                [pscustomobject]@{ Id = 'sitPackage:A'; Type = 'SitPackage'; Name = 'A'; Identity = 'A' }
                [pscustomobject]@{ Id = 'sitPackage:B'; Type = 'SitPackage'; Name = 'B'; Identity = 'B' }
                [pscustomobject]@{ Id = "sit:$sitA"; Type = 'SensitiveInformationType'; Name = $null; Identity = $sitA }
                [pscustomobject]@{ Id = "sit:$sitB"; Type = 'SensitiveInformationType'; Name = $null; Identity = $sitB }
                [pscustomobject]@{ Id = 'dictionary:B'; Type = 'KeywordDictionary'; Name = $null; Identity = 'B' }
                [pscustomobject]@{ Id = 'dictionary:A'; Type = 'KeywordDictionary'; Name = $null; Identity = 'A' }
            )
            Edges = @(
                [pscustomobject]@{ From = 'sitPackage:A'; To = "sit:$sitA"; Type = 'packageContainsSit' }
                [pscustomobject]@{ From = 'sitPackage:B'; To = "sit:$sitB"; Type = 'packageContainsSit' }
                [pscustomobject]@{ From = 'dictionary:B'; To = "sit:$sitA"; Type = 'dictionaryFeedsSit' }
                [pscustomobject]@{ From = 'dictionary:A'; To = "sit:$sitB"; Type = 'dictionaryFeedsSit' }
            )
            Summary = [pscustomobject]@{}
        }
        $assessment = New-TestAssessment -Buckets @{
            'update-in-place' = @(
                New-BucketEntry -ObjectType 'rulePackage' -Ref 'A'
                New-BucketEntry -ObjectType 'rulePackage' -Ref 'B'
            )
        }
        { Get-Compl8PlanOrder -Assessment $assessment -Graph $cycleGraph } |
            Should -Throw -ExpectedMessage '*cycle*'
    }
}

Describe 'Get-Compl8PlanOrder — determinism' {
    It 'produces an identical ordered step list on repeated runs (same inputs)' {
        $sitGuid = '22222222-aaaa-4bbb-8ccc-000000000002'
        $pkg = [pscustomobject]@{ Identity = 'QGISCF-test-01'; Name = 'QGISCF-test-01'; Publisher = 'Compl8'
            SerializedClassificationRuleCollection = (New-PkgXml -EntityId $sitGuid -DictGuid $null) }
        $rule = [pscustomobject]@{ Name = 'QGISCF-QLD-Medium-Email-07'; Identity = 'QGISCF-QLD-Medium-Email-07'; Policy = 'P01'
            ContentContainsSensitiveInformation = "[{`"id`":`"$sitGuid`"}]" }
        $graph = New-TestGraph -SitPackages @($pkg) -DlpRules @($rule)
        $assessment = New-TestAssessment -Buckets @{
            'create'          = @(New-BucketEntry -ObjectType 'dictionary' -Ref '{{DICT_X}}')
            'update-in-place' = @(New-BucketEntry -ObjectType 'rulePackage' -Ref 'QGISCF-test-01')
            'drift'           = @(New-BucketEntry -ObjectType 'dlpRule' -Ref 'QGISCF-QLD-Medium-Email-07')
        }
        $a = @(Get-Compl8PlanOrder -Assessment $assessment -Graph $graph) | ConvertTo-Json -Depth 12
        $b = @(Get-Compl8PlanOrder -Assessment $assessment -Graph $graph) | ConvertTo-Json -Depth 12
        $a | Should -Be $b
    }
}

Describe 'Get-Compl8PlanOrder — coalesce per-rule dereference (P2-1)' {
    BeforeAll {
        # TWO sits, BOTH referenced by the SAME live DLP rule (QGISCF-SharedRule), both being
        # removed in this plan. The old code emitted one `dereference:QGISCF-SharedRule` work
        # item per (removed-sit x rule) pair => two work items with the same Key => duplicate
        # step-id throw in Add-PlanStep. The coalesced behaviour: exactly ONE dereference step
        # for the rule, and BOTH sit removes depend on it.
        $sitGuidA = '44444444-aaaa-4bbb-8ccc-000000000004'
        $sitGuidB = '55555555-aaaa-4bbb-8ccc-000000000005'
        $pkg = [pscustomobject]@{
            Identity = 'QGISCF-shared-pkg'; Name = 'QGISCF-shared-pkg'; Publisher = 'Compl8'
            SerializedClassificationRuleCollection = @"
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="00000000-0000-4000-8000-000000000000"><Version major="1" minor="0" build="0" revision="0" /></RulePack>
  <Rules>
    <Entity id="$sitGuidA" patternsProximity="300" recommendedConfidence="85">
      <Pattern confidenceLevel="85"><IdMatch idRef="kw" /></Pattern>
    </Entity>
    <Entity id="$sitGuidB" patternsProximity="300" recommendedConfidence="85">
      <Pattern confidenceLevel="85"><IdMatch idRef="kw" /></Pattern>
    </Entity>
    <Keyword id="kw"><Group matchStyle="word"><Term>alpha</Term></Group></Keyword>
  </Rules>
</RulePackage>
"@
        }
        # ONE rule referencing BOTH sits.
        $rule = [pscustomobject]@{ Name = 'QGISCF-SharedRule'; Identity = 'QGISCF-SharedRule'; Policy = 'P01'
            ContentContainsSensitiveInformation = "[{`"id`":`"$sitGuidA`"},{`"id`":`"$sitGuidB`"}]" }
        $script:p21Graph = New-TestGraph -SitPackages @($pkg) -DlpRules @($rule)
        $script:p21Assessment = New-TestAssessment -Buckets @{
            'remove' = @(
                New-BucketEntry -ObjectType 'sit' -Ref 'sit-a' -Extra @{ identity = $sitGuidA }
                New-BucketEntry -ObjectType 'sit' -Ref 'sit-b' -Extra @{ identity = $sitGuidB }
            )
        } -Impact @(
            [pscustomobject]@{ objectRef = 'sit-a'; affects = @('dlp-rule: QGISCF-SharedRule') }
            [pscustomobject]@{ objectRef = 'sit-b'; affects = @('dlp-rule: QGISCF-SharedRule') }
        )
    }

    It 'does not throw a duplicate-id error when two removed sits share one referencing rule' {
        { Get-Compl8PlanOrder -Assessment $script:p21Assessment -Graph $script:p21Graph } |
            Should -Not -Throw
    }

    It 'emits EXACTLY ONE dereference step for the shared rule' {
        $steps = @(Get-Compl8PlanOrder -Assessment $script:p21Assessment -Graph $script:p21Graph)
        $deref = @($steps | Where-Object { $_.action -eq 'dereference' -and $_.objectRef -eq 'QGISCF-SharedRule' })
        $deref.Count | Should -Be 1
    }

    It 'makes BOTH sit removes depend on the single dereference step' {
        $steps = @(Get-Compl8PlanOrder -Assessment $script:p21Assessment -Graph $script:p21Graph)
        $deref = @($steps | Where-Object { $_.action -eq 'dereference' -and $_.objectRef -eq 'QGISCF-SharedRule' })[0]
        $removeA = @($steps | Where-Object { $_.action -eq 'remove' -and $_.objectRef -eq 'sit-a' })[0]
        $removeB = @($steps | Where-Object { $_.action -eq 'remove' -and $_.objectRef -eq 'sit-b' })[0]
        @($removeA.dependsOn) | Should -Contain $deref.id
        @($removeB.dependsOn) | Should -Contain $deref.id
    }

    It 'lists both stripped sits in the single dereference step impact' {
        $steps = @(Get-Compl8PlanOrder -Assessment $script:p21Assessment -Graph $script:p21Graph)
        $deref = @($steps | Where-Object { $_.action -eq 'dereference' -and $_.objectRef -eq 'QGISCF-SharedRule' })[0]
        @($deref.impact) | Should -Contain 'sit-a'
        @($deref.impact) | Should -Contain 'sit-b'
    }

    It 'orders the single dereference step before BOTH sit removes' {
        $steps = @(Get-Compl8PlanOrder -Assessment $script:p21Assessment -Graph $script:p21Graph)
        $derefIdx = -1; $removeAIdx = -1; $removeBIdx = -1
        for ($i = 0; $i -lt $steps.Count; $i++) {
            if ($steps[$i].action -eq 'dereference' -and $steps[$i].objectRef -eq 'QGISCF-SharedRule') { $derefIdx = $i }
            if ($steps[$i].action -eq 'remove' -and $steps[$i].objectRef -eq 'sit-a') { $removeAIdx = $i }
            if ($steps[$i].action -eq 'remove' -and $steps[$i].objectRef -eq 'sit-b') { $removeBIdx = $i }
        }
        $derefIdx | Should -BeGreaterThan -1
        $removeAIdx | Should -BeGreaterThan $derefIdx
        $removeBIdx | Should -BeGreaterThan $derefIdx
    }

    It 'produces steps that pass Test-PlanSchema' {
        $steps = @(Get-Compl8PlanOrder -Assessment $script:p21Assessment -Graph $script:p21Graph)
        $plan = New-PlanObject -Workspace 'nonprod' -Id 'plan-p21'
        $plan.steps = @($steps)
        $r = Test-PlanSchema -Plan $plan
        $r.Valid | Should -BeTrue -Because (@($r.Errors) -join '; ')
    }
}

Describe 'Get-Compl8PlanOrder — reverse-edge removal ordering (P2-2)' {
    Context 'policy + the label it targets (policyTargetsLabel) are both removed' {
        BeforeAll {
            # Graph: a dlpPolicy node that targets a label node (edge policyTargetsLabel:
            # From=policy To=label). The policy REFERENCES the label, so when BOTH are removed
            # the policy must be torn down FIRST (the referencer goes before the referent).
            $script:p22Graph = [pscustomobject]@{
                Nodes = @(
                    [pscustomobject]@{ Id = 'dlpPolicy:QGISCF-Policy-1'; Type = 'DlpPolicy'; Name = 'QGISCF-Policy-1'; Identity = 'QGISCF-Policy-1' }
                    [pscustomobject]@{ Id = 'label:QGISCF-Confidential'; Type = 'Label'; Name = 'QGISCF-Confidential'; Identity = 'lblguid-1' }
                )
                Edges = @(
                    [pscustomobject]@{ From = 'dlpPolicy:QGISCF-Policy-1'; To = 'label:QGISCF-Confidential'; Type = 'policyTargetsLabel'; Properties = [pscustomobject]@{ LabelCode = 'QGISCF-Confidential'; RuleName = 'QGISCF-rule' } }
                )
                Summary = [pscustomobject]@{}
            }
            $script:p22Assessment = New-TestAssessment -Buckets @{
                'remove' = @(
                    New-BucketEntry -ObjectType 'label'     -Ref 'QGISCF-Confidential'
                    New-BucketEntry -ObjectType 'dlpPolicy' -Ref 'QGISCF-Policy-1'
                )
            }
            $script:p22Steps = @(Get-Compl8PlanOrder -Assessment $script:p22Assessment -Graph $script:p22Graph)
        }

        It 'orders the policy remove BEFORE the label remove' {
            $policyIdx = -1; $labelIdx = -1
            for ($i = 0; $i -lt $script:p22Steps.Count; $i++) {
                if ($script:p22Steps[$i].action -eq 'remove' -and $script:p22Steps[$i].objectType -eq 'dlpPolicy') { $policyIdx = $i }
                if ($script:p22Steps[$i].action -eq 'remove' -and $script:p22Steps[$i].objectType -eq 'label') { $labelIdx = $i }
            }
            $policyIdx | Should -BeGreaterThan -1
            $labelIdx  | Should -BeGreaterThan -1
            $policyIdx | Should -BeLessThan $labelIdx
        }

        It 'makes the label remove depend on the policy remove' {
            $policyStep = @($script:p22Steps | Where-Object { $_.action -eq 'remove' -and $_.objectType -eq 'dlpPolicy' })[0]
            $labelStep  = @($script:p22Steps | Where-Object { $_.action -eq 'remove' -and $_.objectType -eq 'label' })[0]
            @($labelStep.dependsOn) | Should -Contain $policyStep.id
        }

        It 'produces steps that pass Test-PlanSchema' {
            $plan = New-PlanObject -Workspace 'nonprod' -Id 'plan-p22a'
            $plan.steps = @($script:p22Steps)
            $r = Test-PlanSchema -Plan $plan
            $r.Valid | Should -BeTrue -Because (@($r.Errors) -join '; ')
        }
    }

    Context 'rulePackage + a dlpRule referencing its sit are both removed' {
        BeforeAll {
            # rule --references--> sit --contained-by--> package (graph edges sitReferencedByRule
            # From=sit To=rule, packageContainsSit From=pkg To=sit). The rule is the referencer of
            # the package's classifier, so the rule must be torn down BEFORE the package.
            $sitGuid = '66666666-aaaa-4bbb-8ccc-000000000006'
            $pkg = [pscustomobject]@{ Identity = 'QGISCF-doomed-pkg'; Name = 'QGISCF-doomed-pkg'; Publisher = 'Compl8'
                SerializedClassificationRuleCollection = (New-PkgXml -EntityId $sitGuid -DictGuid $null) }
            $rule = [pscustomobject]@{ Name = 'QGISCF-doomed-rule'; Identity = 'QGISCF-doomed-rule'; Policy = 'P01'
                ContentContainsSensitiveInformation = "[{`"id`":`"$sitGuid`"}]" }
            $script:p22bGraph = New-TestGraph -SitPackages @($pkg) -DlpRules @($rule)
            $script:p22bAssessment = New-TestAssessment -Buckets @{
                'remove' = @(
                    New-BucketEntry -ObjectType 'rulePackage' -Ref 'QGISCF-doomed-pkg'
                    New-BucketEntry -ObjectType 'dlpRule'     -Ref 'QGISCF-doomed-rule'
                )
            }
            $script:p22bSteps = @(Get-Compl8PlanOrder -Assessment $script:p22bAssessment -Graph $script:p22bGraph)
        }

        It 'orders the dlpRule remove BEFORE the rulePackage remove' {
            $ruleIdx = -1; $pkgIdx = -1
            for ($i = 0; $i -lt $script:p22bSteps.Count; $i++) {
                if ($script:p22bSteps[$i].action -eq 'remove' -and $script:p22bSteps[$i].objectType -eq 'dlpRule') { $ruleIdx = $i }
                if ($script:p22bSteps[$i].action -eq 'remove' -and $script:p22bSteps[$i].objectType -eq 'rulePackage') { $pkgIdx = $i }
            }
            $ruleIdx | Should -BeGreaterThan -1
            $pkgIdx  | Should -BeGreaterThan -1
            $ruleIdx | Should -BeLessThan $pkgIdx
        }

        It 'makes the rulePackage remove depend on the dlpRule remove' {
            $ruleStep = @($script:p22bSteps | Where-Object { $_.action -eq 'remove' -and $_.objectType -eq 'dlpRule' })[0]
            $pkgStep  = @($script:p22bSteps | Where-Object { $_.action -eq 'remove' -and $_.objectType -eq 'rulePackage' })[0]
            @($pkgStep.dependsOn) | Should -Contain $ruleStep.id
        }
    }

    Context 'determinism with reverse-edge removal predecessors' {
        It 'produces an identical ordered step list on repeated runs' {
            $graph = [pscustomobject]@{
                Nodes = @(
                    [pscustomobject]@{ Id = 'dlpPolicy:QGISCF-Policy-1'; Type = 'DlpPolicy'; Name = 'QGISCF-Policy-1'; Identity = 'QGISCF-Policy-1' }
                    [pscustomobject]@{ Id = 'label:QGISCF-Confidential'; Type = 'Label'; Name = 'QGISCF-Confidential'; Identity = 'lblguid-1' }
                )
                Edges = @(
                    [pscustomobject]@{ From = 'dlpPolicy:QGISCF-Policy-1'; To = 'label:QGISCF-Confidential'; Type = 'policyTargetsLabel'; Properties = [pscustomobject]@{ LabelCode = 'QGISCF-Confidential'; RuleName = 'QGISCF-rule' } }
                )
                Summary = [pscustomobject]@{}
            }
            $assessment = New-TestAssessment -Buckets @{
                'remove' = @(
                    New-BucketEntry -ObjectType 'label'     -Ref 'QGISCF-Confidential'
                    New-BucketEntry -ObjectType 'dlpPolicy' -Ref 'QGISCF-Policy-1'
                )
            }
            $a = @(Get-Compl8PlanOrder -Assessment $assessment -Graph $graph) | ConvertTo-Json -Depth 12
            $b = @(Get-Compl8PlanOrder -Assessment $assessment -Graph $graph) | ConvertTo-Json -Depth 12
            $a | Should -Be $b
        }
    }

    Context 'policy + label SHARE the same ref but differ in objectType (composite removal identity)' {
        BeforeAll {
            # A dlpPolicy and a label that SHARE the same name/ref ('QGISCF-Shared-Name') are BOTH
            # removed, with a policyTargetsLabel edge between their nodes (policy references label).
            # The removal dependency identity must distinguish objectType as well as ref: keyed by
            # ref ALONE, the referencer (policy) and referent (label) collapse to the same identity
            # and the reverse edge is SKIPPED — so the default tier sort can teardown the label
            # before the policy (unsafe). Keyed by (objectType, ref) they are DISTINCT and the
            # policy-before-label ordering holds.
            $script:p22cGraph = [pscustomobject]@{
                Nodes = @(
                    [pscustomobject]@{ Id = 'dlpPolicy:QGISCF-Shared-Name'; Type = 'DlpPolicy'; Name = 'QGISCF-Shared-Name'; Identity = 'QGISCF-Shared-Name' }
                    [pscustomobject]@{ Id = 'label:QGISCF-Shared-Name'; Type = 'Label'; Name = 'QGISCF-Shared-Name'; Identity = 'lblguid-shared' }
                )
                Edges = @(
                    [pscustomobject]@{ From = 'dlpPolicy:QGISCF-Shared-Name'; To = 'label:QGISCF-Shared-Name'; Type = 'policyTargetsLabel'; Properties = [pscustomobject]@{ LabelCode = 'QGISCF-Shared-Name'; RuleName = 'QGISCF-rule' } }
                )
                Summary = [pscustomobject]@{}
            }
            $script:p22cAssessment = New-TestAssessment -Buckets @{
                'remove' = @(
                    New-BucketEntry -ObjectType 'label'     -Ref 'QGISCF-Shared-Name'
                    New-BucketEntry -ObjectType 'dlpPolicy' -Ref 'QGISCF-Shared-Name'
                )
            }
            $script:p22cSteps = @(Get-Compl8PlanOrder -Assessment $script:p22cAssessment -Graph $script:p22cGraph)
        }

        It 'orders the dlpPolicy remove BEFORE the label remove (shared ref, distinct objectType)' {
            $policyIdx = -1; $labelIdx = -1
            for ($i = 0; $i -lt $script:p22cSteps.Count; $i++) {
                if ($script:p22cSteps[$i].action -eq 'remove' -and $script:p22cSteps[$i].objectType -eq 'dlpPolicy') { $policyIdx = $i }
                if ($script:p22cSteps[$i].action -eq 'remove' -and $script:p22cSteps[$i].objectType -eq 'label') { $labelIdx = $i }
            }
            $policyIdx | Should -BeGreaterThan -1
            $labelIdx  | Should -BeGreaterThan -1
            $policyIdx | Should -BeLessThan $labelIdx
        }

        It 'makes the label remove depend on the policy remove (the reverse edge is NOT skipped)' {
            $policyStep = @($script:p22cSteps | Where-Object { $_.action -eq 'remove' -and $_.objectType -eq 'dlpPolicy' })[0]
            $labelStep  = @($script:p22cSteps | Where-Object { $_.action -eq 'remove' -and $_.objectType -eq 'label' })[0]
            @($labelStep.dependsOn) | Should -Contain $policyStep.id
        }

        It 'produces an identical ordered step list on repeated runs (determinism)' {
            $a = @(Get-Compl8PlanOrder -Assessment $script:p22cAssessment -Graph $script:p22cGraph) | ConvertTo-Json -Depth 12
            $b = @(Get-Compl8PlanOrder -Assessment $script:p22cAssessment -Graph $script:p22cGraph) | ConvertTo-Json -Depth 12
            $a | Should -Be $b
        }
    }
}

# =====================================================================================
# Task 5 — New-Compl8Plan / Test-Compl8PlanCurrent / Compare-Compl8Plan (PHASE 4B).
# New-Compl8Plan turns an assessment (+ reference graph) into a compl8.plan/v1 object:
#   * orders + gate-wires steps via Get-Compl8PlanOrder (Task 4);
#   * stamps each step's impact from the assessment's impact[] / graph;
#   * prepends a generated snapshotBeforeDestroy Step 0.5 that EVERY destructive step
#     (remove / dereference) depends on, WHENEVER the plan has any destructive step;
#   * marks policy-scope steps that carry external references with an externalRefs gate;
#   * builds via Model's New-PlanObject / Add-PlanStep (passes Test-PlanSchema);
#   * writes history/plans/<id>.json + <id>.sha256 sidecar atomically (deterministic id +
#     timestamp are PARAMETERS — Get-Date / Get-Random are banned in the function).
# Test-Compl8PlanCurrent generalises the refit <=24h rule from age to CONTENT hash:
#   false when resolveManifest OR inventory hash drifts, naming which (with -Detail).
# Compare-Compl8Plan is a pure diff: added / removed / changed steps between two plans.
# =====================================================================================

Describe 'Task 5 — module surface' {
    It 'exports New-Compl8Plan, Test-Compl8PlanCurrent and Compare-Compl8Plan from Compl8.Engine' {
        foreach ($fn in 'New-Compl8Plan', 'Test-Compl8PlanCurrent', 'Compare-Compl8Plan') {
            (Get-Command -Name $fn -Module Compl8.Engine -ErrorAction SilentlyContinue) |
                Should -Not -BeNullOrEmpty -Because "$fn must be exported"
        }
    }
}

Describe 'New-Compl8Plan — drives a real assessment + graph into a compl8.plan/v1' {
    BeforeAll {
        $script:FixtureRoot   = Join-Path $script:RepoRoot 'tests' 'fixtures' 'engine' 'assess'
        $script:InventoryPath = Join-Path $script:FixtureRoot 'actual' 'inventory.json'
        $script:ExpectedRoot  = Join-Path $script:RepoRoot 'tests' 'fixtures' 'engine' 'expected'

        $script:planAssessment = Invoke-Compl8Assess `
            -WorkspacePath $script:FixtureRoot -InventoryPath $script:InventoryPath `
            -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'

        # Rebuild the reference graph exactly as assess does (desired packages + actual rules).
        $resolvedDir = Join-Path $script:FixtureRoot 'desired' 'resolved'
        $manifest = Get-Content -LiteralPath (Join-Path $resolvedDir 'resolve-manifest.json') -Raw | ConvertFrom-Json
        $script:planInventory = Get-Content -LiteralPath $script:InventoryPath -Raw | ConvertFrom-Json
        $graphPackages = @(foreach ($pkg in @($manifest.packages)) {
            $pkgFile = Join-Path $resolvedDir ([string]$pkg.file)
            if (-not $pkg.file -or -not (Test-Path -LiteralPath $pkgFile)) { continue }
            [pscustomobject]@{
                Identity = [string]$pkg.name; Name = [string]$pkg.name; Publisher = 'Compl8'
                SerializedClassificationRuleCollection = (Get-Content -LiteralPath $pkgFile -Raw)
            }
        })
        $graphRules = @(foreach ($rule in @($script:planInventory.objects.dlpRules)) {
            [pscustomobject]@{
                Name = [string]$rule.name; Identity = [string]$rule.identity; Policy = [string]$rule.policy
                ContentContainsSensitiveInformation = $rule.contentContainsSensitiveInformation
            }
        })
        $script:planGraph = Get-DeploymentReferenceGraph -SitPackages $graphPackages -DlpRules $graphRules

        # A scratch workspace root the plan can write history/plans/ under.
        $script:WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("compl8plan-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:WorkRoot -Force | Out-Null

        $script:Plan = New-Compl8Plan `
            -Assessment $script:planAssessment -Graph $script:planGraph -Inventory $script:planInventory `
            -Workspace 'nonprod' -Id 'plan-20260613-000000' -GeneratedUtc '2026-06-13T00:00:00Z' `
            -WorkspacePath $script:WorkRoot

        $script:PlanFile     = Join-Path $script:WorkRoot 'history' 'plans' 'plan-20260613-000000.json'
        $script:SidecarFile  = Join-Path $script:WorkRoot 'history' 'plans' 'plan-20260613-000000.sha256'
    }

    AfterAll {
        if ($script:WorkRoot -and (Test-Path -LiteralPath $script:WorkRoot)) {
            Remove-Item -LiteralPath $script:WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'returns a compl8.plan/v1 object that passes Test-PlanSchema' {
        $script:Plan.schemaVersion | Should -Be 'compl8.plan/v1'
        $script:Plan.id            | Should -Be 'plan-20260613-000000'
        $script:Plan.workspace     | Should -Be 'nonprod'
        $r = Test-PlanSchema -Plan $script:Plan
        $r.Valid | Should -BeTrue -Because (@($r.Errors) -join '; ')
    }

    It 'carries the resolveManifest + inventory hashes from the assessment and an assessment hash' {
        $script:Plan.inputs.resolveManifest | Should -Be $script:planAssessment.inputs.resolveManifest
        $script:Plan.inputs.inventory       | Should -Be $script:planAssessment.inputs.inventory
        $script:Plan.inputs.assessment      | Should -Match '^sha256:[0-9a-f]{64}$'
    }

    It 'writes the plan to history/plans/<id>.json with a matching <id>.sha256 sidecar' {
        Test-Path -LiteralPath $script:PlanFile    | Should -BeTrue
        Test-Path -LiteralPath $script:SidecarFile | Should -BeTrue

        $actualHash = (Get-FileHash -LiteralPath $script:PlanFile -Algorithm SHA256).Hash.ToLowerInvariant()
        $sidecarRaw = Get-Content -LiteralPath $script:SidecarFile -Raw
        # Sidecar line format EXACTLY: '<64-hex>  <filename>' (two spaces), like the refit plan.
        $sidecarRaw.TrimEnd("`r", "`n") | Should -Be "$actualHash  plan-20260613-000000.json"
    }

    It 'stamps impact on the rule-package step that contains an impacted classifier' {
        # name-dict (in QGISCF-test-01) is referenced by QGISCF-QLD-Medium-Email-07 in the
        # assessment impact[]; the update step on QGISCF-test-01 must carry that impact.
        $pkgStep = @($script:Plan.steps | Where-Object { $_.objectType -eq 'rulePackage' -and $_.objectRef -eq 'QGISCF-test-01' })[0]
        $pkgStep | Should -Not -BeNullOrEmpty
        @($pkgStep.impact) -join '; ' | Should -Match 'QGISCF-QLD-Medium-Email-07'
    }

    It 'prepends a snapshotBeforeDestroy Step 0.5 that every destructive step depends on' {
        $snap = @($script:Plan.steps | Where-Object { $_.action -eq 'snapshot' })
        $snap.Count | Should -Be 1
        $snap[0].objectType        | Should -Be 'tenant'
        $snap[0].objectRef         | Should -Be '*'
        $snap[0].gate.type         | Should -Be 'snapshotBeforeDestroy'
        # The snapshot step is FIRST (Step 0.5).
        $script:Plan.steps[0].action | Should -Be 'snapshot'

        $destructive = @($script:Plan.steps | Where-Object { $_.action -in 'remove', 'dereference' })
        $destructive.Count | Should -BeGreaterThan 0
        foreach ($d in $destructive) {
            @($d.dependsOn) | Should -Contain $snap[0].id -Because "destructive step '$($d.objectRef)' must depend on the snapshot"
        }
    }
}

Describe 'New-Compl8Plan — no snapshot when the plan has no destructive step' {
    It 'omits the snapshotBeforeDestroy step when nothing is removed/dereferenced' {
        $sitGuid = '22222222-aaaa-4bbb-8ccc-000000000002'
        $pkg = [pscustomobject]@{ Identity = 'QGISCF-test-01'; Name = 'QGISCF-test-01'; Publisher = 'Compl8'
            SerializedClassificationRuleCollection = (New-PkgXml -EntityId $sitGuid -DictGuid $null) }
        $graph = New-TestGraph -SitPackages @($pkg)
        $assessment = New-TestAssessment -Buckets @{
            'create'          = @(New-BucketEntry -ObjectType 'dictionary' -Ref '{{DICT_X}}')
            'update-in-place' = @(New-BucketEntry -ObjectType 'rulePackage' -Ref 'QGISCF-test-01')
        }
        $plan = New-Compl8Plan -Assessment $assessment -Graph $graph `
            -Workspace 'nonprod' -Id 'plan-nosnap' -GeneratedUtc '2026-06-13T00:00:00Z'
        @($plan.steps | Where-Object { $_.action -eq 'snapshot' }).Count | Should -Be 0
        $r = Test-PlanSchema -Plan $plan
        $r.Valid | Should -BeTrue -Because (@($r.Errors) -join '; ')
    }
}

Describe 'New-Compl8Plan — externalRefs gate on a policy-scope step' {
    It 'marks a policy-scope step that carries external references with an externalRefs gate' {
        # A dlpPolicy create whose desired content carries a scope/recipient external ref.
        $assessment = New-TestAssessment -Buckets @{
            'create' = @(
                New-BucketEntry -ObjectType 'dlpPolicy' -Ref 'QGISCF-Policy-Ext' -Extra @{ scope = 'group:Legal-Team@contoso.com' }
            )
        }
        $graph = New-TestGraph
        $plan = New-Compl8Plan -Assessment $assessment -Graph $graph `
            -Workspace 'nonprod' -Id 'plan-extref' -GeneratedUtc '2026-06-13T00:00:00Z'
        $policyStep = @($plan.steps | Where-Object { $_.objectType -eq 'dlpPolicy' -and $_.objectRef -eq 'QGISCF-Policy-Ext' })[0]
        $policyStep | Should -Not -BeNullOrEmpty
        $policyStep.gate.type | Should -Be 'externalRefs'
        $r = Test-PlanSchema -Plan $plan
        $r.Valid | Should -BeTrue -Because (@($r.Errors) -join '; ')
    }

    It 'does NOT mark a policy-scope step with no external reference' {
        $assessment = New-TestAssessment -Buckets @{
            'create' = @(New-BucketEntry -ObjectType 'dlpPolicy' -Ref 'QGISCF-Policy-Plain')
        }
        $plan = New-Compl8Plan -Assessment $assessment -Graph (New-TestGraph) `
            -Workspace 'nonprod' -Id 'plan-noextref' -GeneratedUtc '2026-06-13T00:00:00Z'
        $policyStep = @($plan.steps | Where-Object { $_.objectRef -eq 'QGISCF-Policy-Plain' })[0]
        $policyStep.gate | Should -BeNullOrEmpty
    }
}

Describe 'New-Compl8Plan — determinism + golden plan' {
    BeforeAll {
        # The plan carries the assessment's raw-byte input hashes (inputs.inventory / resolveManifest),
        # so the golden is sensitive to the fixtures' on-disk line endings (a fresh autocrlf=true clone
        # renders the LF-committed fixtures as CRLF). Build the golden inputs from a CR-stripped (LF)
        # copy so they are checkout-independent (the golden was pinned from LF). Deleted in AfterAll.
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
        $script:FixtureRoot   = New-LfFixtureRoot -Src (Join-Path $script:RepoRoot 'tests' 'fixtures' 'engine' 'assess')
        $script:InventoryPath = Join-Path $script:FixtureRoot 'actual' 'inventory.json'
        $script:ExpectedRoot  = Join-Path $script:RepoRoot 'tests' 'fixtures' 'engine' 'expected'

        $script:gAssessment = Invoke-Compl8Assess `
            -WorkspacePath $script:FixtureRoot -InventoryPath $script:InventoryPath `
            -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'
        $resolvedDir = Join-Path $script:FixtureRoot 'desired' 'resolved'
        $manifest = Get-Content -LiteralPath (Join-Path $resolvedDir 'resolve-manifest.json') -Raw | ConvertFrom-Json
        $script:gInventory = Get-Content -LiteralPath $script:InventoryPath -Raw | ConvertFrom-Json
        $graphPackages = @(foreach ($pkg in @($manifest.packages)) {
            $pkgFile = Join-Path $resolvedDir ([string]$pkg.file)
            if (-not $pkg.file -or -not (Test-Path -LiteralPath $pkgFile)) { continue }
            [pscustomobject]@{ Identity = [string]$pkg.name; Name = [string]$pkg.name; Publisher = 'Compl8'
                SerializedClassificationRuleCollection = (Get-Content -LiteralPath $pkgFile -Raw) }
        })
        $graphRules = @(foreach ($rule in @($script:gInventory.objects.dlpRules)) {
            [pscustomobject]@{ Name = [string]$rule.name; Identity = [string]$rule.identity; Policy = [string]$rule.policy
                ContentContainsSensitiveInformation = $rule.contentContainsSensitiveInformation }
        })
        $script:gGraph = Get-DeploymentReferenceGraph -SitPackages $graphPackages -DlpRules $graphRules

        function New-GoldenPlanJson {
            (New-Compl8Plan -Assessment $script:gAssessment -Graph $script:gGraph -Inventory $script:gInventory `
                -Workspace 'nonprod' -Id 'plan-20260613-000000' -GeneratedUtc '2026-06-13T00:00:00Z') |
                ConvertTo-Json -Depth 12
        }
    }

    It 'produces byte-identical plan JSON on repeated runs (same inputs + id + timestamp)' {
        (New-GoldenPlanJson) | Should -Be (New-GoldenPlanJson)
    }

    It 'matches the pinned golden plan JSON (line-ending insensitive)' {
        $goldenPath = Join-Path $script:ExpectedRoot 'plan-nonprod.json'
        $actual = New-GoldenPlanJson
        if (-not (Test-Path -LiteralPath $goldenPath)) {
            $dir = Split-Path -Parent $goldenPath
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Set-Content -LiteralPath $goldenPath -Value $actual -Encoding UTF8 -NoNewline
        }
        $expected = Get-Content -LiteralPath $goldenPath -Raw
        # Compare with line endings normalised on both sides (ConvertTo-Json emits platform newlines).
        ($actual -replace "`r`n", "`n") | Should -Be (($expected -replace "`r`n", "`n").TrimEnd("`n"))
    }

    AfterAll {
        if ($script:FixtureRoot -and (Test-Path -LiteralPath $script:FixtureRoot) -and
            $script:FixtureRoot -like '*lf-fixture-*') {
            Remove-Item -LiteralPath $script:FixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'New-Compl8Plan — determinism guard (Get-Date / Get-Random banned)' {
    It 'never calls Get-Date or Get-Random in the executable body (comments stripped)' {
        $src = Get-Content -LiteralPath (Join-Path $script:EngineDir 'Public' 'New-Compl8Plan.ps1') -Raw
        # Strip block comments <# ... #> and line comments so only executable code is checked —
        # the bans are on CALLS, not on documentation that names the banned cmdlets.
        $code = [regex]::Replace($src, '(?s)<#.*?#>', '')
        $code = ($code -split "`n" | ForEach-Object { ($_ -replace '#.*$', '') }) -join "`n"
        $code | Should -Not -Match 'Get-Date'
        $code | Should -Not -Match 'Get-Random'
    }
}

Describe 'Test-Compl8PlanCurrent — content-hash freshness' {
    BeforeAll {
        $script:tcAssessment = New-TestAssessment -Buckets @{
            'create' = @(New-BucketEntry -ObjectType 'dictionary' -Ref '{{DICT_X}}')
        }
        # New-TestAssessment stamps inputs.resolveManifest='sha256:aa', inventory='sha256:bb'.
        $script:tcPlan = New-Compl8Plan -Assessment $script:tcAssessment -Graph (New-TestGraph) `
            -Workspace 'nonprod' -Id 'plan-fresh' -GeneratedUtc '2026-06-13T00:00:00Z'
    }

    It 'returns true when both input hashes still match' {
        Test-Compl8PlanCurrent -Plan $script:tcPlan `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:bb' | Should -BeTrue
    }

    It 'returns false and names inventory when the inventory hash drifts' {
        Test-Compl8PlanCurrent -Plan $script:tcPlan `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:CHANGED' | Should -BeFalse
        $d = Test-Compl8PlanCurrent -Plan $script:tcPlan `
            -ResolveManifestHash 'sha256:aa' -InventoryHash 'sha256:CHANGED' -Detail
        $d.Current | Should -BeFalse
        $d.Stale   | Should -Contain 'inventory'
        $d.Stale   | Should -Not -Contain 'resolveManifest'
    }

    It 'returns false and names resolveManifest when the manifest hash drifts' {
        $d = Test-Compl8PlanCurrent -Plan $script:tcPlan `
            -ResolveManifestHash 'sha256:CHANGED' -InventoryHash 'sha256:bb' -Detail
        $d.Current | Should -BeFalse
        $d.Stale   | Should -Contain 'resolveManifest'
        $d.Stale   | Should -Not -Contain 'inventory'
    }
}

Describe 'Compare-Compl8Plan — pure plan diff (added / removed / changed)' {
    BeforeAll {
        function New-DiffStep {
            param([string]$Id, [string]$Action, [string]$ObjectType, [string]$ObjectRef,
                  [string[]]$DependsOn = @(), [string[]]$Impact = @(), [pscustomobject]$Gate = $null)
            [pscustomobject]@{ id = $Id; action = $Action; objectType = $ObjectType; objectRef = $ObjectRef
                dependsOn = @($DependsOn); impact = @($Impact); gate = $Gate }
        }
        function New-DiffPlan {
            param([object[]]$Steps)
            $p = New-PlanObject -Workspace 'nonprod' -Id 'p'
            $p.steps = @($Steps)
            $p
        }

        # base plan: create dict, update package (no gate), remove sit.
        $script:planA = New-DiffPlan -Steps @(
            New-DiffStep -Id 's01' -Action 'create' -ObjectType 'dictionary'  -ObjectRef '{{DICT_X}}'
            New-DiffStep -Id 's02' -Action 'update' -ObjectType 'rulePackage' -ObjectRef 'QGISCF-test-01'
            New-DiffStep -Id 's03' -Action 'remove' -ObjectType 'sit'         -ObjectRef 'shared-b'
        )
        # new plan: SAME dict step; CHANGED package step (now carries a propagation gate);
        # REMOVED the remove-sit step; ADDED a create-sit step.
        $script:planB = New-DiffPlan -Steps @(
            New-DiffStep -Id 's01' -Action 'create' -ObjectType 'dictionary'  -ObjectRef '{{DICT_X}}'
            New-DiffStep -Id 's02' -Action 'update' -ObjectType 'rulePackage' -ObjectRef 'QGISCF-test-01' -Gate ([pscustomobject]@{ type = 'propagation'; notBeforeOffsetHours = 4 })
            New-DiffStep -Id 's04' -Action 'create' -ObjectType 'sit'         -ObjectRef 'custom-incident-ref'
        )
        $script:diff = Compare-Compl8Plan -ReferencePlan $script:planA -DifferencePlan $script:planB
    }

    It 'reports the added step (create sit) by objectRef+action' {
        @($script:diff.Added | ForEach-Object { "$($_.action)|$($_.objectRef)" }) | Should -Contain 'create|custom-incident-ref'
    }

    It 'reports the removed step (remove sit) by objectRef+action' {
        @($script:diff.Removed | ForEach-Object { "$($_.action)|$($_.objectRef)" }) | Should -Contain 'remove|shared-b'
    }

    It 'reports the changed step (same ref+action, different gate)' {
        @($script:diff.Changed | ForEach-Object { "$($_.action)|$($_.objectRef)" }) | Should -Contain 'update|QGISCF-test-01'
    }

    It 'does NOT report an unchanged step' {
        foreach ($coll in 'Added', 'Removed', 'Changed') {
            @($script:diff.$coll | ForEach-Object { "$($_.action)|$($_.objectRef)" }) |
                Should -Not -Contain 'create|{{DICT_X}}'
        }
    }
}
