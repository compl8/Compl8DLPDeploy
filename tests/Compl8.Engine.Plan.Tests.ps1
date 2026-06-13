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
