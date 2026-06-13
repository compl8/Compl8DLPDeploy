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

    # ---- Label SCC cmdlet stubs (Task 9). Same global-stub pattern: the LABEL executor invokes
    # New-/Set-/Get-/Remove-Label and *-LabelPolicy DYNAMICALLY, so they must EXIST for
    # `Mock -ModuleName Compl8.Engine` to shadow them. The New/Set-Label stubs declare the full
    # parameter surface the executor splats (the visual-marking + advanced-settings params) so a
    # mock binds without a "parameter cannot be found" error.
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

    # ============================================================================================
    # LABEL EXECUTOR (Task 9) — fixtures + the GENUINE shadow recorder.
    # ============================================================================================
    # The label executor handles two objectTypes: `label` (leaf + group) and `labelPolicy`. The
    # resolved -Content the executor consumes mirrors the label config record (config/labels.json)
    # re-scoped to the deployment prefix, exactly as Deploy-Labels.ps1 derives it via
    # Get-DeploymentObjectName / Resolve-DeploymentLabelName.
    $script:LabelDef = [pscustomobject]@{
        objectRef       = 'QGISCF-OFFICIAL-OFFI'      # the prefix-scoped label NAME (Resolve-DeploymentLabelName output)
        name            = 'QGISCF-OFFICIAL-OFFI'
        displayName     = 'OFFICIAL'
        tooltip         = 'OFFICIAL tooltip'
        priority        = 0
        code            = 'OFFI'
        isGroup         = $false
        parentGroup     = $null
        parentLabelName = $null
        colour          = '#008000'
        headerText      = 'OFFICIAL'
        footerText      = 'OFFICIAL'
    }
    $script:GroupDef = [pscustomobject]@{
        objectRef       = 'QGISCF-SENSITIVE'
        name            = 'QGISCF-SENSITIVE'
        displayName     = 'SENSITIVE'
        tooltip         = 'SENSITIVE group'
        priority        = 1
        code            = $null
        isGroup         = $true
        parentGroup     = $null
        parentLabelName = $null
        colour          = '#0078D4'
        headerText      = $null
        footerText      = $null
    }
    $script:SubLabelDef = [pscustomobject]@{
        objectRef       = 'QGISCF-SENSITIVE-Default-SENS'
        name            = 'QGISCF-SENSITIVE-Default-SENS'
        displayName     = 'SENSITIVE'
        tooltip         = 'SENSITIVE sublabel'
        priority        = 2
        code            = 'SENS'
        isGroup         = $false
        parentGroup     = 'SENSITIVE'
        parentLabelName = 'QGISCF-SENSITIVE'
        colour          = '#0078D4'
        headerText      = 'SENSITIVE'
        footerText      = 'SENSITIVE'
    }
    $script:PolicyDef = [pscustomobject]@{
        objectRef = 'QGISCF-Default-Label-Policy'
        name      = 'QGISCF-Default-Label-Policy'
        scope     = 'DL-InfoSec@agency.gov'
        labels    = @('QGISCF-OFFICIAL-OFFI', 'QGISCF-SENSITIVE-Default-SENS')
    }

    function New-LabelStep {
        param([string]$Id, [string]$Action, [string]$ObjectRef, [string]$ObjectType = 'label')
        [pscustomobject]@{ id = $Id; action = $Action; objectType = $ObjectType; objectRef = $ObjectRef
            dependsOn = @(); impact = @(); gate = $null }
    }

    # ---------------------------------------------------------------- old-side recorder (GENUINE)
    # SHADOW STRATEGY (approach (a) — run the REAL leaf script; documented for reuse by Tasks 10-12):
    # Deploy-Labels.ps1 is a SCRIPT that loads config + connects + loops and does NOT return a
    # structured op list (its -WhatIf only emits ShouldProcess host text, which is NOT programmatically
    # capturable). BUT we can run the script's ACTUAL decision logic genuinely: invoke
    # Deploy-Labels.ps1 against a small committed tenant config fixture with the connection/session/
    # fingerprint BOUNDARY and the SCC cmdlets replaced by GLOBAL function stubs that RECORD their
    # invocations. Because the script resolves these by normal scope (not via Mock -ModuleName), the
    # global stubs shadow them and the script runs to its real label/policy loop. The recorded
    # New-/Set-Label and New-/Set-LabelPolicy CALLS (with the real prefix-scoped identities the
    # production name generator produced) ARE the old path's intended operations — derived from a real
    # run, never hand-authored. We normalise them to the common op-record shape.
    #
    # NOTE on why GLOBAL stubs (not Mock -ModuleName DLP-Deploy): Mock -ModuleName drives the script's
    # mutating cmdlets through ShouldProcess, which returns $false in the non-interactive harness so the
    # mutating cmdlets are never reached. Plain global function stubs execute unconditionally and so
    # capture the real intended operations. This is the reusable recorder shape for Tasks 10-12.
    #
    # RE-RECORD: this recorder runs live each test run (it is NOT a frozen JSON fixture); to retarget it
    # at a different label set, edit $LabelsJson below (or point -TargetEnvironment at a real
    # config/tenants/<env>). No committed fixture to refresh.
    function Get-OldLabelWhatIfOps {
        param([string]$LabelsJson, [string]$SettingsJson, [string]$PublishTo)

        $envName  = 'compl8-shadow-' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
        $cfgRoot  = Join-Path $script:RepoRoot 'config' 'tenants' $envName
        $recorded = [System.Collections.Generic.List[object]]::new()
        $global:Compl8ShadowLabelOps = $recorded
        try {
            New-Item -ItemType Directory -Path $cfgRoot -Force | Out-Null
            Set-Content -Path (Join-Path $cfgRoot 'settings.json') -Value $SettingsJson
            Set-Content -Path (Join-Path $cfgRoot 'labels.json')   -Value $LabelsJson

            Import-Module $script:DlpDeploy -Force

            # Boundary stubs: bypass orchestration gate / connection / session / tenant lookup so the
            # script reaches its label loop without a live tenant. These are NOT the operations under
            # test; only the SCC cmdlet calls are recorded.
            function global:Connect-DLPSession { param() $true }
            function global:Assert-DLPSession { param([string]$CommandToTest) $true }
            function global:Get-DeploymentTenantInfo { [ordered]@{ name = 'shadow'; guid = '00000000-0000-0000-0000-000000000001'; tenantId = '00000000-0000-0000-0000-000000000001' } }

            # The genuine RECORDING SCC stubs. Each records the real call the old path makes.
            function global:Get-Label {
                param([string]$Identity)
                # A pre-existing GROUP so a sublabel's parent resolves (Get-Label on the group returns a
                # Guid + no ContentType => recognised as a group, not a leaf). All other labels are absent
                # (=> creates), so the recorded set is deterministic for the fixture.
                if ($Identity -eq 'QGISCF-SENSITIVE') {
                    return [pscustomobject]@{ Guid = [guid]'00000000-0000-0000-0000-0000000000bb'; ContentType = $null }
                }
                $null
            }
            function global:New-Label {
                param(
                    [string]$Name, [string]$DisplayName, [string]$Tooltip, [string]$Comment, [string]$ContentType,
                    [switch]$IsLabelGroup, [string]$ParentId,
                    [switch]$ApplyContentMarkingHeaderEnabled, [string]$ApplyContentMarkingHeaderText,
                    [int]$ApplyContentMarkingHeaderFontSize, [string]$ApplyContentMarkingHeaderAlignment, [string]$ApplyContentMarkingHeaderFontColor,
                    [switch]$ApplyContentMarkingFooterEnabled, [string]$ApplyContentMarkingFooterText,
                    [int]$ApplyContentMarkingFooterFontSize, [string]$ApplyContentMarkingFooterAlignment, [string]$ApplyContentMarkingFooterFontColor,
                    [hashtable]$AdvancedSettings)
                $global:Compl8ShadowLabelOps.Add([pscustomobject]@{ action = 'create'; objectType = 'label'; objectRef = $Name }) | Out-Null
                [pscustomobject]@{ Guid = [guid]'00000000-0000-0000-0000-0000000000aa' }
            }
            function global:Set-Label {
                param([string]$Identity, [Parameter(ValueFromRemainingArguments = $true)]$Rest)
                $global:Compl8ShadowLabelOps.Add([pscustomobject]@{ action = 'update'; objectType = 'label'; objectRef = $Identity }) | Out-Null
            }
            function global:Remove-Label { param([string]$Identity) }
            function global:Get-LabelPolicy { param([string]$Identity) $null }
            function global:New-LabelPolicy {
                param([string]$Name, [string[]]$Labels, [string]$ExchangeLocation, [string]$Comment)
                $global:Compl8ShadowLabelOps.Add([pscustomobject]@{ action = 'create'; objectType = 'labelPolicy'; objectRef = $Name }) | Out-Null
            }
            function global:Set-LabelPolicy {
                param([string]$Identity, [string[]]$AddLabels, [string]$Comment)
                $global:Compl8ShadowLabelOps.Add([pscustomobject]@{ action = 'update'; objectType = 'labelPolicy'; objectRef = $Identity }) | Out-Null
            }
            function global:Remove-LabelPolicy { param([string]$Identity) }

            $scriptArgs = @{ TargetEnvironment = $envName; AllowDirectRun = $true }
            if ($PublishTo) { $scriptArgs['PublishTo'] = $PublishTo } else { $scriptArgs['SkipPublish'] = $true }
            & (Join-Path $script:RepoRoot 'scripts' 'Deploy-Labels.ps1') @scriptArgs *> $null

            @($recorded)
        } finally {
            foreach ($fn in 'Connect-DLPSession', 'Assert-DLPSession', 'Get-DeploymentTenantInfo',
                'Get-Label', 'New-Label', 'Set-Label', 'Remove-Label',
                'Get-LabelPolicy', 'New-LabelPolicy', 'Set-LabelPolicy', 'Remove-LabelPolicy') {
                Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
            }
            Remove-Variable -Name Compl8ShadowLabelOps -Scope Global -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $cfgRoot -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
            Import-Module $script:EngineDir -Force
            # Re-establish the label SCC global stubs the executor tests rely on (the recorder removed
            # them in this finally block).
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
        }
    }

    # The committed config fixture the recorder + the executor BOTH drive (one create leaf, one
    # pre-existing group => update, one sublabel => create, plus a published policy). Small + genuine.
    $script:ShadowSettingsJson = '{ "namingPrefix": "QGISCF", "labelPolicyName": "Default-Label-Policy", "interCallDelaySec": 0, "maxRetries": 2, "baseDelaySec": 1 }'
    $script:ShadowLabelsJson = @'
[
  { "code":"OFFI", "name":"OFFICIAL", "displayName":"OFFICIAL", "priority":0, "parentGroup":null, "isGroup":false, "colour":"#008000", "encrypt":false, "tooltip":"t", "headerText":"OFFICIAL", "footerText":"OFFICIAL", "contentType":"File, Email" },
  { "code":null, "name":"SENSITIVE", "displayName":"SENSITIVE", "priority":1, "parentGroup":null, "isGroup":true, "colour":"#0078D4", "encrypt":false, "tooltip":"t", "headerText":null, "footerText":null, "contentType":null },
  { "code":"SENS", "name":"SENSITIVE-Default", "displayName":"SENSITIVE", "priority":2, "parentGroup":"SENSITIVE", "isGroup":false, "colour":"#0078D4", "encrypt":false, "tooltip":"t", "headerText":"SENSITIVE", "footerText":"SENSITIVE", "contentType":"File, Email" }
]
'@
}

AfterAll {
    if ($env:COMPL8_PROVENANCE_REGISTRY -and (Test-Path -LiteralPath $env:COMPL8_PROVENANCE_REGISTRY)) {
        Remove-Item -LiteralPath $env:COMPL8_PROVENANCE_REGISTRY -Force -ErrorAction SilentlyContinue
    }
    Remove-Item Env:\COMPL8_PROVENANCE_REGISTRY -ErrorAction SilentlyContinue
    Remove-Item Env:\COMPL8_DEPLOYMENT_ID -ErrorAction SilentlyContinue
    foreach ($fn in 'New-DlpKeywordDictionary', 'Set-DlpKeywordDictionary', 'Get-DlpKeywordDictionary', 'Remove-DlpKeywordDictionary',
        'Get-Label', 'New-Label', 'Set-Label', 'Remove-Label',
        'Get-LabelPolicy', 'New-LabelPolicy', 'Set-LabelPolicy', 'Remove-LabelPolicy') {
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

# =================================================================================================
# Label executor (Task 9) — the FIRST executor that copies the Task-8 pilot template but shadows
# against a leaf SCRIPT (Deploy-Labels.ps1) rather than a function. Handles `label` (leaf + group)
# and `labelPolicy` steps. Ports the old path's New-/Set-/Get-Label + *-LabelPolicy sequence and its
# guards (parent-label resolution + caching, leaf-vs-group type-mismatch guard, Invoke-WithRetry on
# policies, LabelAlreadyPublished dual-publish recovery), stamps provenance on the Comment, and proves
# parity against the GENUINE Deploy-Labels.ps1 run via Get-Compl8ShadowDiff.
# =================================================================================================

Describe 'module surface — label executor' {
    It 'exports Invoke-Compl8LabelExecutor from Compl8.Engine' {
        (Get-Command -Name 'Invoke-Compl8LabelExecutor' -Module Compl8.Engine -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-Compl8LabelExecutor — create label (New-Label)' {
    It 'calls New-Label once for a new leaf label and returns a created result' {
        Mock -ModuleName Compl8.Engine Get-Label { $null }      # nothing exists yet
        Mock -ModuleName Compl8.Engine New-Label { [pscustomobject]@{ Guid = [guid]'00000000-0000-0000-0000-0000000000a1' } }
        Mock -ModuleName Compl8.Engine Set-Label { throw 'must not update on create' }

        $step = New-LabelStep -Id 's01' -Action 'create' -ObjectRef 'QGISCF-OFFICIAL-OFFI'
        $result = Invoke-Compl8LabelExecutor -Step $step -Content $script:LabelDef -Prefix $script:Prefix

        Should -Invoke -ModuleName Compl8.Engine New-Label -Times 1
        Should -Invoke -ModuleName Compl8.Engine Set-Label -Times 0
        $result.status     | Should -Be 'created'
        $result.action     | Should -Be 'create'
        $result.objectType | Should -Be 'label'
        $result.objectRef  | Should -Be 'QGISCF-OFFICIAL-OFFI'
        $result.guid       | Should -Be '00000000-0000-0000-0000-0000000000a1'
    }
}

Describe 'Invoke-Compl8LabelExecutor — update label (Set-Label)' {
    It 'takes the Set-Label path when the label already exists and returns an updated result' {
        Mock -ModuleName Compl8.Engine Get-Label { [pscustomobject]@{ Guid = [guid]'00000000-0000-0000-0000-0000000000b2'; ContentType = 'File, Email' } }
        Mock -ModuleName Compl8.Engine New-Label { throw 'New-Label must not be called on update' }
        Mock -ModuleName Compl8.Engine Set-Label { }

        $step = New-LabelStep -Id 's01' -Action 'update' -ObjectRef 'QGISCF-OFFICIAL-OFFI'
        $result = Invoke-Compl8LabelExecutor -Step $step -Content $script:LabelDef -Prefix $script:Prefix

        Should -Invoke -ModuleName Compl8.Engine Set-Label -Times 1
        Should -Invoke -ModuleName Compl8.Engine New-Label -Times 0
        $result.status | Should -Be 'updated'
        $result.guid   | Should -Be '00000000-0000-0000-0000-0000000000b2'
    }
}

Describe 'Invoke-Compl8LabelExecutor — leaf-vs-group TYPE-MISMATCH guard' {
    It 'BLOCKS when a desired GROUP already exists as a leaf (has ContentType): no New/Set, requires manual cleanup' {
        # The group SENSITIVE already exists as a LEAF label (ContentType set) — the old path refuses
        # to convert and demands a manual delete. The executor must do the same: status 'type-mismatch',
        # no mutation.
        Mock -ModuleName Compl8.Engine Get-Label { [pscustomobject]@{ Guid = [guid]'00000000-0000-0000-0000-0000000000c3'; ContentType = 'File, Email' } }
        Mock -ModuleName Compl8.Engine New-Label { throw 'must not create over a type mismatch' }
        Mock -ModuleName Compl8.Engine Set-Label { throw 'must not update over a type mismatch' }

        $step = New-LabelStep -Id 's01' -Action 'create' -ObjectRef 'QGISCF-SENSITIVE'
        $result = Invoke-Compl8LabelExecutor -Step $step -Content $script:GroupDef -Prefix $script:Prefix

        Should -Invoke -ModuleName Compl8.Engine New-Label -Times 0
        Should -Invoke -ModuleName Compl8.Engine Set-Label -Times 0
        $result.status | Should -Be 'type-mismatch'
        $result.reason | Should -Match 'manual'
    }

    It 'BLOCKS when a desired top-level LEAF already exists as a group (no ContentType): no New/Set' {
        Mock -ModuleName Compl8.Engine Get-Label { [pscustomobject]@{ Guid = [guid]'00000000-0000-0000-0000-0000000000c4'; ContentType = $null } }
        Mock -ModuleName Compl8.Engine New-Label { throw 'must not create over a type mismatch' }
        Mock -ModuleName Compl8.Engine Set-Label { throw 'must not update over a type mismatch' }

        $step = New-LabelStep -Id 's01' -Action 'update' -ObjectRef 'QGISCF-OFFICIAL-OFFI'
        $result = Invoke-Compl8LabelExecutor -Step $step -Content $script:LabelDef -Prefix $script:Prefix

        Should -Invoke -ModuleName Compl8.Engine New-Label -Times 0
        Should -Invoke -ModuleName Compl8.Engine Set-Label -Times 0
        $result.status | Should -Be 'type-mismatch'
    }
}

Describe 'Invoke-Compl8LabelExecutor — parent resolution + caching for a sublabel' {
    It 'resolves the parent group Guid via Get-Label and passes ParentId to New-Label' {
        $script:capturedParentId = $null
        Mock -ModuleName Compl8.Engine Get-Label {
            param([string]$Identity)
            if ($Identity -eq 'QGISCF-SENSITIVE') { return [pscustomobject]@{ Guid = [guid]'00000000-0000-0000-0000-0000000000dd'; ContentType = $null } }
            $null   # the sublabel itself does not yet exist
        }
        Mock -ModuleName Compl8.Engine New-Label {
            $script:capturedParentId = $ParentId
            [pscustomobject]@{ Guid = [guid]'00000000-0000-0000-0000-0000000000ee' }
        }

        $step = New-LabelStep -Id 's03' -Action 'create' -ObjectRef 'QGISCF-SENSITIVE-Default-SENS'
        $result = Invoke-Compl8LabelExecutor -Step $step -Content $script:SubLabelDef -Prefix $script:Prefix

        $result.status            | Should -Be 'created'
        $script:capturedParentId  | Should -Be '00000000-0000-0000-0000-0000000000dd'
    }

    It 'reuses a cached parent Guid (-ParentGuidCache) without re-querying Get-Label for the parent' {
        Mock -ModuleName Compl8.Engine Get-Label { $null }   # sublabel absent; parent NOT looked up because cached
        Mock -ModuleName Compl8.Engine New-Label { [pscustomobject]@{ Guid = [guid]'00000000-0000-0000-0000-0000000000ef' } }

        $cache = @{ 'SENSITIVE' = '00000000-0000-0000-0000-0000000000dd' }
        $step = New-LabelStep -Id 's03' -Action 'create' -ObjectRef 'QGISCF-SENSITIVE-Default-SENS'
        $result = Invoke-Compl8LabelExecutor -Step $step -Content $script:SubLabelDef -Prefix $script:Prefix -ParentGuidCache $cache

        $result.status | Should -Be 'created'
        # The only Get-Label call is the sublabel's own existence probe; the parent came from the cache.
        Should -Invoke -ModuleName Compl8.Engine Get-Label -Times 1
    }

    It 'reports parent-not-found (skipped) when the parent group cannot be resolved' {
        Mock -ModuleName Compl8.Engine Get-Label { $null }   # neither sublabel nor parent exists
        Mock -ModuleName Compl8.Engine New-Label { throw 'must not create a sublabel without a parent' }

        $step = New-LabelStep -Id 's03' -Action 'create' -ObjectRef 'QGISCF-SENSITIVE-Default-SENS'
        $result = Invoke-Compl8LabelExecutor -Step $step -Content $script:SubLabelDef -Prefix $script:Prefix

        Should -Invoke -ModuleName Compl8.Engine New-Label -Times 0
        $result.status | Should -Be 'parent-not-found'
    }
}

Describe 'Invoke-Compl8LabelExecutor — provenance marker on the stamped Comment' {
    It 'stamps the [[Compl8:...]] marker on the label Comment passed to New-Label' {
        $script:capturedComment = $null
        Mock -ModuleName Compl8.Engine Get-Label { $null }
        Mock -ModuleName Compl8.Engine New-Label {
            $script:capturedComment = $Comment
            [pscustomobject]@{ Guid = [guid]'00000000-0000-0000-0000-0000000000f1' }
        }

        $step = New-LabelStep -Id 's01' -Action 'create' -ObjectRef 'QGISCF-OFFICIAL-OFFI'
        $result = Invoke-Compl8LabelExecutor -Step $step -Content $script:LabelDef -Prefix $script:Prefix

        $script:capturedComment    | Should -Match '\[\[Compl8:[0-9a-f]{16}\]\]'
        $result.stampedComment     | Should -Match '\[\[Compl8:[0-9a-f]{16}\]\]'
    }
}

Describe 'Invoke-Compl8LabelExecutor — create label policy (New-LabelPolicy via Invoke-WithRetry)' {
    It 'creates a new policy with the publishable labels and a provenance-stamped Comment' {
        $script:capturedPolicyComment = $null
        Mock -ModuleName Compl8.Engine Get-LabelPolicy { $null }
        Mock -ModuleName Compl8.Engine New-LabelPolicy { $script:capturedPolicyComment = $Comment }
        Mock -ModuleName Compl8.Engine Set-LabelPolicy { throw 'must not Set on create' }
        Mock -ModuleName Compl8.Engine Invoke-WithRetry { & $ScriptBlock }   # exercise the wrapper path

        $step = New-LabelStep -Id 's04' -Action 'create' -ObjectRef 'QGISCF-Default-Label-Policy' -ObjectType 'labelPolicy'
        $result = Invoke-Compl8LabelExecutor -Step $step -Content $script:PolicyDef -Prefix $script:Prefix `
            -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-LabelPolicy -Times 1
        Should -Invoke -ModuleName Compl8.Engine Invoke-WithRetry -Times 1
        $result.status              | Should -Be 'created'
        $result.objectType          | Should -Be 'labelPolicy'
        $script:capturedPolicyComment | Should -Match '\[\[Compl8:[0-9a-f]{16}\]\]'
    }
}

Describe 'Invoke-Compl8LabelExecutor — update label policy (Set-LabelPolicy)' {
    It 'updates an existing policy via Set-LabelPolicy (AddLabels) and returns an updated result' {
        Mock -ModuleName Compl8.Engine Get-LabelPolicy { [pscustomobject]@{ Name = 'QGISCF-Default-Label-Policy'; Guid = [guid]'00000000-0000-0000-0000-0000000000f5' } }
        Mock -ModuleName Compl8.Engine New-LabelPolicy { throw 'must not create an existing policy' }
        Mock -ModuleName Compl8.Engine Set-LabelPolicy { }

        $step = New-LabelStep -Id 's04' -Action 'update' -ObjectRef 'QGISCF-Default-Label-Policy' -ObjectType 'labelPolicy'
        $result = Invoke-Compl8LabelExecutor -Step $step -Content $script:PolicyDef -Prefix $script:Prefix -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine Set-LabelPolicy -Times 1
        Should -Invoke -ModuleName Compl8.Engine New-LabelPolicy -Times 0
        $result.status | Should -Be 'updated'
    }
}

Describe 'Invoke-Compl8LabelExecutor — LabelAlreadyPublished dual-publish recovery' {
    It 'treats a LabelAlreadyPublished error on Set-LabelPolicy as success (no rethrow)' {
        Mock -ModuleName Compl8.Engine Get-LabelPolicy { [pscustomobject]@{ Name = 'QGISCF-Default-Label-Policy'; Guid = [guid]'00000000-0000-0000-0000-0000000000f6' } }
        Mock -ModuleName Compl8.Engine Set-LabelPolicy { throw 'Error: LabelAlreadyPublished — the label is already published to this policy.' }

        $step = New-LabelStep -Id 's04' -Action 'update' -ObjectRef 'QGISCF-Default-Label-Policy' -ObjectType 'labelPolicy'
        $result = Invoke-Compl8LabelExecutor -Step $step -Content $script:PolicyDef -Prefix $script:Prefix -SleepAction { param($s) }

        $result.status | Should -Be 'already-published'
    }

    It 'rethrows a NON-LabelAlreadyPublished error from Set-LabelPolicy' {
        Mock -ModuleName Compl8.Engine Get-LabelPolicy { [pscustomobject]@{ Name = 'QGISCF-Default-Label-Policy'; Guid = [guid]'00000000-0000-0000-0000-0000000000f7' } }
        Mock -ModuleName Compl8.Engine Set-LabelPolicy { throw 'Insufficient permissions to modify the policy.' }

        $step = New-LabelStep -Id 's04' -Action 'update' -ObjectRef 'QGISCF-Default-Label-Policy' -ObjectType 'labelPolicy'
        { Invoke-Compl8LabelExecutor -Step $step -Content $script:PolicyDef -Prefix $script:Prefix -SleepAction { param($s) } } |
            Should -Throw
    }
}

Describe 'Invoke-Compl8LabelExecutor — remove (via Remove-PurviewObject)' {
    It 'removes a label via Remove-PurviewObject and returns a deleted result' {
        Mock -ModuleName Compl8.Engine Get-Label { [pscustomobject]@{ Guid = [guid]'00000000-0000-0000-0000-0000000000f8' } }
        Mock -ModuleName Compl8.Engine Remove-Label { }

        $step = New-LabelStep -Id 's01' -Action 'remove' -ObjectRef 'QGISCF-OFFICIAL-OFFI'
        $result = Invoke-Compl8LabelExecutor -Step $step -Content $script:LabelDef -Prefix $script:Prefix

        Should -Invoke -ModuleName Compl8.Engine Remove-Label -Times 1
        $result.status      | Should -Be 'deleted'
        $result.removeState | Should -Be 'deleted'
    }

    It 'removes a label POLICY via Remove-PurviewObject (Remove-LabelPolicy)' {
        Mock -ModuleName Compl8.Engine Get-LabelPolicy { [pscustomobject]@{ Name = 'QGISCF-Default-Label-Policy' } }
        Mock -ModuleName Compl8.Engine Remove-LabelPolicy { }

        $step = New-LabelStep -Id 's04' -Action 'remove' -ObjectRef 'QGISCF-Default-Label-Policy' -ObjectType 'labelPolicy'
        $result = Invoke-Compl8LabelExecutor -Step $step -Content $script:PolicyDef -Prefix $script:Prefix

        Should -Invoke -ModuleName Compl8.Engine Remove-LabelPolicy -Times 1
        $result.status | Should -Be 'deleted'
    }
}

Describe 'Invoke-Compl8LabelExecutor — planned ops (-WhatIf / plan mode)' {
    It 'emits a normalised create op per label/policy in the Get-Compl8ShadowDiff op shape (NO mutation)' {
        Mock -ModuleName Compl8.Engine New-Label { throw 'no mutation under -WhatIf' }
        Mock -ModuleName Compl8.Engine Set-Label { throw 'no mutation under -WhatIf' }
        Mock -ModuleName Compl8.Engine New-LabelPolicy { throw 'no mutation under -WhatIf' }

        $labelOp = Invoke-Compl8LabelExecutor -Step (New-LabelStep -Id 's01' -Action 'create' -ObjectRef 'QGISCF-OFFICIAL-OFFI') -Content $script:LabelDef -Prefix $script:Prefix -WhatIf
        $polOp   = Invoke-Compl8LabelExecutor -Step (New-LabelStep -Id 's04' -Action 'create' -ObjectRef 'QGISCF-Default-Label-Policy' -ObjectType 'labelPolicy') -Content $script:PolicyDef -Prefix $script:Prefix -WhatIf

        Should -Invoke -ModuleName Compl8.Engine New-Label -Times 0
        $labelOp.objectType | Should -Be 'label'
        $labelOp.action     | Should -Be 'create'
        $labelOp.objectRef  | Should -Be 'QGISCF-OFFICIAL-OFFI'
        $polOp.objectType   | Should -Be 'labelPolicy'
        $polOp.objectRef    | Should -Be 'QGISCF-Default-Label-Policy'
    }
}

Describe 'Invoke-Compl8LabelExecutor — SHADOW PARITY vs Deploy-Labels.ps1 -WhatIf (GENUINE)' {
    It 'executor planned ops MATCH the REAL Deploy-Labels.ps1 ops (Get-Compl8ShadowDiff.Match = $true)' {
        # OLD side: genuinely run Deploy-Labels.ps1 against the committed config fixture, with the
        # connection/session boundary + SCC cmdlets replaced by GLOBAL recording stubs. The recorded
        # New-/Set-Label + New-LabelPolicy calls are the old path's REAL intended operations.
        $oldOps = Get-OldLabelWhatIfOps -LabelsJson $script:ShadowLabelsJson -SettingsJson $script:ShadowSettingsJson -PublishTo $script:PolicyDef.scope

        # ENGINE side: run the executor in -WhatIf over the SAME objects, in the SAME tenant state the
        # recorder modelled (the SENSITIVE group pre-exists => an UPDATE op, everything else CREATE).
        # -WhatIf is pure planning, so we drive the planned-op decision with -ExistingState (the same
        # 'group already exists' fact the recorder's Get-Label encodes) so both sides see one state.
        $existing = @{ 'QGISCF-SENSITIVE' = [pscustomobject]@{ Guid = [guid]'00000000-0000-0000-0000-0000000000bb'; ContentType = $null } }
        $engineSteps = @(
            @{ Step = (New-LabelStep -Id 's01' -Action 'create' -ObjectRef 'QGISCF-OFFICIAL-OFFI');                    Content = $script:LabelDef }
            @{ Step = (New-LabelStep -Id 's02' -Action 'create' -ObjectRef 'QGISCF-SENSITIVE');                        Content = $script:GroupDef }
            @{ Step = (New-LabelStep -Id 's03' -Action 'create' -ObjectRef 'QGISCF-SENSITIVE-Default-SENS');          Content = $script:SubLabelDef }
            @{ Step = (New-LabelStep -Id 's04' -Action 'create' -ObjectRef 'QGISCF-Default-Label-Policy' -ObjectType 'labelPolicy'); Content = $script:PolicyDef }
        )
        $engineOps = foreach ($e in $engineSteps) {
            Invoke-Compl8LabelExecutor -Step $e.Step -Content $e.Content -Prefix $script:Prefix -ExistingState $existing -WhatIf
        }

        # Guard against a vacuous empty == empty pass: the old path MUST have produced operations.
        @($oldOps).Count    | Should -BeGreaterThan 0 -Because 'the fixture must drive real Deploy-Labels.ps1 operations'
        @($oldOps).Count    | Should -Be 4 -Because 'one leaf create, one group update, one sublabel create, one policy create'
        @($engineOps).Count | Should -Be 4

        $diff = Get-Compl8ShadowDiff -EngineOps @($engineOps) -OldOps @($oldOps)
        $diff.Match | Should -BeTrue -Because "executor planned ops must reproduce the real Deploy-Labels.ps1 path. OnlyInEngine=$(@($diff.OnlyInEngine) | ForEach-Object { $_.action + ':' + $_.objectRef } | Join-String -Separator ','); OnlyInOld=$(@($diff.OnlyInOld) | ForEach-Object { $_.action + ':' + $_.objectRef } | Join-String -Separator ',')"
        @($diff.OnlyInEngine).Count | Should -Be 0
        @($diff.OnlyInOld).Count    | Should -Be 0
        @($diff.Differing).Count    | Should -Be 0
    }
}
