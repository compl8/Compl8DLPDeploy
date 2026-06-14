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

    # ---- Rule-package SCC cmdlet stubs (Task 10). Same global-stub pattern: the rule-package executor
    # invokes New-/Set-/Remove-DlpSensitiveInformationTypeRulePackage, the deployed-package probe
    # Get-DlpSensitiveInformationTypeRulePackage, and the post-upload verify poll
    # Get-DlpSensitiveInformationType DYNAMICALLY, so they must EXIST for `Mock -ModuleName Compl8.Engine`
    # to shadow them. (No -ErrorAction/-Confirm redeclared — common params from [CmdletBinding].)
    function global:New-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([byte[]]$FileData) }
    function global:Set-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([byte[]]$FileData) }
    function global:Remove-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }
    function global:Get-DlpSensitiveInformationTypeRulePackage { [CmdletBinding()] param([string]$Identity) }
    function global:Get-DlpSensitiveInformationType { [CmdletBinding()] param([string]$Identity) }

    # ---- DLP rule/policy SCC cmdlet stubs (Task 11). The DLP rule/policy executor invokes
    # New-/Set-/Get-/Remove-DlpComplianceRule and *-DlpCompliancePolicy DYNAMICALLY, so they must EXIST
    # for `Mock -ModuleName Compl8.Engine`. New/Set-Rule declare the full param surface the executor
    # splats (condition + report/notify params) so a mock binds without a "parameter cannot be found".
    function global:Get-DlpCompliancePolicy { [CmdletBinding()] param([string]$Identity) }
    function global:New-DlpCompliancePolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$Comment, [string]$Mode, [string]$ExchangeLocation, [string]$OneDriveLocation, [string]$SharePointLocation, [string]$EndpointDlpLocation, [string]$TeamsLocation) }
    function global:Set-DlpCompliancePolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [string]$Comment, [string]$Mode) }
    function global:Remove-DlpCompliancePolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }
    function global:Get-DlpComplianceRule { [CmdletBinding()] param([string]$Identity, [string]$Policy) }
    function global:New-DlpComplianceRule {
        [CmdletBinding(SupportsShouldProcess)]
        param([string]$Name, [string]$Policy, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule,
            [string]$ReportSeverityLevel, [bool]$Disabled, [string]$AccessScope,
            [string]$GenerateIncidentReport, [string]$IncidentReportContent, [string]$NotifyUser)
    }
    function global:Set-DlpComplianceRule {
        [CmdletBinding(SupportsShouldProcess)]
        param([string]$Identity, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule,
            [string]$ReportSeverityLevel, [bool]$Disabled, [string]$AccessScope,
            [string]$GenerateIncidentReport, [string]$IncidentReportContent, [string]$NotifyUser)
    }
    function global:Remove-DlpComplianceRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }

    # ---- Auto-label SCC cmdlet stubs (Task 12). The auto-label executor invokes
    # New-/Set-/Get-/Remove-AutoSensitivityLabelPolicy and *-AutoSensitivityLabelRule DYNAMICALLY, so
    # they must EXIST for `Mock -ModuleName Compl8.Engine`. New/Set declare the param surface the
    # executor splats so a mock binds without a "parameter cannot be found".
    function global:Get-AutoSensitivityLabelPolicy { [CmdletBinding()] param([string]$Identity) }
    function global:New-AutoSensitivityLabelPolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$ApplySensitivityLabel, [string]$Comment, [string]$Mode, [string]$ExchangeLocation, [string]$OneDriveLocation, [string]$SharePointLocation, [switch]$OverwriteLabel) }
    function global:Set-AutoSensitivityLabelPolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [string]$ApplySensitivityLabel, [string]$Comment, [string]$Mode, [bool]$StartSimulation, [switch]$OverwriteLabel) }
    function global:Remove-AutoSensitivityLabelPolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }
    function global:Get-AutoSensitivityLabelRule { [CmdletBinding()] param([string]$Identity, [string]$Policy) }
    function global:New-AutoSensitivityLabelRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$Policy, [string]$Workload, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled, [string]$AccessScope) }
    function global:Set-AutoSensitivityLabelRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled, [string]$AccessScope) }
    function global:Remove-AutoSensitivityLabelRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }

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
        'Get-LabelPolicy', 'New-LabelPolicy', 'Set-LabelPolicy', 'Remove-LabelPolicy',
        'New-DlpSensitiveInformationTypeRulePackage', 'Set-DlpSensitiveInformationTypeRulePackage',
        'Remove-DlpSensitiveInformationTypeRulePackage', 'Get-DlpSensitiveInformationTypeRulePackage',
        'Get-DlpSensitiveInformationType',
        'Get-DlpCompliancePolicy', 'New-DlpCompliancePolicy', 'Set-DlpCompliancePolicy', 'Remove-DlpCompliancePolicy',
        'Get-DlpComplianceRule', 'New-DlpComplianceRule', 'Set-DlpComplianceRule', 'Remove-DlpComplianceRule',
        'Get-AutoSensitivityLabelPolicy', 'New-AutoSensitivityLabelPolicy', 'Set-AutoSensitivityLabelPolicy', 'Remove-AutoSensitivityLabelPolicy',
        'Get-AutoSensitivityLabelRule', 'New-AutoSensitivityLabelRule', 'Set-AutoSensitivityLabelRule', 'Remove-AutoSensitivityLabelRule') {
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

Describe 'Invoke-Compl8LabelExecutor — SHADOW PARITY vs Deploy-Labels.ps1 -WhatIf (GENUINE)' -Tag 'Slow' {
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

# =================================================================================================
# Rule-package executor (Task 10) — copies the pilot template and shadows against the rule-package
# upload/removal path of scripts/Deploy-Classifiers.ps1. Handles `rulePackage` create|update|remove.
# Ports the operational guards that belong at apply time — the capacity gate (Test-UploadCapacityGate),
# the dictionary-reference assertion (Assert-RulePackageUploadDictionaryReferences /
# Assert-PackageDictionaryReferencesExist), and the post-upload SIT verification poll
# (Test-UploadedSensitiveInformationTypes) — and proves parity against a GENUINE run of the old
# operational code via Get-Compl8ShadowDiff.
#
# SHADOW STRATEGY (genuine, reused from Task 9 but adapted): Deploy-Classifiers.ps1's UPLOAD path is
# guarded by SCRIPT-scoped gates (Invoke-ReadinessGate -> Test-DeploymentReadiness.ps1, the direct-
# upload refit gate, the fingerprint gate) that the global-stub boundary cannot shadow and that are
# NOT the operational mutation code under test (they are SUBSUMED by plan freshness + the apply
# framework). So instead of running the whole script top-to-bottom, the recorder loads the script's
# REAL function definitions via AST (skipping the param block + #region Main, so no deployment runs)
# and invokes the GENUINE Invoke-ClassifierUploadPlan — the real old upload orchestrator that runs the
# real Test-UploadCapacityGate, Resolve-RulePackageUploadContent, Assert-RulePackageUploadDictionary-
# References, Invoke-RulePackageUploadCommand and Test-UploadedSensitiveInformationTypes — with the SCC
# cmdlets replaced by GLOBAL recording stubs. The recorded New-DlpSensitiveInformationTypeRulePackage
# call (with the real prefix-scoped name the old name generator produced) IS the old path's intended
# operation, derived from a real run, never hand-authored. This runs live each test (no frozen fixture).

Describe 'module surface — rule-package executor' {
    It 'exports Invoke-Compl8RulePackageExecutor from Compl8.Engine' {
        (Get-Command -Name 'Invoke-Compl8RulePackageExecutor' -Module Compl8.Engine -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-Compl8RulePackageExecutor — fixtures' {
    BeforeAll {
        # A small, valid resolved rule-package XML with NO dictionary GUID refs (so the dict-ref guard
        # passes trivially) and one declared local SIT id for the post-upload verify poll.
        $script:PkgSitId   = '88888888-8888-8888-8888-888888888888'
        $script:PkgPayload = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="99999999-9999-9999-9999-999999999999">
    <Version major="1" minor="0" build="0" revision="0" />
    <Publisher id="99999999-9999-9999-9999-999999999999" />
    <Details defaultLangCode="en-us"><LocalizedDetails langcode="en-us">
      <PublisherName>Queensland Government CSU</PublisherName><Name>QGISCF-medium-99</Name><Description>Shadow.</Description>
    </LocalizedDetails></Details>
  </RulePack>
  <Rules>
    <Entity id="$($script:PkgSitId)" patternsProximity="300" recommendedConfidence="75">
      <Pattern confidenceLevel="75"><IdMatch idRef="Pattern_shadow" /></Pattern>
    </Entity>
    <Regex id="Pattern_shadow">\b\d{3}\b</Regex>
  </Rules>
</RulePackage>
"@
        $script:PkgContent = [pscustomobject]@{
            name        = 'QGISCF-medium-99'
            payloadXml  = $script:PkgPayload
            localSitIds = @($script:PkgSitId)
        }
    }

    It 'create: calls New-DlpSensitiveInformationTypeRulePackage once and verifies, returns created' {
        Mock -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage { }
        Mock -ModuleName Compl8.Engine Set-DlpSensitiveInformationTypeRulePackage { throw 'must not Set on create' }
        Mock -ModuleName Compl8.Engine Get-DlpSensitiveInformationType { @([pscustomobject]@{ Identity = $script:PkgSitId; Id = $script:PkgSitId; Name = 'QGISCF - Shadow SIT' }) }

        $step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'rulePackage'; objectRef = 'QGISCF-medium-99'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8RulePackageExecutor -Step $step -Content $script:PkgContent -Prefix 'QGISCF' -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage -Times 1
        Should -Invoke -ModuleName Compl8.Engine Set-DlpSensitiveInformationTypeRulePackage -Times 0
        $result.status     | Should -Be 'created'
        $result.action     | Should -Be 'create'
        $result.objectType | Should -Be 'rulePackage'
        $result.objectRef  | Should -Be 'QGISCF-medium-99'
        $result.verified   | Should -BeTrue
    }

    It 'update: takes the Set-DlpSensitiveInformationTypeRulePackage path and returns updated' {
        Mock -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage { throw 'must not New on update' }
        Mock -ModuleName Compl8.Engine Set-DlpSensitiveInformationTypeRulePackage { }
        Mock -ModuleName Compl8.Engine Get-DlpSensitiveInformationType { @([pscustomobject]@{ Identity = $script:PkgSitId; Id = $script:PkgSitId }) }

        $step = [pscustomobject]@{ id = 's01'; action = 'update'; objectType = 'rulePackage'; objectRef = 'QGISCF-medium-99'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8RulePackageExecutor -Step $step -Content $script:PkgContent -Prefix 'QGISCF' -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine Set-DlpSensitiveInformationTypeRulePackage -Times 1
        Should -Invoke -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage -Times 0
        $result.status | Should -Be 'updated'
    }

    It 'remove: goes through Remove-PurviewObject (deleted) addressing the deployed Identity' {
        Mock -ModuleName Compl8.Engine Get-DlpSensitiveInformationTypeRulePackage { [pscustomobject]@{ Identity = 'deployed-id-1'; Name = 'QGISCF-medium-99' } }
        Mock -ModuleName Compl8.Engine Remove-DlpSensitiveInformationTypeRulePackage { }

        $content = [pscustomobject]@{ name = 'QGISCF-medium-99'; identity = 'deployed-id-1' }
        $step = [pscustomobject]@{ id = 's01'; action = 'remove'; objectType = 'rulePackage'; objectRef = 'QGISCF-medium-99'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8RulePackageExecutor -Step $step -Content $content -Prefix 'QGISCF' -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine Remove-DlpSensitiveInformationTypeRulePackage -Times 1
        $result.status      | Should -Be 'deleted'
        $result.removeState | Should -Be 'deleted'
    }

    It 'capacity gate: refuses a create that would exceed the slot cap (no New call), mirrors Test-UploadCapacityGate' {
        Mock -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage { throw 'must not create when over capacity' }

        $step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'rulePackage'; objectRef = 'QGISCF-medium-99'; dependsOn = @(); impact = @(); gate = $null }
        # 10/10 slots used, no removals freed -> no slot available for a new package.
        $result = Invoke-Compl8RulePackageExecutor -Step $step -Content $script:PkgContent -Prefix 'QGISCF' `
            -CurrentSlotsUsed 10 -SlotsFreed 0 -MaxPackageSlots 10 -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage -Times 0
        $result.status | Should -Be 'capacity-blocked'
        $result.reason | Should -Match 'slot'
    }

    It 'dictionary-reference assertion: refuses upload when a referenced dict GUID is absent (no New call)' {
        $dictGuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        $payloadWithDict = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <Rules><Entity id="77777777-7777-7777-7777-777777777777"><Pattern confidenceLevel="75">
    <IdMatch idRef="Pattern_x" /><Match idRef="$dictGuid" /></Pattern></Entity>
  <Regex id="Pattern_x">x</Regex></Rules>
</RulePackage>
"@
        Mock -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage { throw 'must not upload with a missing dictionary reference' }

        $content = [pscustomobject]@{ name = 'QGISCF-medium-99'; payloadXml = $payloadWithDict; localSitIds = @() }
        $step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'rulePackage'; objectRef = 'QGISCF-medium-99'; dependsOn = @(); impact = @(); gate = $null }
        # Tenant inventory does NOT contain the referenced GUID.
        $result = Invoke-Compl8RulePackageExecutor -Step $step -Content $content -Prefix 'QGISCF' `
            -DictionaryInventory @([pscustomobject]@{ Guid = 'ffffffff-ffff-ffff-ffff-ffffffffffff' }) -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage -Times 0
        $result.status        | Should -Be 'dict-ref-missing'
        @($result.dictErrors) | Should -Contain $dictGuid
    }

    It 'dictionary-reference assertion: PASSES when the referenced dict GUID is present in inventory' {
        $dictGuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        $payloadWithDict = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <Rules><Entity id="77777777-7777-7777-7777-777777777777"><Pattern confidenceLevel="75">
    <IdMatch idRef="Pattern_x" /><Match idRef="$dictGuid" /></Pattern></Entity>
  <Regex id="Pattern_x">x</Regex></Rules>
</RulePackage>
"@
        Mock -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage { }
        Mock -ModuleName Compl8.Engine Get-DlpSensitiveInformationType { @() }

        $content = [pscustomobject]@{ name = 'QGISCF-medium-99'; payloadXml = $payloadWithDict; localSitIds = @() }
        $step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'rulePackage'; objectRef = 'QGISCF-medium-99'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8RulePackageExecutor -Step $step -Content $content -Prefix 'QGISCF' `
            -DictionaryInventory @([pscustomobject]@{ Guid = $dictGuid }) -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage -Times 1
        $result.status | Should -Be 'created'
    }

    It 'post-upload verify poll: status verify-failed when a declared SIT never becomes visible' {
        Mock -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage { }
        # Tenant never returns the expected SIT id -> verification times out.
        Mock -ModuleName Compl8.Engine Get-DlpSensitiveInformationType { @([pscustomobject]@{ Identity = 'some-other-id'; Id = 'some-other-id' }) }

        $step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'rulePackage'; objectRef = 'QGISCF-medium-99'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8RulePackageExecutor -Step $step -Content $script:PkgContent -Prefix 'QGISCF' `
            -VerifyTimeoutSeconds 20 -VerifyIntervalSeconds 10 -SleepAction { param($s) }

        $result.status   | Should -Be 'verify-failed'
        $result.verified | Should -BeFalse
    }

    It 'planned ops (-WhatIf): emits a normalised op (create when absent, update when present) NO mutation' {
        Mock -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage { throw 'no mutation under -WhatIf' }
        Mock -ModuleName Compl8.Engine Set-DlpSensitiveInformationTypeRulePackage { throw 'no mutation under -WhatIf' }

        $step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'rulePackage'; objectRef = 'QGISCF-medium-99'; dependsOn = @(); impact = @(); gate = $null }
        $createOp = Invoke-Compl8RulePackageExecutor -Step $step -Content $script:PkgContent -WhatIf
        $updateOp = Invoke-Compl8RulePackageExecutor -Step $step -Content $script:PkgContent -ExistingState @{ 'QGISCF-medium-99' = [pscustomobject]@{ Identity = 'x' } } -WhatIf

        Should -Invoke -ModuleName Compl8.Engine New-DlpSensitiveInformationTypeRulePackage -Times 0
        $createOp.objectType | Should -Be 'rulePackage'
        $createOp.action     | Should -Be 'create'
        $createOp.objectRef  | Should -Be 'QGISCF-medium-99'
        $updateOp.action     | Should -Be 'update'
    }
}

Describe 'Invoke-Compl8RulePackageExecutor — SHADOW PARITY vs Deploy-Classifiers.ps1 upload (GENUINE)' -Tag 'Slow' {
  BeforeAll {
    # The GENUINE old-side recorder: load Deploy-Classifiers.ps1's REAL functions via AST (no main
    # body runs) and invoke the genuine Invoke-ClassifierUploadPlan with recording SCC stubs.
    function Get-OldRulePackageWhatIfOps {
        param([string]$PackageKey, [string]$Payload, [string]$LocalSitId)

        $scriptPath = Join-Path $script:RepoRoot 'scripts' 'Deploy-Classifiers.ps1'
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('clsf-shadow-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $recorded = [System.Collections.Generic.List[object]]::new()
        $global:Compl8ShadowPkgOps = $recorded
        try {
            Import-Module $script:DlpDeploy -Force
            New-Item -ItemType Directory -Path $tmp -Force | Out-Null
            Set-Content -Path (Join-Path $tmp "$PackageKey.xml") -Value $Payload -Encoding UTF8

            # AST-extract ONLY the script's top-level function definitions (skip param + #region Main).
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
            $funcs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Parent -is [System.Management.Automation.Language.NamedBlockAst] }, $false)
            . ([scriptblock]::Create((($funcs | ForEach-Object { $_.Extent.Text }) -join "`n`n")))

            # Script-scope variables the genuine functions read.
            $DeployDir = $tmp
            $XmlDir = $tmp
            $Tier = 'medium'
            $Publisher = 'Queensland Government CSU'
            $Prefix = 'QGISCF'
            $Scope = 'universal'
            $SkipDictionarySync = $true
            $WhatIfPreference = $false
            $Config = @{ maxRetries = 2; baseDelaySec = 1; interCallDelaySec = 0; namingPrefix = 'QGISCF'; sitPrefix = $null; dictionaryManifestUrl = 'https://fixture' }
            $script:SourceNamingPrefix = 'QGISCF'
            $script:DeploymentManifest = $null
            $script:DictionaryGuidMap = @{}
            $Packages = @{ $PackageKey = [pscustomobject]@{ key = $PackageKey; displayName = $PackageKey; rulePackId = '99999999-9999-9999-9999-999999999999' } }

            # GLOBAL recording SCC stubs — the genuine functions resolve these by normal scope.
            function global:Get-DlpSensitiveInformationTypeRulePackage { @() }   # empty tenant => New
            function global:Get-DlpSensitiveInformationType { @([pscustomobject]@{ Identity = $LocalSitId; Id = $LocalSitId; Name = 'QGISCF - Shadow SIT' }) }
            function global:Get-DlpKeywordDictionary { @() }
            function global:New-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([byte[]]$FileData); $global:Compl8ShadowPkgOps.Add([pscustomobject]@{ action = 'create'; objectType = 'rulePackage'; objectRef = $PackageKey }) | Out-Null }
            function global:Set-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([byte[]]$FileData); $global:Compl8ShadowPkgOps.Add([pscustomobject]@{ action = 'update'; objectType = 'rulePackage'; objectRef = $PackageKey }) | Out-Null }
            function global:Remove-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }

            # Build the genuine upload plan record the real loop consumes (New since the tenant is empty)
            # and invoke the REAL Invoke-ClassifierUploadPlan.
            $localInfo = Get-LocalPackageInfo -FilePath (Join-Path $tmp "$PackageKey.xml")
            $uploadPlan = @{ $PackageKey = @{ Action = 'New'; LocalInfo = $localInfo; DeployedInfo = $null; BumpVersion = $null } }
            $null = Invoke-ClassifierUploadPlan -UploadPlan $uploadPlan -Selected @($PackageKey)

            @($recorded)
        } finally {
            foreach ($fn in 'Get-DlpSensitiveInformationTypeRulePackage', 'Get-DlpSensitiveInformationType', 'Get-DlpKeywordDictionary',
                'New-DlpSensitiveInformationTypeRulePackage', 'Set-DlpSensitiveInformationTypeRulePackage', 'Remove-DlpSensitiveInformationTypeRulePackage') {
                Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
            }
            Remove-Variable -Name Compl8ShadowPkgOps -Scope Global -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
            Import-Module $script:EngineDir -Force
            # Re-establish the rule-package SCC global stubs the executor tests rely on.
            function global:New-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([byte[]]$FileData) }
            function global:Set-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([byte[]]$FileData) }
            function global:Remove-DlpSensitiveInformationTypeRulePackage { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }
            function global:Get-DlpSensitiveInformationTypeRulePackage { [CmdletBinding()] param([string]$Identity) }
            function global:Get-DlpSensitiveInformationType { [CmdletBinding()] param([string]$Identity) }
        }
    }
  }

    It 'executor planned ops MATCH the REAL Deploy-Classifiers upload ops (Get-Compl8ShadowDiff.Match = $true)' {
        $sitId = '88888888-8888-8888-8888-888888888888'
        $payload = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="99999999-9999-9999-9999-999999999999">
    <Version major="1" minor="0" build="0" revision="0" />
    <Publisher id="99999999-9999-9999-9999-999999999999" />
    <Details defaultLangCode="en-us"><LocalizedDetails langcode="en-us">
      <PublisherName>TestPattern</PublisherName><Name>QGISCF-medium-99</Name><Description>Shadow.</Description>
    </LocalizedDetails></Details>
  </RulePack>
  <Rules>
    <Entity id="$sitId" patternsProximity="300" recommendedConfidence="75">
      <Pattern confidenceLevel="75"><IdMatch idRef="Pattern_shadow" /></Pattern>
    </Entity>
    <Regex id="Pattern_shadow">\b\d{3}\b</Regex>
    <LocalizedStrings><Resource idRef="$sitId">
      <Name default="true" langcode="en-us">TestPattern - Shadow SIT</Name>
      <Description default="true" langcode="en-us">Shadow SIT.</Description>
    </Resource></LocalizedStrings>
  </Rules>
</RulePackage>
"@
        # OLD side: genuinely run the real Invoke-ClassifierUploadPlan against an empty tenant.
        $oldOps = Get-OldRulePackageWhatIfOps -PackageKey 'QGISCF-medium-99' -Payload $payload -LocalSitId $sitId

        # ENGINE side: run the executor in -WhatIf over the same package in the same (empty) tenant state.
        $content = [pscustomobject]@{ name = 'QGISCF-medium-99'; payloadXml = $payload; localSitIds = @($sitId) }
        $step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'rulePackage'; objectRef = 'QGISCF-medium-99'; dependsOn = @(); impact = @(); gate = $null }
        $engineOps = @(Invoke-Compl8RulePackageExecutor -Step $step -Content $content -Prefix 'QGISCF' -WhatIf)

        # Guard against a vacuous empty == empty pass: the old path MUST have produced operations.
        @($oldOps).Count    | Should -BeGreaterThan 0 -Because 'the fixture must drive a real Invoke-ClassifierUploadPlan upload'
        @($oldOps).Count    | Should -Be 1 -Because 'one package, empty tenant => one create'
        @($engineOps).Count | Should -Be 1

        $diff = Get-Compl8ShadowDiff -EngineOps @($engineOps) -OldOps @($oldOps)
        $diff.Match | Should -BeTrue -Because "executor planned ops must reproduce the real Deploy-Classifiers upload path. OnlyInEngine=$(@($diff.OnlyInEngine) | ForEach-Object { $_.action + ':' + $_.objectRef } | Join-String -Separator ','); OnlyInOld=$(@($diff.OnlyInOld) | ForEach-Object { $_.action + ':' + $_.objectRef } | Join-String -Separator ',')"
        @($diff.OnlyInEngine).Count | Should -Be 0
        @($diff.OnlyInOld).Count    | Should -Be 0
        @($diff.Differing).Count    | Should -Be 0
    }
}


# =================================================================================================
# DLP rule + policy executor (Task 11) — copies the pilot template and shadows against the inline
# deployment loop of scripts/Deploy-DLPRules.ps1. Handles `dlpPolicy` and `dlpRule`
# create|update|remove, PLUS the planner-generated `dereference` action (D5): strip the removed SIT
# GUID(s) carried on the step's impact from the rule's ContentContainsSensitiveInformation, and DELETE
# the rule if no SIT remains. Ports the SIT-validation gate, the name-conflict pre-flight, and
# Invoke-WithRetry, stamps provenance, and proves parity against a GENUINE Deploy-DLPRules.ps1 run.
#
# SHADOW STRATEGY (genuine, reused from Task 9): Deploy-DLPRules.ps1's deployment loop is the script's
# TOP-LEVEL body, and its gates (Connect-/Assert-DLPSession, Test-DeploymentTenantFingerprint,
# Start-DeploymentLog) are module-scoped functions the global-stub boundary CAN shadow. So the recorder
# runs the WHOLE real script against a committed per-tenant config fixture with those boundary functions
# + the SCC cmdlets replaced by GLOBAL recording stubs. The recorded New-DlpCompliancePolicy /
# New-DlpComplianceRule calls (with the real prefix-scoped names the production name generator produced)
# ARE the old path's intended operations, derived from a real run. Runs live each test (no frozen fixture).

Describe 'module surface — DLP rule/policy executor' {
    It 'exports Invoke-Compl8DlpRuleExecutor from Compl8.Engine' {
        (Get-Command -Name 'Invoke-Compl8DlpRuleExecutor' -Module Compl8.Engine -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-Compl8DlpRuleExecutor — policy + rule create/update/remove' {
    BeforeAll {
        $script:DlpPolicyContent = [pscustomobject]@{
            name = 'P01-ECH-QGISCF-EXT-ADT'; mode = 'TestWithNotifications'; comment = 'policy c'
            locations = @{ ExchangeLocation = 'All' }
        }
        $script:DlpRuleContent = [pscustomobject]@{
            name = 'P01-R01-ECH-OFFI-EXT-ADT'; policy = 'P01-ECH-QGISCF-EXT-ADT'; comment = 'rule c'
            sitIds = @('50b8b56b-4ef8-44c2-a924-03374f5831ce')
            condition = @{ Format = 'Simple'; Value = @{ operator = 'And'; groups = @(@{ operator = 'Or'; name = 'Default'; sensitivetypes = @(@{ id = '50b8b56b-4ef8-44c2-a924-03374f5831ce'; name = 'All Full Names' }) }) } }
        }
    }

    It 'policy create: New-DlpCompliancePolicy once, provenance-stamped Comment, returns created' {
        $script:capturedPolicyComment = $null
        Mock -ModuleName Compl8.Engine Get-DlpCompliancePolicy { $null }
        Mock -ModuleName Compl8.Engine New-DlpCompliancePolicy { $script:capturedPolicyComment = $Comment }
        Mock -ModuleName Compl8.Engine Set-DlpCompliancePolicy { throw 'must not Set on create' }

        $step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'dlpPolicy'; objectRef = 'P01-ECH-QGISCF-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8DlpRuleExecutor -Step $step -Content $script:DlpPolicyContent -Prefix 'QGISCF' -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-DlpCompliancePolicy -Times 1
        $result.status               | Should -Be 'created'
        $result.objectType           | Should -Be 'dlpPolicy'
        $script:capturedPolicyComment | Should -Match '\[\[Compl8:[0-9a-f]{16}\]\]'
    }

    It 'policy update: Set-DlpCompliancePolicy when it already exists, returns updated' {
        Mock -ModuleName Compl8.Engine Get-DlpCompliancePolicy { [pscustomobject]@{ Name = 'P01-ECH-QGISCF-EXT-ADT' } }
        Mock -ModuleName Compl8.Engine New-DlpCompliancePolicy { throw 'must not New on update' }
        Mock -ModuleName Compl8.Engine Set-DlpCompliancePolicy { }

        $step = [pscustomobject]@{ id = 's01'; action = 'update'; objectType = 'dlpPolicy'; objectRef = 'P01-ECH-QGISCF-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8DlpRuleExecutor -Step $step -Content $script:DlpPolicyContent -Prefix 'QGISCF' -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine Set-DlpCompliancePolicy -Times 1
        $result.status | Should -Be 'updated'
    }

    It 'rule create: New-DlpComplianceRule once, provenance Comment, ContentContainsSensitiveInformation set' {
        $script:capturedCcsi = $null
        Mock -ModuleName Compl8.Engine Get-DlpComplianceRule { $null }
        Mock -ModuleName Compl8.Engine New-DlpComplianceRule { $script:capturedCcsi = $ContentContainsSensitiveInformation }
        Mock -ModuleName Compl8.Engine Set-DlpComplianceRule { throw 'must not Set on create' }

        $step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'dlpRule'; objectRef = 'P01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8DlpRuleExecutor -Step $step -Content $script:DlpRuleContent -Prefix 'QGISCF' -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-DlpComplianceRule -Times 1
        $result.status      | Should -Be 'created'
        $result.objectType  | Should -Be 'dlpRule'
        $script:capturedCcsi | Should -Not -BeNullOrEmpty
    }

    It 'rule update: Set-DlpComplianceRule when it already exists' {
        Mock -ModuleName Compl8.Engine Get-DlpComplianceRule { [pscustomobject]@{ Name = 'P01-R01-ECH-OFFI-EXT-ADT' } }
        Mock -ModuleName Compl8.Engine New-DlpComplianceRule { throw 'must not New on update' }
        Mock -ModuleName Compl8.Engine Set-DlpComplianceRule { }

        $step = [pscustomobject]@{ id = 's01'; action = 'update'; objectType = 'dlpRule'; objectRef = 'P01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8DlpRuleExecutor -Step $step -Content $script:DlpRuleContent -Prefix 'QGISCF' -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine Set-DlpComplianceRule -Times 1
        $result.status | Should -Be 'updated'
    }

    It 'rule remove: via Remove-PurviewObject (deleted)' {
        Mock -ModuleName Compl8.Engine Get-DlpComplianceRule { [pscustomobject]@{ Name = 'P01-R01-ECH-OFFI-EXT-ADT' } }
        Mock -ModuleName Compl8.Engine Remove-DlpComplianceRule { }

        $step = [pscustomobject]@{ id = 's01'; action = 'remove'; objectType = 'dlpRule'; objectRef = 'P01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8DlpRuleExecutor -Step $step -Content $script:DlpRuleContent -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine Remove-DlpComplianceRule -Times 1
        $result.status | Should -Be 'deleted'
    }
}

Describe 'Invoke-Compl8DlpRuleExecutor — SIT validation + name-conflict gates' {
    BeforeAll {
        $script:DlpRuleContent = [pscustomobject]@{
            name = 'P01-R01-ECH-OFFI-EXT-ADT'; policy = 'P01-ECH-QGISCF-EXT-ADT'; comment = 'rule c'
            sitIds = @('50b8b56b-4ef8-44c2-a924-03374f5831ce')
            condition = @{ Format = 'Simple'; Value = @{ operator = 'And'; groups = @(@{ operator = 'Or'; name = 'Default'; sensitivetypes = @(@{ id = '50b8b56b-4ef8-44c2-a924-03374f5831ce'; name = 'All Full Names' }) }) } }
        }
    }

    It 'SIT validation gate: refuses a create whose SIT GUID is missing from the tenant (no New call)' {
        Mock -ModuleName Compl8.Engine Get-DlpComplianceRule { $null }
        Mock -ModuleName Compl8.Engine New-DlpComplianceRule { throw 'must not create a rule referencing a missing SIT' }

        $step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'dlpRule'; objectRef = 'P01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        # Tenant inventory does NOT contain the referenced SIT id.
        $result = Invoke-Compl8DlpRuleExecutor -Step $step -Content $script:DlpRuleContent -Prefix 'QGISCF' `
            -TenantSitInventory @([pscustomobject]@{ Id = '99999999-9999-9999-9999-999999999999'; Name = 'Other' }) -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-DlpComplianceRule -Times 0
        $result.status | Should -Be 'sit-invalid'
    }

    It 'SIT validation gate: PASSES (creates) when the SIT GUID is present in the tenant' {
        Mock -ModuleName Compl8.Engine Get-DlpComplianceRule { $null }
        Mock -ModuleName Compl8.Engine New-DlpComplianceRule { }

        $step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'dlpRule'; objectRef = 'P01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8DlpRuleExecutor -Step $step -Content $script:DlpRuleContent -Prefix 'QGISCF' `
            -TenantSitInventory @([pscustomobject]@{ Id = '50b8b56b-4ef8-44c2-a924-03374f5831ce'; Name = 'All Full Names' }) -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-DlpComplianceRule -Times 1
        $result.status | Should -Be 'created'
    }

    It 'name-conflict pre-flight: refuses a CREATE whose name is an active existing object (no New call)' {
        Mock -ModuleName Compl8.Engine Get-DlpComplianceRule { [pscustomobject]@{ Name = 'P01-R01-ECH-OFFI-EXT-ADT' } }   # active conflict
        Mock -ModuleName Compl8.Engine New-DlpComplianceRule { throw 'must not create over an active name conflict' }
        Mock -ModuleName Compl8.Engine Set-DlpComplianceRule { throw 'create must not Set' }

        $step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'dlpRule'; objectRef = 'P01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8DlpRuleExecutor -Step $step -Content $script:DlpRuleContent -Prefix 'QGISCF' -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-DlpComplianceRule -Times 0
        $result.status | Should -Be 'name-conflict'
    }
}

Describe 'Invoke-Compl8DlpRuleExecutor — DEREFERENCE (D5: strip removed SITs / delete empty rule)' {
    It 'strips the removed SIT(s) from the rule condition and Set-DlpComplianceRule (SITs remain)' {
        $keepId = '11111111-1111-1111-1111-111111111111'
        $dropId = '22222222-2222-2222-2222-222222222222'
        $script:capturedDerefCcsi = $null
        # The live rule references TWO SITs; one is removed.
        Mock -ModuleName Compl8.Engine Get-DlpComplianceRule {
            [pscustomobject]@{ Name = 'P01-R01-ECH-OFFI-EXT-ADT'; ContentContainsSensitiveInformation = @{
                operator = 'And'
                groups   = @(@{ operator = 'Or'; name = 'Default'; sensitivetypes = @(
                    @{ id = $keepId; name = 'Keep SIT' }
                    @{ id = $dropId; name = 'Drop SIT' }
                ) }) } }
        }
        Mock -ModuleName Compl8.Engine Set-DlpComplianceRule { $script:capturedDerefCcsi = $ContentContainsSensitiveInformation }
        Mock -ModuleName Compl8.Engine Remove-DlpComplianceRule { throw 'must not delete a rule that still references a SIT' }

        $step = [pscustomobject]@{ id = 's05'; action = 'dereference'; objectType = 'dlpRule'; objectRef = 'P01-R01-ECH-OFFI-EXT-ADT'
            dependsOn = @(); impact = @($dropId); gate = $null }
        $content = [pscustomobject]@{ name = 'P01-R01-ECH-OFFI-EXT-ADT' }
        $result = Invoke-Compl8DlpRuleExecutor -Step $step -Content $content -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine Set-DlpComplianceRule -Times 1
        Should -Invoke -ModuleName Compl8.Engine Remove-DlpComplianceRule -Times 0
        $result.status            | Should -Be 'dereferenced'
        @($result.strippedSits)   | Should -Contain $dropId
        @($result.remainingSits)  | Should -Contain $keepId
        # The Set condition must NOT contain the dropped SIT and MUST contain the kept SIT.
        $remainingIds = @($script:capturedDerefCcsi.groups[0].sensitivetypes | ForEach-Object { $_.id })
        $remainingIds | Should -Contain $keepId
        $remainingIds | Should -Not -Contain $dropId
    }

    It 'DELETES the rule when stripping the removed SIT leaves it referencing no SIT (D5 empty-rule delete)' {
        $dropId = '22222222-2222-2222-2222-222222222222'
        Mock -ModuleName Compl8.Engine Get-DlpComplianceRule {
            [pscustomobject]@{ Name = 'P01-R01-ECH-OFFI-EXT-ADT'; ContentContainsSensitiveInformation = @{
                operator = 'And'
                groups   = @(@{ operator = 'Or'; name = 'Default'; sensitivetypes = @(@{ id = $dropId; name = 'Drop SIT' }) }) } }
        }
        Mock -ModuleName Compl8.Engine Set-DlpComplianceRule { throw 'must not Set a rule that will be deleted' }
        Mock -ModuleName Compl8.Engine Remove-DlpComplianceRule { }

        $step = [pscustomobject]@{ id = 's05'; action = 'dereference'; objectType = 'dlpRule'; objectRef = 'P01-R01-ECH-OFFI-EXT-ADT'
            dependsOn = @(); impact = @($dropId); gate = $null }
        $content = [pscustomobject]@{ name = 'P01-R01-ECH-OFFI-EXT-ADT' }
        $result = Invoke-Compl8DlpRuleExecutor -Step $step -Content $content -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine Remove-DlpComplianceRule -Times 1
        Should -Invoke -ModuleName Compl8.Engine Set-DlpComplianceRule -Times 0
        $result.status          | Should -Be 'rule-emptied-deleted'
        @($result.strippedSits) | Should -Contain $dropId
        @($result.remainingSits).Count | Should -Be 0
    }

    It 'planned op for a dereference step is action=dereference (NO mutation under -WhatIf)' {
        Mock -ModuleName Compl8.Engine Set-DlpComplianceRule { throw 'no mutation under -WhatIf' }
        $step = [pscustomobject]@{ id = 's05'; action = 'dereference'; objectType = 'dlpRule'; objectRef = 'P01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @('22222222-2222-2222-2222-222222222222'); gate = $null }
        $op = Invoke-Compl8DlpRuleExecutor -Step $step -WhatIf
        $op.action     | Should -Be 'dereference'
        $op.objectType | Should -Be 'dlpRule'
        $op.objectRef  | Should -Be 'P01-R01-ECH-OFFI-EXT-ADT'
    }
}

Describe 'Invoke-Compl8DlpRuleExecutor — SHADOW PARITY vs Deploy-DLPRules.ps1 (GENUINE)' -Tag 'Slow' {
  BeforeAll {
    # GENUINE old-side recorder: run the WHOLE real Deploy-DLPRules.ps1 against a committed per-tenant
    # config fixture, with the connection/session/fingerprint boundary + the SCC cmdlets replaced by
    # GLOBAL recording stubs. The recorded New-DlpCompliancePolicy / New-DlpComplianceRule calls are the
    # old path's REAL intended operations (real prefix-scoped names), derived from a real run.
    function Get-OldDlpWhatIfOps {
        $envName = 'compl8-shadow-' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
        $cfgRoot = Join-Path $script:RepoRoot 'config' 'tenants' $envName
        $recorded = [System.Collections.Generic.List[object]]::new()
        $global:Compl8ShadowDlpOps = $recorded
        try {
            New-Item -ItemType Directory -Path $cfgRoot -Force | Out-Null
            Set-Content -Path (Join-Path $cfgRoot 'settings.json') -Value '{ "namingPrefix":"QGISCF","namingSuffix":"EXT-ADT","auditMode":true,"notifyUser":false,"generateIncidentReport":false,"skipSitValidation":true,"suppressRuleOutput":true,"interCallDelaySec":0,"maxRetries":2,"baseDelaySec":1,"publisher":"QGISCF","sitPrefix":"QGISCF","nameTemplates":{"dlpPolicy":"P{policyNumber}-{policyCode}-{prefix}-{suffix}","dlpRule":"P{policyNumber}-R{ruleNumber}{chunkLetter}-{policyCode}-{labelCode}-{suffix}"} }'
            Set-Content -Path (Join-Path $cfgRoot 'labels.json')   -Value '[ { "code":"OFFI","name":"OFFICIAL","displayName":"OFFICIAL","fullName":"OFFICIAL","priority":0,"parentGroup":null,"isGroup":false,"colour":"#008000","encrypt":false,"tooltip":"t","contentType":"File, Email" } ]'
            Set-Content -Path (Join-Path $cfgRoot 'policies.json') -Value '[ { "number":1,"code":"ECH","comment":"c","location":{"ExchangeLocation":"All"},"scopeParam":"AccessScope","scopeValue":"NotInOrganization","optional":false,"enabled":true } ]'
            Set-Content -Path (Join-Path $cfgRoot 'classifiers.json') -Value '{ "OFFI":[ {"name":"All Full Names","id":"50b8b56b-4ef8-44c2-a924-03374f5831ce","confidencelevel":"Medium","minCount":1,"maxCount":-1}, {"name":"IP Address","id":"1daa4ad5-e2dd-4ca4-a788-54722c09efb2","confidencelevel":"Medium","minCount":1,"maxCount":-1} ] }'
            Set-Content -Path (Join-Path $cfgRoot 'rule-overrides.json') -Value '{}'

            Import-Module $script:DlpDeploy -Force
            function global:Connect-DLPSession { param() $true }
            function global:Assert-DLPSession { param([string]$CommandToTest) $true }
            function global:Test-DeploymentTenantFingerprint { param() [pscustomobject]@{ passed = $true; environment = 'shadow'; mode = 'warn'; actual = @{ name = 's'; guid = 'g' }; messages = @(); mismatches = @(); configured = $true; matched = $true } }
            function global:Start-DeploymentLog { param([string]$ScriptName) $null }
            function global:Stop-Transcript { }
            function global:Get-DlpSensitiveInformationType { @() }
            function global:Get-DlpCompliancePolicy { param([string]$Identity) $null }
            function global:New-DlpCompliancePolicy { param([string]$Name, [string]$Comment, [string]$Mode, [string]$ExchangeLocation, [string]$OneDriveLocation, [string]$SharePointLocation, [string]$EndpointDlpLocation, [string]$TeamsLocation); $global:Compl8ShadowDlpOps.Add([pscustomobject]@{ action = 'create'; objectType = 'dlpPolicy'; objectRef = $Name }) | Out-Null }
            function global:Set-DlpCompliancePolicy { param([string]$Identity, [string]$Comment, [string]$Mode); $global:Compl8ShadowDlpOps.Add([pscustomobject]@{ action = 'update'; objectType = 'dlpPolicy'; objectRef = $Identity }) | Out-Null }
            function global:Get-DlpComplianceRule { param([string]$Identity, [string]$Policy) $null }
            function global:New-DlpComplianceRule { param([string]$Name, [string]$Policy, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled, [string]$AccessScope, [string]$GenerateIncidentReport, [string]$IncidentReportContent, [string]$NotifyUser); $global:Compl8ShadowDlpOps.Add([pscustomobject]@{ action = 'create'; objectType = 'dlpRule'; objectRef = $Name }) | Out-Null }
            function global:Set-DlpComplianceRule { param([string]$Identity, $ContentContainsSensitiveInformation); $global:Compl8ShadowDlpOps.Add([pscustomobject]@{ action = 'update'; objectType = 'dlpRule'; objectRef = $Identity }) | Out-Null }
            function global:Remove-DlpComplianceRule { param([string]$Identity) }
            function global:Remove-DlpCompliancePolicy { param([string]$Identity) }

            & (Join-Path $script:RepoRoot 'scripts' 'Deploy-DLPRules.ps1') -TargetEnvironment $envName -SkipValidation -SkipVerification -AllowDirectRun *> $null

            @($recorded)
        } finally {
            foreach ($fn in 'Connect-DLPSession', 'Assert-DLPSession', 'Test-DeploymentTenantFingerprint', 'Start-DeploymentLog', 'Stop-Transcript',
                'Get-DlpSensitiveInformationType', 'Get-DlpCompliancePolicy', 'New-DlpCompliancePolicy', 'Set-DlpCompliancePolicy', 'Remove-DlpCompliancePolicy',
                'Get-DlpComplianceRule', 'New-DlpComplianceRule', 'Set-DlpComplianceRule', 'Remove-DlpComplianceRule') {
                Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
            }
            Remove-Variable -Name Compl8ShadowDlpOps -Scope Global -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $cfgRoot -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
            Import-Module $script:EngineDir -Force
            # Re-establish the DLP SCC global stubs the executor tests rely on.
            function global:Get-DlpCompliancePolicy { [CmdletBinding()] param([string]$Identity) }
            function global:New-DlpCompliancePolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$Comment, [string]$Mode, [string]$ExchangeLocation, [string]$OneDriveLocation, [string]$SharePointLocation, [string]$EndpointDlpLocation, [string]$TeamsLocation) }
            function global:Set-DlpCompliancePolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [string]$Comment, [string]$Mode) }
            function global:Remove-DlpCompliancePolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }
            function global:Get-DlpComplianceRule { [CmdletBinding()] param([string]$Identity, [string]$Policy) }
            function global:New-DlpComplianceRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$Policy, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled, [string]$AccessScope, [string]$GenerateIncidentReport, [string]$IncidentReportContent, [string]$NotifyUser) }
            function global:Set-DlpComplianceRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled, [string]$AccessScope, [string]$GenerateIncidentReport, [string]$IncidentReportContent, [string]$NotifyUser) }
            function global:Remove-DlpComplianceRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }
        }
    }
  }

    It 'executor planned ops MATCH the REAL Deploy-DLPRules.ps1 ops (Get-Compl8ShadowDiff.Match = $true)' {
        # OLD side: genuinely run the whole Deploy-DLPRules.ps1 against the fixture (empty tenant => all create).
        $oldOps = Get-OldDlpWhatIfOps

        # ENGINE side: run the executor in -WhatIf over the SAME objects in the SAME (empty) tenant state.
        $engineSteps = @(
            @{ Step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'dlpPolicy'; objectRef = 'P01-ECH-QGISCF-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }; Content = [pscustomobject]@{ name = 'P01-ECH-QGISCF-EXT-ADT'; mode = 'TestWithNotifications'; comment = 'c'; locations = @{ ExchangeLocation = 'All' } } }
            @{ Step = [pscustomobject]@{ id = 's02'; action = 'create'; objectType = 'dlpRule'; objectRef = 'P01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }; Content = [pscustomobject]@{ name = 'P01-R01-ECH-OFFI-EXT-ADT'; policy = 'P01-ECH-QGISCF-EXT-ADT'; comment = 'c' } }
        )
        $engineOps = foreach ($e in $engineSteps) {
            Invoke-Compl8DlpRuleExecutor -Step $e.Step -Content $e.Content -Prefix 'QGISCF' -WhatIf
        }

        # Guard against a vacuous empty == empty pass.
        @($oldOps).Count    | Should -BeGreaterThan 0 -Because 'the fixture must drive real Deploy-DLPRules.ps1 operations'
        @($oldOps).Count    | Should -Be 2 -Because 'one policy create + one rule create'
        @($engineOps).Count | Should -Be 2

        $diff = Get-Compl8ShadowDiff -EngineOps @($engineOps) -OldOps @($oldOps)
        $diff.Match | Should -BeTrue -Because "executor planned ops must reproduce the real Deploy-DLPRules.ps1 path. OnlyInEngine=$(@($diff.OnlyInEngine) | ForEach-Object { $_.action + ':' + $_.objectType + ':' + $_.objectRef } | Join-String -Separator ','); OnlyInOld=$(@($diff.OnlyInOld) | ForEach-Object { $_.action + ':' + $_.objectType + ':' + $_.objectRef } | Join-String -Separator ',')"
        @($diff.OnlyInEngine).Count | Should -Be 0
        @($diff.OnlyInOld).Count    | Should -Be 0
        @($diff.Differing).Count    | Should -Be 0
    }
}


# =================================================================================================
# Auto-label executor (Task 12) — copies the pilot template and shadows against the inline deployment
# loop of scripts/Deploy-AutoLabeling.ps1. Handles `autoLabelPolicy` and `autoLabelRule`
# create|update|remove. Ports the 125-classifier-per-rule CHUNKING (Split-ClassifierChunks parity —
# the AutoLabelMaxSitsPerRule consumption limit, distinct from the 50-SIT authoring cap), the SIT-
# validation gate, the name-conflict pre-flight, and simulation-mode policy creation
# (Mode=TestWithoutNotifications). Proves parity against a GENUINE Deploy-AutoLabeling.ps1 run.
#
# SHADOW STRATEGY (genuine, reused from Task 9/11): Deploy-AutoLabeling.ps1's deployment loop is the
# script's TOP-LEVEL body. Its session gate (Assert-DLPSession) PROBES Get-DlpCompliancePolicy, so
# stubbing that probe cmdlet lets the REAL Assert-DLPSession pass; the fingerprint gate warn-passes for
# an unconfigured -TargetEnvironment. So the recorder runs the WHOLE real script against the real global
# config with those boundary cmdlets + the SCC cmdlets replaced by GLOBAL recording stubs. The recorded
# New-AutoSensitivityLabelPolicy / New-AutoSensitivityLabelRule calls (real prefix-scoped names) ARE the
# old path's intended operations. The ENGINE side INDEPENDENTLY generates the same names via the same
# config + Get-DeploymentObjectName (not echoing the old side), so the diff is non-vacuous.

Describe 'module surface — auto-label executor' {
    It 'exports Invoke-Compl8AutoLabelExecutor from Compl8.Engine' {
        (Get-Command -Name 'Invoke-Compl8AutoLabelExecutor' -Module Compl8.Engine -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-Compl8AutoLabelExecutor — policy + rule create/update/remove' {
    BeforeAll {
        $script:AlPolicyContent = [pscustomobject]@{
            name = 'AL01-OFFI-QGISCF-EXT-ADT'; label = 'QGISCF-OFFICIAL-OFFI'; mode = 'TestWithoutNotifications'
            comment = 'auto-label OFFICIAL'; locations = @{ ExchangeLocation = 'All' }
        }
        $script:AlRuleContent = [pscustomobject]@{
            name = 'AL01-R01-ECH-OFFI-EXT-ADT'; policy = 'AL01-OFFI-QGISCF-EXT-ADT'; workload = 'Exchange'
            comment = 'OFFICIAL - Exchange'; scopeParam = 'AccessScope'; scopeValue = 'NotInOrganization'
            classifiers = @(
                [pscustomobject]@{ Id = '50b8b56b-4ef8-44c2-a924-03374f5831ce'; Name = 'All Full Names'; minCount = 1; maxCount = -1; confidencelevel = 'Medium' }
            )
        }
    }

    It 'policy create: New-AutoSensitivityLabelPolicy once, Mode=TestWithoutNotifications, provenance Comment' {
        $script:capturedAlMode = $null
        $script:capturedAlComment = $null
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelPolicy { $null }
        Mock -ModuleName Compl8.Engine New-AutoSensitivityLabelPolicy { $script:capturedAlMode = $Mode; $script:capturedAlComment = $Comment }
        Mock -ModuleName Compl8.Engine Set-AutoSensitivityLabelPolicy { throw 'must not Set on create' }

        $step = [pscustomobject]@{ id = 's01'; action = 'create'; objectType = 'autoLabelPolicy'; objectRef = 'AL01-OFFI-QGISCF-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8AutoLabelExecutor -Step $step -Content $script:AlPolicyContent -Prefix 'QGISCF' -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-AutoSensitivityLabelPolicy -Times 1
        $result.status            | Should -Be 'created'
        $result.objectType        | Should -Be 'autoLabelPolicy'
        $script:capturedAlMode    | Should -Be 'TestWithoutNotifications'
        $script:capturedAlComment | Should -Match '\[\[Compl8:[0-9a-f]{16}\]\]'
    }

    It 'policy update: Set-AutoSensitivityLabelPolicy when it already exists' {
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelPolicy { [pscustomobject]@{ Name = 'AL01-OFFI-QGISCF-EXT-ADT' } }
        Mock -ModuleName Compl8.Engine New-AutoSensitivityLabelPolicy { throw 'must not New on update' }
        Mock -ModuleName Compl8.Engine Set-AutoSensitivityLabelPolicy { }

        $step = [pscustomobject]@{ id = 's01'; action = 'update'; objectType = 'autoLabelPolicy'; objectRef = 'AL01-OFFI-QGISCF-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8AutoLabelExecutor -Step $step -Content $script:AlPolicyContent -Prefix 'QGISCF' -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine Set-AutoSensitivityLabelPolicy -Times 1
        $result.status | Should -Be 'updated'
    }

    It 'rule create (single chunk): New-AutoSensitivityLabelRule once, returns created' {
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { $null }
        Mock -ModuleName Compl8.Engine New-AutoSensitivityLabelRule { }
        Mock -ModuleName Compl8.Engine Set-AutoSensitivityLabelRule { throw 'must not Set on create' }

        $step = [pscustomobject]@{ id = 's02'; action = 'create'; objectType = 'autoLabelRule'; objectRef = 'AL01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8AutoLabelExecutor -Step $step -Content $script:AlRuleContent -Prefix 'QGISCF' -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-AutoSensitivityLabelRule -Times 1
        $result.status     | Should -Be 'created'
        $result.objectType | Should -Be 'autoLabelRule'
    }

    It 'rule remove: via Remove-PurviewObject (deleted)' {
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { [pscustomobject]@{ Name = 'AL01-R01-ECH-OFFI-EXT-ADT' } }
        Mock -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule { }

        $step = [pscustomobject]@{ id = 's02'; action = 'remove'; objectType = 'autoLabelRule'; objectRef = 'AL01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8AutoLabelExecutor -Step $step -Content $script:AlRuleContent -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule -Times 1
        $result.status | Should -Be 'deleted'
    }

    It 'SIT validation gate: refuses a rule create whose SIT GUID is missing from the tenant (no New call)' {
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { $null }
        Mock -ModuleName Compl8.Engine New-AutoSensitivityLabelRule { throw 'must not create a rule referencing a missing SIT' }

        $step = [pscustomobject]@{ id = 's02'; action = 'create'; objectType = 'autoLabelRule'; objectRef = 'AL01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8AutoLabelExecutor -Step $step -Content $script:AlRuleContent -Prefix 'QGISCF' `
            -TenantSitInventory @([pscustomobject]@{ Id = '99999999-9999-9999-9999-999999999999'; Name = 'Other' }) -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-AutoSensitivityLabelRule -Times 0
        $result.status | Should -Be 'sit-invalid'
    }
}

Describe 'Invoke-Compl8AutoLabelExecutor — 125-classifier CHUNKING (Split-ClassifierChunks parity)' {
    BeforeAll {
        # Build a classifier list > 125 to force a split.
        $script:Big = 1..130 | ForEach-Object {
            [pscustomobject]@{ Id = ([guid]::NewGuid().ToString()); Name = "SIT-$_"; minCount = 1; maxCount = -1; confidencelevel = 'Medium' }
        }
    }

    It 'splits a 130-classifier rule into 2 chunked rules (a/b), creating one rule per chunk' {
        $script:createdRuleNames = [System.Collections.Generic.List[string]]::new()
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { $null }
        Mock -ModuleName Compl8.Engine New-AutoSensitivityLabelRule { $script:createdRuleNames.Add($Name) | Out-Null }

        $content = [pscustomobject]@{ name = 'AL01-R01-ECH-OFFI-EXT-ADT'; policy = 'AL01-OFFI-QGISCF-EXT-ADT'; workload = 'Exchange'; classifiers = $script:Big }
        $step = [pscustomobject]@{ id = 's02'; action = 'create'; objectType = 'autoLabelRule'; objectRef = 'AL01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8AutoLabelExecutor -Step $step -Content $content -Prefix 'QGISCF' -SleepAction { param($s) }

        # 130 classifiers / 125 cap -> 2 chunks of 65 each -> 2 rules with chunk letters a, b.
        Should -Invoke -ModuleName Compl8.Engine New-AutoSensitivityLabelRule -Times 2
        $result.status        | Should -Be 'chunked'
        @($result.chunks).Count | Should -Be 2
        @($script:createdRuleNames) | Should -Contain 'AL01-R01a-ECH-OFFI-EXT-ADT'
        @($script:createdRuleNames) | Should -Contain 'AL01-R01b-ECH-OFFI-EXT-ADT'
    }

    It 'a 250-classifier rule splits into 2 chunks of 125 (still 2, even split)' {
        $big = 1..250 | ForEach-Object { [pscustomobject]@{ Id = ([guid]::NewGuid().ToString()); Name = "SIT-$_" } }
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { $null }
        Mock -ModuleName Compl8.Engine New-AutoSensitivityLabelRule { }

        $content = [pscustomobject]@{ name = 'AL01-R01-ECH-OFFI-EXT-ADT'; policy = 'p'; workload = 'Exchange'; classifiers = $big }
        $step = [pscustomobject]@{ id = 's02'; action = 'create'; objectType = 'autoLabelRule'; objectRef = 'AL01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8AutoLabelExecutor -Step $step -Content $content -Prefix 'QGISCF' -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-AutoSensitivityLabelRule -Times 2
        @($result.chunks).Count | Should -Be 2
    }

    It 'a 300-classifier rule splits into 3 chunks of 100 (ceil(300/125)=3)' {
        $big = 1..300 | ForEach-Object { [pscustomobject]@{ Id = ([guid]::NewGuid().ToString()); Name = "SIT-$_" } }
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { $null }
        Mock -ModuleName Compl8.Engine New-AutoSensitivityLabelRule { }

        $content = [pscustomobject]@{ name = 'AL01-R01-ECH-OFFI-EXT-ADT'; policy = 'p'; workload = 'Exchange'; classifiers = $big }
        $step = [pscustomobject]@{ id = 's02'; action = 'create'; objectType = 'autoLabelRule'; objectRef = 'AL01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8AutoLabelExecutor -Step $step -Content $content -Prefix 'QGISCF' -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-AutoSensitivityLabelRule -Times 3
        @($result.chunks).Count | Should -Be 3
    }

    It 'a <=125-classifier rule is NOT split (single rule, no chunk letter)' {
        $small = 1..50 | ForEach-Object { [pscustomobject]@{ Id = ([guid]::NewGuid().ToString()); Name = "SIT-$_" } }
        $script:smallNames = [System.Collections.Generic.List[string]]::new()
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { $null }
        Mock -ModuleName Compl8.Engine New-AutoSensitivityLabelRule { $script:smallNames.Add($Name) | Out-Null }

        $content = [pscustomobject]@{ name = 'AL01-R01-ECH-OFFI-EXT-ADT'; policy = 'p'; workload = 'Exchange'; classifiers = $small }
        $step = [pscustomobject]@{ id = 's02'; action = 'create'; objectType = 'autoLabelRule'; objectRef = 'AL01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $result = Invoke-Compl8AutoLabelExecutor -Step $step -Content $content -Prefix 'QGISCF' -SleepAction { param($s) }

        Should -Invoke -ModuleName Compl8.Engine New-AutoSensitivityLabelRule -Times 1
        @($script:smallNames) | Should -Contain 'AL01-R01-ECH-OFFI-EXT-ADT'   # no chunk letter
        $result.status | Should -Be 'created'
    }

    It 'planned ops (-WhatIf) for a >125-classifier rule emit one op per chunk (chunk-letter names)' {
        Mock -ModuleName Compl8.Engine New-AutoSensitivityLabelRule { throw 'no mutation under -WhatIf' }

        $content = [pscustomobject]@{ name = 'AL01-R01-ECH-OFFI-EXT-ADT'; policy = 'p'; workload = 'Exchange'; classifiers = $script:Big }
        $step = [pscustomobject]@{ id = 's02'; action = 'create'; objectType = 'autoLabelRule'; objectRef = 'AL01-R01-ECH-OFFI-EXT-ADT'; dependsOn = @(); impact = @(); gate = $null }
        $ops = @(Invoke-Compl8AutoLabelExecutor -Step $step -Content $content -Prefix 'QGISCF' -WhatIf)

        @($ops).Count | Should -Be 2
        @($ops.objectRef) | Should -Contain 'AL01-R01a-ECH-OFFI-EXT-ADT'
        @($ops.objectRef) | Should -Contain 'AL01-R01b-ECH-OFFI-EXT-ADT'
    }
}

Describe 'Invoke-Compl8AutoLabelExecutor — SHADOW PARITY vs Deploy-AutoLabeling.ps1 (GENUINE)' -Tag 'Slow' {
  BeforeAll {
    # GENUINE old-side recorder: run the WHOLE real Deploy-AutoLabeling.ps1 against the REAL global
    # config, stubbing Get-DlpCompliancePolicy (the Assert-DLPSession probe) + a nonexistent
    # -TargetEnvironment (so the fingerprint gate warn-passes) + recording AL SCC stubs. The recorded
    # New-AutoSensitivityLabelPolicy / New-AutoSensitivityLabelRule names are the old path's REAL ops.
    function Get-OldAlWhatIfOps {
        $recorded = [System.Collections.Generic.List[object]]::new()
        $global:Compl8ShadowAlOps = $recorded
        try {
            Import-Module $script:DlpDeploy -Force
            function global:Connect-DLPSession { param() $true }
            function global:Start-DeploymentLog { param([string]$ScriptName) $null }
            function global:Stop-Transcript { }
            function global:Get-DlpCompliancePolicy { param([string]$Identity) @() }   # Assert-DLPSession probe
            function global:Get-DlpSensitiveInformationType { @() }
            function global:Get-AutoSensitivityLabelPolicy { param([string]$Identity) $null }
            function global:Get-AutoSensitivityLabelRule { param([string]$Identity, [string]$Policy) $null }
            function global:New-AutoSensitivityLabelPolicy { param([string]$Name, [string]$ApplySensitivityLabel, [string]$Comment, [string]$Mode, [string]$ExchangeLocation, [string]$OneDriveLocation, [string]$SharePointLocation, [switch]$OverwriteLabel); $global:Compl8ShadowAlOps.Add([pscustomobject]@{ action = 'create'; objectType = 'autoLabelPolicy'; objectRef = $Name }) | Out-Null }
            function global:Set-AutoSensitivityLabelPolicy { param([string]$Identity, [string]$ApplySensitivityLabel, [string]$Comment, [string]$Mode, [bool]$StartSimulation, [switch]$OverwriteLabel); if ($PSBoundParameters.ContainsKey('StartSimulation')) { return }; $global:Compl8ShadowAlOps.Add([pscustomobject]@{ action = 'update'; objectType = 'autoLabelPolicy'; objectRef = $Identity }) | Out-Null }
            function global:New-AutoSensitivityLabelRule { param([string]$Name, [string]$Policy, [string]$Workload, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled, [string]$AccessScope); $global:Compl8ShadowAlOps.Add([pscustomobject]@{ action = 'create'; objectType = 'autoLabelRule'; objectRef = $Name }) | Out-Null }
            function global:Set-AutoSensitivityLabelRule { param([string]$Identity); $global:Compl8ShadowAlOps.Add([pscustomobject]@{ action = 'update'; objectType = 'autoLabelRule'; objectRef = $Identity }) | Out-Null }
            function global:Remove-AutoSensitivityLabelRule { param([string]$Identity) }
            function global:Remove-AutoSensitivityLabelPolicy { param([string]$Identity) }

            & (Join-Path $script:RepoRoot 'scripts' 'Deploy-AutoLabeling.ps1') -TargetEnvironment 'compl8-shadow-noenv' -SkipValidation -SkipVerification -AllowDirectRun *> $null

            @($recorded)
        } finally {
            foreach ($fn in 'Connect-DLPSession', 'Start-DeploymentLog', 'Stop-Transcript', 'Get-DlpCompliancePolicy', 'Get-DlpSensitiveInformationType',
                'Get-AutoSensitivityLabelPolicy', 'Get-AutoSensitivityLabelRule', 'New-AutoSensitivityLabelPolicy', 'Set-AutoSensitivityLabelPolicy',
                'New-AutoSensitivityLabelRule', 'Set-AutoSensitivityLabelRule', 'Remove-AutoSensitivityLabelRule', 'Remove-AutoSensitivityLabelPolicy') {
                Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
            }
            Remove-Variable -Name Compl8ShadowAlOps -Scope Global -ErrorAction SilentlyContinue
            Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
            Import-Module $script:EngineDir -Force
            # Re-establish the AL SCC global stubs the executor tests rely on.
            function global:Get-AutoSensitivityLabelPolicy { [CmdletBinding()] param([string]$Identity) }
            function global:New-AutoSensitivityLabelPolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$ApplySensitivityLabel, [string]$Comment, [string]$Mode, [string]$ExchangeLocation, [string]$OneDriveLocation, [string]$SharePointLocation, [switch]$OverwriteLabel) }
            function global:Set-AutoSensitivityLabelPolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [string]$ApplySensitivityLabel, [string]$Comment, [string]$Mode, [bool]$StartSimulation, [switch]$OverwriteLabel) }
            function global:Remove-AutoSensitivityLabelPolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }
            function global:Get-AutoSensitivityLabelRule { [CmdletBinding()] param([string]$Identity, [string]$Policy) }
            function global:New-AutoSensitivityLabelRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$Policy, [string]$Workload, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled, [string]$AccessScope) }
            function global:Set-AutoSensitivityLabelRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled, [string]$AccessScope) }
            function global:Remove-AutoSensitivityLabelRule { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity) }
        }
    }

    # The ENGINE side independently generates the same AL policy/rule names + steps from the SAME real
    # config (labels, classifiers, workloads), via the module's own name generator — NOT by echoing the
    # old ops. Returns the executor's -WhatIf planned ops over those steps.
    function Get-EngineAlWhatIfOps {
        Import-Module $script:DlpDeploy -Force
        try {
            $cfgDir = Join-Path $script:RepoRoot 'config'
            $Defaults = Get-ModuleDefaults
            $gj  = Import-JsonConfig -FilePath (Join-Path $cfgDir 'settings.json')   -Description s
            $lj  = Import-JsonConfig -FilePath (Join-Path $cfgDir 'labels.json')     -Description l
            $pj  = Import-JsonConfig -FilePath (Join-Path $cfgDir 'policies.json')   -Description p
            $cj  = Import-JsonConfig -FilePath (Join-Path $cfgDir 'classifiers.json') -Description c
            $Config = Merge-GlobalConfig -Defaults $Defaults -GlobalJson $gj
            $Labels = Resolve-LabelConfig -LabelsJson $lj
            $Policies = Resolve-PolicyConfig -PoliciesJson $pj
            $Classifiers = Resolve-ClassifierConfig -ClassifiersJson $cj -Defaults $Defaults

            # Same workload map + filter as the old script.
            $wlMap = @{ 'ECH' = 'Exchange'; 'SPO' = 'SharePoint'; 'ODB' = 'OneDriveForBusiness' }
            $workloads = @()
            foreach ($p in ($Policies | Where-Object { $_.Enabled })) {
                if ($wlMap.ContainsKey($p.Code)) { $workloads += @{ Code = $p.Code; Workload = $wlMap[$p.Code]; ScopeParam = $p.ScopeParam; ScopeValue = $p.ScopeValue } }
            }
            # Same label filter as the old script: non-group labels that have classifiers.
            $Labels = $Labels | Where-Object { $_.code -and $Classifiers.ContainsKey($_.code) }
            $LabelNameLookup = @{}
            foreach ($l in $lj) { if ($l.code) { $LabelNameLookup[$l.code] = Get-DeploymentObjectName -Config $Config -ObjectType 'label' -Name $l.name -Tokens @{ labelCode = $l.code; displayName = $l.displayName } } }

            $ops = [System.Collections.Generic.List[object]]::new()
            $policyNum = 0
            foreach ($label in $Labels) {
                $policyNum++
                $policyName = Get-DeploymentObjectName -Config $Config -ObjectType 'autoLabelPolicy' -Tokens @{ policyNumber = ('{0:D2}' -f $policyNum); labelCode = $label.code }
                $polStep = [pscustomobject]@{ id = "p$policyNum"; action = 'create'; objectType = 'autoLabelPolicy'; objectRef = $policyName; dependsOn = @(); impact = @(); gate = $null }
                $polContent = [pscustomobject]@{ name = $policyName; label = $LabelNameLookup[$label.code]; mode = 'TestWithoutNotifications'; comment = 'c'; locations = @{ ExchangeLocation = 'All' } }
                foreach ($o in @(Invoke-Compl8AutoLabelExecutor -Step $polStep -Content $polContent -Prefix 'QGISCF' -WhatIf)) { $ops.Add($o) | Out-Null }

                $ruleNum = 0
                foreach ($wl in $workloads) {
                    $ruleNum++
                    $ruleName = Get-DeploymentObjectName -Config $Config -ObjectType 'autoLabelRule' -Tokens @{ policyNumber = ('{0:D2}' -f $policyNum); ruleNumber = ('{0:D2}' -f $ruleNum); chunkLetter = ''; workloadCode = $wl.Code; labelCode = $label.code }
                    $ruleStep = [pscustomobject]@{ id = "r$policyNum-$ruleNum"; action = 'create'; objectType = 'autoLabelRule'; objectRef = $ruleName; dependsOn = @(); impact = @(); gate = $null }
                    $ruleContent = [pscustomobject]@{ name = $ruleName; policy = $policyName; workload = $wl.Workload; comment = 'c'; scopeParam = $wl.ScopeParam; scopeValue = $wl.ScopeValue; classifiers = @($Classifiers[$label.code]) }
                    foreach ($o in @(Invoke-Compl8AutoLabelExecutor -Step $ruleStep -Content $ruleContent -Prefix 'QGISCF' -WhatIf)) { $ops.Add($o) | Out-Null }
                }
            }
            @($ops)
        } finally {
            Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
            Import-Module $script:EngineDir -Force
        }
    }
  }

    It 'executor planned ops MATCH the REAL Deploy-AutoLabeling.ps1 ops (Get-Compl8ShadowDiff.Match = $true)' {
        # OLD side: genuinely run the whole Deploy-AutoLabeling.ps1 against the real config (empty tenant => all create).
        $oldOps = Get-OldAlWhatIfOps
        # ENGINE side: independently generate the same steps + names and run the executor in -WhatIf.
        $engineOps = Get-EngineAlWhatIfOps

        # Guard against a vacuous empty == empty pass.
        @($oldOps).Count    | Should -BeGreaterThan 0 -Because 'the fixture must drive real Deploy-AutoLabeling.ps1 operations'
        @($engineOps).Count | Should -BeGreaterThan 0
        @($engineOps).Count | Should -Be (@($oldOps).Count) -Because 'engine and old path generate the same per-label/workload AL policy+rule set'

        $diff = Get-Compl8ShadowDiff -EngineOps @($engineOps) -OldOps @($oldOps)
        $diff.Match | Should -BeTrue -Because "executor planned ops must reproduce the real Deploy-AutoLabeling.ps1 path. OnlyInEngine=$(@($diff.OnlyInEngine) | ForEach-Object { $_.action + ':' + $_.objectRef } | Select-Object -First 5 | Join-String -Separator ','); OnlyInOld=$(@($diff.OnlyInOld) | ForEach-Object { $_.action + ':' + $_.objectRef } | Select-Object -First 5 | Join-String -Separator ',')"
        @($diff.OnlyInEngine).Count | Should -Be 0
        @($diff.OnlyInOld).Count    | Should -Be 0
        @($diff.Differing).Count    | Should -Be 0
    }
}

