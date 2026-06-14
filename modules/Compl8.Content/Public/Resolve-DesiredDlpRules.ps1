function Resolve-DesiredDlpRules {
    <#
    .SYNOPSIS
        Resolves the DESIRED DLP policy + rule set from config, with per-rule content hashes that are
        comparable (via Get-DlpRuleContentHash, DR-1) against the ACTUAL tenant rules. (DR-2.)

    .DESCRIPTION
        The DESIRED-side resolver that feeds assess's DLP-rule drift bucket. Today there is no desired
        rule representation — DLP rules are only ever materialised inside scripts/Deploy-DLPRules.ps1's
        deployment loop. This function lifts that materialisation OUT of the deploy script into a pure,
        config-driven projection so assess can diff desired-vs-actual rules.

        For each ENABLED policy x each DLP-ELIGIBLE label (non-group, non-dlpExclude, with classifiers
        for its code) x each classifier chunk (>125 SITs split a,b,...), it emits a record:

            policyName  : Get-PolicyName (the deterministic name template)
            ruleName    : Get-RuleName (with the chunk letter when split)
            labelCode / policyCode / policyNumber / ruleNumber / chunkLetter / chunkIndex / chunkCount
            content     : the build params (the ContentContainsSensitiveInformation / AdvancedRule
                          hashtable + scope/severity/actions/disabled) Deploy-DLPRules would pass to
                          New-DlpComplianceRule
            contentHash : Get-DlpRuleContentHash of that content (DR-1; equals the actual-readback hash)

        SOURCE vs BUILD separation (the Stage-5 seam): the SOURCE is read by an internal config loader
        keyed on -ConfigPath (defaulting to <repo>/config). Re-pointing the source at desired/resolved in
        a future stage means changing ONLY that loader; the rule-BUILDING below (name templates,
        chunking, the ported New-DLPSITCondition builder, override merge) is source-agnostic.

        The rule-building REUSES the canonical pieces shared with Deploy-DLPRules.ps1 — Get-PolicyName,
        Get-RuleName, and the ported New-DLPSITCondition / New-AdvancedRuleJson builders (now in
        Compl8.Model) — so the desired projection is byte-for-byte the same content the deploy path
        constructs. That parity is the gate proved by the shadow test against a real Deploy-DLPRules run.

        Pure: no tenant calls, no Get-Date / Get-Random. Reads only the config files under -ConfigPath.

    .PARAMETER ConfigPath
        The config source directory. Defaults to <repo>/config. The Stage-5 re-point seam.

    .PARAMETER ConfigRoot
        Alias-style alternative to -ConfigPath (same meaning); -ConfigPath wins if both are supplied.

    .OUTPUTS
        [pscustomobject] with .Policies (policyName/policyCode/policyNumber/mode/locations/comment) and
        .Rules (the per-rule records described above).
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [string]$ConfigRoot
    )

    # ----- SOURCE: resolve the config directory (the separable Stage-5 seam) -------------------
    $sourceDir = if ($ConfigPath) { $ConfigPath } elseif ($ConfigRoot) { $ConfigRoot } else {
        # This file lives at modules/Compl8.Content/Public/ — repo root is three levels up.
        $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
        Join-Path $repoRoot 'config'
    }
    if (-not (Test-Path -LiteralPath $sourceDir -PathType Container)) {
        throw "Resolve-DesiredDlpRules: config source directory not found: $sourceDir"
    }

    function Read-DesiredConfigJson {
        param([string]$Name)
        $path = Join-Path $sourceDir $Name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Resolve-DesiredDlpRules: required config file missing: $path"
        }
        return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
    }

    $settingsJson   = Read-DesiredConfigJson -Name 'settings.json'
    $labelsJson     = Read-DesiredConfigJson -Name 'labels.json'
    $policiesJson   = Read-DesiredConfigJson -Name 'policies.json'
    $classifiersJson = Read-DesiredConfigJson -Name 'classifiers.json'
    $overridesJson  = if (Test-Path -LiteralPath (Join-Path $sourceDir 'rule-overrides.json') -PathType Leaf) {
        Read-DesiredConfigJson -Name 'rule-overrides.json'
    } else { $null }

    # ----- SOURCE -> structured config (config-reading; intentionally kept out of rule-building) -----
    # Defaults that the deploy path applies via Get-ModuleDefaults for the few fields we consume.
    $defaults = @{
        sitMinCount = 1; sitMaxCount = -1; sitConfidenceLevel = 'High'
        incidentReportSeverity = 'Medium'
    }

    # settings.json merged into a Config hashtable shaped exactly as Get-PolicyName/Get-RuleName expect
    # (namingPrefix/namingSuffix/nameTemplates plus the action/incident fields the rule loop reads).
    $config = @{}
    foreach ($prop in $settingsJson.PSObject.Properties) {
        if ($prop.Name -eq 'nameTemplates' -and $prop.Value) {
            $templates = @{}
            foreach ($tp in $prop.Value.PSObject.Properties) { $templates[$tp.Name] = $tp.Value }
            $config['nameTemplates'] = $templates
        } else {
            $config[$prop.Name] = $prop.Value
        }
    }

    # Policies -> structured (mirrors Resolve-PolicyConfig).
    $policies = @()
    foreach ($p in $policiesJson) {
        $location = @{}
        foreach ($lp in $p.location.PSObject.Properties) { $location[$lp.Name] = $lp.Value }
        $policies += [pscustomobject]@{
            Number     = [int]$p.number
            Code       = $p.code
            Comment    = $p.comment
            Location   = $location
            ScopeParam = if ($null -eq $p.scopeParam -or $p.scopeParam -eq '') { $null } else { $p.scopeParam }
            ScopeValue = if ($null -eq $p.scopeValue -or $p.scopeValue -eq '') { 'NotInOrganization' } else { $p.scopeValue }
            Optional   = [bool]$p.optional
            Enabled    = if ($null -eq $p.enabled) { $true } else { [bool]$p.enabled }
        }
    }

    # Classifiers -> label-code -> classifier-list (mirrors Resolve-ClassifierConfig).
    $classifiers = @{}
    foreach ($prop in $classifiersJson.PSObject.Properties) {
        $entryList = @()
        foreach ($item in $prop.Value) {
            if ($item.classifierType -eq 'MLModel') {
                $entryList += @{ Name = $item.name; Id = $item.id; ClassifierType = 'MLModel' }
            } else {
                $entryList += @{
                    Name            = $item.name
                    Id              = $item.id
                    minCount        = if ($null -ne $item.minCount) { [int]$item.minCount } else { $defaults.sitMinCount }
                    maxCount        = if ($null -ne $item.maxCount) { [int]$item.maxCount } else { $defaults.sitMaxCount }
                    confidencelevel = if ($item.confidenceLevel) { $item.confidenceLevel } else { $defaults.sitConfidenceLevel }
                }
            }
        }
        $classifiers[$prop.Name] = $entryList
    }

    # Labels -> only non-group, non-dlpExclude labels (mirrors Resolve-LabelConfig).
    $labels = @($labelsJson | Where-Object { -not $_.isGroup -and -not $_.dlpExclude } | ForEach-Object {
        [pscustomobject]@{ code = $_.code; fullName = if ($_.displayName) { $_.displayName } else { $_.name } }
    })
    # ...and only labels that actually have classifiers for their code (the deploy path's filter).
    $labels = @($labels | Where-Object { $classifiers.ContainsKey($_.code) })

    # Rule overrides -> byPolicy/byLabel/byRule (mirrors Resolve-RuleOverrides).
    $overrides = @{ byLabel = @{}; byPolicy = @{}; byRule = @{} }
    if ($overridesJson) {
        foreach ($section in @('byLabel', 'byPolicy', 'byRule')) {
            $sectionObj = $overridesJson.$section
            if ($sectionObj) {
                foreach ($prop in $sectionObj.PSObject.Properties) {
                    $hash = @{}
                    foreach ($inner in $prop.Value.PSObject.Properties) { $hash[$inner.Name] = $inner.Value }
                    $overrides[$section][$prop.Name] = $hash
                }
            }
        }
    }

    # Policy mode (mirrors Resolve-PolicyMode); affects only the policy record, not rule content.
    $auditMode  = [bool]$config['auditMode']
    $notifyUser = [bool]$config['notifyUser']
    $policyMode = if ($auditMode) {
        if ($notifyUser) { 'TestWithNotifications' } else { 'TestWithoutNotifications' }
    } else { 'Enable' }

    $generateIncidentReport = [bool]$config['generateIncidentReport']
    $incidentReportRecipient = if ($config.ContainsKey('incidentReportRecipient') -and $config['incidentReportRecipient']) { $config['incidentReportRecipient'] } else { 'SiteAdmin' }
    $incidentReportSeverity  = if ($config.ContainsKey('incidentReportSeverity') -and $config['incidentReportSeverity']) { $config['incidentReportSeverity'] } else { $defaults.incidentReportSeverity }

    # ----- chunking (mirrors Split-ClassifierChunks / Get-ChunkLetter) -------------------------
    function Split-DesiredClassifierChunks {
        param([array]$ClassifierList, [int]$MaxPerRule = 125)
        $total = $ClassifierList.Count
        if ($total -eq 0) { return @(, @()) }
        if ($total -le $MaxPerRule) { return @(, $ClassifierList) }
        $chunkCount = [math]::Ceiling($total / $MaxPerRule)
        if ($chunkCount -gt 26) {
            throw "Cannot split $total classifiers into chunks of $MaxPerRule — would need $chunkCount chunks but maximum is 26 (a-z)."
        }
        $chunkSize = [math]::Ceiling($total / $chunkCount)
        $chunks = @()
        for ($i = 0; $i -lt $total; $i += $chunkSize) {
            $end = [math]::Min($i + $chunkSize, $total)
            $chunks += , @($ClassifierList[$i..($end - 1)])
        }
        return $chunks
    }
    function Get-DesiredChunkLetter {
        param([int]$ChunkIndex)
        if ($ChunkIndex -lt 1 -or $ChunkIndex -gt 26) {
            throw "Chunk index $ChunkIndex is out of range (1-26)."
        }
        return [char]([int][char]'a' + $ChunkIndex - 1)
    }

    # Merge byPolicy < byLabel < byRule onto base params (mirrors Get-MergedRuleParams).
    function Merge-DesiredOverrides {
        param([hashtable]$BaseParams, [string]$LabelCode, [string]$PolicyCode, [string]$RuleName)
        $merged = @{}
        foreach ($k in $BaseParams.Keys) { $merged[$k] = $BaseParams[$k] }
        if ($overrides.byPolicy.ContainsKey($PolicyCode)) { foreach ($k in $overrides.byPolicy[$PolicyCode].Keys) { $merged[$k] = $overrides.byPolicy[$PolicyCode][$k] } }
        if ($overrides.byLabel.ContainsKey($LabelCode))   { foreach ($k in $overrides.byLabel[$LabelCode].Keys)   { $merged[$k] = $overrides.byLabel[$LabelCode][$k] } }
        if ($overrides.byRule.ContainsKey($RuleName))     { foreach ($k in $overrides.byRule[$RuleName].Keys)     { $merged[$k] = $overrides.byRule[$RuleName][$k] } }
        return $merged
    }

    # ----- BUILD: policy + rule records --------------------------------------------------------
    $policyRecords = [System.Collections.Generic.List[object]]::new()
    $ruleRecords   = [System.Collections.Generic.List[object]]::new()

    foreach ($policy in ($policies | Where-Object { $_.Enabled })) {
        $policyName = Get-PolicyName -PolicyNumber $policy.Number -PolicyCode $policy.Code -Config $config

        $policyRecords.Add([pscustomobject]@{
            policyName   = $policyName
            policyCode   = $policy.Code
            policyNumber = $policy.Number
            mode         = $policyMode
            comment      = $policy.Comment
            locations    = $policy.Location
            optional     = $policy.Optional
        }) | Out-Null

        $ruleNum = 0
        foreach ($label in $labels) {
            $ruleNum++
            $labelCode      = $label.code
            $classifierList = $classifiers[$labelCode]
            $chunks = @(Split-DesiredClassifierChunks -ClassifierList $classifierList -MaxPerRule 125)

            $chunkIndex = 0
            foreach ($chunk in $chunks) {
                $chunkIndex++
                $chunkLetter = if ($chunks.Count -gt 1) { Get-DesiredChunkLetter -ChunkIndex $chunkIndex } else { '' }
                $ruleName = Get-RuleName -PolicyNumber $policy.Number -RuleNumber $ruleNum -PolicyCode $policy.Code `
                    -LabelCode $labelCode -ChunkLetter $chunkLetter -Config $config

                # The classifier condition — the SAME builder Deploy-DLPRules uses (ported to Model).
                $condition = New-DLPSITCondition -ClassifierList $chunk -ScopeParam $policy.ScopeParam -ScopeValue $policy.ScopeValue

                $chunkNote = if ($chunks.Count -gt 1) { " [chunk $chunkIndex/$($chunks.Count)]" } else { '' }
                $baseRuleParams = @{
                    Name                = $ruleName
                    Policy              = $policyName
                    Comment             = "$($label.fullName)$chunkNote ($($chunk.Count) classifiers)"
                    ReportSeverityLevel = $(if ($generateIncidentReport) { $incidentReportSeverity } else { 'Low' })
                    Disabled            = $false
                }
                if ($condition.Format -eq 'AdvancedRule') {
                    $baseRuleParams['AdvancedRule'] = $condition.Value
                } else {
                    $baseRuleParams['ContentContainsSensitiveInformation'] = $condition.Value
                    if ($policy.ScopeParam) { $baseRuleParams[$policy.ScopeParam] = $policy.ScopeValue }
                }
                if ($generateIncidentReport) {
                    $baseRuleParams['GenerateIncidentReport'] = $incidentReportRecipient
                    $baseRuleParams['IncidentReportContent']  = 'All'
                }
                if ($notifyUser) {
                    $baseRuleParams['NotifyUser'] = 'SiteAdmin,LastModifier,Owner'
                }

                $finalRuleParams = Merge-DesiredOverrides -BaseParams $baseRuleParams -LabelCode $labelCode -PolicyCode $policy.Code -RuleName $ruleName

                $ruleRecords.Add([pscustomobject]@{
                    policyName   = $policyName
                    ruleName     = $ruleName
                    policyCode   = $policy.Code
                    policyNumber = $policy.Number
                    labelCode    = $labelCode
                    ruleNumber   = $ruleNum
                    chunkIndex   = $chunkIndex
                    chunkCount   = $chunks.Count
                    chunkLetter  = $chunkLetter
                    conditionFormat = $condition.Format
                    content      = $finalRuleParams
                    contentHash  = (Get-DlpRuleContentHash -DesiredParams $finalRuleParams)
                }) | Out-Null
            }
        }
    }

    return [pscustomobject]@{
        Policies = @($policyRecords)
        Rules    = @($ruleRecords)
    }
}
