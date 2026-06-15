function Resolve-DesiredAutoLabel {
    <#
    .SYNOPSIS
        Resolves the DESIRED auto-labeling POLICY set from config, with content (mode + applied label
        + locations) comparable against the ACTUAL tenant auto-label policies. The autoLabelPolicy
        analogue of Resolve-DesiredDlpRules (DR-2) — it feeds assess's auto-label-policy drift bucket.

    .DESCRIPTION
        Today there is no desired auto-label representation — auto-label policies are only ever
        materialised inside scripts/Deploy-AutoLabeling.ps1's deployment loop. This function lifts
        that policy materialisation OUT of the deploy script into a pure, config-driven projection so
        assess can diff desired-vs-actual auto-label policies.

        Deploy-AutoLabeling creates ONE auto-label policy per DLP-ELIGIBLE label (non-group,
        non-dlpExclude, with classifiers for its code), numbered sequentially in label order, that:
          * applies that label (ApplySensitivityLabel = the deployed label NAME),
          * runs in Mode 'TestWithoutNotifications' (the deploy script HARD-CODES this — it does NOT
            use the auditMode/notifyUser path that DLP policies use),
          * is scoped to the UNION of the ENABLED supported-workload locations read from policies.json
            (ECH -> ExchangeLocation, SPO -> SharePointLocation, ODB -> OneDriveLocation; Endpoint /
            Teams are unsupported for auto-labeling and skipped).
        This resolver reproduces exactly that policy set:

            policyName  : Get-DeploymentObjectName autoLabelPolicy ({policyNumber:D2}, {labelCode})
            labelCode / policyNumber / fullName
            label       : the applied sensitivity-label NAME (the SAME LabelNameLookup value Deploy
                          passes to ApplySensitivityLabel — Get-DeploymentObjectName 'label')
            mode        : 'TestWithoutNotifications'
            locations   : { <LocationKey> = 'All' } for each ENABLED supported workload (the union
                          Deploy passes on create)
            comment     : the RAW pre-stamp comment ('Auto-label <fullName> (<code>)')

        Drift is computed by assess from mode + applied label + locations; the comment is provenance
        metadata and is EXCLUDED from the comparison (the same exclusion the dlpPolicy path makes —
        Deploy wraps the comment with the provenance stamp, so the actual comment never equals the
        raw desired comment). No rules are emitted here: assess buckets at the autoLabelPolicy
        granularity (the only owned auto-label object type in the assessment schema).

        SOURCE vs BUILD separation (the Stage-5 seam): the SOURCE is read by an internal config loader
        keyed on -ConfigPath (defaulting to <repo>/config). The policy-BUILDING (name template, label
        lookup, workload/location union) is source-agnostic.

        Pure: no tenant calls, no Get-Date / Get-Random. Reads only the config files under -ConfigPath.

    .PARAMETER ConfigPath
        The config source directory. Defaults to <repo>/config. The Stage-5 re-point seam.
    .PARAMETER ConfigRoot
        Alias-style alternative to -ConfigPath (same meaning); -ConfigPath wins if both are supplied.

    .OUTPUTS
        [pscustomobject] with .Policies (policyName/labelCode/policyNumber/fullName/label/mode/
        locations/comment).
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
        throw "Resolve-DesiredAutoLabel: config source directory not found: $sourceDir"
    }

    function Read-DesiredConfigJson {
        param([string]$Name)
        $path = Join-Path $sourceDir $Name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Resolve-DesiredAutoLabel: required config file missing: $path"
        }
        return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
    }

    $settingsJson    = Read-DesiredConfigJson -Name 'settings.json'
    $labelsJson      = Read-DesiredConfigJson -Name 'labels.json'
    $policiesJson    = Read-DesiredConfigJson -Name 'policies.json'
    $classifiersJson = Read-DesiredConfigJson -Name 'classifiers.json'

    # settings.json -> a Config hashtable shaped exactly as Get-DeploymentObjectName expects
    # (namingPrefix/namingSuffix + the nameTemplates map).
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

    # MATCH THE DEPLOY CONFIG (codex review P2). Deploy-AutoLabeling.ps1 merges Get-ModuleDefaults UNDER
    # settings.json (Merge-GlobalConfig) before it names anything, so a config that OMITS naming fields
    # from settings.json STILL deploys auto-label policies using the module defaults. We must resolve the
    # SAME desired set the deploy path creates — not silently emit nothing or diverging names — so supply
    # the deploy-relevant defaults as fallbacks here (settings.json wins on conflict). The values mirror
    # Get-ModuleDefaults so a desired policy hashes/compares EQUAL to its deployed counterpart even when
    # the operator relied entirely on the defaults. (Get-ModuleDefaults lives in the DLP-Deploy facade,
    # which the layer modules must NOT import — keep these mirrored values in sync with it.)
    #
    # SCALAR naming defaults (namingPrefix/namingSuffix): the {prefix}/{suffix} tokens the label and
    # autoLabelPolicy templates consume. Omitting these previously produced empty tokens (e.g.
    # 'AL01-OFFI' instead of 'AL01-OFFI-DLP-EXT-ADT'), diverging from the deploy path → false drift.
    $defaultNamingScalars = @{ namingPrefix = 'DLP'; namingSuffix = 'EXT-ADT' }
    foreach ($k in $defaultNamingScalars.Keys) {
        if (-not $config.ContainsKey($k) -or [string]::IsNullOrWhiteSpace([string]$config[$k])) {
            $config[$k] = $defaultNamingScalars[$k]
        }
    }
    if (-not ($config['nameTemplates'] -is [System.Collections.IDictionary])) { $config['nameTemplates'] = @{} }
    $defaultNameTemplates = @{
        label           = '{prefix}-{name}-{labelCode}'
        autoLabelPolicy = 'AL{policyNumber}-{labelCode}-{prefix}-{suffix}'
    }
    foreach ($tplKey in $defaultNameTemplates.Keys) {
        if (-not $config['nameTemplates'].ContainsKey($tplKey)) { $config['nameTemplates'][$tplKey] = $defaultNameTemplates[$tplKey] }
    }

    # Supported auto-label workloads (mirrors Deploy-AutoLabeling's $AutoLabelWorkloadMap exactly).
    $workloadMap = @{
        'ECH' = @{ Workload = 'Exchange';            LocationKey = 'ExchangeLocation' }
        'SPO' = @{ Workload = 'SharePoint';          LocationKey = 'SharePointLocation' }
        'ODB' = @{ Workload = 'OneDriveForBusiness'; LocationKey = 'OneDriveLocation' }
    }

    # classifiers.json -> the set of label codes that HAVE classifiers (the deploy eligibility filter).
    $classifierCodes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($prop in $classifiersJson.PSObject.Properties) {
        if (@($prop.Value).Count -gt 0) { [void]$classifierCodes.Add($prop.Name) }
    }

    # policies.json (enabled + supported-workload) -> the UNION of location params Deploy passes on
    # create. Insertion order follows policies.json; the location set is deterministic for a config.
    $locationParams = [ordered]@{}
    foreach ($p in $policiesJson) {
        $enabled = if ($null -eq $p.enabled) { $true } else { [bool]$p.enabled }
        if (-not $enabled) { continue }
        $wlDef = $workloadMap[[string]$p.code]
        if (-not $wlDef) { continue }   # unsupported workload (Endpoint / Teams) — skipped
        $locationParams[$wlDef.LocationKey] = 'All'
    }
    if (@($locationParams.Keys).Count -eq 0) {
        # No supported auto-label workloads => Deploy-AutoLabeling emits no policies. Match that.
        return [pscustomobject]@{ Policies = @() }
    }

    # labels.json -> non-group, non-dlpExclude labels that HAVE classifiers (the deploy filter), with
    # the applied-label NAME (the deployed label name Deploy passes to ApplySensitivityLabel —
    # Get-DeploymentObjectName 'label', mirroring Deploy-AutoLabeling's $LabelNameLookup exactly).
    $labels = @()
    foreach ($l in $labelsJson) {
        if ($l.isGroup -or $l.dlpExclude) { continue }
        if ([string]::IsNullOrWhiteSpace([string]$l.code)) { continue }
        if (-not $classifierCodes.Contains([string]$l.code)) { continue }
        $appliedLabel = Get-DeploymentObjectName -Config $config -ObjectType 'label' -Name $l.name -Tokens @{
            labelCode   = $l.code
            displayName = $l.displayName
        }
        $labels += [pscustomobject]@{
            code         = [string]$l.code
            fullName     = if ($l.displayName) { [string]$l.displayName } else { [string]$l.name }
            appliedLabel = [string]$appliedLabel
        }
    }

    # ----- BUILD: one policy per label (sequential policyNumber, mirroring Deploy-AutoLabeling) -----
    $mode = 'TestWithoutNotifications'   # Deploy HARD-CODES this for auto-label (not the auditMode path).
    $policyRecords = [System.Collections.Generic.List[object]]::new()
    $policyNum = 0
    foreach ($label in $labels) {
        $policyNum++
        $policyName = Get-DeploymentObjectName -Config $config -ObjectType 'autoLabelPolicy' -Tokens @{
            policyNumber = ('{0:D2}' -f $policyNum)
            labelCode    = $label.code
        }
        # A fresh ordered copy of the shared location union so callers can't mutate it cross-record.
        $loc = [ordered]@{}
        foreach ($k in $locationParams.Keys) { $loc[$k] = $locationParams[$k] }

        $policyRecords.Add([pscustomobject]@{
            policyName   = $policyName
            labelCode    = $label.code
            policyNumber = $policyNum
            fullName     = $label.fullName
            label        = $label.appliedLabel
            mode         = $mode
            locations    = $loc
            comment      = "Auto-label $($label.fullName) ($($label.code))"
        }) | Out-Null
    }

    return [pscustomobject]@{ Policies = @($policyRecords) }
}
