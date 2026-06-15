function Get-DlpRuleContentHash {
    <#
    .SYNOPSIS
        Stable, shape-agnostic content hash of a DLP rule's SEMANTIC content (DR-1).

    .DESCRIPTION
        THE canonical content-hash convention for DLP rules, used on BOTH sides of an assess diff
        so a desired rule and the actual tenant rule it maps to compare EQUAL when semantically
        identical, and differ the moment any meaningful field changes. It is the rule-level analogue
        of Get-DlpEntityContentHash (SIT entities) — same UTF-8 SHA-256 'sha256:'-prefixed convention.

        The problem this solves: the SAME rule is described two incompatible ways.

          * DESIRED (build) shape — the hashtable Deploy-DLPRules.ps1 constructs to feed
            New-DlpComplianceRule: $baseRuleParams with .ContentContainsSensitiveInformation
            (New-DLPSITCondition's Simple Value: { operator; groups=@({ operator; name;
            sensitivetypes=@({ name; id; mincount; maxcount; confidencelevel }) }) }) OR .AdvancedRule
            (a JSON string), plus AccessScope/<scopeParam>, ReportSeverityLevel, Disabled,
            GenerateIncidentReport, NotifyUser.

          * ACTUAL (readback) shape — what Get-DlpComplianceRule returns:
            .ContentContainsSensitiveInformation (the service re-serializes it: PascalCased keys,
            numeric Minconfidence 65/75/85 instead of the string confidencelevel Low/Medium/High,
            and sometimes a FLAT sensitivetypes array rather than the nested groups wrapper),
            .AdvancedRule, .AccessScope, .GenerateIncidentReport, .NotifyUser, .ReportSeverityLevel,
            .Disabled.

        Both map to ONE canonical projection:

            {
              sensitiveTypes : SORTED [ { id; mincount; maxcount; confidence } ]   (sorted by id)
              advancedRule   : <normalized JSON projection, or null>
              accessScope    : <string, or null>
              generateIncidentReport : <recipient string, or null>
              notifyUser     : <normalized string, or null>
              reportSeverity : <string, or null>
              disabled       : <bool>
            }

        Normalization absorbs every INCIDENTAL difference between the two shapes:
          * hashtable vs PSCustomObject, and arbitrary key order;
          * sensitivetypes nested under groups vs a flat array;
          * confidence as the string Low/Medium/High vs numeric Minconfidence 65/75/85 (both fold to
            the numeric 65/75/85 — case-insensitively for the string form);
          * sensitivetypes array order (sorted by GUID);
          * a SIT's friendly Name (the GUID alone identifies it — names are not part of the content);
          * missing-vs-empty-vs-null for the optional scalar fields (all fold to null).

        A genuine content edit — a changed confidence / mincount / maxcount, an added/removed SIT,
        a flipped action (GenerateIncidentReport, NotifyUser), a changed scope, severity, or Disabled
        flag, or any edit inside the AdvancedRule JSON — changes the canonical projection and therefore
        the hash.

        Pure: no tenant calls, no file IO, no Get-Date / Get-Random. Deterministic across processes.

    .PARAMETER DesiredParams
        The desired-build hashtable (the $baseRuleParams / New-DLPSITCondition shape).

    .PARAMETER ActualRule
        The actual-readback object from Get-DlpComplianceRule.

    .PARAMETER Rule
        Either shape — auto-detected. A plain [hashtable] is treated as DesiredParams; anything else
        (a PSCustomObject from the tenant) is treated as ActualRule.

    .OUTPUTS
        [string] 'sha256:' + 64 lowercase hex chars.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Auto')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Desired')]
        [hashtable]$DesiredParams,

        [Parameter(Mandatory, ParameterSetName = 'Actual')]
        [object]$ActualRule,

        [Parameter(Mandatory, ParameterSetName = 'Auto', Position = 0)]
        [object]$Rule
    )

    # ----- resolve which shape we were handed -------------------------------------------------
    $source = $null
    switch ($PSCmdlet.ParameterSetName) {
        'Desired' { $source = $DesiredParams }
        'Actual'  { $source = $ActualRule }
        'Auto'    { $source = $Rule }
    }

    # Property/key accessor that works for both hashtables and PSCustomObjects, case-insensitively.
    function Get-RuleField {
        param($Object, [string[]]$Names)
        if ($null -eq $Object) { return $null }
        foreach ($name in $Names) {
            if ($Object -is [System.Collections.IDictionary]) {
                foreach ($key in $Object.Keys) {
                    if ([string]::Equals([string]$key, $name, [System.StringComparison]::OrdinalIgnoreCase)) {
                        return $Object[$key]
                    }
                }
            } elseif ($Object.PSObject -and $Object.PSObject.Properties) {
                $prop = $Object.PSObject.Properties | Where-Object { [string]::Equals($_.Name, $name, [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
                if ($prop) { return $prop.Value }
            }
        }
        return $null
    }

    # Treat empty/whitespace strings as absent; fold to $null so missing == "" == $null.
    function ConvertTo-OptionalString {
        param($Value)
        if ($null -eq $Value) { return $null }
        $s = [string]$Value
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        return $s
    }

    # Confidence -> numeric 65/75/85. Accepts the string Low/Medium/High (case-insensitive) or an
    # already-numeric Minconfidence. Unknown/absent -> 75 (the Medium default the builders use).
    function ConvertTo-CanonicalConfidence {
        param($Value)
        if ($null -eq $Value -or ([string]::IsNullOrWhiteSpace([string]$Value))) { return 75 }
        $s = ([string]$Value).Trim()
        $n = 0
        if ([int]::TryParse($s, [ref]$n)) { return $n }
        switch ($s.ToLowerInvariant()) {
            'low'    { return 65 }
            'medium' { return 75 }
            'high'   { return 85 }
            default  { return 75 }
        }
    }

    # Pull the flat list of sensitivetype entries from a CCSI value, whether it is the nested
    # groups wrapper or a flat array (and whether CCSI itself is wrapped in a single-element array,
    # as the service readback often is).
    function Get-CcsiSensitiveTypes {
        param($Ccsi)
        $result = [System.Collections.Generic.List[object]]::new()
        if ($null -eq $Ccsi) { return $result }

        foreach ($node in @($Ccsi)) {
            if ($null -eq $node) { continue }

            $groups = Get-RuleField -Object $node -Names @('groups')
            $directSits = Get-RuleField -Object $node -Names @('sensitivetypes')

            if ($groups) {
                foreach ($group in @($groups)) {
                    foreach ($sit in @(Get-RuleField -Object $group -Names @('sensitivetypes'))) {
                        if ($sit) { $result.Add($sit) | Out-Null }
                    }
                }
            } elseif ($directSits) {
                foreach ($sit in @($directSits)) {
                    if ($sit) { $result.Add($sit) | Out-Null }
                }
            } else {
                # A bare sensitivetype entry (has an id) handed in directly.
                $id = Get-RuleField -Object $node -Names @('id')
                if ($id) { $result.Add($node) | Out-Null }
            }
        }
        return $result
    }

    # Canonical per-SIT projection: { id (lowercased); mincount; maxcount; confidence }. Name is
    # intentionally excluded — the GUID identifies the SIT; the display name is incidental.
    function ConvertTo-CanonicalSits {
        param($SitEntries)
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($sit in @($SitEntries)) {
            if ($null -eq $sit) { continue }
            $id = Get-RuleField -Object $sit -Names @('id')
            if (-not $id) { continue }
            $minRaw = Get-RuleField -Object $sit -Names @('mincount')
            $maxRaw = Get-RuleField -Object $sit -Names @('maxcount')
            # Confidence: prefer the explicit numeric Minconfidence, else the string confidencelevel.
            $confRaw = Get-RuleField -Object $sit -Names @('minconfidence')
            if ($null -eq $confRaw) { $confRaw = Get-RuleField -Object $sit -Names @('confidencelevel', 'confidence') }
            $list.Add([ordered]@{
                id         = ([string]$id).ToLowerInvariant()
                mincount   = if ($null -ne $minRaw -and "$minRaw" -ne '') { [int]$minRaw } else { 1 }
                maxcount   = if ($null -ne $maxRaw -and "$maxRaw" -ne '') { [int]$maxRaw } else { -1 }
                confidence = ConvertTo-CanonicalConfidence -Value $confRaw
            }) | Out-Null
        }
        # Sort by id (stable across declaration order); then by the numeric fields as a tiebreak in
        # the (pathological) case of the same GUID appearing twice with different thresholds.
        return @($list | Sort-Object -Property `
            @{ Expression = { $_.id } }, `
            @{ Expression = { $_.mincount } }, `
            @{ Expression = { $_.maxcount } }, `
            @{ Expression = { $_.confidence } })
    }

    # Normalize an AdvancedRule JSON string to a stable canonical projection (whitespace/key-order/
    # casing agnostic). We project the SIT closure + access scope out of the JSON the same way as the
    # Simple path, so an edit anywhere in the meaningful content perturbs the hash, while a re-serialize
    # by the service (pretty-print vs compressed) does not.
    function ConvertTo-CanonicalAdvancedRule {
        param([string]$Json)
        if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
        $parsed = $null
        try { $parsed = $Json | ConvertFrom-Json -ErrorAction Stop } catch { $parsed = $null }
        if ($null -eq $parsed) {
            # Unparseable — fall back to a whitespace-collapsed form so it still compares to itself.
            return ([ordered]@{ raw = ([regex]::Replace([string]$Json, '\s+', ' ')).Trim() })
        }

        $version = Get-RuleField -Object $parsed -Names @('version')
        $condition = Get-RuleField -Object $parsed -Names @('condition')
        $operator = Get-RuleField -Object $condition -Names @('operator')
        $subConditions = Get-RuleField -Object $condition -Names @('subconditions')

        $sitEntries = [System.Collections.Generic.List[object]]::new()
        $accessScope = $null
        $extraSubs = [System.Collections.Generic.List[object]]::new()
        foreach ($sub in @($subConditions)) {
            if ($null -eq $sub) { continue }
            $cname = [string](Get-RuleField -Object $sub -Names @('conditionname'))
            $cval = Get-RuleField -Object $sub -Names @('value')
            if ($cname -ieq 'ContentContainsSensitiveInformation') {
                foreach ($e in (Get-CcsiSensitiveTypes -Ccsi $cval)) { $sitEntries.Add($e) | Out-Null }
            } elseif ($cname -ieq 'AccessScope') {
                $accessScope = ConvertTo-OptionalString -Value $cval
            } else {
                # Preserve any other subcondition verbatim-ish so an edit to it still moves the hash.
                $extraSubs.Add([ordered]@{ name = $cname.ToLowerInvariant(); value = ($cval | ConvertTo-Json -Depth 20 -Compress) }) | Out-Null
            }
        }

        return [ordered]@{
            kind         = 'advancedRule'
            version      = ConvertTo-OptionalString -Value $version
            operator     = ConvertTo-OptionalString -Value $operator
            sensitiveTypes = ConvertTo-CanonicalSits -SitEntries $sitEntries
            accessScope  = $accessScope
            extra        = @($extraSubs | Sort-Object -Property @{ Expression = { $_.name } })
        }
    }

    # ----- build the canonical projection for the whole rule ----------------------------------
    $ccsi = Get-RuleField -Object $source -Names @('ContentContainsSensitiveInformation')
    $advancedRuleJson = Get-RuleField -Object $source -Names @('AdvancedRule')

    $sensitiveTypes = ConvertTo-CanonicalSits -SitEntries (Get-CcsiSensitiveTypes -Ccsi $ccsi)
    $advancedRule = ConvertTo-CanonicalAdvancedRule -Json ([string]$advancedRuleJson)

    # GenerateIncidentReport: a boolean true OR a recipient string both mean "on". Fold to the
    # recipient string when given, else 'on' for a bare $true, else null.
    $girRaw = Get-RuleField -Object $source -Names @('GenerateIncidentReport')
    $generateIncidentReport = $null
    if ($null -ne $girRaw) {
        if ($girRaw -is [bool]) { $generateIncidentReport = if ($girRaw) { 'on' } else { $null } }
        else { $generateIncidentReport = ConvertTo-OptionalString -Value $girRaw }
    }

    $canonical = [ordered]@{
        sensitiveTypes         = $sensitiveTypes
        advancedRule           = $advancedRule
        accessScope            = ConvertTo-OptionalString -Value (Get-RuleField -Object $source -Names @('AccessScope'))
        generateIncidentReport = $generateIncidentReport
        notifyUser             = ConvertTo-OptionalString -Value (Get-RuleField -Object $source -Names @('NotifyUser'))
        reportSeverity         = ConvertTo-OptionalString -Value (Get-RuleField -Object $source -Names @('ReportSeverityLevel'))
        disabled               = [bool](Get-RuleField -Object $source -Names @('Disabled'))
    }

    # Serialize the projection deterministically, then hash through the shared canonical-XML hasher
    # so we reuse the exact UTF-8 SHA-256 'sha256:' convention used by Get-DlpEntityContentHash.
    $projectionJson = $canonical | ConvertTo-Json -Depth 30 -Compress
    return Get-DlpEntityContentHash -EntityXml "<dlprule>$([System.Security.SecurityElement]::Escape($projectionJson))</dlprule>"
}
