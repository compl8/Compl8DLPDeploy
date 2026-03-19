#==============================================================================
# AutoLabel-Converter Module
# Pure conversion logic for DLP-to-auto-labeling policy conversion.
# Import with: Import-Module .\modules\AutoLabel-Converter.psm1 -Force
#==============================================================================

#region Condition Convertibility Lookup

function Get-ConditionConvertibility {
    <#
    .SYNOPSIS
        Classifies a DLP rule condition as convertible, droppable, or unknown
        for auto-labeling policy conversion.
    .PARAMETER ConditionName
        The name of the DLP rule condition property.
    .OUTPUTS
        Hashtable with Status (convertible/droppable/unknown) and optionally What/Why.
    #>
    param(
        [Parameter(Mandatory)][string]$ConditionName
    )

    $convertible = @(
        'ContentContainsSensitiveInformation'
        'ExceptIfContentContainsSensitiveInformation'
        'AccessScope'
        'ExceptIfAccessScope'
        'ContentExtensionMatchesWords'
        'ExceptIfContentExtensionMatchesWords'
        'ContentPropertyContainsWords'
        'DocumentIsPasswordProtected'
        'DocumentIsUnsupported'
        'DocumentCreatedBy'
        'DocumentNameMatchesWords'
        'DocumentSizeOver'
        'SubjectMatchesPatterns'
        'HeaderMatchesPatterns'
        'SenderDomainIs'
        'RecipientDomainIs'
        'SentTo'
        'SentToMemberOf'
        'AnyOfRecipientAddressContainsWords'
        'AnyOfRecipientAddressMatchesPatterns'
        'FromAddressContainsWords'
        'FromAddressMatchesPatterns'
        'SenderIPRanges'
        'ProcessingLimitExceeded'
    )

    $droppable = [ordered]@{
        'FromScope' = @{
            What = 'Sender location filtering removed'
            Why  = 'No sender location filtering in auto-labeling'
        }
        'From' = @{
            What = 'Sender filter removed'
            Why  = 'Reserved for internal Microsoft use on auto-labeling cmdlets'
        }
        'FromMemberOf' = @{
            What = 'Sender group filter removed'
            Why  = 'Reserved for internal Microsoft use on auto-labeling cmdlets'
        }
        'SenderADAttributeContainsWords' = @{
            What = 'Sender AD attribute filter removed'
            Why  = 'No AD attribute conditions in auto-labeling'
        }
        'SenderADAttributeMatchesPatterns' = @{
            What = 'Sender AD attribute pattern filter removed'
            Why  = 'No AD attribute conditions in auto-labeling'
        }
        'RecipientADAttributeContainsWords' = @{
            What = 'Recipient AD attribute filter removed'
            Why  = 'No AD attribute conditions in auto-labeling'
        }
        'RecipientADAttributeMatchesPatterns' = @{
            What = 'Recipient AD attribute pattern filter removed'
            Why  = 'No AD attribute conditions in auto-labeling'
        }
        'MessageTypeMatches' = @{
            What = 'Message type filter removed'
            Why  = 'No message type filtering in auto-labeling'
        }
        'SubjectContainsWords' = @{
            What = 'Subject word filter removed'
            Why  = 'Only regex patterns available (SubjectMatchesPatterns)'
        }
        'SubjectOrBodyContainsWords' = @{
            What = 'Subject/body word filter removed'
            Why  = 'No body content matching in auto-labeling'
        }
        'SubjectOrBodyMatchesPatterns' = @{
            What = 'Subject/body pattern filter removed'
            Why  = 'No body content matching in auto-labeling'
        }
        'DocumentContainsWords' = @{
            What = 'Document body word filter removed'
            Why  = 'No document body search in auto-labeling'
        }
        'DocumentMatchesPatterns' = @{
            What = 'Document body pattern filter removed'
            Why  = 'No document body search in auto-labeling'
        }
        'DocumentNameMatchesPatterns' = @{
            What = 'Document name pattern filter removed'
            Why  = 'Only word matching available (DocumentNameMatchesWords)'
        }
        'HeaderContainsWords' = @{
            What = 'Header word filter removed'
            Why  = 'Only regex patterns available (HeaderMatchesPatterns)'
        }
        'ContentIsNotLabeled' = @{
            What = 'Unlabeled content condition removed'
            Why  = 'Cannot condition on label state in auto-labeling'
        }
        'AttachmentIsNotLabeled' = @{
            What = 'Unlabeled attachment condition removed'
            Why  = 'Cannot condition on label state in auto-labeling'
        }
        'MessageIsNotLabeled' = @{
            What = 'Unlabeled message condition removed'
            Why  = 'Cannot condition on label state in auto-labeling'
        }
        'ContentIsShared' = @{
            What = 'Content sharing condition removed'
            Why  = 'Not available in auto-labeling'
        }
        'HasSenderOverride' = @{
            What = 'Sender override condition removed'
            Why  = 'Not available in auto-labeling'
        }
        'MessageSizeOver' = @{
            What = 'Message size condition removed'
            Why  = 'Not available in auto-labeling'
        }
        'WithImportance' = @{
            What = 'Importance condition removed'
            Why  = 'Not available in auto-labeling'
        }
        'StopPolicyProcessing' = @{
            What = 'Stop processing flag removed'
            Why  = 'Not available in auto-labeling'
        }
        'EvaluateRulePerComponent' = @{
            What = 'Per-component evaluation removed'
            Why  = 'Not available in auto-labeling'
        }
        'SharedByIRMUserRisk' = @{
            What = 'IRM user risk condition removed'
            Why  = 'Not available in auto-labeling'
        }
    }

    if ($ConditionName -in $convertible) {
        return @{ Status = 'convertible' }
    }

    if ($droppable.Contains($ConditionName)) {
        $entry = $droppable[$ConditionName]
        return @{
            Status = 'droppable'
            What   = $entry.What
            Why    = $entry.Why
        }
    }

    return @{ Status = 'unknown' }
}

#endregion

#region Helper Functions

function Convert-PSOToHashtable {
    <#
    .SYNOPSIS
        Recursively converts a PSObject tree to nested hashtables.
    #>
    param(
        [object]$InputObject
    )

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Collections.IList]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) {
            $list.Add((Convert-PSOToHashtable -InputObject $item))
        }
        return @($list)
    }

    if ($InputObject -is [PSCustomObject]) {
        $ht = [ordered]@{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $ht[$prop.Name] = Convert-PSOToHashtable -InputObject $prop.Value
        }
        return $ht
    }

    # Primitive value — return as-is
    return $InputObject
}

function Find-CCSIInAdvancedRule {
    <#
    .SYNOPSIS
        Walks AdvancedRule JSON (parsed object) to find the
        ContentContainsSensitiveInformation subcondition.
    .PARAMETER Parsed
        The parsed AdvancedRule object (from ConvertFrom-Json).
    .OUTPUTS
        The Value of the CCSI subcondition, or $null if not found.
    #>
    param(
        [Parameter(Mandatory)][object]$Parsed
    )

    $condition = $Parsed.Condition
    if (-not $condition) { return $null }

    $subConditions = $condition.SubConditions
    if (-not $subConditions) { return $null }

    foreach ($sub in $subConditions) {
        if ($sub.ConditionName -eq 'ContentContainsSensitiveInformation') {
            return $sub.Value
        }
        # Recurse into nested conditions
        if ($sub.SubConditions) {
            foreach ($inner in $sub.SubConditions) {
                if ($inner.ConditionName -eq 'ContentContainsSensitiveInformation') {
                    return $inner.Value
                }
            }
        }
    }

    return $null
}

function Find-AccessScopeInAdvancedRule {
    <#
    .SYNOPSIS
        Extracts AccessScope value from AdvancedRule JSON.
    .PARAMETER Parsed
        The parsed AdvancedRule object (from ConvertFrom-Json).
    .OUTPUTS
        The AccessScope value string, or $null if not found.
    #>
    param(
        [Parameter(Mandatory)][object]$Parsed
    )

    $condition = $Parsed.Condition
    if (-not $condition) { return $null }

    $subConditions = $condition.SubConditions
    if (-not $subConditions) { return $null }

    foreach ($sub in $subConditions) {
        if ($sub.ConditionName -eq 'AccessScope') {
            return $sub.Value
        }
    }

    return $null
}

function Test-HasTrainableClassifier {
    <#
    .SYNOPSIS
        Checks if an AdvancedRule JSON contains any MLModel (trainable classifier) entries.
    .PARAMETER Parsed
        The parsed AdvancedRule object (from ConvertFrom-Json).
    .OUTPUTS
        Boolean indicating presence of trainable classifiers.
    #>
    param(
        [Parameter(Mandatory)][object]$Parsed
    )

    $json = $Parsed | ConvertTo-Json -Depth 20
    return ($json -match '"Classifiertype"\s*:\s*"MLModel"' -or $json -match '"classifiertype"\s*:\s*"MLModel"')
}

#endregion

#region Condition Extraction

function ConvertFrom-DlpRuleConditions {
    <#
    .SYNOPSIS
        Extracts and classifies conditions from a DLP rule object.
    .PARAMETER DlpRule
        A PSObject as returned by Get-DlpComplianceRule.
    .OUTPUTS
        Hashtable with HasSIT, HasTrainableClassifier, Converted, ExceptIf, Dropped.
    #>
    param(
        [Parameter(Mandatory)][PSObject]$DlpRule
    )

    $result = @{
        HasSIT                  = $false
        HasTrainableClassifier  = $false
        Converted               = [ordered]@{}
        ExceptIf                = [ordered]@{}
        Dropped                 = @()
    }

    # Determine if simple or advanced format
    $advancedRuleStr = $null
    if ($DlpRule.PSObject.Properties['AdvancedRule'] -and $DlpRule.AdvancedRule) {
        $advancedRuleStr = $DlpRule.AdvancedRule
    }

    if ($advancedRuleStr) {
        # AdvancedRule format
        $parsed = $advancedRuleStr | ConvertFrom-Json

        $ccsiValue = Find-CCSIInAdvancedRule -Parsed $parsed
        if ($ccsiValue) {
            $result.HasSIT = $true
            $result.Converted['ContentContainsSensitiveInformation'] = Convert-PSOToHashtable -InputObject $ccsiValue
        }

        $accessScope = Find-AccessScopeInAdvancedRule -Parsed $parsed
        if ($accessScope) {
            $result.Converted['AccessScope'] = $accessScope
        }

        $result.HasTrainableClassifier = Test-HasTrainableClassifier -Parsed $parsed
    } else {
        # Simple format — read CCSI directly
        if ($DlpRule.PSObject.Properties['ContentContainsSensitiveInformation'] -and $DlpRule.ContentContainsSensitiveInformation) {
            $ccsi = $DlpRule.ContentContainsSensitiveInformation

            # Purview API returns CCSI as a flat ArrayList of SIT hashtables (not the
            # nested groups/operator/sensitivetypes structure used when creating rules).
            # Normalise to our internal format.
            if ($ccsi -is [System.Collections.IList] -and $ccsi.Count -gt 0 -and $ccsi[0] -is [System.Collections.IDictionary]) {
                # Flat ArrayList of SIT hashtables from API — wrap into groups structure
                $result.HasSIT = $true
                $sitList = @($ccsi | ForEach-Object { Convert-PSOToHashtable -InputObject $_ })
                $result.Converted['ContentContainsSensitiveInformation'] = [ordered]@{
                    operator = "And"
                    groups = @([ordered]@{
                        operator       = "Or"
                        name           = "Default"
                        sensitivetypes = $sitList
                    })
                }
            } elseif ($ccsi -is [PSCustomObject]) {
                # Already structured (groups/operator format)
                $result.HasSIT = $true
                $result.Converted['ContentContainsSensitiveInformation'] = Convert-PSOToHashtable -InputObject $ccsi
            } elseif ($ccsi -is [System.Collections.IDictionary]) {
                # Single hashtable with groups key
                $result.HasSIT = $true
                $result.Converted['ContentContainsSensitiveInformation'] = Convert-PSOToHashtable -InputObject $ccsi
            }
        }

        # Also handle ExceptIfCCSI in flat format
        if ($DlpRule.PSObject.Properties['ExceptIfContentContainsSensitiveInformation'] -and $DlpRule.ExceptIfContentContainsSensitiveInformation) {
            $exceptCcsi = $DlpRule.ExceptIfContentContainsSensitiveInformation
            if ($exceptCcsi -is [System.Collections.IList] -and $exceptCcsi.Count -gt 0 -and $exceptCcsi[0] -is [System.Collections.IDictionary]) {
                $sitList = @($exceptCcsi | ForEach-Object { Convert-PSOToHashtable -InputObject $_ })
                $result.ExceptIf['ExceptIfContentContainsSensitiveInformation'] = [ordered]@{
                    operator = "And"
                    groups = @([ordered]@{
                        operator       = "Or"
                        name           = "Default"
                        sensitivetypes = $sitList
                    })
                }
            } elseif ($exceptCcsi -is [PSCustomObject] -or $exceptCcsi -is [System.Collections.IDictionary]) {
                $result.ExceptIf['ExceptIfContentContainsSensitiveInformation'] = Convert-PSOToHashtable -InputObject $exceptCcsi
            }
        }
    }

    # Scan all properties for condition classification
    # Skip known non-condition properties
    $nonConditionProps = @(
        'Name', 'Policy', 'Comment', 'Disabled', 'Priority', 'Workload',
        'Mode', 'RuleErrorAction', 'ImmutableId', 'ContentMatchQuery',
        'IsValid', 'ObjectState', 'WhenChangedUTC', 'WhenCreatedUTC',
        'ExchangeVersion', 'DistinguishedName', 'Identity', 'Id', 'Guid',
        'ExchangeObjectId', 'ParentPolicyName', 'CreatedBy', 'LastModifiedBy',
        'AdvancedRule', 'ContentContainsSensitiveInformation',
        'ExceptIfContentContainsSensitiveInformation', 'PSComputerName',
        'PSShowComputerName', 'RunspaceId', 'ReadOnly', 'OrganizationId',
        'IncidentReportContent', 'GenerateIncidentReport', 'GenerateAlert',
        'AlertProperties', 'NotifyUser', 'NotifyPolicyTipCustomText',
        'NotifyOverrideRequirements', 'NotifyAllowOverride',
        'NotifyEmailCustomText', 'NotifyPolicyTipCustomTextTranslations',
        'ReportSeverityLevel', 'RuleDesignerFlags', 'AnyOfRecipientAddressContains',
        'BlockAccess', 'BlockAccessScope', 'Actions'
    )

    foreach ($prop in $DlpRule.PSObject.Properties) {
        $name = $prop.Name
        $value = $prop.Value

        # Skip null/empty values
        if ($null -eq $value) { continue }
        if ($value -is [string] -and [string]::IsNullOrEmpty($value)) { continue }
        if ($value -is [bool] -and -not $value) { continue }
        if ($value -is [System.Collections.IList] -and $value.Count -eq 0) { continue }

        # Skip non-condition properties
        if ($name -in $nonConditionProps) { continue }

        # Already handled
        if ($name -eq 'ContentContainsSensitiveInformation') { continue }

        $conv = Get-ConditionConvertibility -ConditionName $name
        switch ($conv.Status) {
            'convertible' {
                if ($name -like 'ExceptIf*') {
                    $result.ExceptIf[$name] = $value
                } else {
                    $result.Converted[$name] = $value
                }
            }
            'droppable' {
                $result.Dropped += @{
                    Condition = $name
                    Value     = $value
                    What      = $conv.What
                    Why       = $conv.Why
                }
            }
            # 'unknown' — skip silently (non-condition properties)
        }
    }

    return $result
}

#endregion

#region Label Resolution

function Resolve-LabelAssignment {
    <#
    .SYNOPSIS
        Resolves which sensitivity label a DLP rule should map to.
    .PARAMETER RuleName
        The DLP rule name.
    .PARAMETER Mappings
        Array of mapping objects with Pattern and LabelCode properties.
    .PARAMETER TenantLabels
        Array of tenant label objects with ImmutableId/DisplayName.
    .PARAMETER LabelsJson
        Array of label config objects (from labels.json) with code and displayName.
    .OUTPUTS
        Hashtable with Label, LabelCode, AssignedBy.
    #>
    param(
        [Parameter(Mandatory)][string]$RuleName,
        [AllowNull()][array]$Mappings,
        [AllowNull()][array]$TenantLabels,
        [AllowNull()][array]$LabelsJson
    )

    # Strategy 1: Toolkit naming convention
    # Format: P{nn}-R{nn}-{Workload}-{LabelCode}-{Suffix}
    if ($RuleName -match '^P\d{2}-R\d{2}-([^-]+)-([^-]+)-') {
        $labelCode = $Matches[2]

        if ($LabelsJson) {
            $matchedLabel = $LabelsJson | Where-Object { $_.code -eq $labelCode } | Select-Object -First 1
            if ($matchedLabel) {
                $displayName = if ($matchedLabel.displayName) { $matchedLabel.displayName } else { $matchedLabel.name }
                return @{
                    Label      = $displayName
                    LabelCode  = $labelCode
                    AssignedBy = 'naming-convention'
                }
            }
        }
    }

    # Strategy 2: Mapping JSON (wildcard matching)
    if ($Mappings) {
        foreach ($mapping in $Mappings) {
            if ($RuleName -like $mapping.Pattern) {
                $label = $null
                if ($LabelsJson) {
                    $matchedLabel = $LabelsJson | Where-Object { $_.code -eq $mapping.LabelCode } | Select-Object -First 1
                    if ($matchedLabel) {
                        $label = if ($matchedLabel.displayName) { $matchedLabel.displayName } else { $matchedLabel.name }
                    }
                }
                return @{
                    Label      = $label
                    LabelCode  = $mapping.LabelCode
                    AssignedBy = 'mapping-json'
                }
            }
        }
    }

    # Strategy 3: Unresolved
    return @{
        Label      = $null
        LabelCode  = $null
        AssignedBy = 'unresolved'
    }
}

#endregion

#region Rule Classification

function Get-DlpRuleClassification {
    <#
    .SYNOPSIS
        Classifies a DLP rule as full, partial, or unconvertible for auto-labeling.
    .PARAMETER ExtractedConditions
        Hashtable from ConvertFrom-DlpRuleConditions.
    .OUTPUTS
        String: "full", "partial", or "unconvertible".
    #>
    param(
        [Parameter(Mandatory)][hashtable]$ExtractedConditions
    )

    # No SIT = unconvertible (auto-labeling requires SIT conditions)
    if (-not $ExtractedConditions.HasSIT) {
        return 'unconvertible'
    }

    # Trainable classifiers not supported in auto-labeling
    if ($ExtractedConditions.HasTrainableClassifier) {
        return 'unconvertible'
    }

    # Has dropped conditions = partial conversion
    if ($ExtractedConditions.Dropped -and $ExtractedConditions.Dropped.Count -gt 0) {
        return 'partial'
    }

    return 'full'
}

#endregion

#region Workload Detection

function Get-WorkloadFromPolicy {
    <#
    .SYNOPSIS
        Derives workload string from DLP policy location properties.
    .PARAMETER Policy
        A PSObject representing a DLP compliance policy.
    .OUTPUTS
        String workload identifier.
    #>
    param(
        [Parameter(Mandatory)][PSObject]$Policy
    )

    if ($Policy.PSObject.Properties['ExchangeLocation'] -and $Policy.ExchangeLocation) {
        return 'Exchange'
    }
    if ($Policy.PSObject.Properties['SharePointLocation'] -and $Policy.SharePointLocation) {
        return 'SharePoint'
    }
    if ($Policy.PSObject.Properties['OneDriveLocation'] -and $Policy.OneDriveLocation) {
        return 'OneDriveForBusiness'
    }
    if ($Policy.PSObject.Properties['TeamsLocation'] -and $Policy.TeamsLocation) {
        return 'Teams'
    }
    if ($Policy.PSObject.Properties['EndpointDlpLocation'] -and $Policy.EndpointDlpLocation) {
        return 'Endpoint'
    }

    return 'Unknown'
}

#endregion

#region SIT Merging

function Merge-SITConditions {
    <#
    .SYNOPSIS
        Merges multiple ContentContainsSensitiveInformation condition hashtables.
    .PARAMETER Sources
        Array of CCSI hashtables (each with operator, groups containing sensitivetypes).
    .OUTPUTS
        Hashtable with Merged (hashtable) and Notes (string array).
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Sources
    )

    $notes = [System.Collections.Generic.List[string]]::new()

    if ($Sources.Count -eq 0) {
        return @{
            Merged = $null
            Notes  = @()
        }
    }

    if ($Sources.Count -eq 1) {
        return @{
            Merged = $Sources[0]
            Notes  = @()
        }
    }

    # Confidence string to numeric for comparison (lower = more permissive)
    $confidenceMap = @{
        'Low'    = 1
        'Medium' = 2
        'High'   = 3
    }

    $confidenceReverse = @{
        1 = 'Low'
        2 = 'Medium'
        3 = 'High'
    }

    # Collect all SITs across all sources
    $sitIndex = [ordered]@{}

    $sourceIdx = 0
    foreach ($source in $Sources) {
        $sourceIdx++
        $groups = $null
        if ($source -is [hashtable] -or $source -is [System.Collections.Specialized.OrderedDictionary]) {
            $groups = $source['groups']
            if (-not $groups) { $groups = $source['Groups'] }
        }
        if (-not $groups) { continue }

        foreach ($group in $groups) {
            $sits = $null
            if ($group -is [hashtable] -or $group -is [System.Collections.Specialized.OrderedDictionary]) {
                $sits = $group['sensitivetypes']
                if (-not $sits) { $sits = $group['Sensitivetypes'] }
            }
            if (-not $sits) { continue }

            foreach ($sit in $sits) {
                $id = $null
                $name = $null
                $minCount = $null
                $maxCount = $null
                $confidence = $null

                if ($sit -is [hashtable] -or $sit -is [System.Collections.Specialized.OrderedDictionary]) {
                    $id = if ($sit.Contains('id')) { $sit['id'] } elseif ($sit.Contains('Id')) { $sit['Id'] } else { $null }
                    $name = if ($sit.Contains('name')) { $sit['name'] } elseif ($sit.Contains('Name')) { $sit['Name'] } else { $null }
                    $minCount = if ($sit.Contains('mincount')) { $sit['mincount'] } elseif ($sit.Contains('minCount')) { $sit['minCount'] } elseif ($sit.Contains('Mincount')) { $sit['Mincount'] } else { $null }
                    $maxCount = if ($sit.Contains('maxcount')) { $sit['maxcount'] } elseif ($sit.Contains('maxCount')) { $sit['maxCount'] } elseif ($sit.Contains('Maxcount')) { $sit['Maxcount'] } else { $null }
                    $confidence = if ($sit.Contains('confidencelevel')) { $sit['confidencelevel'] } elseif ($sit.Contains('confidenceLevel')) { $sit['confidenceLevel'] } else { $null }
                }

                if (-not $id) { continue }

                if ($sitIndex.Contains($id)) {
                    # Duplicate — use most permissive values
                    $existing = $sitIndex[$id]
                    $changed = $false

                    # Lower minCount = more permissive
                    if ($null -ne $minCount -and $null -ne $existing['mincount'] -and [int]$minCount -lt [int]$existing['mincount']) {
                        $existing['mincount'] = [int]$minCount
                        $changed = $true
                    }

                    # Lower confidence = more permissive
                    if ($confidence -and $existing['confidencelevel']) {
                        $existingNum = $confidenceMap[$existing['confidencelevel']]
                        $newNum = $confidenceMap[$confidence]
                        if ($null -ne $existingNum -and $null -ne $newNum -and $newNum -lt $existingNum) {
                            $existing['confidencelevel'] = $confidence
                            $changed = $true
                        }
                    }

                    if ($changed) {
                        $notes.Add("Duplicate SIT '$name' ($id): merged with most permissive values")
                    }
                } else {
                    $sitEntry = [ordered]@{}
                    if ($name) { $sitEntry['name'] = $name }
                    if ($id) { $sitEntry['id'] = $id }
                    if ($null -ne $minCount) { $sitEntry['mincount'] = [int]$minCount }
                    if ($null -ne $maxCount) { $sitEntry['maxcount'] = [int]$maxCount }
                    if ($confidence) { $sitEntry['confidencelevel'] = $confidence }
                    $sitIndex[$id] = $sitEntry
                }
            }
        }
    }

    $mergedSITs = @($sitIndex.Values)
    $notes.Add("Merged $($Sources.Count) sources into $($mergedSITs.Count) unique SITs")

    $merged = [ordered]@{
        operator = 'And'
        groups   = @(
            [ordered]@{
                operator       = 'Or'
                name           = 'Default'
                sensitivetypes = $mergedSITs
            }
        )
    }

    return @{
        Merged = $merged
        Notes  = @($notes)
    }
}

#endregion

#region Conversion Plan

function New-ConversionPlan {
    <#
    .SYNOPSIS
        Creates a new conversion plan structure.
    .PARAMETER Tenant
        Tenant identifier string.
    .PARAMETER ScannedBy
        Who initiated the scan.
    .PARAMETER ExistingPolicies
        Count of existing auto-labeling policies in the tenant.
    .PARAMETER ScalingStatus
        Scaling status hashtable from Test-ScalingLimits.
    .OUTPUTS
        Ordered hashtable representing the conversion plan.
    #>
    param(
        [Parameter(Mandatory)][string]$Tenant,
        [Parameter(Mandatory)][string]$ScannedBy,
        [int]$ExistingPolicies = 0,
        [object]$ScalingStatus = $null
    )

    return [ordered]@{
        Version          = '1'
        Tenant           = $Tenant
        ScannedBy        = $ScannedBy
        ScannedAt        = (Get-Date -Format 'o')
        ExistingPolicies = $ExistingPolicies
        ScalingStatus    = $ScalingStatus
        Entries          = [System.Collections.Generic.List[object]]::new()
    }
}

function Export-ConversionPlan {
    <#
    .SYNOPSIS
        Writes a conversion plan to a JSON file.
    .PARAMETER Plan
        The conversion plan hashtable.
    .PARAMETER Path
        Output file path.
    #>
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][string]$Path
    )

    $dir = Split-Path $Path -Parent
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $Plan | ConvertTo-Json -Depth 20 | Set-Content -Path $Path -Encoding UTF8
}

function Import-ConversionPlan {
    <#
    .SYNOPSIS
        Reads a conversion plan from a JSON file.
    .PARAMETER Path
        Input file path.
    .OUTPUTS
        The deserialized conversion plan object.
    #>
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path $Path)) {
        Write-Error "Conversion plan not found: $Path"
        return $null
    }

    $content = Get-Content -Path $Path -Raw -ErrorAction Stop
    return ($content | ConvertFrom-Json)
}

#endregion

#region Scaling Limits

function Test-ScalingLimits {
    <#
    .SYNOPSIS
        Checks whether adding planned auto-labeling policies would exceed tenant limits.
    .PARAMETER ExistingPolicies
        Current count of auto-labeling policies in the tenant.
    .PARAMETER PlannedPolicies
        Number of new policies to be created.
    .PARAMETER WarnAt
        Percentage threshold for warning status. Default 80.
    .PARAMETER MaxPolicies
        Maximum allowed policies. Default 100.
    .OUTPUTS
        Hashtable with Status (ok/warning/blocked), Total, Message.
    #>
    param(
        [Parameter(Mandatory)][int]$ExistingPolicies,
        [Parameter(Mandatory)][int]$PlannedPolicies,
        [int]$WarnAt = 80,
        [int]$MaxPolicies = 100
    )

    $total = $ExistingPolicies + $PlannedPolicies
    $warnThreshold = [math]::Floor($MaxPolicies * $WarnAt / 100)

    if ($total -gt $MaxPolicies) {
        return @{
            Status  = 'blocked'
            Total   = $total
            Message = "Would exceed limit: $total / $MaxPolicies policies (need to remove $($total - $MaxPolicies))"
        }
    }

    if ($total -ge $warnThreshold) {
        return @{
            Status  = 'warning'
            Total   = $total
            Message = "Approaching limit: $total / $MaxPolicies policies ($([math]::Round($total / $MaxPolicies * 100))% used)"
        }
    }

    return @{
        Status  = 'ok'
        Total   = $total
        Message = "Within limits: $total / $MaxPolicies policies"
    }
}

#endregion

# Export all public functions
Export-ModuleMember -Function @(
    'Get-ConditionConvertibility'
    'Convert-PSOToHashtable'
    'Find-CCSIInAdvancedRule'
    'Find-AccessScopeInAdvancedRule'
    'Test-HasTrainableClassifier'
    'ConvertFrom-DlpRuleConditions'
    'Resolve-LabelAssignment'
    'Get-DlpRuleClassification'
    'Get-WorkloadFromPolicy'
    'Merge-SITConditions'
    'New-ConversionPlan'
    'Export-ConversionPlan'
    'Import-ConversionPlan'
    'Test-ScalingLimits'
)
