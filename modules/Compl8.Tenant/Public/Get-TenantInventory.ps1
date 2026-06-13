function Get-TenantInventory {
    <#
    .SYNOPSIS
        Reads the six SCC object families and returns a normalised tenant inventory.
    .DESCRIPTION
        Shells the read-only SCC cmdlets — Get-DlpKeywordDictionary,
        Get-DlpSensitiveInformationTypeRulePackage, Get-DlpComplianceRule,
        Get-DlpCompliancePolicy, Get-Label, Get-LabelPolicy,
        Get-AutoSensitivityLabelPolicy, Get-AutoSensitivityLabelRule — and folds their
        output into one normalised inventory object (compl8.inventory/v1). One record list
        per object type; every record carries the ours/foreign discriminator so the Engine's
        assess pass can bucket it without re-reading the tenant. Read-only: no mutating cmdlet.

        Offline-first (D7): in CI every read cmdlet is mocked -ModuleName Compl8.Tenant.
        The single real network touch is an operator-run recording into actual/.

    .OUTPUTS
        A compl8.inventory/v1 object:

            schemaVersion : 'compl8.inventory/v1'
            prefix        : the naming prefix used for the ours-discriminator
            generatedUtc  : caller-supplied stamp (or $null — Get-Date is NOT called here)
            tenant        : Get-DeploymentTenantInfo header (name/id/guid/...), or $null
            objects       : an object with one array property per type, each a list of records:
                dictionaries      : { name, identity, ours }
                sitPackages       : { name, identity, ours, publisher, rulePackId,
                                      entityIds[], sha256, contentHash, sits[] }
                sits              : { name, identity, ours, package, contentHash }
                dlpRules          : { name, identity, ours, policy, priority, disabled,
                                      contentContainsSensitiveInformation }
                dlpPolicies       : { name, identity, ours, mode }
                labels            : { name, identity, ours, guid }
                labelPolicies     : { name, identity, ours, guid }
                autoLabelPolicies : { name, identity, ours, mode, label }
                autoLabelRules    : { name, identity, ours, policy, workload }

        ASSESS-CONSUMABLE SIT SHAPE (Stage 4 PHASE 4A; closes codex 4A P1). The deployed SIT
        rule packages returned by Get-DlpSensitiveInformationTypeRulePackage carry their
        entity definitions in a SerializedClassificationRuleCollection. The reader parses
        each package (Convert-DlpSerializedRulePackageToText then [xml]) and emits:
          * sitPackages[].entityIds  — sorted entity GUIDs in the deployed package.
          * sitPackages[].sits       — recovered per-entity slugs (the same back-compat list).
          * sitPackages[].sha256     — RAW hash of the serialized collection bytes. Informational
                                        ONLY: it is NOT comparable to a desired resolved .xml file
                                        hash because the service re-serializes the package
                                        (different encoding/whitespace). Never diff it across the
                                        desired/actual boundary.
          * sitPackages[].contentHash — a CANONICAL, comparable package digest derived from the
                                        package's entities via the SHARED Get-DlpEntityContentHash
                                        helper (see that function). Computable identically from a
                                        resolved desired package, so update-in-place / drift can be
                                        diffed without crossing the file/serialized boundary.
          * objects.sits[]           — one record PER ENTITY: { name (recovered slug), identity
                                        (entity GUID), ours, package (containing package name),
                                        contentHash (shared canonical entity hash) }. This is the
                                        list Invoke-Compl8Assess buckets for repack-move / drift /
                                        remove / orphan and joins by entity GUID for impact.
          * dlpRules[].contentContainsSensitiveInformation — the classifier-reference text assess
                                        feeds the reference graph (which live rules name each SIT
                                        GUID), used for per-classifier impact edges.

        Slug recovery: a deployed entity's slug is recovered from its first IdMatch/Match
        idRef (the resolve pipeline encodes ids as '<Kind>_<...>_<slug>', see
        ConvertTo-CustomSitFragment) — the trailing hyphenated token after the last '_'.
        When no idRef is present the slug falls back to the LocalizedStrings display name,
        then the entity GUID. This is the same join key the desired assignment slugs use.

        Every record has at minimum name, identity and ours (boolean). `ours` is true when
        the object name carries the '<Prefix>-' marker (D6: prefix is the primary signal,
        corroborated by the provenance stamp; here the prefix is authoritative). Microsoft /
        foreign objects have ours=$false and are NEVER touched by later layers.

    .PARAMETER Prefix
        Naming prefix (e.g. 'QGISCF') driving the ours-discriminator via Remove-DeploymentNamePrefix.
    .PARAMETER GeneratedUtc
        Optional stamp written verbatim to .generatedUtc. Supplied by the caller so the reader
        stays deterministic in tests (Get-Date is banned here).
    .PARAMETER OutFile
        Optional path. When set, the inventory is also written as JSON to this path.
    .PARAMETER IncludeTenantHeader
        When set, embeds the Get-DeploymentTenantInfo header under .tenant.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Prefix,

        [string]$GeneratedUtc,

        [string]$OutFile,

        [switch]$IncludeTenantHeader
    )

    # --- Discriminator: an object is 'ours' when its name starts with '<Prefix>-' (D6). ---
    # Remove-DeploymentNamePrefix strips the marker; if the name changed, it carried the prefix.
    function Test-Ours {
        param([string]$Name)
        if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
        return (Remove-DeploymentNamePrefix -Name $Name -Prefix $Prefix) -ne $Name
    }

    function Get-Prop {
        param($Object, [string[]]$Names)
        Get-DeploymentObjectProperty -InputObject $Object -Names $Names
    }

    # --- Read the six SCC families. Direct calls (no Get-Command guard) so each is mockable. ---
    $rawDictionaries = @(Get-DlpKeywordDictionary -ErrorAction Stop)
    $rawSitPackages  = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)
    $rawDlpRules     = @(Get-DlpComplianceRule -ErrorAction Stop)
    $rawDlpPolicies  = @(Get-DlpCompliancePolicy -ErrorAction Stop)
    $rawLabels       = @(Get-Label -ErrorAction Stop)
    $rawLabelPols    = @(Get-LabelPolicy -ErrorAction Stop)
    $rawAlPolicies   = @(Get-AutoSensitivityLabelPolicy -ErrorAction Stop)
    $rawAlRules      = @(Get-AutoSensitivityLabelRule -ErrorAction Stop)

    function ConvertTo-Record {
        param(
            $Object,
            [hashtable]$Extra = @{}
        )
        $name = Get-Prop -Object $Object -Names @('Name')
        $identity = Get-Prop -Object $Object -Names @('Identity', 'Name')
        if ([string]::IsNullOrWhiteSpace($name)) { $name = $identity }

        $record = [ordered]@{
            name     = if ($null -ne $name) { [string]$name } else { $null }
            identity = if ($null -ne $identity) { [string]$identity } else { $null }
            ours     = [bool](Test-Ours -Name $name)
        }
        foreach ($key in $Extra.Keys) { $record[$key] = $Extra[$key] }
        [pscustomobject]$record
    }

    $dictionaries = @($rawDictionaries | ForEach-Object { ConvertTo-Record -Object $_ })

    # Recover a deployed entity's slug from its first IdMatch/Match idRef (the resolve
    # pipeline encodes ids as '<Kind>_<...>_<slug>'; the slug is the trailing hyphenated
    # token after the last '_'). Falls back to the LocalizedStrings display name, then GUID.
    function Get-EntitySlug {
        param([System.Xml.XmlElement]$Entity, [hashtable]$NameByGuid, [string]$Guid)
        $idRef = $null
        foreach ($descendant in @($Entity.SelectNodes('.//*'))) {
            if (($descendant.LocalName -eq 'IdMatch' -or $descendant.LocalName -eq 'Match')) {
                $candidate = $descendant.GetAttribute('idRef')
                if (-not [string]::IsNullOrWhiteSpace($candidate) -and $candidate -notmatch '^\{\{.*\}\}$') {
                    $idRef = $candidate
                    break
                }
            }
        }
        if ($idRef -and $idRef.Contains('_')) {
            $slug = $idRef.Substring($idRef.LastIndexOf('_') + 1)
            if (-not [string]::IsNullOrWhiteSpace($slug)) { return $slug }
        }
        if ($Guid -and $NameByGuid.ContainsKey($Guid) -and -not [string]::IsNullOrWhiteSpace($NameByGuid[$Guid])) {
            return $NameByGuid[$Guid]
        }
        return $Guid
    }

    # Parse a deployed SIT rule package into its entities (GUID + recovered slug + canonical
    # content hash). Pure-ish: uses the shared Compl8.Model helpers; tolerates unparseable XML.
    function Get-PackageEntities {
        param($Package, [string]$PackageName, [bool]$Ours)
        # Read the serialized collection from the RAW property — NOT via Get-Prop, which
        # coerces to .ToString() and would destroy a byte[] (UTF-16 packages come back as
        # bytes). Convert-DlpSerializedRulePackageToText handles byte[]/BOM/encoding decode.
        $serialized = $null
        foreach ($propName in 'SerializedClassificationRuleCollection', 'RulePackXml') {
            $prop = $Package.PSObject.Properties[$propName]
            if ($prop -and $null -ne $prop.Value) { $serialized = $prop.Value; break }
        }
        $rawText = if ($null -ne $serialized) { Convert-DlpSerializedRulePackageToText -Raw $serialized } else { $null }
        # A decoded UTF-16/UTF-8-BOM package keeps a leading U+FEFF; [xml] rejects it. Strip it.
        if ($rawText -and $rawText.Length -gt 0 -and $rawText[0] -eq [char]0xFEFF) {
            $rawText = $rawText.Substring(1)
        }

        $entities = @()
        $sha256 = $null
        if (-not [string]::IsNullOrWhiteSpace($rawText)) {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$rawText))
                $sha256 = -join ($bytes | ForEach-Object { $_.ToString('x2') })
            } finally { $sha.Dispose() }
            try {
                [xml]$pkgXml = $rawText
                $rulesNode = $pkgXml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq 'Rules' } | Select-Object -First 1
                if ($rulesNode) {
                    # Map entity GUID -> LocalizedStrings display name (slug fallback).
                    $nameByGuid = @{}
                    $locStrings = $rulesNode.ChildNodes | Where-Object { $_.LocalName -eq 'LocalizedStrings' } | Select-Object -First 1
                    if ($locStrings) {
                        foreach ($resource in @($locStrings.ChildNodes | Where-Object { $_.LocalName -eq 'Resource' })) {
                            $idRef = $resource.GetAttribute('idRef')
                            $nameNode = $resource.ChildNodes | Where-Object { $_.LocalName -eq 'Name' } | Select-Object -First 1
                            if ($idRef -and $nameNode) { $nameByGuid[$idRef] = [string]$nameNode.InnerText }
                        }
                    }
                    foreach ($entity in @($rulesNode.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -eq 'Entity' })) {
                        $guid = $entity.GetAttribute('id')
                        if ([string]::IsNullOrWhiteSpace($guid)) { continue }
                        $guid = $guid.ToLowerInvariant()
                        $slug = Get-EntitySlug -Entity $entity -NameByGuid $nameByGuid -Guid $guid
                        $entities += [pscustomobject]@{
                            Guid        = $guid
                            Slug        = $slug
                            # codex 4A P2-A: hash the entity PLUS the transitive idRef closure of its
                            # sibling <Regex>/<Keyword>/<Filter>/<Validator> support elements, resolved
                            # within THIS package's <Rules> pool. Computed identically on the desired
                            # side so editing a deployed regex body (entity node unchanged) drifts.
                            ContentHash = Get-DlpEntityClosureContentHash -Entity $entity -RulesNode $rulesNode
                        }
                    }
                }
            } catch { }
        }
        [pscustomobject]@{ Entities = @($entities); Sha256 = $sha256 }
    }

    # Build the assess-consumable SIT shape: one objects.sits[] record per deployed entity,
    # plus per-package entityIds + comparable contentHash. (codex 4A P1)
    $sitRecords = [System.Collections.Generic.List[object]]::new()
    $sitPackages = @($rawSitPackages | ForEach-Object {
        $pkgName = [string](Get-Prop -Object $_ -Names @('Name'))
        if ([string]::IsNullOrWhiteSpace($pkgName)) { $pkgName = [string](Get-Prop -Object $_ -Names @('Identity')) }
        $pkgOurs = [bool](Test-Ours -Name $pkgName)
        $parsed  = Get-PackageEntities -Package $_ -PackageName $pkgName -Ours $pkgOurs

        $entityIds = @(@($parsed.Entities) | ForEach-Object { $_.Guid } | Sort-Object)
        $sitSlugs  = @(@($parsed.Entities) | ForEach-Object { $_.Slug } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        foreach ($entity in @($parsed.Entities)) {
            $sitRecords.Add([pscustomobject][ordered]@{
                name        = [string]$entity.Slug
                identity    = [string]$entity.Guid
                ours        = $pkgOurs
                package     = $pkgName
                contentHash = [string]$entity.ContentHash
            }) | Out-Null
        }
        # Canonical, comparable package digest: the shared canonical hash over the package's
        # sorted '<guid>=<entityContentHash>' projection. Derived from entities, so it is
        # comparable to a resolved desired package computed the same way (NOT a raw-byte sha).
        #
        # codex 4A P2-B: when the package could NOT be parsed (missing/garbage serialized XML)
        # there are zero comparable entities. Emitting a hash of an empty <pkg/> projection would
        # be a valid-looking digest that assess would diff against a real desired package and
        # falsely bucket update-in-place. Emit $null (omit) instead so assess treats it as
        # "cannot compare" and leaves it out of update-in-place on hash grounds.
        $pkgContentHash = $null
        if (@($parsed.Entities).Count -gt 0) {
            $pkgProjection = (@($parsed.Entities) | Sort-Object Guid | ForEach-Object { "$($_.Guid)=$($_.ContentHash)" }) -join "`n"
            $pkgContentHash = Get-DlpEntityContentHash -EntityXml "<pkg>$([System.Security.SecurityElement]::Escape($pkgProjection))</pkg>"
        }

        ConvertTo-Record -Object $_ -Extra @{
            publisher   = [string](Get-Prop -Object $_ -Names @('Publisher'))
            rulePackId  = [string](Get-Prop -Object $_ -Names @('RulePackId', 'Id'))
            entityIds   = $entityIds
            sits        = $sitSlugs
            sha256      = if ($parsed.Sha256) { $parsed.Sha256 } else { $null }
            contentHash = $pkgContentHash
        }
    })
    $sits = @($sitRecords)

    # Capture the DLP rule classifier-reference text (which SIT GUIDs each rule names) so
    # assess can build per-classifier impact edges WITHOUT re-reading the tenant. We emit the
    # raw ContentContainsSensitiveInformation value (compact JSON when it is an object) and,
    # when richer reference surfaces exist (AdvancedRule, ExceptIf..., Conditions), fold in the
    # shared Get-DlpRuleClassifierReferenceText flattening so no GUID reference is lost.
    function Get-RuleClassifierField {
        param($Rule)
        # codex 4A P2-C: a SIT GUID can be referenced from ANY of the classifier-reference
        # surfaces — ContentContainsSensitiveInformation, ExceptIfContentContainsSensitiveInformation,
        # AdvancedRule, Conditions, Exceptions. The old code early-returned on the primary field
        # and dropped GUIDs that appear ONLY in the others, so assess's impact missed live rules.
        # Always fold in the shared flatten helper, which already joins all five surfaces, so the
        # emitted reference text is the UNION across every surface. The compact-JSON of the primary
        # field is retained first for shape back-compat, then the flattened union is appended.
        $parts = New-Object System.Collections.Generic.List[string]
        $primary = $Rule.PSObject.Properties['ContentContainsSensitiveInformation']
        if ($primary -and $null -ne $primary.Value) {
            try { $parts.Add(($primary.Value | ConvertTo-Json -Depth 20 -Compress)) | Out-Null }
            catch { $parts.Add([string]$primary.Value) | Out-Null }
        }
        $flattened = Get-DlpRuleClassifierReferenceText -Rule $Rule
        if (-not [string]::IsNullOrWhiteSpace($flattened)) { $parts.Add($flattened) | Out-Null }
        return ($parts -join "`n")
    }

    $dlpRules = @($rawDlpRules | ForEach-Object {
        ConvertTo-Record -Object $_ -Extra @{
            policy   = [string](Get-Prop -Object $_ -Names @('Policy', 'ParentPolicyName'))
            priority = Get-Prop -Object $_ -Names @('Priority')
            disabled = [bool](Get-Prop -Object $_ -Names @('Disabled'))
            contentContainsSensitiveInformation = Get-RuleClassifierField -Rule $_
        }
    })

    $dlpPolicies = @($rawDlpPolicies | ForEach-Object {
        ConvertTo-Record -Object $_ -Extra @{
            mode = [string](Get-Prop -Object $_ -Names @('Mode'))
        }
    })

    $labels = @($rawLabels | ForEach-Object {
        ConvertTo-Record -Object $_ -Extra @{
            guid = [string](Get-Prop -Object $_ -Names @('Guid', 'ImmutableId'))
        }
    })

    $labelPolicies = @($rawLabelPols | ForEach-Object {
        ConvertTo-Record -Object $_ -Extra @{
            guid = [string](Get-Prop -Object $_ -Names @('Guid', 'ImmutableId'))
        }
    })

    $autoLabelPolicies = @($rawAlPolicies | ForEach-Object {
        ConvertTo-Record -Object $_ -Extra @{
            mode  = [string](Get-Prop -Object $_ -Names @('Mode'))
            label = [string](Get-Prop -Object $_ -Names @('ApplySensitivityLabel'))
        }
    })

    $autoLabelRules = @($rawAlRules | ForEach-Object {
        ConvertTo-Record -Object $_ -Extra @{
            policy   = [string](Get-Prop -Object $_ -Names @('Policy', 'ParentPolicyName'))
            workload = [string](Get-Prop -Object $_ -Names @('Workload'))
        }
    })

    $tenantHeader = $null
    if ($IncludeTenantHeader) {
        try { $tenantHeader = Get-DeploymentTenantInfo } catch { $tenantHeader = $null }
    }

    $inventory = [pscustomobject][ordered]@{
        schemaVersion = 'compl8.inventory/v1'
        prefix        = $Prefix
        generatedUtc  = if ($GeneratedUtc) { $GeneratedUtc } else { $null }
        tenant        = $tenantHeader
        objects       = [pscustomobject][ordered]@{
            dictionaries      = $dictionaries
            sitPackages       = $sitPackages
            sits              = $sits
            dlpRules          = $dlpRules
            dlpPolicies       = $dlpPolicies
            labels            = $labels
            labelPolicies     = $labelPolicies
            autoLabelPolicies = $autoLabelPolicies
            autoLabelRules    = $autoLabelRules
        }
    }

    if ($OutFile) {
        $dir = Split-Path -Parent $OutFile
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $inventory | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $OutFile -Encoding UTF8
    }

    return $inventory
}
