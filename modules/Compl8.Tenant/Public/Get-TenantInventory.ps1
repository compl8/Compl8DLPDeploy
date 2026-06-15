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
                dlpRules          : { name, identity, ours, policy, priority, disabled, comment,
                                      contentContainsSensitiveInformation, contentCondition,
                                      advancedRule, accessScope, generateIncidentReport,
                                      notifyUser, reportSeverity, contentHash }
                dlpPolicies       : { name, identity, ours, mode, locations, comment }
                labels            : { name, identity, ours, guid }
                labelPolicies     : { name, identity, ours, guid }
                autoLabelPolicies : { name, identity, ours, mode, label, locations, comment }
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

        ASSESS-CONSUMABLE DLP RULE/POLICY CONTENT (DR-3; the DLP-rule drift feed). The reader also
        carries enough of each rule's READBACK content that assess can hash it via
        Get-DlpRuleContentHash -ActualRule and compare it to the DESIRED rule's content hash
        (Resolve-DesiredDlpRules / Get-DlpRuleContentHash -DesiredParams). The split mirrors how
        sitPackages carry contentHash — the reader computes a contentHash here so assess never has
        to re-project the rule, but ALSO carries the structured content so the hash is re-derivable:
          * dlpRules[].contentCondition       — the STRUCTURED ContentContainsSensitiveInformation
                                        readback value (the nested Groups/Sensitivetypes object the
                                        service returns: PascalCased keys, numeric Minconfidence),
                                        NOT the flattened reference text above. This is the value
                                        the canonical hash re-projects (sorted SIT id/min/max/conf).
          * dlpRules[].advancedRule           — the AdvancedRule JSON string (or null).
          * dlpRules[].accessScope            — AccessScope (or the readback scope value; or null).
          * dlpRules[].generateIncidentReport — GenerateIncidentReport recipient/flag (or null).
          * dlpRules[].notifyUser             — NotifyUser (or null).
          * dlpRules[].reportSeverity         — ReportSeverityLevel (or null).
          * dlpRules[].contentHash            — Get-DlpRuleContentHash -ActualRule over the rule's
                                        readback content (the SAME 'sha256:' convention the desired
                                        side emits). Assess buckets a rule as 'drift' when this
                                        diverges from the desired rule's contentHash. The flat
                                        contentContainsSensitiveInformation field is UNCHANGED so
                                        the impact reference graph keeps working as before.
          * dlpPolicies[].mode / .locations / .comment — the policy content assess compares for
                                        policy create/drift/orphan/foreign (mode + locations + comment).
          * autoLabelPolicies[].mode / .label / .locations / .comment — the auto-label policy content
                                        assess compares for autoLabelPolicy create/drift/orphan/foreign
                                        (mode + applied label + locations; the comment is provenance
                                        metadata, carried for the ownership stamp but NOT hashed).

        Slug recovery: a deployed entity's slug is recovered from its first IdMatch/Match
        idRef (the resolve pipeline encodes ids as '<Kind>_<...>_<slug>', see
        ConvertTo-CustomSitFragment) — the trailing hyphenated token after the last '_'.
        When no idRef is present the slug falls back to the LocalizedStrings display name,
        then the entity GUID. This is the same join key the desired assignment slugs use.

        Every record has at minimum name, identity and ours (boolean). The OWNERSHIP DISCRIMINATOR
        differs by object family:

          * dictionaries / sitPackages / sits / labels / labelPolicies / autoLabelRules — `ours` is
            true when the object NAME carries the '<Prefix>-' START marker (D6: prefix is authoritative;
            these names are generated to begin with the prefix). Driven by Remove-DeploymentNamePrefix.

          * dlpRules / dlpPolicies / autoLabelPolicies — their names DO NOT start with '<Prefix>-'
            (templates: dlpPolicy 'P{n}-{code}-{prefix}-{suffix}' and autoLabelPolicy
            'AL{n}-{labelCode}-{prefix}-{suffix}' both carry the prefix in the MIDDLE;
            dlpRule 'P{n}-R{n}{chunk}-{code}-{labelCode}-{suffix}' has NO prefix), so the prefix-START
            check would mark every deployed Compl8 rule/policy foreign. Ownership is instead the
            PREFIX-SCOPED DEPLOYMENT PROVENANCE STAMP that Deploy-DLPRules writes into each
            rule's/policy's Comment (the '[[Compl8:...]]' marker carried on the record as .comment).
            PRIMARY: Get-DeploymentProvenanceStamp parses the Comment; when it returns a RESOLVED stamp
            (long form is self-contained; short form is resolved from the local provenance registry)
            the object is ours ONLY when the stamp's prefix EQUALS this inventory's prefix — a stamp
            from a DIFFERENT prefix is another deployment's object and is foreign (a tenant may hold
            objects from a different Compl8 deployment, which must never be claimed). A short marker
            that this machine's registry cannot resolve (prefix unknowable) is NOT claimed on the
            marker; it falls through to the FALLBACK. FALLBACK (stamp-less / unresolved): the name
            matches the generated template shape — a P-numbered rule/policy ('^P\d+-' with an optional
            '-R\d+' rule segment) that carries the prefix as a name token ('-<Prefix>-' or trailing
            '-<Prefix>'). Because rule names carry NO prefix token, a stamp-less/unresolved RULE stays
            ours=$false (a deliberately CONSERVATIVE under-claim: foreign is never touched, whereas
            over-claiming another deployment's object is the hazard removed here). See Test-OursDlp.

        Microsoft / foreign objects have ours=$false and are NEVER touched by later layers.

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
    # CORRECT for SITs / packages / dictionaries / labels — those names START with the prefix.
    function Test-Ours {
        param([string]$Name)
        if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
        return (Remove-DeploymentNamePrefix -Name $Name -Prefix $Prefix) -ne $Name
    }

    # --- DLP rule/policy discriminator (codex review P1): the prefix-START check above is WRONG
    # for DLP rules and policies, whose NAMES DO NOT start with '<Prefix>-' (the templates are
    # dlpPolicy = 'P{n}-{code}-{prefix}-{suffix}' with the prefix in the MIDDLE, and
    # dlpRule = 'P{n}-R{n}{chunk}-{code}-{labelCode}-{suffix}' with the prefix ABSENT). Using
    # Test-Ours there marks every deployed Compl8 rule/policy ours=$false, so assess buckets it
    # 'foreign' and skips ALL drift/create/orphan handling. Ownership here is instead driven by
    # the DEPLOYMENT PROVENANCE STAMP that Deploy-DLPRules.ps1 writes into each rule's/policy's
    # Comment via Add-DeploymentProvenanceStamp. Get-TenantInventory carries that Comment (DR-3).
    #
    # OWNERSHIP MUST BE PREFIX-SCOPED (codex review SAFETY P1). A tenant can legitimately hold
    # objects from a DIFFERENT Compl8 deployment (a different prefix / customer). A bare 'this
    # Comment carries ANY Compl8 marker => ours' rule would CLAIM another deployment's objects as
    # ours, and assess/apply could then bucket them drift/orphan and target objects that belong to a
    # different deployment. The stamp's PREFIX must therefore match THIS inventory's $Prefix.
    #
    #   PRIMARY  : Get-DeploymentProvenanceStamp -Text $Comment.
    #              * $null            => no marker; fall through to the FALLBACK.
    #              * Found+Resolved+Prefix => the stamp's full fields are known (long form is
    #                self-contained; short form was resolved from the local provenance registry):
    #                  - ours=$true  ONLY when $stamp.Prefix equals $Prefix (OrdinalIgnoreCase).
    #                  - DIFFERENT prefix => return $false DEFINITIVELY (it is another deployment's
    #                    object; do NOT fall through to the name fallback — the name could otherwise
    #                    coincidentally match the template shape and re-claim it).
    #              * Found but NOT Resolved (a short marker absent from THIS machine's registry => the
    #                prefix is UNKNOWABLE) => do NOT claim on the bare marker; fall through to the
    #                FALLBACK. (We never claim a marker whose prefix we cannot verify.)
    #   FALLBACK : prefix-scoped already — the name must be a P-numbered (DLP) or AL-numbered
    #              (auto-label) rule/policy ('^(P|AL)\d+-' optionally with an '-R\d+' rule segment) AND
    #              carry the prefix as a name token ('-<Prefix>-' or trailing '-<Prefix>'), which is how
    #              the dlpPolicy ('P{n}-{code}-{prefix}-{suffix}') and autoLabelPolicy
    #              ('AL{n}-{labelCode}-{prefix}-{suffix}') templates embed the prefix. This confirms our
    #              own policies (whose names embed the prefix); auto-label RULE names embed it too.
    #
    # CONSERVATIVE RULE TRADE-OFF: a dlpRule NAME carries NO prefix token, so a stamp-less or
    # unresolved-short-marker RULE cannot be confirmed by the fallback and stays ours=$false. This is
    # deliberate and SAFE: under-detecting OUR OWN rule only means assess leaves it alone (foreign is
    # never touched), whereas OVER-claiming ANOTHER deployment's rule is the hazard this fix removes.
    # The mitigation for our own rules is to deploy a self-contained long-form (or registry-resolved)
    # prefix-bearing stamp, which the PRIMARY path confirms regardless of the name.
    function Test-OursDlp {
        param([string]$Name, [string]$Comment)
        # PRIMARY: prefix-scoped provenance stamp on the carried Comment.
        if (-not [string]::IsNullOrWhiteSpace($Comment)) {
            $stamp = Get-DeploymentProvenanceStamp -Text $Comment
            if ($null -ne $stamp -and $stamp.Found -and $stamp.Resolved -and $stamp.Prefix) {
                # Resolved stamp: ownership is decided here and we do NOT fall through either way.
                return [string]::Equals([string]$stamp.Prefix, [string]$Prefix, [System.StringComparison]::OrdinalIgnoreCase)
            }
            # Found-but-unresolved (prefix unknowable) or no marker => fall through to the FALLBACK.
        }
        # FALLBACK: match the generated P-numbered (DLP) or AL-numbered (auto-label) template shape
        # carrying the prefix (prefix-scoped).
        if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
        $isNumberedTemplate = $Name -match '^(P|AL)\d+(-R\d+[A-Za-z]?)?-'
        if (-not $isNumberedTemplate) { return $false }
        if ([string]::IsNullOrWhiteSpace($Prefix)) { return $false }
        $escapedPrefix = [regex]::Escape($Prefix)
        return ($Name -match "-$escapedPrefix(-|$)")
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

    # DR-3: read a rule's readback property by ANY of its candidate names (PascalCase from the
    # service; tolerant of the build-side casing too). Returns $null when absent/empty.
    function Get-RuleContentProp {
        param($Rule, [string[]]$Names)
        $v = Get-Prop -Object $Rule -Names $Names
        if ($null -eq $v) { return $null }
        if (($v -is [string]) -and [string]::IsNullOrWhiteSpace($v)) { return $null }
        return $v
    }

    # DR-3: project a readback rule into the canonical actual-rule shape Get-DlpRuleContentHash
    # -ActualRule reads (PascalCase property names), then compute its content hash. The STRUCTURED
    # ContentContainsSensitiveInformation value is carried verbatim — the hash canonicalises the
    # service's re-serialisation (PascalCase keys, numeric Minconfidence, nested groups) so it
    # compares EQUAL to the desired build hash for the same rule.
    function Get-RuleActualContentHash {
        param($Rule, $ContentCondition, $AdvancedRule, $AccessScope, $GenerateIncidentReport, $NotifyUser, $ReportSeverity, [bool]$Disabled)
        $projection = [pscustomobject][ordered]@{
            ContentContainsSensitiveInformation = $ContentCondition
            AdvancedRule                        = $AdvancedRule
            AccessScope                         = $AccessScope
            GenerateIncidentReport              = $GenerateIncidentReport
            NotifyUser                          = $NotifyUser
            ReportSeverityLevel                 = $ReportSeverity
            Disabled                            = $Disabled
        }
        return (Get-DlpRuleContentHash -ActualRule $projection)
    }

    $dlpRules = @($rawDlpRules | ForEach-Object {
        # Read the STRUCTURED readback content directly (NOT via Get-Prop's .ToString() coercion,
        # which would flatten the nested CCSI object). The flat reference text the impact graph
        # consumes is computed separately by Get-RuleClassifierField and kept under the existing
        # contentContainsSensitiveInformation field (back-compat, unchanged).
        $ccsiProp = $_.PSObject.Properties['ContentContainsSensitiveInformation']
        $contentCondition = if ($ccsiProp -and $null -ne $ccsiProp.Value) { $ccsiProp.Value } else { $null }
        $advancedRule           = Get-RuleContentProp -Rule $_ -Names @('AdvancedRule')
        $accessScope            = Get-RuleContentProp -Rule $_ -Names @('AccessScope')
        $generateIncidentReport = Get-RuleContentProp -Rule $_ -Names @('GenerateIncidentReport')
        $notifyUser             = Get-RuleContentProp -Rule $_ -Names @('NotifyUser')
        $reportSeverity         = Get-RuleContentProp -Rule $_ -Names @('ReportSeverityLevel')
        # Read Disabled as a REAL bool from the raw property — NOT via Get-Prop, which coerces to a
        # string ('False'), and [bool]'False' is $true. Mis-reading Disabled would corrupt the
        # canonical content hash (Disabled is part of the rule's semantic content).
        $disabledProp = $_.PSObject.Properties['Disabled']
        $disabled     = if ($disabledProp -and $null -ne $disabledProp.Value) {
            if ($disabledProp.Value -is [bool]) { $disabledProp.Value }
            else { [string]::Equals([string]$disabledProp.Value, 'true', [System.StringComparison]::OrdinalIgnoreCase) }
        } else { $false }

        $contentHash = Get-RuleActualContentHash -Rule $_ `
            -ContentCondition $contentCondition -AdvancedRule $advancedRule -AccessScope $accessScope `
            -GenerateIncidentReport $generateIncidentReport -NotifyUser $notifyUser `
            -ReportSeverity $reportSeverity -Disabled $disabled

        # codex review P1: a DLP rule's name never starts with '<Prefix>-', so ownership is the
        # provenance stamp on its Comment (with the template-shape fallback) — NOT the prefix-START
        # check ConvertTo-Record applies. Compute it here and OVERRIDE the record's 'ours'.
        $ruleName    = [string](Get-Prop -Object $_ -Names @('Name'))
        $ruleComment = [string](Get-Prop -Object $_ -Names @('Comment'))
        $record = ConvertTo-Record -Object $_ -Extra @{
            policy   = [string](Get-Prop -Object $_ -Names @('Policy', 'ParentPolicyName'))
            priority = Get-Prop -Object $_ -Names @('Priority')
            disabled = $disabled
            comment  = $ruleComment
            contentContainsSensitiveInformation = Get-RuleClassifierField -Rule $_
            contentCondition       = $contentCondition
            advancedRule           = if ($null -ne $advancedRule) { [string]$advancedRule } else { $null }
            accessScope            = if ($null -ne $accessScope) { [string]$accessScope } else { $null }
            generateIncidentReport = if ($null -ne $generateIncidentReport) { [string]$generateIncidentReport } else { $null }
            notifyUser             = if ($null -ne $notifyUser) { [string]$notifyUser } else { $null }
            reportSeverity         = if ($null -ne $reportSeverity) { [string]$reportSeverity } else { $null }
            contentHash            = $contentHash
        }
        $record.ours = [bool](Test-OursDlp -Name $ruleName -Comment $ruleComment)
        $record
    })

    # DR-3: dlpPolicies carry mode + the structured locations object + comment so assess can
    # compare policy content (mode/locations) for policy create/drift/orphan/foreign.
    $dlpPolicies = @($rawDlpPolicies | ForEach-Object {
        $locations = [ordered]@{}
        foreach ($locName in @('ExchangeLocation', 'OneDriveLocation', 'SharePointLocation', 'EndpointDlpLocation', 'TeamsLocation')) {
            $locProp = $_.PSObject.Properties[$locName]
            if ($locProp -and $null -ne $locProp.Value) {
                $locVal = @($locProp.Value | ForEach-Object { [string]$_ }) | Sort-Object
                if (@($locVal).Count -gt 0) { $locations[$locName] = @($locVal) }
            }
        }
        # codex review P1: a DLP policy's name carries the prefix in the MIDDLE (not at the start),
        # so ownership is the provenance stamp on its Comment (with the template-shape fallback) —
        # NOT the prefix-START check ConvertTo-Record applies. Override the record's 'ours'.
        $policyName    = [string](Get-Prop -Object $_ -Names @('Name'))
        $policyComment = [string](Get-Prop -Object $_ -Names @('Comment'))
        $record = ConvertTo-Record -Object $_ -Extra @{
            mode      = [string](Get-Prop -Object $_ -Names @('Mode'))
            locations = [pscustomobject]$locations
            comment   = $policyComment
        }
        $record.ours = [bool](Test-OursDlp -Name $policyName -Comment $policyComment)
        $record
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

    # Auto-label drift: autoLabelPolicies carry mode + applied label + the structured locations object
    # + comment so assess can compare auto-label policy content (mode + label + locations) for
    # autoLabelPolicy create/drift/orphan/foreign. Ownership is the provenance stamp on the Comment
    # (with the AL-numbered template-shape fallback) — NOT the prefix-START check ConvertTo-Record
    # applies, because an auto-label policy name carries the prefix in the MIDDLE
    # ('AL{n}-{labelCode}-{prefix}-{suffix}'), exactly like a dlpPolicy. Override the record's 'ours'.
    $autoLabelPolicies = @($rawAlPolicies | ForEach-Object {
        $locations = [ordered]@{}
        foreach ($locName in @('ExchangeLocation', 'OneDriveLocation', 'SharePointLocation', 'EndpointDlpLocation', 'TeamsLocation')) {
            $locProp = $_.PSObject.Properties[$locName]
            if ($locProp -and $null -ne $locProp.Value) {
                $locVal = @($locProp.Value | ForEach-Object { [string]$_ }) | Sort-Object
                if (@($locVal).Count -gt 0) { $locations[$locName] = @($locVal) }
            }
        }
        $alPolicyName    = [string](Get-Prop -Object $_ -Names @('Name'))
        $alPolicyComment = [string](Get-Prop -Object $_ -Names @('Comment'))
        $record = ConvertTo-Record -Object $_ -Extra @{
            mode      = [string](Get-Prop -Object $_ -Names @('Mode'))
            label     = [string](Get-Prop -Object $_ -Names @('ApplySensitivityLabel'))
            locations = [pscustomobject]$locations
            comment   = $alPolicyComment
        }
        $record.ours = [bool](Test-OursDlp -Name $alPolicyName -Comment $alPolicyComment)
        $record
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
