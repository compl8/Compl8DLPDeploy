function Invoke-Compl8Assess {
    <#
    .SYNOPSIS
        Read-only diff of the DESIRED state (a Stage-3 desired/resolved) against the ACTUAL
        tenant state (an inventory.json), bucketed over the reference graph.

    .DESCRIPTION
        The first verb of the Engine lifecycle (arch design §5; PHASE 4A). Assess is the
        FIRST consumer of Get-DeploymentReferenceGraph (Compl8.Model, D6). It produces a
        compl8.assessment/v1 object (built by Model's New-AssessmentObject and validated by
        Test-AssessmentSchema) that assigns every tenant object to EXACTLY ONE of seven
        buckets, plus per-object impact (which live DLP rules reference each changed
        classifier) and the upgrade conflicts carried from the resolve manifest.

        Read-only contract (D3/D7): assess calls NO mutating SCC cmdlet. The only tenant
        read is the inventory, which is supplied as a file path or object (recorded once by
        an operator into actual/), never fetched live here. In CI the inventory is a fixture.

        THE SEVEN BUCKETS (each object lands in exactly one — enforced by Test-AssessmentSchema):
          create          — desired, not present in actual.
          update-in-place — present in both, ours, same identity, content differs (a refit:
                            the rule package sha256 / sit content changed but the object and
                            its entity GUIDs are retained).
          repack-move     — a sit/slug whose package assignment changed between actual and
                            desired (the entity is re-homed into a different rule package).
          remove          — a DESIRED removal: an actual ours object that the desired pipeline
                            DELIBERATELY retired. The discriminator is the entity ledger — a
                            slug recorded in state 'disabled' is a planned, tracked retirement.
          orphan          — ours but UNEXPECTED: an actual ours object the desired pipeline has
                            no record of at all (no resolve assignment, no ledger entry). Assess
                            flags it for human review rather than auto-removing it.
          foreign         — actual, NOT ours (no '<prefix>-' marker, no provenance stamp). Per
                            spec §8 opacity-as-safety, foreign objects are NEVER touched and are
                            asserted never to appear in any actionable bucket.
          drift           — actual, ours, still desired and in the same package, but its content
                            changed OUT-OF-BAND relative to desired/resolved (someone edited the
                            tenant object directly).

        ORPHAN vs REMOVE (the rule this function picks; spec leaves the precise line to
        judgement): both are 'ours, no longer desired', but `remove` is an INTENTIONAL,
        ledger-recorded retirement (slug present in the entity-ledger with state='disabled' —
        the desired pipeline meant to drop it) whereas `orphan` is an UNEXPECTED leftover (ours
        but with no ledger trace and no desired assignment — we cannot account for why it is in
        the tenant). remove = "we meant to retire this"; orphan = "ours but we don't know why
        it's here, do not auto-act". This keeps a destructive auto-action (remove) gated to
        objects the pipeline owns end-to-end, and routes everything else to human review.

        DIFF UNITS. Assess diffs at the object granularity the desired/resolved pipeline
        produces and the inventory records: rule packages (by name), sits (by slug/name with
        entity GUID for graph impact), and dictionaries (by name). The desired side comes from
        the committed resolve-manifest (packages[], packing.assignments) plus the package XML
        entities and the dictionary placeholders the desired sits reference; the actual side
        comes from the inventory's sitPackages / sits / dictionaries record lists. Objects that
        are in-sync (present, ours, unchanged, same assignment) land in NO bucket — the seven
        buckets are the actionable delta, not a full census.

    .PARAMETER WorkspacePath
        Workspace root. Assess reads <WorkspacePath>/desired/resolved/resolve-manifest.json
        (the desired side) and <WorkspacePath>/entity-ledger.json (the remove/orphan
        discriminator). It re-runs NOTHING — the resolve is a committed input.

    .PARAMETER InventoryPath
        Path to a compl8.inventory/v1 actual/inventory.json (the Task-2 reader's shape, with
        the assess-fixture sit-aware extensions: sitPackages carry sha256+sits, a sits[] list
        records each entity's current package+contentHash, dlpRules carry the classifier
        reference text used for impact). Supplied, never fetched live.

    .PARAMETER Inventory
        An already-parsed inventory object (alternative to -InventoryPath; used by callers that
        injected the inventory). Exactly one of -InventoryPath / -Inventory is required.

    .PARAMETER Workspace
        Logical workspace name written to the assessment (e.g. 'nonprod').

    .PARAMETER GeneratedUtc
        Stamp written verbatim to .generatedUtc (Get-Date is NOT called — determinism).

    .PARAMETER OutFile
        Optional. When set, the assessment is also written as JSON to this path.

    .PARAMETER ConfigRoot
        Optional. The config source for the DESIRED DLP rule/policy set (DR-4) — now the FALLBACK
        after the Stage-5 re-point (D7). DESIRED-RULE SOURCE ORDER:
          1. <WorkspacePath>/desired/resolved/dlp-rules.json — the persisted desired rule set written
             by Resolve-DesiredContent (the re-point; makes the workspace self-contained). When this
             file is present assess reads it verbatim and does NOT re-resolve any config.
          2. else -ConfigRoot (if supplied) -> Resolve-DesiredDlpRules -ConfigPath <ConfigRoot>.
          3. else the workspace config dir (<WorkspacePath>/desired/config, then <WorkspacePath>/config).
        If NONE of these yield a desired set, assess emits NO dlpRule/dlpPolicy buckets — so SIT-only
        fixtures/workspaces that carry no rule config are unaffected, and the existing DR-4 fixtures
        (which pass -ConfigRoot but write no dlp-rules.json) keep working via the config-bridge fallback.
        The bucketing logic (create/drift/orphan/foreign) is UNCHANGED — only the desired SOURCE moved.

        ConfigRoot (and the workspace config-dir fallback) ALSO drives the DESIRED auto-label policy
        set via Resolve-DesiredAutoLabel, so assess buckets autoLabelPolicy create/drift/orphan/foreign
        the same way it does dlpRule/dlpPolicy. Auto-label has no persisted desired/resolved projection
        yet (the dlp-rules.json re-point is DLP-only), so it is always sourced from config here; a
        config that does not define the autoLabelPolicy name template yields no auto-label buckets.

    .OUTPUTS
        A compl8.assessment/v1 object (see New-AssessmentObject / Test-AssessmentSchema).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WorkspacePath,

        [string]$InventoryPath,

        [pscustomobject]$Inventory,

        [Parameter(Mandatory)]
        [string]$Workspace,

        [string]$GeneratedUtc,

        [string]$OutFile,

        [string]$ConfigRoot
    )

    # Deterministic SHA-256 over UTF-8 text, lowercase hex (no Get-FileHash temp files).
    function Get-AssessTextHash {
        param([string]$Text)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$Text))
            -join ($bytes | ForEach-Object { $_.ToString('x2') })
        } finally { $sha.Dispose() }
    }

    # ------------------------------------------------------------------ inputs (read-only)
    $resolvedDir  = Join-Path $WorkspacePath 'desired' 'resolved'
    $manifestPath = Join-Path $resolvedDir 'resolve-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Assess: no desired/resolved manifest at '$manifestPath' — resolve the workspace first."
    }
    $manifestRaw = Get-Content -LiteralPath $manifestPath -Raw
    $manifest    = $manifestRaw | ConvertFrom-Json

    if ($PSBoundParameters.ContainsKey('Inventory') -and $Inventory) {
        $inv = $Inventory
        $inventoryRaw = ($inv | ConvertTo-Json -Depth 12)
    } elseif ($InventoryPath) {
        if (-not (Test-Path -LiteralPath $InventoryPath -PathType Leaf)) {
            throw "Assess: inventory file not found at '$InventoryPath'."
        }
        $inventoryRaw = Get-Content -LiteralPath $InventoryPath -Raw
        $inv = $inventoryRaw | ConvertFrom-Json
    } else {
        throw "Assess: supply -InventoryPath or -Inventory (the actual tenant state)."
    }

    # Entity ledger — the remove/orphan discriminator. Slugs recorded 'disabled' are planned
    # retirements (=> remove); everything else absent from desired with no ledger trace is orphan.
    $ledgerPath = Join-Path $WorkspacePath 'entity-ledger.json'
    $disabledSlugs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ledgerSlugs   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path -LiteralPath $ledgerPath -PathType Leaf) {
        $ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
        foreach ($entry in @($ledger.entries)) {
            if ($entry.slug) {
                $ledgerSlugs.Add([string]$entry.slug) | Out-Null
                if ($entry.state -eq 'disabled') { $disabledSlugs.Add([string]$entry.slug) | Out-Null }
            }
        }
    }

    # ----------------------------------------------------------------- input hashes
    $resolveManifestHash = 'sha256:' + (Get-AssessTextHash -Text $manifestRaw)
    $inventoryHash       = 'sha256:' + (Get-AssessTextHash -Text $inventoryRaw)

    # ----------------------------------------------------------------- desired side
    # Desired rule packages (by name) and their content sha256.
    $desiredPackages = @{}
    foreach ($pkg in @($manifest.packages)) {
        if ($pkg.name) { $desiredPackages[[string]$pkg.name] = $pkg }
    }
    # Desired slug -> package assignment.
    $desiredAssignment = @{}
    if ($manifest.packing -and $manifest.packing.assignments) {
        foreach ($prop in $manifest.packing.assignments.PSObject.Properties) {
            $desiredAssignment[[string]$prop.Name] = [string]$prop.Value
        }
    }
    # Desired sit slugs = the assigned slugs (the sits the resolve composed into packages).
    $desiredSits = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($slug in $desiredAssignment.Keys) { $desiredSits.Add($slug) | Out-Null }

    # Desired dictionaries = the placeholders the desired packages reference, AND the desired
    # per-sit content hash keyed by entity GUID — the latter is the drift baseline (an actual
    # sit whose recorded contentHash diverges from this changed out-of-band).
    #
    # COMPARABILITY (closes codex 4A P1): the desired hash is computed via the SHARED canonical
    # helper Get-DlpEntityContentHash — the SAME convention Get-TenantInventory uses when it
    # reads the deployed package back. Both sides therefore canonicalize the entity XML
    # (encoding/whitespace/empty-element-form-agnostic) before hashing, so a semantically
    # identical entity hashes EQUAL on both sides and only a real content edit registers as
    # drift. We also derive a per-package content hash from those entity hashes (the same
    # '<guid>=<hash>' projection the reader hashes), so update-in-place is entity-derived and
    # never crosses the unreliable desired(file-bytes)/actual(re-serialized) boundary.
    $desiredDictionaries     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $desiredSitHashByGuid    = @{}
    $desiredPkgContentByName = @{}
    foreach ($pkg in @($manifest.packages)) {
        $pkgFile = Join-Path $resolvedDir ([string]$pkg.file)
        if (-not $pkg.file -or -not (Test-Path -LiteralPath $pkgFile -PathType Leaf)) { continue }
        $pkgText = Get-Content -LiteralPath $pkgFile -Raw
        foreach ($m in [regex]::Matches($pkgText, '\{\{[A-Za-z0-9_]+\}\}')) {
            $desiredDictionaries.Add($m.Value) | Out-Null
        }
        $pkgEntityHashes = [System.Collections.Generic.List[string]]::new()
        try {
            [xml]$pkgXml = $pkgText
            $rulesNode = $pkgXml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq 'Rules' } | Select-Object -First 1
            if ($rulesNode) {
                foreach ($entity in @($rulesNode.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -eq 'Entity' })) {
                    $eid = $entity.GetAttribute('id')
                    if (-not [string]::IsNullOrWhiteSpace($eid)) {
                        $eidLower = $eid.ToLowerInvariant()
                        # codex 4A P2-A: hash the entity PLUS the transitive idRef closure of its
                        # sibling support elements, resolved within THIS package's <Rules> pool —
                        # IDENTICALLY to the actual side (Get-TenantInventory). An edit to a
                        # referenced <Regex> body (entity node unchanged) now changes this hash.
                        $entityHash = Get-DlpEntityClosureContentHash -Entity $entity -RulesNode $rulesNode
                        $desiredSitHashByGuid[$eidLower] = $entityHash
                        $pkgEntityHashes.Add("$eidLower=$entityHash") | Out-Null
                    }
                }
            }
        } catch { }
        if ($pkg.name) {
            # codex 4A P2-B: only emit a comparable desired package hash when there is at least one
            # parsed entity. A zero-entity (unparsable/empty) desired package gets $null so it never
            # falsely diffs against an actual package on hash grounds. The comparison below already
            # requires BOTH sides non-null before bucketing update-in-place.
            if (@($pkgEntityHashes).Count -gt 0) {
                $projection = (@($pkgEntityHashes) | Sort-Object) -join "`n"
                $desiredPkgContentByName[[string]$pkg.name] =
                    Get-DlpEntityContentHash -EntityXml "<pkg>$([System.Security.SecurityElement]::Escape($projection))</pkg>"
            }
        }
    }

    # ----------------------------------------------------------------- desired DLP rules/policies (DR-4)
    # DESIRED-RULE SOURCE (Stage-5 re-point, D7). The desired rule/policy set now comes FIRST from the
    # persisted workspace projection desired/resolved/dlp-rules.json (written by Resolve-DesiredContent);
    # the config bridge (Resolve-DesiredDlpRules) is the FALLBACK only when that file is absent. Either
    # way the content is the same shape the deploy path constructs (Resolve-DesiredDlpRules is
    # shadow-proven against Deploy-DLPRules). If neither yields a set we leave the desired set EMPTY so
    # SIT-only fixtures emit no dlpRule/dlpPolicy buckets.
    #
    # DRIFT-VS-UPDATE NOTE: assess cannot tell "desired changed" from "tenant hand-edited" by content
    # hash alone — both surface as a rule/policy that is ours, present in both, content differs. We
    # bucket BOTH as 'drift' (matching the SIT drift semantics: ours + content-differs out-of-band vs
    # desired/resolved); the reconciliation in either case is the same — push the desired content.
    # There is no separate update-in-place bucket for rules/policies: a rule has no entity-GUID identity
    # to "refit" the way a SIT rule package does, so an ours rule whose content diverges is uniformly drift.
    $desiredRuleHashByName   = @{}
    $desiredPolicyByName     = @{}
    $haveDesiredRuleConfig   = $false
    # Initialised here (not only in the SOURCE 2/3 fallback below) so the R1 graph-label lookup can read
    # it even when SOURCE 1 (dlp-rules.json) is taken and the fallback is skipped — otherwise a
    # Set-StrictMode caller throws on the unassigned variable (codex R1 review).
    $configSource = $null

    # SOURCE 1 — the persisted workspace projection (the re-point). Read it verbatim; no config touch.
    $dlpRulesFile = Join-Path $resolvedDir 'dlp-rules.json'
    if (Test-Path -LiteralPath $dlpRulesFile -PathType Leaf) {
        $haveDesiredRuleConfig = $true
        $dlpRulesDoc = Get-Content -LiteralPath $dlpRulesFile -Raw | ConvertFrom-Json
        foreach ($r in @($dlpRulesDoc.rules)) {
            if ($r.ruleName) { $desiredRuleHashByName[[string]$r.ruleName] = [string]$r.contentHash }
        }
        foreach ($p in @($dlpRulesDoc.policies)) {
            if ($p.policyName) { $desiredPolicyByName[[string]$p.policyName] = $p }
        }
    } else {
        # SOURCE 2/3 — config-bridge fallback: explicit -ConfigRoot, else a workspace config dir.
        # ($configSource was initialised above.)
        if ($PSBoundParameters.ContainsKey('ConfigRoot') -and -not [string]::IsNullOrWhiteSpace($ConfigRoot)) {
            $configSource = $ConfigRoot
        } else {
            foreach ($candidate in @((Join-Path $WorkspacePath 'desired' 'config'), (Join-Path $WorkspacePath 'config'))) {
                if (Test-Path -LiteralPath $candidate -PathType Container) { $configSource = $candidate; break }
            }
        }
        # When NO config source exists, assess does NOT bucket dlpRules/dlpPolicies AT ALL — not even
        # foreign — so SIT-only fixtures/workspaces that carry no rule config produce an identical
        # assessment to before DR-4. Foreign rules only become asserted-never-actionable once we are
        # actually diffing the rule layer (i.e. a desired set is present).
        if ($configSource -and (Test-Path -LiteralPath $configSource -PathType Container)) {
            $haveDesiredRuleConfig = $true
            $desired = Resolve-DesiredDlpRules -ConfigPath $configSource
            foreach ($r in @($desired.Rules)) {
                if ($r.ruleName) { $desiredRuleHashByName[[string]$r.ruleName] = [string]$r.contentHash }
            }
            foreach ($p in @($desired.Policies)) {
                if ($p.policyName) { $desiredPolicyByName[[string]$p.policyName] = $p }
            }
        }
    }

    # ----------------------------------------------------------------- desired auto-label policies (config bridge)
    # The autoLabelPolicy analogue of the DR-4 DLP rule/policy desired source above. Auto-label
    # policies are resolved from the SAME config (settings/labels/policies/classifiers) via
    # Resolve-DesiredAutoLabel, sourced from -ConfigRoot or a workspace config dir. (There is no
    # persisted desired/resolved projection for auto-label yet — the dlp-rules.json re-point is
    # DLP-only; persisting auto-label is future Stage-5 work. Until then auto-label drift uses the
    # config bridge.) Gated on $haveDesiredAutoLabel so a config-free workspace (and any config that
    # does not define the autoLabelPolicy name template) emits NO autoLabelPolicy buckets.
    $desiredAutoLabelByName = @{}
    $haveDesiredAutoLabel   = $false
    $alConfigSource = $null
    if ($PSBoundParameters.ContainsKey('ConfigRoot') -and -not [string]::IsNullOrWhiteSpace($ConfigRoot)) {
        $alConfigSource = $ConfigRoot
    } else {
        foreach ($candidate in @((Join-Path $WorkspacePath 'desired' 'config'), (Join-Path $WorkspacePath 'config'))) {
            if (Test-Path -LiteralPath $candidate -PathType Container) { $alConfigSource = $candidate; break }
        }
    }
    if ($alConfigSource -and (Test-Path -LiteralPath $alConfigSource -PathType Container)) {
        # This block triggers on ANY config dir (broader than the DLP source, which skips config when
        # the dlp-rules.json re-point is present), so a partial/non-auto-label config must NOT break
        # assess: treat a resolve failure as "auto-label not managed here" rather than throwing.
        try {
            $desiredAL = Resolve-DesiredAutoLabel -ConfigPath $alConfigSource
            foreach ($p in @($desiredAL.Policies)) { if ($p.policyName) { $desiredAutoLabelByName[[string]$p.policyName] = $p } }
            # A SUCCESSFUL resolve over a valid config means auto-label IS managed here — even when it
            # yields ZERO desired policies (e.g. all supported workloads disabled, or no eligible
            # labels). Existing OURS auto-label policies must then bucket as ORPHANS, not be silently
            # ignored (codex review P2a). Gating on a non-empty desired set would skip that detection.
            # A resolve FAILURE (the config dir is not auto-label-shaped — a required file missing) is
            # caught below and leaves auto-label UNMANAGED, so non-auto-label workspaces are unaffected.
            $haveDesiredAutoLabel = $true
        } catch { $desiredAutoLabelByName = @{}; $haveDesiredAutoLabel = $false }
    }

    # ----------------------------------------------------------------- actual side
    $actualPackages   = @($inv.objects.sitPackages)
    $actualSits       = @($inv.objects.sits)
    $actualDicts      = @($inv.objects.dictionaries)
    $actualDlpRules   = @($inv.objects.dlpRules)
    $actualDlpPolicies = @($inv.objects.dlpPolicies)
    $actualAutoLabelPolicies = @($inv.objects.autoLabelPolicies)

    $actualPackageByName = @{}
    foreach ($p in $actualPackages) { if ($p.name) { $actualPackageByName[[string]$p.name] = $p } }

    # ----------------------------------------------------------------- reference graph (impact)
    # Build the graph over the DESIRED packages (their XML carries the entity GUIDs) and the
    # ACTUAL dlp rules (their classifier-reference text names the GUIDs). The sitReferencedByRule
    # edges give per-classifier impact: which live rules reference each changed sit.
    $graphPackages = @(foreach ($pkg in @($manifest.packages)) {
        $pkgFile = Join-Path $resolvedDir ([string]$pkg.file)
        if (-not $pkg.file -or -not (Test-Path -LiteralPath $pkgFile -PathType Leaf)) { continue }
        [pscustomobject]@{
            Identity                                = [string]$pkg.name
            Name                                    = [string]$pkg.name
            Publisher                               = 'Compl8'
            SerializedClassificationRuleCollection  = (Get-Content -LiteralPath $pkgFile -Raw)
        }
    })
    $graphRules = @(foreach ($rule in @($inv.objects.dlpRules)) {
        [pscustomobject]@{
            Name                                = [string]$rule.name
            Identity                            = [string]$rule.identity
            Policy                              = [string]$rule.policy
            ContentContainsSensitiveInformation = $rule.contentContainsSensitiveInformation
        }
    })
    # R1 (graph completeness): feed the graph the FULL object set so the whole reference chain
    # (dictionary -> sit -> rule -> policy -> label) is built, not just packages+rules. Dictionaries +
    # policies come from the actual inventory; labels from the desired config when a source is available.
    # This does NOT change impact (still derived from sitReferencedByRule below), so the assessment is
    # byte-stable — it completes the graph the removal-cascade planner + reconciliation reason over.
    $graphDicts    = @($inv.objects.dictionaries)
    $graphPolicies = @($inv.objects.dlpPolicies)
    $graphLabels   = @()
    foreach ($cand in @($alConfigSource, $configSource, (Join-Path $WorkspacePath 'desired' 'config'), (Join-Path $WorkspacePath 'config'))) {
        if ([string]::IsNullOrWhiteSpace($cand)) { continue }
        $labelsPath = Join-Path $cand 'labels.json'
        if (Test-Path -LiteralPath $labelsPath -PathType Leaf) {
            try { $graphLabels = @(Get-Content -LiteralPath $labelsPath -Raw | ConvertFrom-Json) } catch { $graphLabels = @() }
            break
        }
    }
    $graph = Get-DeploymentReferenceGraph -Dictionaries $graphDicts -SitPackages $graphPackages `
        -DlpRules $graphRules -DlpPolicies $graphPolicies -Labels $graphLabels

    # Index nodes and sitReferencedByRule edges by sit entity GUID -> referencing rule names.
    $nodesById = @{}
    foreach ($node in @($graph.Nodes)) { $nodesById[$node.Id] = $node }
    $rulesBySitGuid = @{}
    foreach ($edge in @($graph.Edges | Where-Object { $_.Type -eq 'sitReferencedByRule' })) {
        if (-not $edge.From.StartsWith('sit:', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $sitGuid = $edge.From.Substring(4).ToLowerInvariant()
        $ruleNode = $nodesById[$edge.To]
        $ruleName = if ($ruleNode -and $ruleNode.Name) { $ruleNode.Name } elseif ($edge.To -like 'dlpRule:*') { $edge.To.Substring(8) } else { $edge.To }
        if (-not $rulesBySitGuid.ContainsKey($sitGuid)) {
            $rulesBySitGuid[$sitGuid] = [System.Collections.Generic.List[string]]::new()
        }
        if (-not $rulesBySitGuid[$sitGuid].Contains($ruleName)) { $rulesBySitGuid[$sitGuid].Add($ruleName) }
    }

    # ----------------------------------------------------------------- bucketing
    $assessment = New-AssessmentObject -Workspace $Workspace -GeneratedUtc $GeneratedUtc `
        -ResolveManifestHash $resolveManifestHash -InventoryHash $inventoryHash

    $buckets = [ordered]@{}
    foreach ($name in (Get-Compl8EngineSchemaEnums).Buckets) {
        $buckets[$name] = [System.Collections.Generic.List[object]]::new()
    }
    # Track the entity GUIDs of CHANGED classifiers (for impact). Maps sit ref -> entity GUID.
    $changedSitGuids = [ordered]@{}

    function Add-Bucket {
        param([string]$Bucket, [string]$ObjectType, [string]$Ref, [hashtable]$Extra = @{})
        $rec = [ordered]@{ objectType = $ObjectType; ref = $Ref }
        # Extra keys in a STABLE (alphabetical) order — a plain hashtable's .Keys enumeration
        # order is not deterministic across process runs, which would break byte-identical JSON.
        foreach ($k in (@($Extra.Keys) | Sort-Object)) { $rec[$k] = $Extra[$k] }
        $buckets[$Bucket].Add([pscustomobject]$rec) | Out-Null
    }

    # --- rule packages -------------------------------------------------------------------
    # create: desired package absent from actual; update-in-place: in both, ours, sha differs;
    # foreign: actual not-ours; orphan/remove: actual ours, not desired (packages have no slug
    # ledger entry, so an ours package not in desired is an orphan).
    foreach ($name in ($desiredPackages.Keys | Sort-Object)) {
        if (-not $actualPackageByName.ContainsKey($name)) {
            Add-Bucket -Bucket 'create' -ObjectType 'rulePackage' -Ref $name -Extra @{ reason = 'desired rule package not present in actual' }
            continue
        }
        $actualPkg = $actualPackageByName[$name]
        if (-not $actualPkg.ours) {
            # An actual foreign package that happens to share a desired name — opacity-as-safety.
            continue
        }
        # update-in-place is detected from the ENTITY-DERIVED canonical content hash (comparable
        # across the desired/actual boundary), NOT the raw serialized sha256. The inventory's
        # contentHash is the shared '<guid>=<entityHash>' digest; we compute the desired side the
        # same way above. Falling back to nothing when either side lacks a comparable hash avoids
        # the false-positive storm a raw-byte cross-boundary sha comparison would cause.
        $desiredPkgHash = if ($desiredPkgContentByName.ContainsKey($name)) { [string]$desiredPkgContentByName[$name] } else { $null }
        $actualPkgHash  = if ($actualPkg.PSObject.Properties['contentHash']) { [string]$actualPkg.contentHash } else { $null }
        if ($desiredPkgHash -and $actualPkgHash -and ($desiredPkgHash -ne $actualPkgHash)) {
            Add-Bucket -Bucket 'update-in-place' -ObjectType 'rulePackage' -Ref $name -Extra @{
                entityId = [string]$desiredPackages[$name].rulePackId
                reason   = 'refit — same rule package, canonical content hash differs'
            }
        }
    }
    foreach ($actualPkg in $actualPackages) {
        $name = [string]$actualPkg.name
        if (-not $actualPkg.ours) {
            Add-Bucket -Bucket 'foreign' -ObjectType 'rulePackage' -Ref $name -Extra @{ reason = 'not ours — never touched' }
            continue
        }
        if (-not $desiredPackages.ContainsKey($name)) {
            # Ours, not desired, no ledger slug record for a package => unexpected leftover.
            Add-Bucket -Bucket 'orphan' -ObjectType 'rulePackage' -Ref $name -Extra @{ reason = 'ours rule package not in desired and not a planned removal' }
        }
    }

    # --- sits ----------------------------------------------------------------------------
    # repack-move: assignment changed; drift: same package, content changed out-of-band;
    # remove: ledger-disabled; orphan: ours, no desired assignment AND no ledger trace;
    # foreign: not ours; create: desired slug with no actual sit.
    $actualSitByName = @{}
    foreach ($s in $actualSits) { if ($s.name) { $actualSitByName[[string]$s.name] = $s } }

    foreach ($s in $actualSits) {
        $ref = [string]$s.name
        if (-not $s.ours) {
            Add-Bucket -Bucket 'foreign' -ObjectType 'sit' -Ref $ref -Extra @{ reason = 'not ours — never touched' }
            continue
        }
        $desiredHasIt = $desiredSits.Contains($ref)
        if ($desiredHasIt) {
            $desiredPkg = $desiredAssignment[$ref]
            $actualPkg  = [string]$s.package
            if ($desiredPkg -and $actualPkg -and ($desiredPkg -ne $actualPkg)) {
                Add-Bucket -Bucket 'repack-move' -ObjectType 'sit' -Ref $ref -Extra @{
                    from = $actualPkg; to = $desiredPkg; reason = 'package assignment changed'
                }
                if ($s.identity) { $changedSitGuids[$ref] = ([string]$s.identity).ToLowerInvariant() }
                continue
            }
            # Same package — drift when the live (actual) per-sit content hash diverges from the
            # desired-derived entity hash. The desired baseline is the entity OuterXml hash from
            # the composed package; an actual contentHash that differs is an out-of-band edit.
            $guid = if ($s.identity) { ([string]$s.identity).ToLowerInvariant() } else { $null }
            $desiredHash = if ($guid -and $desiredSitHashByGuid.ContainsKey($guid)) { $desiredSitHashByGuid[$guid] } else { $null }
            $actualHash  = if ($s.PSObject.Properties['contentHash']) { [string]$s.contentHash } else { $null }
            if ($desiredHash -and $actualHash -and ($desiredHash -ne $actualHash)) {
                Add-Bucket -Bucket 'drift' -ObjectType 'sit' -Ref $ref -Extra @{ reason = 'ours — content changed out-of-band vs desired/resolved' }
                if ($guid) { $changedSitGuids[$ref] = $guid }
            }
            continue
        }
        # Not desired. remove if the ledger retired the slug; otherwise orphan.
        if ($disabledSlugs.Contains($ref)) {
            Add-Bucket -Bucket 'remove' -ObjectType 'sit' -Ref $ref -Extra @{ reason = 'ledger-disabled — desired (planned) removal' }
            if ($s.identity) { $changedSitGuids[$ref] = ([string]$s.identity).ToLowerInvariant() }
        } else {
            Add-Bucket -Bucket 'orphan' -ObjectType 'sit' -Ref $ref -Extra @{ reason = 'ours — not desired and not a planned removal' }
        }
    }
    # create: a desired sit slug with no actual sit at all.
    foreach ($slug in ($desiredSits | Sort-Object)) {
        if (-not $actualSitByName.ContainsKey($slug)) {
            Add-Bucket -Bucket 'create' -ObjectType 'sit' -Ref $slug -Extra @{ reason = 'desired sit not present in actual' }
        }
    }

    # --- dictionaries --------------------------------------------------------------------
    # create: desired dictionary placeholder absent from actual; foreign: actual not-ours;
    # orphan: ours, not desired.
    $actualDictByName = @{}
    foreach ($d in $actualDicts) { if ($d.name) { $actualDictByName[[string]$d.name] = $d } }
    foreach ($placeholder in ($desiredDictionaries | Sort-Object)) {
        if (-not $actualDictByName.ContainsKey($placeholder)) {
            Add-Bucket -Bucket 'create' -ObjectType 'dictionary' -Ref $placeholder -Extra @{ reason = 'desired dictionary not present in actual' }
        }
    }
    foreach ($d in $actualDicts) {
        $ref = [string]$d.name
        if (-not $d.ours) {
            Add-Bucket -Bucket 'foreign' -ObjectType 'dictionary' -Ref $ref -Extra @{ reason = 'not ours — never touched' }
            continue
        }
        if (-not $desiredDictionaries.Contains($ref)) {
            Add-Bucket -Bucket 'orphan' -ObjectType 'dictionary' -Ref $ref -Extra @{ reason = 'ours dictionary not in desired and not a planned removal' }
        }
    }

    # --- dlp rules + policies (DR-4) -----------------------------------------------------
    # create: desired rule/policy name absent from actual; drift: ours, present in both, content
    # hash differs (the hand-edit OR config-change signal — see the drift-vs-update note above);
    # orphan: ours actual not in the desired set; foreign: actual not ours (never actionable).
    # Keyed by NAME (the deterministic Get-RuleName/Get-PolicyName templates Resolve-DesiredDlpRules
    # emits). The WHOLE block is gated on $haveDesiredRuleConfig so a config-free workspace produces
    # no dlpRule/dlpPolicy buckets (the pre-DR-4 behaviour SIT-only fixtures depend on).
    if ($haveDesiredRuleConfig) {
    $actualRuleByName = @{}
    foreach ($r in $actualDlpRules) { if ($r.name) { $actualRuleByName[[string]$r.name] = $r } }
    foreach ($r in $actualDlpRules) {
        $ref = [string]$r.name
        if (-not $r.ours) {
            Add-Bucket -Bucket 'foreign' -ObjectType 'dlpRule' -Ref $ref -Extra @{ reason = 'not ours — never touched' }
            continue
        }
        if ($desiredRuleHashByName.ContainsKey($ref)) {
            # ours, present in both — drift when the content hash diverges from desired/resolved.
            $desiredHash = [string]$desiredRuleHashByName[$ref]
            $actualHash  = if ($r.PSObject.Properties['contentHash']) { [string]$r.contentHash } else { $null }
            if ($desiredHash -and $actualHash -and ($desiredHash -ne $actualHash)) {
                Add-Bucket -Bucket 'drift' -ObjectType 'dlpRule' -Ref $ref -Extra @{ reason = 'ours — content changed out-of-band vs desired/resolved' }
            }
            continue
        }
        # ours, not in the desired set — an unexpected leftover (rules carry no entity ledger).
        Add-Bucket -Bucket 'orphan' -ObjectType 'dlpRule' -Ref $ref -Extra @{ reason = 'ours rule not in desired and not a planned removal' }
    }
    foreach ($ruleName in ($desiredRuleHashByName.Keys | Sort-Object)) {
        if (-not $actualRuleByName.ContainsKey($ruleName)) {
            Add-Bucket -Bucket 'create' -ObjectType 'dlpRule' -Ref $ruleName -Extra @{ reason = 'desired rule not present in actual' }
        }
    }

    # --- dlp policies (DR-4) -------------------------------------------------------------
    # Same create/drift/orphan/foreign by policy NAME, comparing a policy content projection
    # (mode + sorted locations). drift = ours, present in both, content differs.
    #
    # codex review P2: the projection deliberately EXCLUDES the policy Comment. Deploy-DLPRules wraps
    # the raw policies.json comment with the provenance stamp at deploy time (Add-DeploymentProvenanceStamp),
    # whereas Resolve-DesiredDlpRules keeps the RAW comment — so desired.comment != actual.comment for
    # EVERY owned policy, which falsely reported drift the moment ownership was fixed (P1). The mode and
    # the sorted locations are the meaningful policy content; the Comment is provenance metadata, not
    # drift-relevant, so it is dropped from the hash entirely.
    # Per-ASPECT policy projection (NOT one combined hash) so drift can attribute WHICH aspect changed:
    # a `mode` change is reconcilable by the executor's update path (it sets -Mode, exactly what the leaf
    # does), but a `locations` change is NOT (neither the leaf nor the engine sets locations on an
    # existing policy — Set-DlpCompliancePolicy is called with Mode+Comment only; locations need a
    # recreate). Comment is excluded (provenance noise: the actual side is stamped, the desired side raw).
    function Get-DlpPolicyLocationProjection {
        param($Locations)
        if ($null -eq $Locations) { return '' }
        $pairs = [System.Collections.Generic.List[string]]::new()
        if ($Locations -is [System.Collections.IDictionary]) {
            foreach ($k in @($Locations.Keys)) { $pairs.Add("$k=$(@($Locations[$k]) -join ',')") | Out-Null }
        } elseif ($Locations.PSObject -and $Locations.PSObject.Properties) {
            foreach ($p in $Locations.PSObject.Properties) { $pairs.Add("$($p.Name)=$(@($p.Value) -join ',')") | Out-Null }
        }
        (@($pairs) | Sort-Object) -join ';'
    }
    $actualPolicyByName = @{}
    foreach ($p in $actualDlpPolicies) { if ($p.name) { $actualPolicyByName[[string]$p.name] = $p } }
    foreach ($p in $actualDlpPolicies) {
        $ref = [string]$p.name
        if (-not $p.ours) {
            Add-Bucket -Bucket 'foreign' -ObjectType 'dlpPolicy' -Ref $ref -Extra @{ reason = 'not ours — never touched' }
            continue
        }
        if ($desiredPolicyByName.ContainsKey($ref)) {
            $desiredP = $desiredPolicyByName[$ref]
            $actualLocations = if ($p.PSObject.Properties['locations']) { $p.locations } else { $null }
            $driftFields = [System.Collections.Generic.List[string]]::new()
            if ([string]$desiredP.mode -ne [string]$p.mode) { $driftFields.Add('mode') | Out-Null }
            if ((Get-DlpPolicyLocationProjection -Locations $desiredP.locations) -ne (Get-DlpPolicyLocationProjection -Locations $actualLocations)) { $driftFields.Add('locations') | Out-Null }
            if ($driftFields.Count -gt 0) {
                Add-Bucket -Bucket 'drift' -ObjectType 'dlpPolicy' -Ref $ref -Extra @{
                    reason      = 'ours — content changed out-of-band vs desired/resolved'
                    driftFields = @($driftFields)
                }
            }
            continue
        }
        Add-Bucket -Bucket 'orphan' -ObjectType 'dlpPolicy' -Ref $ref -Extra @{ reason = 'ours policy not in desired and not a planned removal' }
    }
    foreach ($policyName in ($desiredPolicyByName.Keys | Sort-Object)) {
        if (-not $actualPolicyByName.ContainsKey($policyName)) {
            Add-Bucket -Bucket 'create' -ObjectType 'dlpPolicy' -Ref $policyName -Extra @{ reason = 'desired policy not present in actual' }
        }
    }
    } # end if ($haveDesiredRuleConfig)

    # --- auto-label policies (auto-label drift) ------------------------------------------
    # create: desired auto-label policy name absent from actual; drift: ours, present in both, content
    # hash differs (mode + applied label + locations — the hand-edit OR config-change signal); orphan:
    # ours actual not in the desired set; foreign: actual not ours (never actionable). Keyed by the
    # AL-numbered NAME the autoLabelPolicy template emits. The WHOLE block is gated on
    # $haveDesiredAutoLabel so a config-free workspace (or a config that does not define auto-label
    # naming) produces NO autoLabelPolicy buckets — the SIT/DLP-only fixtures are unaffected.
    #
    # The policy content hash deliberately EXCLUDES the Comment (mirrors the dlpPolicy P2 fix): Deploy-
    # AutoLabeling wraps the raw comment with the provenance stamp, so the actual comment never equals
    # the raw desired comment; the mode, applied label, and locations are the drift-relevant content.
    # There is no update-in-place bucket for auto-label policies (no entity-GUID identity to refit) — an
    # ours policy whose content diverges is uniformly drift, exactly as for DLP rules/policies.
    if ($haveDesiredAutoLabel) {
    # Per-ASPECT auto-label projection (mode / label / locations) so drift attributes WHICH aspect
    # changed: `mode` and `label` are reconcilable by the executor's update path (Set-AutoSensitivity-
    # LabelPolicy sets -Mode + -ApplySensitivityLabel — what the leaf does), but `locations` are NOT
    # (locations are a create-time parameter only; a locations change needs a recreate).
    function Get-AutoLabelLocationProjection {
        param($Locations)
        if ($null -eq $Locations) { return '' }
        $pairs = [System.Collections.Generic.List[string]]::new()
        if ($Locations -is [System.Collections.IDictionary]) {
            foreach ($k in @($Locations.Keys)) { $pairs.Add("$k=$(@($Locations[$k]) -join ',')") | Out-Null }
        } elseif ($Locations.PSObject -and $Locations.PSObject.Properties) {
            foreach ($p in $Locations.PSObject.Properties) { $pairs.Add("$($p.Name)=$(@($p.Value) -join ',')") | Out-Null }
        }
        (@($pairs) | Sort-Object) -join ';'
    }
    $actualAlByName = @{}
    foreach ($p in $actualAutoLabelPolicies) { if ($p.name) { $actualAlByName[[string]$p.name] = $p } }
    foreach ($p in $actualAutoLabelPolicies) {
        $ref = [string]$p.name
        if (-not $p.ours) {
            Add-Bucket -Bucket 'foreign' -ObjectType 'autoLabelPolicy' -Ref $ref -Extra @{ reason = 'not ours — never touched' }
            continue
        }
        if ($desiredAutoLabelByName.ContainsKey($ref)) {
            $desiredP = $desiredAutoLabelByName[$ref]
            $actualLocations = if ($p.PSObject.Properties['locations']) { $p.locations } else { $null }
            $driftFields = [System.Collections.Generic.List[string]]::new()
            if ([string]$desiredP.mode  -ne [string]$p.mode)  { $driftFields.Add('mode')  | Out-Null }
            if ([string]$desiredP.label -ne [string]$p.label) { $driftFields.Add('label') | Out-Null }
            if ((Get-AutoLabelLocationProjection -Locations $desiredP.locations) -ne (Get-AutoLabelLocationProjection -Locations $actualLocations)) { $driftFields.Add('locations') | Out-Null }
            if ($driftFields.Count -gt 0) {
                Add-Bucket -Bucket 'drift' -ObjectType 'autoLabelPolicy' -Ref $ref -Extra @{
                    reason      = 'ours — content changed out-of-band vs desired/resolved'
                    driftFields = @($driftFields)
                }
            }
            continue
        }
        Add-Bucket -Bucket 'orphan' -ObjectType 'autoLabelPolicy' -Ref $ref -Extra @{ reason = 'ours auto-label policy not in desired and not a planned removal' }
    }
    foreach ($policyName in ($desiredAutoLabelByName.Keys | Sort-Object)) {
        if (-not $actualAlByName.ContainsKey($policyName)) {
            Add-Bucket -Bucket 'create' -ObjectType 'autoLabelPolicy' -Ref $policyName -Extra @{ reason = 'desired auto-label policy not present in actual' }
        }
    }
    } # end if ($haveDesiredAutoLabel)

    # ----------------------------------------------------------------- impact (graph-derived)
    $impact = [System.Collections.Generic.List[object]]::new()
    foreach ($ref in $changedSitGuids.Keys) {
        $guid = $changedSitGuids[$ref]
        if ($rulesBySitGuid.ContainsKey($guid)) {
            $affects = @($rulesBySitGuid[$guid] | Sort-Object | ForEach-Object { "dlp-rule: $_" })
            $impact.Add([pscustomobject]@{ objectRef = $ref; affects = $affects }) | Out-Null
        }
    }

    # ----------------------------------------------------------------- upgrade conflicts
    $conflicts = [System.Collections.Generic.List[object]]::new()
    foreach ($w in @($manifest.warnings)) {
        # Resolve manifest conflict warnings have the shape 'conflict:<kind>:<slug> — <detail>'.
        $m = [regex]::Match([string]$w, '^conflict:(?<kind>[^:]+):(?<slug>[^ ]+)\s*[—-]?\s*(?<detail>.*)$')
        if ($m.Success) {
            $conflicts.Add([pscustomobject]@{
                slug   = $m.Groups['slug'].Value
                kind   = $m.Groups['kind'].Value
                detail = $m.Groups['detail'].Value.Trim()
            }) | Out-Null
        }
    }

    # ----------------------------------------------------------------- name-collision conflicts
    # A desired object whose NAME is held by a NOT-OURS (foreign) actual cannot deploy: the engine
    # never overwrites a foreign object (opacity-as-safety, spec §8) and will not create a duplicate
    # name — so WITHOUT this the desired object SILENTLY never deploys (no create emitted because the
    # name is taken, no conflict raised). Surface each as a first-class conflict so the plan/report
    # shows the blockage natively instead of a silent no-op. (A name held by an OURS actual is not a
    # collision — it is drift/update/in-sync, already bucketed above.)
    $desiredNamesByType = [ordered]@{
        dictionary      = @($desiredDictionaries)
        rulePackage     = @($desiredPackages.Keys)
        sit             = @($desiredSits)
        dlpRule         = @($desiredRuleHashByName.Keys)
        dlpPolicy       = @($desiredPolicyByName.Keys)
        autoLabelPolicy = @($desiredAutoLabelByName.Keys)
    }
    $foreignNamesByType = @{}
    foreach ($entry in @($buckets['foreign'])) {
        $ft = [string]$entry.objectType
        if (-not $foreignNamesByType.ContainsKey($ft)) {
            $foreignNamesByType[$ft] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
        $foreignNamesByType[$ft].Add([string]$entry.ref) | Out-Null
    }
    foreach ($t in $desiredNamesByType.Keys) {
        if (-not $foreignNamesByType.ContainsKey($t)) { continue }
        foreach ($name in (@($desiredNamesByType[$t]) | Sort-Object -Unique)) {
            if ($foreignNamesByType[$t].Contains([string]$name)) {
                $conflicts.Add([pscustomobject]@{
                    slug   = [string]$name
                    kind   = 'name-collision'
                    detail = "desired $t '$name' is blocked — a foreign (not-ours) object holds this name; the engine will neither overwrite it nor create a duplicate."
                }) | Out-Null
            }
        }
    }

    # ----------------------------------------------------------------- assemble (deterministic)
    # Sort each bucket's entries by ref so the JSON is byte-stable regardless of walk order.
    $bucketOut = [ordered]@{}
    foreach ($name in (Get-Compl8EngineSchemaEnums).Buckets) {
        $bucketOut[$name] = @($buckets[$name] | Sort-Object @{ Expression = { $_.objectType } }, @{ Expression = { $_.ref } })
    }
    $assessment.buckets = [pscustomobject]$bucketOut
    $assessment.impact  = @($impact | Sort-Object objectRef)
    $assessment.upgradeConflicts = @($conflicts | Sort-Object slug, kind)

    if ($OutFile) {
        $dir = Split-Path -Parent $OutFile
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $assessment | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $OutFile -Encoding UTF8
    }

    return $assessment
}
