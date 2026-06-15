function New-Compl8Plan {
    <#
    .SYNOPSIS
        Turns an assessment (Invoke-Compl8Assess output) + reference graph into a gated,
        ordered compl8.plan/v1 object, optionally written to history/plans/ with a sha256
        sidecar (PHASE 4B, Task 5).

    .DESCRIPTION
        A near-pure transform (the ONLY I/O is the optional atomic write of the plan +
        sidecar; arch design §5, D3/D4). It builds the plan in four steps:

          1. ORDER + WIRE. Calls Get-Compl8PlanOrder (Task 4) for the ordered,
             dependency-wired steps. That function already attaches `propagation` gates to
             rule/auto-label steps whose dependency package is changed this plan, and
             GENERATES `dereference` steps for still-referenced classifier removals (D5).

          2. IMPACT. Stamps each step's `impact` (the live DLP rules a step affects) from
             the assessment's impact[] and the graph:
               * direct match  — an impact[] entry whose objectRef equals the step's
                 objectRef (e.g. a sit/repack-move step) is stamped onto that step;
               * package roll-up — a rulePackage step is stamped with the union of the
                 impacts of the sits it CONTAINS (graph packageContainsSit -> sit GUID,
                 resolved to a sit name via the supplied -Inventory). A changed rule
                 package therefore advertises every live rule its classifiers feed.
             Impact already present on a step (Get-Compl8PlanOrder stamps dlpRule steps) is
             unioned in, deduplicated and sorted for determinism.

          3. snapshotBeforeDestroy STEP 0.5 (D4). WHENEVER the plan contains any destructive
             step (action remove / dereference), a single generated snapshot step
               { action='snapshot'; objectType='tenant'; objectRef='*';
                 gate={ type='snapshotBeforeDestroy' } }
             is PREPENDED as the first step (id 's00' — Step 0.5), and EVERY destructive step
             is made to dependsOn it (apply cannot tear anything down before the snapshot
             lands). When the plan has NO destructive step, no snapshot step is emitted.

          4. externalRefs GATE (D4). A policy-scope step (dlpPolicy / labelPolicy /
             autoLabelPolicy) whose desired content carries an EXTERNAL reference is marked
             with { type='externalRefs' }. v1 is PLAN-TIME / PURE: it only MARKS the step;
             the actual resolution (do the named groups/users/sites resolve in the tenant?)
             is an apply-time check, deferred (spec §8 — halt-and-confirm, no resolver yet).
             TRIGGER (documented, minimal, defensible): the step's assessment bucket entry
             carries a `scope` or `recipient` field (the external-ref carrier). The gate is
             attached only when the step has no other gate, so a real propagation timing
             constraint on an auto-label policy is never overwritten.

        Plan validity is by CONTENT HASH, not age: inputs.resolveManifest + inputs.inventory
        are carried verbatim from the assessment, and inputs.assessment is the sha256 of the
        assessment JSON. Test-Compl8PlanCurrent re-checks those hashes against the live inputs.

        DETERMINISM (golden-testable): the plan id and timestamp are PARAMETERS — Get-Date and
        Get-Random are BANNED inside this function. Same assessment + graph + inventory + id +
        GeneratedUtc => byte-identical plan JSON.

    .PARAMETER Assessment
        A compl8.assessment/v1 object (Invoke-Compl8Assess / New-AssessmentObject shape). Its
        inputs.resolveManifest / inputs.inventory hashes are carried into the plan; its
        buckets + impact[] drive ordering, impact and the externalRefs trigger.

    .PARAMETER Graph
        A Get-DeploymentReferenceGraph result (Nodes / Edges / Summary), the same graph assess
        built over desired packages + actual rules. Passed straight through to Get-Compl8PlanOrder
        and consulted here for package -> contained-sit impact roll-up.

    .PARAMETER Inventory
        Optional. The parsed inventory object (the same actual/inventory.json assess consumed).
        Supplied, it resolves a package's contained sit GUIDs to sit NAMES so package-level
        impact roll-up works. Absent, impact stamping degrades to direct-objectRef matching.

    .PARAMETER Workspace
        Logical workspace name written to the plan (e.g. 'nonprod').

    .PARAMETER Id
        The deterministic plan id (e.g. 'plan-20260613-000000'). -PlanId is an accepted alias.
        Get-Date / Get-Random are banned, so the caller stamps the id for golden testing.

    .PARAMETER GeneratedUtc
        The generatedUtc stamp, written verbatim (Get-Date is NOT called).

    .PARAMETER WorkspacePath
        Optional. When set, the plan is written to <WorkspacePath>/history/plans/<id>.json with
        a <id>.sha256 sidecar, atomically (temp file + move). Use -OutFile to override the path.

    .PARAMETER OutFile
        Optional. Explicit plan output path (overrides the -WorkspacePath history/plans default).
        The sidecar is written alongside as <OutFile-without-ext>.sha256.

    .OUTPUTS
        A compl8.plan/v1 object (New-PlanObject / Add-PlanStep shape; passes Test-PlanSchema).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Assessment,

        [Parameter(Mandatory)]
        [pscustomobject]$Graph,

        [pscustomobject]$Inventory,

        [Parameter(Mandatory)]
        [string]$Workspace,

        [Parameter(Mandatory)]
        [Alias('PlanId')]
        [string]$Id,

        [string]$GeneratedUtc,

        [string]$WorkspacePath,

        [string]$OutFile
    )

    # Deterministic SHA-256 over UTF-8 text, lowercase hex (mirrors Get-AssessTextHash so the
    # assessment hash convention matches Invoke-Compl8Assess's input-hash convention).
    function Get-PlanTextHash {
        param([string]$Text)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$Text))
            -join ($bytes | ForEach-Object { $_.ToString('x2') })
        } finally { $sha.Dispose() }
    }

    # ------------------------------------------------------------------ ordered + wired steps
    $orderedSteps = @(Get-Compl8PlanOrder -Assessment $Assessment -Graph $Graph)

    # ------------------------------------------------------------------ impact roll-up indexes
    # impact[] keyed by objectRef (sit name) -> affects[].
    $affectsByRef = @{}
    foreach ($im in @($Assessment.impact)) {
        if ($im.objectRef) { $affectsByRef[[string]$im.objectRef] = @($im.affects) }
    }

    # sit GUID -> sit name, from the inventory (so a package's contained GUIDs map to names).
    $sitNameByGuid = @{}
    if ($Inventory -and $Inventory.objects -and $Inventory.objects.sits) {
        foreach ($s in @($Inventory.objects.sits)) {
            if ($s.identity -and $s.name) { $sitNameByGuid[([string]$s.identity).ToLowerInvariant()] = [string]$s.name }
        }
    }

    # graph node id -> node, and package node name -> contained sit GUIDs (packageContainsSit).
    $nodesById = @{}
    foreach ($node in @($Graph.Nodes)) { if ($node.Id) { $nodesById[[string]$node.Id] = $node } }
    $sitGuidsByPackageName = @{}
    foreach ($edge in @($Graph.Edges | Where-Object { $_.Type -eq 'packageContainsSit' })) {
        if (-not ([string]$edge.To).StartsWith('sit:', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $sitGuid = ([string]$edge.To).Substring(4).ToLowerInvariant()
        $pkgNode = $nodesById[[string]$edge.From]
        $pkgName = if ($pkgNode -and $pkgNode.Name) { [string]$pkgNode.Name }
                   elseif (([string]$edge.From).StartsWith('sitPackage:', [System.StringComparison]::OrdinalIgnoreCase)) { ([string]$edge.From).Substring(11) }
                   else { [string]$edge.From }
        if (-not $sitGuidsByPackageName.ContainsKey($pkgName)) { $sitGuidsByPackageName[$pkgName] = [System.Collections.Generic.List[string]]::new() }
        if (-not $sitGuidsByPackageName[$pkgName].Contains($sitGuid)) { $sitGuidsByPackageName[$pkgName].Add($sitGuid) }
    }

    # ------------------------------------------------------------------ bucket-entry index
    # Every actionable bucket entry indexed by 'objectType|ref' -> entry, for the externalRefs
    # trigger (scope/recipient lookup) on policy-scope steps.
    $entryByKey = @{}
    foreach ($bucketName in (Get-Compl8EngineSchemaEnums).Buckets) {
        foreach ($entry in @($Assessment.buckets.$bucketName)) {
            if ($entry.objectType -and $entry.ref) {
                $key = "$($entry.objectType)|$($entry.ref)"
                if (-not $entryByKey.ContainsKey($key)) { $entryByKey[$key] = $entry }
            }
        }
    }

    $policyTypes = @('dlpPolicy', 'labelPolicy', 'autoLabelPolicy')

    # ------------------------------------------------------------------ enrich each step
    # Compute the final impact + gate for every ordered step BEFORE the snapshot prepend, so the
    # snapshot wiring can reference the (unchanged) original step ids.
    $enriched = foreach ($step in $orderedSteps) {
        # ---- impact ------------------------------------------------------------------------
        $impactSet = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($a in @($step.impact)) { if ($a) { $impactSet.Add([string]$a) | Out-Null } }
        # Direct objectRef match.
        if ($affectsByRef.ContainsKey([string]$step.objectRef)) {
            foreach ($a in @($affectsByRef[[string]$step.objectRef])) { if ($a) { $impactSet.Add([string]$a) | Out-Null } }
        }
        # Package roll-up: union the impacts of the sits this package contains.
        if ($step.objectType -eq 'rulePackage' -and $sitGuidsByPackageName.ContainsKey([string]$step.objectRef)) {
            foreach ($guid in @($sitGuidsByPackageName[[string]$step.objectRef])) {
                $sitName = if ($sitNameByGuid.ContainsKey($guid)) { $sitNameByGuid[$guid] } else { $null }
                if ($sitName -and $affectsByRef.ContainsKey($sitName)) {
                    foreach ($a in @($affectsByRef[$sitName])) { if ($a) { $impactSet.Add([string]$a) | Out-Null } }
                }
            }
        }
        $impact = @($impactSet)

        # ---- externalRefs gate (only when the step carries no other gate) -----------------
        $gate = $step.gate
        if ($null -eq $gate -and ($policyTypes -contains [string]$step.objectType)) {
            $entry = $entryByKey["$($step.objectType)|$($step.objectRef)"]
            $hasExternal = $false
            if ($entry) {
                foreach ($field in 'scope', 'recipient', 'recipients', 'sharedWith') {
                    if ($entry.PSObject.Properties[$field] -and -not [string]::IsNullOrWhiteSpace([string]$entry.$field)) { $hasExternal = $true; break }
                }
            }
            if ($hasExternal) { $gate = [pscustomobject]@{ type = 'externalRefs' } }
        }

        [pscustomobject]@{
            id         = [string]$step.id
            action     = [string]$step.action
            objectType = [string]$step.objectType
            objectRef  = [string]$step.objectRef
            dependsOn  = @($step.dependsOn)
            impact     = $impact
            gate       = $gate
        }
    }
    $enriched = @($enriched)

    # ------------------------------------------------------------------ snapshotBeforeDestroy 0.5
    $destructive = @($enriched | Where-Object { $_.action -in 'remove', 'dereference' })
    $snapshotId = 's00'
    $hasSnapshot = $destructive.Count -gt 0
    if ($hasSnapshot) {
        # Make every destructive step depend on the snapshot.
        foreach ($d in $destructive) {
            if (@($d.dependsOn) -notcontains $snapshotId) {
                $d.dependsOn = @(@($d.dependsOn) + $snapshotId | Where-Object { $_ })
            }
        }
    }

    # ------------------------------------------------------------------ assessment hash
    $assessmentJson = $Assessment | ConvertTo-Json -Depth 12
    $assessmentHash = 'sha256:' + (Get-PlanTextHash -Text $assessmentJson)

    # ------------------------------------------------------------------ build the plan object
    $plan = New-PlanObject -Workspace $Workspace -Id $Id -GeneratedUtc $GeneratedUtc `
        -ResolveManifestHash ([string]$Assessment.inputs.resolveManifest) `
        -InventoryHash ([string]$Assessment.inputs.inventory) `
        -AssessmentHash $assessmentHash

    if ($hasSnapshot) {
        $plan = Add-PlanStep -Plan $plan -Id $snapshotId -Action 'snapshot' `
            -ObjectType 'tenant' -ObjectRef '*' -DependsOn @() -Impact @() `
            -Gate ([pscustomobject]@{ type = 'snapshotBeforeDestroy' })
    }
    foreach ($s in $enriched) {
        $plan = Add-PlanStep -Plan $plan -Id $s.id -Action $s.action `
            -ObjectType $s.objectType -ObjectRef $s.objectRef -DependsOn @($s.dependsOn) `
            -Impact @($s.impact) -Gate $s.gate
    }

    # Validate before we ever write — a malformed plan must not reach disk.
    $check = Test-PlanSchema -Plan $plan
    if (-not $check.Valid) {
        throw "New-Compl8Plan produced an invalid plan: $((@($check.Errors)) -join '; ')"
    }

    # ------------------------------------------------------------------ optional atomic write
    $targetFile = if ($OutFile) {
        $OutFile
    } elseif ($WorkspacePath) {
        Join-Path $WorkspacePath 'history' 'plans' "$Id.json"
    } else {
        $null
    }

    if ($targetFile) {
        $dir = Split-Path -Parent $targetFile
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

        $json = $plan | ConvertTo-Json -Depth 12
        $fileName = Split-Path -Leaf $targetFile

        # Atomic: write to a temp sibling, hash it, then move into place; write the sidecar last.
        $tmp = "$targetFile.$([guid]::NewGuid().ToString('n')).tmp"
        try {
            Set-Content -LiteralPath $tmp -Value $json -Encoding UTF8 -NoNewline
            $sha = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLowerInvariant()
            if (Test-Path -LiteralPath $targetFile) { Remove-Item -LiteralPath $targetFile -Force -Confirm:$false }
            Move-Item -LiteralPath $tmp -Destination $targetFile

            # Sidecar line format EXACTLY '<64-hex>  <filename>' (two spaces), matching the refit
            # plan sidecar (Write-ClassifierRefitPlanArtifacts in scripts/Deploy-Classifiers.ps1).
            $sidecarPath = [System.IO.Path]::ChangeExtension($targetFile, '.sha256')
            $sidecarTmp = "$sidecarPath.$([guid]::NewGuid().ToString('n')).tmp"
            try {
                Set-Content -LiteralPath $sidecarTmp -Value "$sha  $fileName" -Encoding ASCII -NoNewline
                if (Test-Path -LiteralPath $sidecarPath) { Remove-Item -LiteralPath $sidecarPath -Force -Confirm:$false }
                Move-Item -LiteralPath $sidecarTmp -Destination $sidecarPath
            } finally {
                if (Test-Path -LiteralPath $sidecarTmp) { Remove-Item -LiteralPath $sidecarTmp -Force -ErrorAction SilentlyContinue }
            }
        } finally {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }

    return $plan
}
