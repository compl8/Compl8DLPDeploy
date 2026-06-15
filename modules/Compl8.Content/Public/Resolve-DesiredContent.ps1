function Resolve-DesiredContent {
    <#
    .SYNOPSIS
        Resolves a workspace's desired state: merge → ledger → pack → compose → manifest.
    .DESCRIPTION
        The repack engine entry point (arch design §4). Reads desired/release + desired/
        overlay, maintains the entity ledger (seed release items, mint custom adds, flip
        disable state with GUID retention), packs deterministically (prior assignments from
        the existing resolve manifest are sticky), composes each package under the
        byte-parity contract, and writes desired/resolved atomically — packages plus
        resolve-manifest.json land in one staging-directory swap, so a failed resolve never
        leaves a half-written output. desired/resolved is a pure function of
        (release, overlay, ledger): identical inputs reproduce identical package bytes.

        Hard failures (abort, nothing written): dictionary budget over the 1 MB cap,
        composed package over the 150 KB hard limit, or Test-SITRulePackageXml rejection.
        Soft signals (recorded in manifest warnings): merge conflicts, budget warnings,
        items dropped at the tenant package cap.

        DLP-RULE DESIRED RE-POINT (Stage-5 D7). When -ConfigRoot is supplied, resolve ALSO projects
        the DESIRED DLP rule/policy set from that config (via Resolve-DesiredDlpRules) and persists it
        as desired/resolved/dlp-rules.json (schemaVersion compl8.dlp-rules/v1: the rule/policy list,
        each rule carrying its Get-DlpRuleContentHash content hash). It is written into the SAME
        atomic staging swap as the packages + manifest, so the workspace becomes self-contained:
        Invoke-Compl8Assess reads the desired rules from this file instead of re-resolving config.
        When -ConfigRoot is absent, no dlp-rules.json is written (SIT-only workspaces are unaffected,
        and assess keeps its config-bridge fallback for the existing DR-4 fixtures).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WorkspacePath,

        [Parameter(Mandatory)]
        [string]$Prefix,

        [Parameter(Mandatory)]
        [string]$Publisher,

        # The config source for the DESIRED DLP rule/policy set (the Stage-5 re-point seam). When
        # supplied, the resolved desired rules are persisted to desired/resolved/dlp-rules.json so the
        # workspace is self-contained for assess; when absent, no dlp-rules.json is written.
        [string]$ConfigRoot,

        # Optional explicit manifest timestamp. When supplied it is written verbatim (determinism for
        # callers/tests). When omitted, a no-op re-resolve REUSES the prior manifest's stamp (idempotent —
        # see the generatedUtc note below), else the current time is stamped.
        [string]$GeneratedUtc
    )

    $releasePath = Join-Path $WorkspacePath 'desired' 'release'
    $overlayPath = Join-Path $WorkspacePath 'desired' 'overlay'
    $ledgerPath = Join-Path $WorkspacePath 'entity-ledger.json'
    $resolvedPath = Join-Path $WorkspacePath 'desired' 'resolved'

    $release = Import-ContentRelease -Path $releasePath
    $overlay = Import-ContentOverlay -Path $overlayPath -Release $release

    # Ledger maintenance: seed release items, mint adds, align disable state (GUIDs retained).
    Initialize-EntityLedger -Release $release -Path $ledgerPath | Out-Null
    foreach ($add in @($overlay.Add)) {
        Update-EntityLedger -Path $ledgerPath -Add $add.Slug | Out-Null
    }
    $ledgerEntries = (Get-EntityLedger -Path $ledgerPath).Entries
    $disabledSlugs = @($overlay.Disable | ForEach-Object Slug)
    $addedSlugs = @($overlay.Add | ForEach-Object Slug)
    foreach ($entry in $ledgerEntries) {
        $shouldBeDisabled = if ($entry.source -eq 'custom') {
            $addedSlugs -notcontains $entry.slug
        } else {
            $disabledSlugs -contains $entry.slug
        }
        if ($shouldBeDisabled -and $entry.state -eq 'active') {
            Update-EntityLedger -Path $ledgerPath -Disable $entry.slug | Out-Null
        } elseif (-not $shouldBeDisabled -and $entry.state -eq 'disabled') {
            Update-EntityLedger -Path $ledgerPath -Enable $entry.slug | Out-Null
        }
    }
    $ledger = Get-EntityLedger -Path $ledgerPath
    $bindings = @{}
    foreach ($entry in $ledger.Entries) { $bindings[$entry.slug] = $entry.entityId }

    $merged = Merge-DesiredContent -Release $release -Overlay $overlay

    # Render custom fragments with their ledger-minted GUIDs.
    $items = @(foreach ($item in $merged.Items) {
        if ($item.Source -eq 'custom') {
            $fragment = ConvertTo-CustomSitFragment -Definition $item.Definition -EntityId $bindings[$item.Slug]
            [pscustomobject]@{
                Slug           = $item.Slug
                Source         = 'custom'
                EntityId       = $fragment.EntityId
                Name           = $item.Name
                DictionaryRefs = @()
                Sections       = $fragment.Sections
                AttrPatches    = @{}
            }
        } else {
            $item
        }
    })

    # Dictionary budget gate — hard errors abort before anything is composed.
    $usedPlaceholders = @($items | ForEach-Object { $_.DictionaryRefs } | Where-Object { $_ } | Sort-Object -Unique)
    $budget = Test-ContentDictionaryBudget -Dictionaries $release.Dictionaries -UsedPlaceholders $usedPlaceholders
    if (@($budget.Errors).Count -gt 0) {
        throw "Dictionary budget exceeded; resolve aborted: $($budget.Errors -join ' | ')"
    }

    # Packing: sizes are projections from fragment bytes; priors come from the last manifest.
    $itemMap = @{}
    $packItems = @(foreach ($item in $items) {
        $itemMap[$item.Slug] = $item
        $sectionText = @(
            $item.Sections.Entity
            $item.Sections.Regexes; $item.Sections.Keywords
            $item.Sections.Filters; $item.Sections.Validators
            $item.Sections.Resources
        ) -join "`n"
        [pscustomobject]@{
            Slug      = $item.Slug
            SizeBytes = [System.Text.Encoding]::UTF8.GetByteCount($sectionText)
        }
    })

    $manifestPath = Join-Path $resolvedPath 'resolve-manifest.json'
    $prior = $null
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        $priorManifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $prior = @{}
        foreach ($prop in $priorManifest.packing.assignments.PSObject.Properties) {
            $prior[$prop.Name] = $prop.Value
        }
    }

    $assignment = Get-RulePackageAssignment -Items $packItems -Prior $prior -Prefix $Prefix -Tier $release.Tier

    # Compose everything into a staging directory; swap into place only when all packages pass.
    $staging = Join-Path $WorkspacePath 'desired' ".resolved-staging-$PID"
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force -Confirm:$false }
    New-Item -ItemType Directory -Path $staging | Out-Null
    try {
        $hardCap = (Get-DeploymentLimits).MaxRulePackageBytes
        $packagesOut = @(foreach ($package in $assignment.Packages) {
            $packageItems = @($package.Slugs | ForEach-Object { $itemMap[$_] })
            # RulePack ids are ledger-pinned: regenerating desired/resolved from scratch must
            # reproduce the same package GUIDs (§3 pure-function invariant).
            $rulePackId = (Update-EntityLedger -Path $ledgerPath -BindPackage $package.Name).rulePackId
            $composed = ConvertTo-RulePackageXml -Name $package.Name -Items $packageItems `
                -Ledger $ledger -Publisher $Publisher -RulePackId $rulePackId
            if ($composed.SizeBytes -gt $hardCap) {
                throw "Composed package '$($package.Name)' is $($composed.SizeBytes) bytes — over the $hardCap-byte hard cap; resolve aborted."
            }
            $fileName = "$($package.Name).xml"
            $filePath = Join-Path $staging $fileName
            [System.IO.File]::WriteAllBytes($filePath, $composed.Bytes)
            $validation = Test-SITRulePackageXml -FilePath $filePath
            if (-not $validation.Valid) {
                throw "Composed package '$($package.Name)' failed validation: $($validation.Errors -join ' | ')"
            }
            [pscustomobject]@{
                name        = $package.Name
                file        = $fileName
                sha256      = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
                rulePackId  = $rulePackId
                entities    = $composed.EntityCount
                sizeBytes   = $composed.SizeBytes
            }
        })

        $warnings = @()
        foreach ($conflict in @($merged.Conflicts)) {
            $warnings += "conflict:$($conflict.Kind):$($conflict.Slug) — $($conflict.Detail)"
        }
        foreach ($warning in @($budget.Warnings)) { $warnings += "budget:$warning" }
        foreach ($drop in @($assignment.Dropped)) { $warnings += "dropped:$($drop.Slug) — $($drop.Reason)" }

        $hashes = Get-ContentInputHash -ReleasePath $releasePath -OverlayPath $overlayPath -LedgerPath $ledgerPath

        # generatedUtc: desired/resolved is a PURE function of (release, overlay, ledger) — the stamp must
        # not break that. Explicit -GeneratedUtc wins (determinism for callers/tests); else REUSE the prior
        # manifest's stamp when the input hashes are unchanged, so a no-op re-resolve produces byte-identical
        # output and does NOT stale every plan that hashes the manifest (codex rescue review P2); else stamp now.
        $resolvedGeneratedUtc = if (-not [string]::IsNullOrWhiteSpace($GeneratedUtc)) {
            $GeneratedUtc
        } else {
            $priorManifestPath = Join-Path $resolvedPath 'resolve-manifest.json'
            $reuse = $null
            if (Test-Path -LiteralPath $priorManifestPath -PathType Leaf) {
                try {
                    $priorText = Get-Content -LiteralPath $priorManifestPath -Raw
                    $prior = $priorText | ConvertFrom-Json
                    if ($prior.inputs -and
                        [string]$prior.inputs.releaseHash -eq [string]$hashes.ReleaseHash -and
                        [string]$prior.inputs.overlayHash  -eq [string]$hashes.OverlayHash -and
                        [string]$prior.inputs.ledgerHash   -eq [string]$hashes.LedgerHash) {
                        # Extract the generatedUtc value from the RAW TEXT — ConvertFrom-Json coerces the
                        # ISO string into a [datetime], and [string]-casting that re-formats it in local
                        # culture (e.g. '06/15/2026 11:51:17'), corrupting the stamp. The raw value is exact.
                        $gm = [regex]::Match($priorText, '"generatedUtc"\s*:\s*"([^"]*)"')
                        if ($gm.Success) { $reuse = $gm.Groups[1].Value }
                    }
                } catch { $reuse = $null }
            }
            if ($reuse) { $reuse } else { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
        }
        $manifest = [pscustomobject]@{
            schemaVersion = 'compl8.resolve-manifest/v1'
            generatedUtc  = $resolvedGeneratedUtc
            inputs        = [pscustomobject]@{
                releaseVersion = $hashes.ReleaseVersion
                releaseHash    = $hashes.ReleaseHash
                overlayHash    = $hashes.OverlayHash
                ledgerHash     = $hashes.LedgerHash
            }
            packing       = [pscustomobject]@{ assignments = $assignment.Assignments }
            packages      = $packagesOut
            warnings      = $warnings
        }
        $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $staging 'resolve-manifest.json')

        # DLP-rule desired re-point (D7): persist the desired DLP rule/policy set into the workspace
        # so assess reads it from desired/resolved instead of re-resolving config. Written into the
        # SAME staging swap so it lands atomically with the packages + manifest. Each rule carries its
        # Get-DlpRuleContentHash content hash (already computed by Resolve-DesiredDlpRules).
        if ($PSBoundParameters.ContainsKey('ConfigRoot') -and -not [string]::IsNullOrWhiteSpace($ConfigRoot)) {
            $desiredRules = Resolve-DesiredDlpRules -ConfigPath $ConfigRoot
            $dlpRulesDoc = [pscustomobject]@{
                schemaVersion = 'compl8.dlp-rules/v1'
                generatedUtc  = $manifest.generatedUtc
                configRoot    = $ConfigRoot
                rules         = @($desiredRules.Rules)
                policies      = @($desiredRules.Policies)
            }
            $dlpRulesDoc | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $staging 'dlp-rules.json') -Encoding UTF8
        }

        if (Test-Path -LiteralPath $resolvedPath) {
            Remove-Item -LiteralPath $resolvedPath -Recurse -Force -Confirm:$false
        }
        Move-Item -LiteralPath $staging -Destination $resolvedPath
    } catch {
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
        throw
    }

    $manifest
}
