#==============================================================================
# Convert-ToWorkspace.ps1
#
# Stage 5 / Task 5A-2 (arch design §3 migration mapping; decisions D2, D3).
#
# A ONE-OFF, NON-DESTRUCTIVE migration: reads today's scattered legacy state
# (config/ xml/ reports/ backups/ plans/ logs/) and writes a per-environment
# workspace (workspaces/<env>/) in the Stage-3+ desired/ actual/ history/ model.
# It NEVER moves or deletes any original — every legacy path is COPIED. Precious
# files (provenance registry, package XML, backups) are hash-verified after copy.
# Reversible: delete the workspace, the legacy state is untouched.
#
# One environment per run. Deterministic: the only timestamp is the injected
# -GeneratedUtc (Get-Date / Get-Random are BANNED in this path).
#
#   Convert-ToWorkspace -Environment <env> [-RepoRoot <path>] [-WorkspaceRoot <path>]
#                       [-GeneratedUtc <iso8601>] [-WhatIf] [-Verify] [-Force]
#
# Returns a structured migration report:
#   { workspace; whatIf; copied:[{source,target,sha256,bytes}]; warnings:[]; skipped:[] }
#
# §3 MAPPING (all COPY; originals UNTOUCHED; SHA-256 verify each precious copy):
#   config/tenant-fingerprints.json <env>  -> <ws>/tenant.json            (compl8.tenant/v1)
#   config/tenant-sits.json (flat array)   -> <ws>/actual/inventory.json  (compl8.inventory/v1 partial seed)
#   xml/deploy/*.xml + deploy-registry.json-> <ws>/desired/resolved/      (packages + synthesized resolve-manifest.json)
#   reports/provenance-registry.json       -> <ws>/history/applies/provenance.json (VERBATIM; PRECIOUS)
#   backups/                               -> <ws>/history/snapshots/
#   plans/                                 -> <ws>/history/plans/
#   logs/                                  -> <ws>/history/logs/
#   config/tenants/<env>/                  -> <ws>/desired/overlay/        (D3 auto-diff vs global config)
#   config/last-classifier-upload.json     -> <ws>/history/metadata.json  (informational)
#   entity-ledger                          -> <ws>/entity-ledger.json      (empty stub; first Resolve seeds it)
#
# IDEMPOTENCY / RE-RUN POLICY: refuses if <ws> already exists, UNLESS -Force is
# given. With -Force the target is rebuilt from scratch (the workspace is a
# DERIVED copy of legacy state — never user-authored here — so a clean rebuild is
# safe and the precious copies remain byte-identical to their legacy sources).
#==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Environment,

    # Repo root holding the legacy config/ xml/ reports/ backups/ plans/ logs/.
    # Defaults to the repo this script lives in (scripts/ -> repo root is one up).
    [string]$RepoRoot,

    # Workspace root; the per-env workspace is <WorkspaceRoot>/<Environment>.
    # Defaults to $env:COMPL8_WORKSPACE_ROOT else <RepoRoot>/workspaces.
    [string]$WorkspaceRoot,

    # Migration timestamp written into derived docs (inventory/manifest/metadata).
    # Injected for determinism; Get-Date is banned here.
    [string]$GeneratedUtc,

    # Print the plan and write NOTHING.
    [switch]$WhatIf,

    # Re-hash each copied precious file (provenance, packages, backups) and assert
    # target == source. (A targeted verify always runs for the precious package
    # copies; -Verify extends the assertion to every copied file.)
    [switch]$Verify,

    # Rebuild over an existing workspace (default: refuse if <ws> exists).
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── -Environment safety validation (P1; codex 5A review) ─────────────────────
# MUST run BEFORE the workspace path is computed and BEFORE ANYTHING destructive (the -Force
# recursive delete below). A mistyped -Environment that contains a path separator or '..' would make
# `Join-Path $WorkspaceRoot $Environment` resolve OUTSIDE the intended workspace, and the -Force delete
# could then remove an UNRELATED directory. So the env key is rejected here unless it is a simple safe
# token. Reject when it is: empty/whitespace; contains a path separator ('/' or '\'); contains '..';
# or is not the safe token ^[A-Za-z0-9][A-Za-z0-9._-]*$. The error NAMES the bad value. (A defensive
# under-WorkspaceRoot check on the resolved path follows once the roots are known, below.)
if ([string]::IsNullOrWhiteSpace($Environment)) {
    throw "Convert-ToWorkspace: -Environment is empty/whitespace, which is unsafe (it would not resolve to a per-environment workspace). Supply a simple environment key (e.g. nonprod, ecq)."
}
if ($Environment -match '[\\/]') {
    throw "Convert-ToWorkspace: -Environment '$Environment' is unsafe — it contains a path separator ('/' or '\'). The environment key must be a single path segment so the workspace stays under the workspace root. Supply a simple key (e.g. nonprod)."
}
if ($Environment -match '\.\.') {
    throw "Convert-ToWorkspace: -Environment '$Environment' is unsafe — it contains '..' (parent traversal), which could resolve OUTSIDE the workspace root and let -Force delete an unrelated directory. Supply a simple key (e.g. nonprod)."
}
if ($Environment -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
    throw "Convert-ToWorkspace: -Environment '$Environment' is unsafe — it is not a simple environment key. Use only letters, digits, '.', '_' and '-' (starting with a letter or digit), e.g. nonprod or ecq-1."
}

# ── Module load (helpers live in Compl8.Tenant) ──────────────────────────────
$repoForModules = if ($RepoRoot) { $RepoRoot } else { Split-Path $PSScriptRoot -Parent }
$tenantModule = Join-Path $repoForModules 'modules' 'Compl8.Tenant'
if (-not (Test-Path -LiteralPath $tenantModule)) {
    # Fall back to the script's own repo when -RepoRoot points at a bare fixture tree.
    $tenantModule = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'Compl8.Tenant'
}
Import-Module $tenantModule -Force

# ── Resolve roots ────────────────────────────────────────────────────────────
if (-not $RepoRoot)      { $RepoRoot = Split-Path $PSScriptRoot -Parent }
if (-not $WorkspaceRoot) {
    $WorkspaceRoot = if ($env:COMPL8_WORKSPACE_ROOT) { $env:COMPL8_WORKSPACE_ROOT } else { Join-Path $RepoRoot 'workspaces' }
}
$workspacePath = Join-Path $WorkspaceRoot $Environment

# ── Defensive containment check (P1; belt-and-braces over the token validation above) ────────
# Confirm the resolved workspace path is STRICTLY under the workspace root before anything destructive
# can touch it. Compare NORMALISED full paths (GetFullPath collapses any '.'/'..' segments) so even a
# pathological -WorkspaceRoot/-Environment combination cannot point the -Force delete outside the root.
$normalizedRoot = [System.IO.Path]::GetFullPath($WorkspaceRoot)
$normalizedWs   = [System.IO.Path]::GetFullPath($workspacePath)
$rootPrefix = $normalizedRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
if (-not $normalizedWs.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Convert-ToWorkspace: the resolved workspace path '$normalizedWs' (for -Environment '$Environment') is unsafe — it is NOT strictly under the workspace root '$normalizedRoot'. Refusing before any destructive operation."
}

$configRoot = Join-Path $RepoRoot 'config'

# ── Report accumulators ──────────────────────────────────────────────────────
$copied   = [System.Collections.Generic.List[object]]::new()
$warnings = [System.Collections.Generic.List[string]]::new()
$skipped  = [System.Collections.Generic.List[string]]::new()

function Get-Sha256Hex {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# Record a planned/performed copy of a single FILE. In -WhatIf the source is
# hashed (cheap, read-only) and nothing is written; otherwise the file is copied,
# then (always for precious, or when -Verify) the target is re-hashed and asserted
# byte-identical to the source.
function Add-CopyFile {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Target,
        [switch]$Precious
    )
    $srcHash  = Get-Sha256Hex -Path $Source
    $srcBytes = (Get-Item -LiteralPath $Source).Length
    if (-not $WhatIf) {
        $dir = Split-Path -Parent $Target
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        Copy-Item -LiteralPath $Source -Destination $Target -Force
        if ($Precious -or $Verify) {
            $dstHash = Get-Sha256Hex -Path $Target
            if ($dstHash -ne $srcHash) {
                throw "Hash mismatch after copy: '$Source' ($srcHash) != '$Target' ($dstHash). Migration aborted."
            }
        }
    }
    $copied.Add([pscustomobject]@{
        source = $Source
        target = $Target
        sha256 = $srcHash
        bytes  = [int64]$srcBytes
    }) | Out-Null
}

# Write a DERIVED (non-precious) JSON document. Skips the write in -WhatIf but
# still records the intent in the report (target + the size it would be).
function Write-DerivedJson {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Target,
        [int]$Depth = 12
    )
    $json = $Object | ConvertTo-Json -Depth $Depth
    $bytes = [System.Text.Encoding]::UTF8.GetByteCount($json)
    if (-not $WhatIf) {
        $dir = Split-Path -Parent $Target
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        Set-Content -LiteralPath $Target -Value $json -Encoding UTF8
    }
    $copied.Add([pscustomobject]@{
        source = '(derived)'
        target = $Target
        sha256 = $null
        bytes  = [int64]$bytes
    }) | Out-Null
}

# Copy a directory TREE file-by-file (so each copy is hash-trackable). Missing
# source => recorded as skipped, not an error.
function Add-CopyTree {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Label,
        [switch]$Precious
    )
    if (-not (Test-Path -LiteralPath $Source)) {
        $skipped.Add("$Label — source '$Source' does not exist; skipped.") | Out-Null
        return
    }
    $files = @(Get-ChildItem -LiteralPath $Source -Recurse -File -ErrorAction SilentlyContinue)
    if (-not $WhatIf -and -not (Test-Path -LiteralPath $Target)) {
        New-Item -ItemType Directory -Path $Target -Force | Out-Null
    }
    foreach ($file in $files) {
        $relative = $file.FullName.Substring($Source.Length).TrimStart('\', '/')
        $dest = Join-Path $Target $relative
        Add-CopyFile -Source $file.FullName -Target $dest -Precious:$Precious
    }
    if ($files.Count -eq 0) {
        $skipped.Add("$Label — source '$Source' is empty; directory created, nothing copied.") | Out-Null
    }
}

# ── Pre-flight: re-run policy (D2 idempotency) ───────────────────────────────
if ((Test-Path -LiteralPath $workspacePath) -and -not $WhatIf) {
    if ($Force) {
        # The workspace is a DERIVED copy of legacy state (never user-authored
        # here), so a clean rebuild is safe. Remove only the target workspace dir.
        Remove-Item -LiteralPath $workspacePath -Recurse -Force -Confirm:$false
    } else {
        throw "Workspace '$workspacePath' already exists. Re-run with -Force to rebuild it (it is a derived copy of legacy state), or remove it first."
    }
}

# ── (1) tenant.json from the fingerprint env entry + settings prefix ──────────
$fingerprintPath = Join-Path $configRoot 'tenant-fingerprints.json'
if (-not (Test-Path -LiteralPath $fingerprintPath)) {
    throw "config/tenant-fingerprints.json not found at '$fingerprintPath' — cannot resolve the tenant pin for '$Environment'."
}
$fingerprints = Get-Content -LiteralPath $fingerprintPath -Raw | ConvertFrom-Json
$envProp = $null
if ($fingerprints.PSObject.Properties['environments'] -and $fingerprints.environments) {
    $envProp = $fingerprints.environments.PSObject.Properties | Where-Object { $_.Name -eq $Environment } | Select-Object -First 1
}
if (-not $envProp) {
    $available = if ($fingerprints.PSObject.Properties['environments'] -and $fingerprints.environments) {
        @($fingerprints.environments.PSObject.Properties.Name) -join ', '
    } else { '(none)' }
    throw "tenant-fingerprints.json has no entry for environment '$Environment'. Available: $available."
}

# Prefix + settings from config/settings.json (the single source today).
$prefix = $null
$settings = $null
$settingsPath = Join-Path $configRoot 'settings.json'
if (Test-Path -LiteralPath $settingsPath) {
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    if ($settings.PSObject.Properties['namingPrefix'] -and $settings.namingPrefix) {
        $prefix = [string]$settings.namingPrefix
    }
}
$tenantJson = New-WorkspaceTenantJson -Environment $Environment -FingerprintEntry $envProp.Value `
    -Prefix $prefix -Settings $settings
Write-DerivedJson -Object $tenantJson -Target (Join-Path $workspacePath 'tenant.json')

# ── (2) actual/inventory.json — flat SIT array -> compl8.inventory/v1 seed ────
$sitsPath = Join-Path $configRoot 'tenant-sits.json'
if (Test-Path -LiteralPath $sitsPath) {
    $flatSits = @(Get-Content -LiteralPath $sitsPath -Raw | ConvertFrom-Json)
    $inventory = ConvertFrom-LegacyTenantSits -Sits $flatSits -Prefix $prefix -GeneratedUtc $GeneratedUtc
    Write-DerivedJson -Object $inventory -Target (Join-Path $workspacePath 'actual' 'inventory.json')
} else {
    $skipped.Add("inventory — source '$sitsPath' does not exist; actual/inventory.json not seeded.") | Out-Null
}

# ── (3) desired/resolved — copy xml/deploy/*.xml + synthesize resolve-manifest ─
$deployDir = Join-Path (Join-Path $RepoRoot 'xml') 'deploy'
$resolvedDir = Join-Path (Join-Path $workspacePath 'desired') 'resolved'
if (Test-Path -LiteralPath $deployDir) {
    $packageFiles = @(Get-ChildItem -LiteralPath $deployDir -Filter '*.xml' -File -ErrorAction SilentlyContinue | Sort-Object Name)

    # deploy-registry.json supplies tier + per-package {key, entities, sizeKB}.
    $registry = $null
    $registryPath = Join-Path $deployDir 'deploy-registry.json'
    if (Test-Path -LiteralPath $registryPath) {
        $registry = Get-Content -LiteralPath $registryPath -Raw | ConvertFrom-Json
    } else {
        $warnings.Add("desired/resolved — no deploy-registry.json at '$registryPath'; resolve-manifest packages will lack tier/entity metadata.") | Out-Null
    }
    $registryByKey = @{}
    if ($registry -and $registry.PSObject.Properties['packages'] -and $registry.packages) {
        foreach ($pkg in @($registry.packages)) {
            if ($pkg.PSObject.Properties['key'] -and $pkg.key) { $registryByKey[[string]$pkg.key] = $pkg }
        }
    }

    $manifestPackages = [System.Collections.Generic.List[object]]::new()
    foreach ($file in $packageFiles) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $dest = Join-Path $resolvedDir $file.Name
        # Packages are PRECIOUS — verify the byte-for-byte copy.
        Add-CopyFile -Source $file.FullName -Target $dest -Precious
        $sha = Get-Sha256Hex -Path $file.FullName
        $reg = if ($registryByKey.ContainsKey($name)) { $registryByKey[$name] } else { $null }
        $entities = if ($reg -and $reg.PSObject.Properties['entities']) { [int]$reg.entities } else { $null }
        $sizeBytes = (Get-Item -LiteralPath $file.FullName).Length
        $manifestPackages.Add([pscustomobject]([ordered]@{
            name       = $name
            file       = $file.Name
            sha256     = $sha
            rulePackId = $null
            entities   = $entities
            sizeBytes  = [int64]$sizeBytes
        })) | Out-Null
    }

    # Synthesize a compl8.resolve-manifest/v1 manifest (the Resolve-DesiredContent shape).
    # This is a MIGRATION manifest: the packing assignments + input hashes are not
    # reconstructable from legacy state, so they are left empty and the manifest is
    # marked .source='migration' so a later Resolve-DesiredContent run is known to
    # be the authoritative regeneration.
    $tier = if ($registry -and $registry.PSObject.Properties['tier']) { [string]$registry.tier } else { $null }
    $manifest = [pscustomobject]([ordered]@{
        schemaVersion = 'compl8.resolve-manifest/v1'
        generatedUtc  = if ($GeneratedUtc) { $GeneratedUtc } else { $null }
        source        = 'migration'
        tier          = $tier
        inputs        = [pscustomobject]([ordered]@{
            releaseVersion = $null
            releaseHash    = $null
            overlayHash    = $null
            ledgerHash     = $null
        })
        packing       = [pscustomobject]@{ assignments = [pscustomobject]@{} }
        packages      = @($manifestPackages)
        warnings      = @('migration seed: packing assignments + input hashes are not reconstructable from legacy state; regenerate with Resolve-DesiredContent.')
    })
    Write-DerivedJson -Object $manifest -Target (Join-Path $resolvedDir 'resolve-manifest.json')
} else {
    $skipped.Add("desired/resolved — source '$deployDir' does not exist; no packages copied.") | Out-Null
}

# ── (4) provenance registry — VERBATIM precious copy ─────────────────────────
$provenanceSrc = Join-Path (Join-Path $RepoRoot 'reports') 'provenance-registry.json'
if (Test-Path -LiteralPath $provenanceSrc) {
    $provenanceDst = Join-Path (Join-Path (Join-Path $workspacePath 'history') 'applies') 'provenance.json'
    Add-CopyFile -Source $provenanceSrc -Target $provenanceDst -Precious
} else {
    $skipped.Add("history/applies/provenance.json — source '$provenanceSrc' does not exist; skipped.") | Out-Null
}

# ── (5) history trees: backups -> snapshots, plans, logs ─────────────────────
Add-CopyTree -Source (Join-Path $RepoRoot 'backups') `
    -Target (Join-Path (Join-Path $workspacePath 'history') 'snapshots') -Label 'history/snapshots (backups/)' -Precious
Add-CopyTree -Source (Join-Path $RepoRoot 'plans') `
    -Target (Join-Path (Join-Path $workspacePath 'history') 'plans') -Label 'history/plans (plans/)'
Add-CopyTree -Source (Join-Path $RepoRoot 'logs') `
    -Target (Join-Path (Join-Path $workspacePath 'history') 'logs') -Label 'history/logs (logs/)'

# ── (6) overlay (D3 auto-diff vs global config) ──────────────────────────────
# Diff each per-tenant config file against the GLOBAL config/<same>.json:
#   identical (the common case)  -> empty overlay.json + release ref note
#   differs                      -> raw file into overlay/_unmapped/<file> + WARN
$overlayDir = Join-Path (Join-Path $workspacePath 'desired') 'overlay'
$perTenantDir = Join-Path (Join-Path $configRoot 'tenants') $Environment
$overlayHadUnmapped = $false
if (Test-Path -LiteralPath $perTenantDir) {
    $perTenantFiles = @(Get-ChildItem -LiteralPath $perTenantDir -File -ErrorAction SilentlyContinue | Sort-Object Name)
    foreach ($file in $perTenantFiles) {
        $globalCounterpart = Join-Path $configRoot $file.Name
        $isIdentity = $false
        if (Test-Path -LiteralPath $globalCounterpart) {
            $isIdentity = ((Get-Sha256Hex -Path $file.FullName) -eq (Get-Sha256Hex -Path $globalCounterpart))
        }
        if (-not $isIdentity) {
            # Real divergence — never guess a translation; quarantine + warn (D3).
            $overlayHadUnmapped = $true
            $unmappedTarget = Join-Path (Join-Path $overlayDir '_unmapped') $file.Name
            Add-CopyFile -Source $file.FullName -Target $unmappedTarget
            $why = if (Test-Path -LiteralPath $globalCounterpart) { 'differs from the global config' } else { 'has no global counterpart' }
            $warnings.Add("overlay — per-tenant '$($file.Name)' $why; written to desired/overlay/_unmapped/$($file.Name) for review (NOT auto-translated).") | Out-Null
        }
    }
} else {
    $skipped.Add("overlay — no per-tenant config dir at '$perTenantDir'; emitting an empty overlay.") | Out-Null
}

# Always write an empty compl8.overlay/v1 (the common case is no customisation).
# It records the migration release ref so the workspace validates as an empty overlay.
$overlay = [pscustomobject]([ordered]@{
    schemaVersion = 'compl8.overlay/v1'
    releaseRef    = [pscustomobject]([ordered]@{ source = 'migration'; environment = $Environment; generatedUtc = if ($GeneratedUtc) { $GeneratedUtc } else { $null } })
    add           = @()
    override      = @()
    disable       = @()
})
Write-DerivedJson -Object $overlay -Target (Join-Path $overlayDir 'overlay.json')

# ── (7) history/metadata.json — last-classifier-upload (informational) ───────
$metaSrc = Join-Path $configRoot 'last-classifier-upload.json'
if (Test-Path -LiteralPath $metaSrc) {
    Add-CopyFile -Source $metaSrc -Target (Join-Path (Join-Path $workspacePath 'history') 'metadata.json')
} else {
    $skipped.Add("history/metadata.json — source '$metaSrc' does not exist; skipped.") | Out-Null
}

# ── (8) entity-ledger.json — empty stub (first Resolve-DesiredContent seeds it) ─
# Per §3: the real ledger seed is idempotent and happens on the first
# Resolve-DesiredContent. Writing an empty stub here lets the workspace validate.
$ledgerStub = [pscustomobject]([ordered]@{
    schemaVersion = 'compl8.entity-ledger/v1'
    entries       = @()
    packages      = @()
})
Write-DerivedJson -Object $ledgerStub -Target (Join-Path $workspacePath 'entity-ledger.json') -Depth 5

# ── Report ───────────────────────────────────────────────────────────────────
[pscustomobject]([ordered]@{
    workspace = $workspacePath
    whatIf    = [bool]$WhatIf
    copied    = @($copied)
    warnings  = @($warnings)
    skipped   = @($skipped)
})
