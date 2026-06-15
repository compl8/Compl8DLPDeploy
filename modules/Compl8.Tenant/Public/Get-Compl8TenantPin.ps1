function Get-Compl8TenantPin {
    <#
    .SYNOPSIS
        Resolves a tenant pin (tenantId + fingerprint mode + prefix + engineRoutes) for an
        environment from a workspace tenant.json, falling back to config/tenant-fingerprints.json.
    .DESCRIPTION
        Pure resolution — reads files only, never calls a live tenant. This is the source layer
        underneath New-Compl8Context (D1): it decides WHERE the pin came from and returns the raw
        fields. New-Compl8Context layers the workspace-relative paths and override semantics on top.

        Resolution order:
          1. <WorkspacePath>/tenant.json  (compl8.tenant/v1) when present.
          2. <ConfigRoot>/tenant-fingerprints.json env entry, with the prefix synthesized from
             <ConfigRoot>/settings.json (namingPrefix). Used during the migration window before a
             workspace has its own tenant.json (Convert-ToWorkspace writes it later — Task 5A-2).

        tenant.json (compl8.tenant/v1) schema:
          {
            "schemaVersion": "compl8.tenant/v1",
            "environment":   "<env>",
            "identity":   { "tenantId": "<guid>", "prefix": "<namingPrefix>" },
            "fingerprint":{ "mode": "warn" | "block" },
            "settings":   { "namingSuffix": "...", ... },   # free-form deployment settings
            "engineRoutes": { "dictionary": false, "label": false, "rulePackage": false,
                              "dlpRule": false, "autoLabel": false }   # optional (D4); absent => all false
          }

        Returns a hashtable: @{ Source; TenantId; FingerprintMode; Prefix; EngineRoutes; Settings }
        where Source is 'tenant.json' or 'tenant-fingerprints.json'. EngineRoutes is the raw block
        from tenant.json (or $null when absent); the all-false default is applied by the caller.
        Throws when neither source carries an entry for the environment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Environment,

        [Parameter(Mandatory)]
        [string]$WorkspacePath,

        # Legacy config root holding tenant-fingerprints.json + settings.json. Used only for the
        # fallback path; defaults to <repo>/config when omitted.
        [string]$ConfigRoot
    )

    $tenantJsonPath = Join-Path $WorkspacePath 'tenant.json'

    # ── Source 1: workspace tenant.json (compl8.tenant/v1) ────────────────────────
    if (Test-Path -LiteralPath $tenantJsonPath) {
        try {
            $doc = Get-Content -LiteralPath $tenantJsonPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        } catch {
            throw "tenant.json at '$tenantJsonPath' could not be parsed: $($_.Exception.Message)"
        }

        $schema = if ($doc.schemaVersion) { $doc.schemaVersion.ToString() } else { '' }
        if ($schema -ne 'compl8.tenant/v1') {
            throw "tenant.json at '$tenantJsonPath' has unsupported schemaVersion '$schema'; expected 'compl8.tenant/v1'."
        }

        $tenantId = if ($doc.identity) { $doc.identity.tenantId } else { $null }
        $prefix   = if ($doc.identity) { $doc.identity.prefix } else { $null }
        $mode     = if ($doc.fingerprint -and $doc.fingerprint.mode) { $doc.fingerprint.mode.ToString().ToLowerInvariant() } else { 'warn' }

        return @{
            Source          = 'tenant.json'
            TenantId        = if ($tenantId) { $tenantId.ToString() } else { $null }
            FingerprintMode = $mode
            Prefix          = if ($prefix) { $prefix.ToString() } else { $null }
            EngineRoutes    = $doc.engineRoutes
            Settings        = $doc.settings
        }
    }

    # ── Source 2: legacy config/tenant-fingerprints.json env entry ────────────────
    if (-not $ConfigRoot) {
        # This file lives at modules/Compl8.Tenant/Public/ — repo root is three levels up.
        $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
        $ConfigRoot = Join-Path $repoRoot 'config'
    }

    $fingerprintPath = Join-Path $ConfigRoot 'tenant-fingerprints.json'
    if (-not (Test-Path -LiteralPath $fingerprintPath)) {
        throw "No tenant pin for environment '$Environment': no tenant.json at '$tenantJsonPath' and no config/tenant-fingerprints.json at '$fingerprintPath'."
    }

    try {
        $config = Get-Content -LiteralPath $fingerprintPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "config/tenant-fingerprints.json at '$fingerprintPath' could not be parsed: $($_.Exception.Message)"
    }

    $envProp = $null
    if ($config.environments) {
        $envProp = $config.environments.PSObject.Properties | Where-Object { $_.Name -eq $Environment } | Select-Object -First 1
    }
    if (-not $envProp) {
        $available = if ($config.environments) { @($config.environments.PSObject.Properties.Name) -join ', ' } else { '(none)' }
        throw "No tenant pin for environment '$Environment': no tenant.json at '$tenantJsonPath', and tenant-fingerprints.json has no entry for '$Environment'. Available: $available."
    }

    $entry = $envProp.Value
    $mode  = if ($entry.mode) { $entry.mode.ToString().ToLowerInvariant() } else { 'warn' }

    # Prefix is synthesized from settings.json (namingPrefix) — the single source today.
    $prefix = $null
    $settingsPath = Join-Path $ConfigRoot 'settings.json'
    if (Test-Path -LiteralPath $settingsPath) {
        try {
            $settings = Get-Content -LiteralPath $settingsPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($settings.namingPrefix) { $prefix = $settings.namingPrefix.ToString() }
        } catch {
            throw "config/settings.json at '$settingsPath' could not be parsed: $($_.Exception.Message)"
        }
    }

    return @{
        Source          = 'tenant-fingerprints.json'
        TenantId        = if ($entry.tenantId) { $entry.tenantId.ToString() } else { $null }
        FingerprintMode = $mode
        Prefix          = $prefix
        EngineRoutes    = $null
        Settings        = $null
    }
}
