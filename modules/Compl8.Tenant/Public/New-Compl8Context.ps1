function New-Compl8Context {
    <#
    .SYNOPSIS
        Resolves a Compl8 deployment context — the single tenant-boundary object that replaces the
        hand-threaded 7-field bundle (-UPN -Tenant -TargetEnvironment -Prefix -Delegated
        -RegisterFingerprint -FingerprintMode [+ -ExpectedTenantId]).
    .DESCRIPTION
        Stage 5 / D1, D4, D7, D8. PURE resolution: reads files only, never calls a live tenant
        (no Get-OrganizationConfig / Get-ConnectionInformation). The fingerprint mode and tenant pin
        are RESOLVED here; ENFORCING them against a connected tenant remains the job of
        Test-DeploymentTenantFingerprint downstream. The context is deterministic — same inputs
        produce a byte-identical object — so no Get-Date / Get-Random.

        Resolution sources (in order, via Get-Compl8TenantPin):
          1. A workspace tenant.json (compl8.tenant/v1) at <WorkspacePath>/tenant.json.
          2. Else the legacy config/tenant-fingerprints.json env entry, with the prefix synthesized
             from config/settings.json (namingPrefix) — the migration-window fallback before
             Convert-ToWorkspace (Task 5A-2) writes a workspace tenant.json.

        Workspace-path layering (deliberate): Compl8.Tenant does NOT import Compl8.Content (a SIBLING
        layer — both sit above Compl8.Model). Get-Compl8WorkspacePath (Content) remains the canonical
        resolver for the surface, but its rule is trivial — $env:COMPL8_WORKSPACE_ROOT else
        <repo>/workspaces, then /<env> — so it is reproduced inline here to avoid a cross-layer import.
        The SURFACE is free to pass a pre-resolved -WorkspaceRoot it obtained from Get-Compl8WorkspacePath.

        tenant.json (compl8.tenant/v1) schema:
          {
            "schemaVersion": "compl8.tenant/v1",
            "environment":   "<env>",
            "identity":   { "tenantId": "<guid>", "prefix": "<namingPrefix>" },
            "fingerprint":{ "mode": "warn" | "block" },
            "settings":   { "namingSuffix": "...", ... },
            "engineRoutes": { "dictionary": false, "label": false, "rulePackage": false,
                              "dlpRule": false, "autoLabel": false }   # optional (D4); absent => all false
          }

        Returned context object (PSCustomObject):
          Environment            the target environment key
          WorkspacePath          <WorkspaceRoot>/<env>  (the resolved workspace dir)
          TenantId               the pinned tenant GUID
          Prefix                 effective naming prefix (-Prefix override wins)
          FingerprintMode        'warn' | 'block'
          UPN                    operator UPN (pass-through, may be $null)
          Delegated              [bool] delegated-auth flag
          DesiredRoot            <WorkspacePath>/desired/resolved  (D7 re-point target; path-only)
          ProvenanceRegistryPath <WorkspacePath>/history/applies/provenance.json (D8; path-only, NOT created)
          EngineRoutes           PSCustomObject { dictionary; label; rulePackage; dlpRule; autoLabel }
                                 (D4) — default ALL false; honoured from tenant.json when present.
    .PARAMETER TargetEnvironment
        Environment key (e.g. nonprod, ecq). Drives both the workspace path and the tenant pin lookup.
    .PARAMETER WorkspaceRoot
        Override for the workspace root. When omitted: $env:COMPL8_WORKSPACE_ROOT else <repo>/workspaces.
    .PARAMETER ConfigRoot
        Override for the legacy config root (tenant-fingerprints.json / settings.json) used only on
        the fallback path. Defaults to <repo>/config.
    .PARAMETER Prefix
        Naming-prefix override. Wins over the tenant.json / settings.json prefix when supplied.
    .PARAMETER UPN
        Operator user principal name carried on the context (pass-through to the connect step).
    .PARAMETER Delegated
        Marks delegated (interactive) auth on the context.
    .EXAMPLE
        $ctx = New-Compl8Context -TargetEnvironment nonprod
        Invoke-Compl8Assess -Context $ctx
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$TargetEnvironment,

        [string]$WorkspaceRoot,

        [string]$ConfigRoot,

        [string]$Prefix,

        [string]$UPN,

        [switch]$Delegated
    )

    # ── Workspace path (inline; mirrors Get-Compl8WorkspacePath, no cross-layer import) ──
    $root = if ($WorkspaceRoot) {
        $WorkspaceRoot
    } elseif ($env:COMPL8_WORKSPACE_ROOT) {
        $env:COMPL8_WORKSPACE_ROOT
    } else {
        # This file lives at modules/Compl8.Tenant/Public/ — repo root is three levels up.
        $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
        Join-Path $repoRoot 'workspaces'
    }
    $workspacePath = Join-Path $root $TargetEnvironment

    # ── Tenant pin (tenant.json → fingerprint fallback). Throws when neither has the env. ──
    $pinArgs = @{ Environment = $TargetEnvironment; WorkspacePath = $workspacePath }
    if ($ConfigRoot) { $pinArgs['ConfigRoot'] = $ConfigRoot }
    $pin = Get-Compl8TenantPin @pinArgs

    # ── Effective prefix: -Prefix override wins over the resolved pin prefix. ──
    $effectivePrefix = if (-not [string]::IsNullOrWhiteSpace($Prefix)) { $Prefix.Trim() } else { $pin.Prefix }

    # ── EngineRoutes (D4): all-false default; merge a tenant.json engineRoutes block over it. ──
    $routes = [ordered]@{
        dictionary  = $false
        label       = $false
        rulePackage = $false
        dlpRule     = $false
        autoLabel   = $false
    }
    if ($pin.EngineRoutes) {
        foreach ($key in @($routes.Keys)) {
            $prop = $pin.EngineRoutes.PSObject.Properties | Where-Object { $_.Name -eq $key } | Select-Object -First 1
            if ($prop) { $routes[$key] = [bool]$prop.Value }
        }
    }

    # ── Workspace-relative path computations (D7 desired re-point, D8 provenance re-point). ──
    #     Path-only — neither is created here.
    $desiredRoot            = Join-Path (Join-Path $workspacePath 'desired') 'resolved'
    $provenanceRegistryPath = Join-Path (Join-Path (Join-Path $workspacePath 'history') 'applies') 'provenance.json'

    [pscustomobject]([ordered]@{
        Environment            = $TargetEnvironment
        WorkspacePath          = $workspacePath
        TenantId               = $pin.TenantId
        Prefix                 = $effectivePrefix
        FingerprintMode        = $pin.FingerprintMode
        UPN                    = if ([string]::IsNullOrWhiteSpace($UPN)) { $null } else { $UPN }
        Delegated              = [bool]$Delegated
        DesiredRoot            = $desiredRoot
        ProvenanceRegistryPath = $provenanceRegistryPath
        EngineRoutes           = [pscustomobject]$routes
    })
}
