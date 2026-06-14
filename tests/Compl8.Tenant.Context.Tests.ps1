#Requires -Modules Pester

# Task 5A-1 (Stage 5 / D1, D4, D7, D8): New-Compl8Context — the tenant-boundary
# resolution function that replaces the hand-threaded 7-field deployment bundle.
# Pure resolution (no live tenant call): a workspace tenant.json (compl8.tenant/v1) when
# present, else the legacy config/tenant-fingerprints.json env entry (synthesized).

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0
    $script:TenantDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'Compl8.Tenant'
    # Isolation: DLP-Deploy's facade may claim ownership of these names; remove it so the
    # Compl8.Tenant standalone import is authoritative (same pattern as Compl8.Tenant.Tests.ps1).
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:TenantDir -Force

    # Helper: write a compl8.tenant/v1 tenant.json into a workspace dir.
    function script:New-TenantJsonFixture {
        param(
            [Parameter(Mandatory)][string]$WorkspacePath,
            [Parameter(Mandatory)][string]$Environment,
            [string]$TenantId = 'de93acc9-777c-4ac2-bbd6-262fe9063bf5',
            [string]$Prefix = 'QGISCF',
            [string]$Mode = 'block',
            [hashtable]$EngineRoutes
        )
        New-Item -ItemType Directory -Path $WorkspacePath -Force | Out-Null
        $obj = [ordered]@{
            schemaVersion = 'compl8.tenant/v1'
            environment   = $Environment
            identity      = [ordered]@{ tenantId = $TenantId; prefix = $Prefix }
            fingerprint   = [ordered]@{ mode = $Mode }
            settings      = [ordered]@{ namingSuffix = 'EXT-ADT' }
        }
        if ($EngineRoutes) { $obj['engineRoutes'] = $EngineRoutes }
        $obj | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $WorkspacePath 'tenant.json') -Encoding UTF8
    }

    # Helper: write a legacy config/tenant-fingerprints.json (real shape) + a settings.json.
    function script:New-LegacyConfigFixture {
        param(
            [Parameter(Mandatory)][string]$ConfigRoot,
            [string]$DefaultEnvironment = 'ecq',
            [hashtable]$Environments = @{ nonprod = @{ mode = 'block'; tenantId = 'de93acc9-777c-4ac2-bbd6-262fe9063bf5' } },
            [string]$NamingPrefix = 'QGISCF'
        )
        New-Item -ItemType Directory -Path $ConfigRoot -Force | Out-Null
        $fp = [ordered]@{ defaultEnvironment = $DefaultEnvironment; environments = [ordered]@{} }
        foreach ($k in $Environments.Keys) { $fp.environments[$k] = $Environments[$k] }
        $fp | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $ConfigRoot 'tenant-fingerprints.json') -Encoding UTF8
        ([ordered]@{ namingPrefix = $NamingPrefix; namingSuffix = 'EXT-ADT' } | ConvertTo-Json) |
            Set-Content -LiteralPath (Join-Path $ConfigRoot 'settings.json') -Encoding UTF8
    }
}

Describe 'New-Compl8Context' {

    Context 'resolution from a workspace tenant.json (compl8.tenant/v1)' {
        BeforeEach {
            $script:Root = Join-Path $TestDrive ([guid]::NewGuid().Guid)
            $script:WsRoot = Join-Path $script:Root 'workspaces'
            $script:Env = 'nonprod'
            $script:WsPath = Join-Path $script:WsRoot $script:Env
            New-TenantJsonFixture -WorkspacePath $script:WsPath -Environment $script:Env `
                -TenantId 'de93acc9-777c-4ac2-bbd6-262fe9063bf5' -Prefix 'QGISCF' -Mode 'block'
        }

        It 'resolves a full context from the tenant.json' {
            $ctx = New-Compl8Context -TargetEnvironment $script:Env -WorkspaceRoot $script:WsRoot
            $ctx.Environment     | Should -Be 'nonprod'
            $ctx.WorkspacePath   | Should -Be $script:WsPath
            $ctx.TenantId        | Should -Be 'de93acc9-777c-4ac2-bbd6-262fe9063bf5'
            $ctx.Prefix          | Should -Be 'QGISCF'
            $ctx.FingerprintMode | Should -Be 'block'
        }

        It 'computes DesiredRoot and ProvenanceRegistryPath as workspace-relative paths' {
            $ctx = New-Compl8Context -TargetEnvironment $script:Env -WorkspaceRoot $script:WsRoot
            $ctx.DesiredRoot             | Should -Be (Join-Path $script:WsPath 'desired' | Join-Path -ChildPath 'resolved')
            $ctx.ProvenanceRegistryPath  | Should -Be (Join-Path (Join-Path (Join-Path $script:WsPath 'history') 'applies') 'provenance.json')
        }

        It 'does not create the DesiredRoot or provenance file (path-only)' {
            $ctx = New-Compl8Context -TargetEnvironment $script:Env -WorkspaceRoot $script:WsRoot
            Test-Path -LiteralPath $ctx.DesiredRoot            | Should -BeFalse
            Test-Path -LiteralPath $ctx.ProvenanceRegistryPath | Should -BeFalse
        }

        It 'carries UPN and Delegated when supplied' {
            $ctx = New-Compl8Context -TargetEnvironment $script:Env -WorkspaceRoot $script:WsRoot `
                -UPN 'nathan@aairii.com' -Delegated
            $ctx.UPN       | Should -Be 'nathan@aairii.com'
            $ctx.Delegated | Should -BeTrue
        }

        It 'defaults Delegated to false and UPN to null when not supplied' {
            $ctx = New-Compl8Context -TargetEnvironment $script:Env -WorkspaceRoot $script:WsRoot
            $ctx.Delegated | Should -BeFalse
            $ctx.UPN       | Should -BeNullOrEmpty
        }
    }

    Context 'EngineRoutes (D4) — the per-object-type cutover toggle' {
        BeforeEach {
            $script:Root = Join-Path $TestDrive ([guid]::NewGuid().Guid)
            $script:WsRoot = Join-Path $script:Root 'workspaces'
            $script:WsPath = Join-Path $script:WsRoot 'nonprod'
        }

        It 'defaults every cutover route to false and exposes the 5 keys' {
            New-TenantJsonFixture -WorkspacePath $script:WsPath -Environment 'nonprod'
            $ctx = New-Compl8Context -TargetEnvironment 'nonprod' -WorkspaceRoot $script:WsRoot
            $keys = @('dictionary', 'label', 'rulePackage', 'dlpRule', 'autoLabel')
            foreach ($k in $keys) {
                $ctx.EngineRoutes.PSObject.Properties.Name | Should -Contain $k
                $ctx.EngineRoutes.$k | Should -BeFalse
            }
            @($ctx.EngineRoutes.PSObject.Properties.Name).Count | Should -Be 5
        }

        It 'honours an engineRoutes block in tenant.json (partial overrides merge over the all-false default)' {
            New-TenantJsonFixture -WorkspacePath $script:WsPath -Environment 'nonprod' `
                -EngineRoutes @{ dictionary = $true; label = $true }
            $ctx = New-Compl8Context -TargetEnvironment 'nonprod' -WorkspaceRoot $script:WsRoot
            $ctx.EngineRoutes.dictionary  | Should -BeTrue
            $ctx.EngineRoutes.label       | Should -BeTrue
            $ctx.EngineRoutes.rulePackage | Should -BeFalse
            $ctx.EngineRoutes.dlpRule     | Should -BeFalse
            $ctx.EngineRoutes.autoLabel   | Should -BeFalse
        }
    }

    Context 'fallback to legacy config/tenant-fingerprints.json (no tenant.json present)' {
        BeforeEach {
            $script:Root = Join-Path $TestDrive ([guid]::NewGuid().Guid)
            $script:WsRoot = Join-Path $script:Root 'workspaces'
            $script:ConfigRoot = Join-Path $script:Root 'config'
            $script:WsPath = Join-Path $script:WsRoot 'nonprod'
            New-Item -ItemType Directory -Path $script:WsPath -Force | Out-Null   # workspace exists, no tenant.json
            New-LegacyConfigFixture -ConfigRoot $script:ConfigRoot `
                -Environments @{ nonprod = @{ mode = 'block'; tenantId = 'de93acc9-777c-4ac2-bbd6-262fe9063bf5'; name = 'Contoso' } } `
                -NamingPrefix 'QGISCF'
        }

        It 'synthesizes the context from the fingerprint env entry + settings prefix' {
            $ctx = New-Compl8Context -TargetEnvironment 'nonprod' -WorkspaceRoot $script:WsRoot -ConfigRoot $script:ConfigRoot
            $ctx.Environment     | Should -Be 'nonprod'
            $ctx.TenantId        | Should -Be 'de93acc9-777c-4ac2-bbd6-262fe9063bf5'
            $ctx.FingerprintMode | Should -Be 'block'
            $ctx.Prefix          | Should -Be 'QGISCF'
        }

        It 'falls back with all EngineRoutes false' {
            $ctx = New-Compl8Context -TargetEnvironment 'nonprod' -WorkspaceRoot $script:WsRoot -ConfigRoot $script:ConfigRoot
            $ctx.EngineRoutes.dictionary | Should -BeFalse
            @($ctx.EngineRoutes.PSObject.Properties.Name).Count | Should -Be 5
        }
    }

    Context 'overrides win' {
        BeforeEach {
            $script:Root = Join-Path $TestDrive ([guid]::NewGuid().Guid)
            $script:WsRoot = Join-Path $script:Root 'workspaces'
            $script:WsPath = Join-Path $script:WsRoot 'nonprod'
            New-TenantJsonFixture -WorkspacePath $script:WsPath -Environment 'nonprod' -Prefix 'QGISCF'
        }

        It '-Prefix overrides the tenant.json prefix' {
            $ctx = New-Compl8Context -TargetEnvironment 'nonprod' -WorkspaceRoot $script:WsRoot -Prefix 'OVERRIDE'
            $ctx.Prefix | Should -Be 'OVERRIDE'
        }

        It '-WorkspaceRoot drives the workspace path (override of the default root)' {
            $ctx = New-Compl8Context -TargetEnvironment 'nonprod' -WorkspaceRoot $script:WsRoot
            $ctx.WorkspacePath | Should -Be $script:WsPath
        }
    }

    Context 'error handling' {
        It 'throws a clear error when neither tenant.json nor a fingerprint entry exists for the env' {
            $root = Join-Path $TestDrive ([guid]::NewGuid().Guid)
            $wsRoot = Join-Path $root 'workspaces'
            $configRoot = Join-Path $root 'config'
            New-Item -ItemType Directory -Path (Join-Path $wsRoot 'nonprod') -Force | Out-Null
            New-LegacyConfigFixture -ConfigRoot $configRoot `
                -Environments @{ ecq = @{ mode = 'block'; tenantId = 'a0ecd844-047a-45c9-8f3f-0a09574d15d2' } }
            { New-Compl8Context -TargetEnvironment 'nonprod' -WorkspaceRoot $wsRoot -ConfigRoot $configRoot } |
                Should -Throw "*nonprod*"
        }

        It 'throws when no tenant.json and no config at all' {
            $root = Join-Path $TestDrive ([guid]::NewGuid().Guid)
            $wsRoot = Join-Path $root 'workspaces'
            New-Item -ItemType Directory -Path (Join-Path $wsRoot 'nonprod') -Force | Out-Null
            { New-Compl8Context -TargetEnvironment 'nonprod' -WorkspaceRoot $wsRoot -ConfigRoot (Join-Path $root 'config') } |
                Should -Throw "*nonprod*"
        }
    }

    Context 'determinism — same inputs, identical context' {
        It 'produces an identical context object for identical inputs (deep compare)' {
            $root = Join-Path $TestDrive ([guid]::NewGuid().Guid)
            $wsRoot = Join-Path $root 'workspaces'
            $wsPath = Join-Path $wsRoot 'nonprod'
            New-TenantJsonFixture -WorkspacePath $wsPath -Environment 'nonprod' `
                -EngineRoutes @{ dictionary = $true }
            $a = New-Compl8Context -TargetEnvironment 'nonprod' -WorkspaceRoot $wsRoot -UPN 'nathan@aairii.com' -Delegated
            $b = New-Compl8Context -TargetEnvironment 'nonprod' -WorkspaceRoot $wsRoot -UPN 'nathan@aairii.com' -Delegated
            ($a | ConvertTo-Json -Depth 10) | Should -Be ($b | ConvertTo-Json -Depth 10)
        }
    }
}
