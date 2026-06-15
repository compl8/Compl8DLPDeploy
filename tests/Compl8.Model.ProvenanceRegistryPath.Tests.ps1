#Requires -Modules Pester

# Task 5A-3 PART 2 — provenance registry path re-points to the workspace (D8).
#
# Resolve-DeploymentProvenanceRegistryPath today defaults to <repo>/reports/provenance-registry.json.
# It now PREFERS <WorkspacePath>/history/applies/provenance.json when a workspace is supplied
# (one-writer: the Engine writes history/). Back-compat is preserved: without -WorkspacePath the
# precedence is unchanged (explicit -RegistryPath > $env:COMPL8_PROVENANCE_REGISTRY > repo default).
#
# The helper is private to Compl8.Model, so these tests exercise it via InModuleScope.

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    Remove-Module DLP-Deploy -ErrorAction SilentlyContinue
    $script:ModelDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'Compl8.Model'
    Import-Module $script:ModelDir -Force
    $script:OuterRegistry = $env:COMPL8_PROVENANCE_REGISTRY
}

AfterAll {
    if ($null -ne $script:OuterRegistry) { $env:COMPL8_PROVENANCE_REGISTRY = $script:OuterRegistry }
    else { Remove-Item Env:\COMPL8_PROVENANCE_REGISTRY -ErrorAction SilentlyContinue }
}

Describe 'Resolve-DeploymentProvenanceRegistryPath — workspace re-point (D8)' {
    BeforeEach {
        # Clear any outer env override so the precedence tests are deterministic.
        Remove-Item Env:\COMPL8_PROVENANCE_REGISTRY -ErrorAction SilentlyContinue
    }

    It 'returns <ws>/history/applies/provenance.json when -WorkspacePath is supplied' {
        InModuleScope Compl8.Model {
            $ws = Join-Path ([System.IO.Path]::GetTempPath()) 'ws-prov-A'
            $expected = Join-Path $ws 'history' 'applies' 'provenance.json'
            Resolve-DeploymentProvenanceRegistryPath -WorkspacePath $ws | Should -Be $expected
        }
    }

    It 'the workspace path wins over an explicit -RegistryPath and the env var' {
        InModuleScope Compl8.Model {
            $env:COMPL8_PROVENANCE_REGISTRY = 'C:\env\registry.json'
            $ws = Join-Path ([System.IO.Path]::GetTempPath()) 'ws-prov-B'
            $expected = Join-Path $ws 'history' 'applies' 'provenance.json'
            Resolve-DeploymentProvenanceRegistryPath -WorkspacePath $ws -RegistryPath 'C:\explicit\registry.json' |
                Should -Be $expected
            Remove-Item Env:\COMPL8_PROVENANCE_REGISTRY -ErrorAction SilentlyContinue
        }
    }

    It 'preserves today behaviour when no workspace is given: explicit -RegistryPath wins' {
        InModuleScope Compl8.Model {
            Resolve-DeploymentProvenanceRegistryPath -RegistryPath 'C:\explicit\registry.json' |
                Should -Be 'C:\explicit\registry.json'
        }
    }

    It 'preserves today behaviour when no workspace is given: env var is next' {
        InModuleScope Compl8.Model {
            $env:COMPL8_PROVENANCE_REGISTRY = 'C:\env\registry.json'
            Resolve-DeploymentProvenanceRegistryPath | Should -Be 'C:\env\registry.json'
            Remove-Item Env:\COMPL8_PROVENANCE_REGISTRY -ErrorAction SilentlyContinue
        }
    }

    It 'preserves today behaviour when no workspace is given: repo default last' {
        InModuleScope Compl8.Model {
            $resolved = Resolve-DeploymentProvenanceRegistryPath
            $resolved | Should -Match 'reports[\\/]provenance-registry\.json$'
        }
    }
}
