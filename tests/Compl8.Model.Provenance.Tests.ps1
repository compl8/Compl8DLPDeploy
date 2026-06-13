#Requires -Modules Pester

<#
.SYNOPSIS
    Standalone tests for the provenance stamp generation functions ported into Compl8.Model
    (architecture decision D3 — enables the Compl8.Engine apply executors to stamp provenance).

    These tests import ONLY Compl8.Model — never DLP-Deploy — to prove the moved functions work
    with NO dependency on the legacy DLP-Deploy module scope. The companion facade tests in
    tests/DLP-Deploy.Tests.ps1 cover the dot-sourced-into-DLP-Deploy path; this file covers the
    standalone Engine-scope path.

    The provenance registry is isolated to a per-test temp file (via $TestDrive and the
    COMPL8_PROVENANCE_REGISTRY env var) so these tests never touch the real
    reports/provenance-registry.json.
#>

BeforeAll {
    Remove-Module DLP-Deploy -ErrorAction SilentlyContinue
    $script:ModelDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'Compl8.Model'
    Import-Module $script:ModelDir -Force

    # Save any outer registry override so it can be restored after the run.
    $script:OuterRegistry = $env:COMPL8_PROVENANCE_REGISTRY
}

AfterAll {
    if ($null -ne $script:OuterRegistry) {
        $env:COMPL8_PROVENANCE_REGISTRY = $script:OuterRegistry
    } else {
        Remove-Item Env:\COMPL8_PROVENANCE_REGISTRY -ErrorAction SilentlyContinue
    }
}

Describe 'Compl8.Model provenance exports (standalone, no DLP-Deploy)' {
    It 'does not have DLP-Deploy loaded' {
        Get-Module DLP-Deploy | Should -BeNullOrEmpty
    }

    It 'exports all seven provenance functions from Compl8.Model' {
        $exported = Get-Command -Module Compl8.Model | Select-Object -ExpandProperty Name
        foreach ($name in @(
            'New-DeploymentProvenanceId',
            'Read-DeploymentProvenanceRegistry',
            'Set-DeploymentProvenanceRegistryEntry',
            'Get-DeploymentProvenanceRegistryEntry',
            'New-DeploymentProvenanceStamp',
            'Get-DeploymentProvenanceStamp',
            'Add-DeploymentProvenanceStamp'
        )) {
            $exported | Should -Contain $name
        }
    }

    It 'keeps the internal path/decode helpers private (not exported)' {
        $exported = Get-Command -Module Compl8.Model | Select-Object -ExpandProperty Name
        $exported | Should -Not -Contain 'Resolve-DeploymentProvenanceRegistryPath'
        $exported | Should -Not -Contain 'ConvertFrom-DeploymentProvenanceFieldValue'
    }
}

Describe 'Compl8.Model provenance round-trip (standalone, no DLP-Deploy)' {
    BeforeEach {
        # Isolate the registry to a throwaway file under TestDrive so the repo registry is untouched.
        $script:RegistryPath = Join-Path $TestDrive ("prov-{0}.json" -f ([guid]::NewGuid().ToString('N')))
        $env:COMPL8_PROVENANCE_REGISTRY = $script:RegistryPath
    }
    AfterEach {
        Remove-Item Env:\COMPL8_PROVENANCE_REGISTRY -ErrorAction SilentlyContinue
    }

    It 'Add-DeploymentProvenanceStamp produces a short opaque marker' {
        $stamp = Add-DeploymentProvenanceStamp -Text 'Managed rule' -Prefix 'QGISCF' -Component 'DlpRule' -DeploymentId 'd-1'
        $stamp | Should -Match '\[\[Compl8:[0-9a-f]{16}\]\]'
        $stamp | Should -Not -Match 'provenance'
        $stamp | Should -Match '^Managed rule'
    }

    It 'Get-DeploymentProvenanceStamp reads the stamp back via the registry (full round-trip)' {
        $stamp = Add-DeploymentProvenanceStamp -Text 'Managed rule' -Prefix 'QGISCF' -Component 'DlpRule' `
            -DeploymentId 'd-1' -TargetEnvironment 'nonprod' -Metadata @{ LabelCode = 'SENS_Fin' }

        $parsed = Get-DeploymentProvenanceStamp -Text $stamp
        $parsed.Found             | Should -BeTrue
        $parsed.Resolved          | Should -BeTrue
        $parsed.Toolkit           | Should -Be 'Compl8DLPDeploy'
        $parsed.Prefix            | Should -Be 'QGISCF'
        $parsed.Component         | Should -Be 'DlpRule'
        $parsed.DeploymentId      | Should -Be 'd-1'
        $parsed.TargetEnvironment | Should -Be 'nonprod'
        $parsed.Fields.LabelCode  | Should -Be 'SENS_Fin'
    }

    It 'writes the registry to the isolated TestDrive path, not the repo' {
        New-DeploymentProvenanceStamp -Prefix 'QGISCF' -Component 'DlpRule' -DeploymentId 'd-1' | Out-Null
        Test-Path -LiteralPath $script:RegistryPath | Should -BeTrue
    }

    It 'New-DeploymentProvenanceId is deterministic for identical fields' {
        $a = New-DeploymentProvenanceId -Fields ([ordered]@{ prefix = 'QGISCF'; component = 'DlpRule'; deploymentId = 'd-1' })
        $b = New-DeploymentProvenanceId -Fields ([ordered]@{ prefix = 'QGISCF'; component = 'DlpRule'; deploymentId = 'd-1' })
        $a | Should -Be $b
        $a | Should -Match '^[0-9a-f]{16}$'
    }

    It 'Read/Set/Get registry entry helpers work standalone against an explicit path' {
        $explicit = Join-Path $TestDrive ("explicit-{0}.json" -f ([guid]::NewGuid().ToString('N')))
        Set-DeploymentProvenanceRegistryEntry -Id 'abc123' -Entry ([ordered]@{ prefix = 'P'; component = 'C' }) -RegistryPath $explicit
        $reg = Read-DeploymentProvenanceRegistry -RegistryPath $explicit
        $reg.entries.Contains('abc123') | Should -BeTrue
        (Get-DeploymentProvenanceRegistryEntry -Id 'abc123' -RegistryPath $explicit).prefix | Should -Be 'P'
    }

    It 'decodes a legacy long-form marker without a registry (private decode helper resolves)' {
        $legacy = '[[Compl8DLPDeploy:provenance:v1;prefix=QGISCF;component=DlpRule;deploymentId=one;environment=nonprod]]'
        $parsed = Get-DeploymentProvenanceStamp -Text "Human comment`n$legacy"
        $parsed.Found             | Should -BeTrue
        $parsed.Resolved          | Should -BeTrue
        $parsed.Prefix            | Should -Be 'QGISCF'
        $parsed.TargetEnvironment | Should -Be 'nonprod'
    }
}
