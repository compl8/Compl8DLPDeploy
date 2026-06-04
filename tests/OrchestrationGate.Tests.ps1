#Requires -Modules Pester

BeforeAll {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'DLP-Deploy.psm1'
    Import-Module $ModulePath -Force
}

Describe 'Assert-OrchestrationGate' {
    BeforeEach { Remove-Item Env:\COMPL8_ORCHESTRATED -ErrorAction SilentlyContinue }
    AfterEach  { Remove-Item Env:\COMPL8_ORCHESTRATED -ErrorAction SilentlyContinue }

    It 'returns silently when COMPL8_ORCHESTRATED is set' {
        $env:COMPL8_ORCHESTRATED = '1'
        { Assert-OrchestrationGate -ScriptName 'X' } | Should -Not -Throw
    }
    It 'returns silently with -AllowDirectRun' {
        { Assert-OrchestrationGate -ScriptName 'X' -AllowDirectRun } | Should -Not -Throw
    }
    It 'returns silently with a non-empty -SessionPath' {
        { Assert-OrchestrationGate -ScriptName 'X' -SessionPath 'C:\s' } | Should -Not -Throw
    }
    It 'throws on a raw non-interactive run, mentioning -AllowDirectRun' {
        Mock -ModuleName DLP-Deploy Test-IsInteractive { $false }
        { Assert-OrchestrationGate -ScriptName 'X' } | Should -Throw '*AllowDirectRun*'
    }
    It 'throws when interactive and the user declines' {
        Mock -ModuleName DLP-Deploy Test-IsInteractive { $true }
        Mock -ModuleName DLP-Deploy Read-Host { 'n' }
        { Assert-OrchestrationGate -ScriptName 'X' } | Should -Throw
    }
    It 'returns when interactive and the user confirms' {
        Mock -ModuleName DLP-Deploy Test-IsInteractive { $true }
        Mock -ModuleName DLP-Deploy Read-Host { 'y' }
        { Assert-OrchestrationGate -ScriptName 'X' } | Should -Not -Throw
    }
}
