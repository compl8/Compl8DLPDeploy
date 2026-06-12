#Requires -Modules Pester

BeforeAll {
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    $script:ContentDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Content'
    $script:FixtureRoot = Join-Path $PSScriptRoot 'fixtures' 'content'
    Import-Module $script:ContentDir -Force
}

Describe 'Get-Compl8WorkspacePath' {
    BeforeEach {
        $script:SavedRoot = $env:COMPL8_WORKSPACE_ROOT
    }
    AfterEach {
        if ($null -ne $script:SavedRoot) { $env:COMPL8_WORKSPACE_ROOT = $script:SavedRoot }
        else { Remove-Item Env:\COMPL8_WORKSPACE_ROOT -ErrorAction SilentlyContinue }
    }

    It 'defaults to <repo>\workspaces when COMPL8_WORKSPACE_ROOT is unset' {
        Remove-Item Env:\COMPL8_WORKSPACE_ROOT -ErrorAction SilentlyContinue
        $expected = Join-Path $script:RepoRoot 'workspaces' 'nonprod'
        Get-Compl8WorkspacePath -Environment nonprod | Should -Be $expected
    }

    It 'honours COMPL8_WORKSPACE_ROOT when set' {
        $env:COMPL8_WORKSPACE_ROOT = Join-Path $TestDrive 'wsroot'
        Get-Compl8WorkspacePath -Environment nonprod |
            Should -Be (Join-Path $TestDrive 'wsroot' 'nonprod')
    }

    It 'joins a forward-slash subpath under the environment' {
        $env:COMPL8_WORKSPACE_ROOT = Join-Path $TestDrive 'wsroot'
        Get-Compl8WorkspacePath -Environment nonprod -Path 'desired/release' |
            Should -Be (Join-Path $TestDrive 'wsroot' 'nonprod' 'desired' 'release')
    }

    It 'creates the directory tree with -EnsureExists' {
        $env:COMPL8_WORKSPACE_ROOT = Join-Path $TestDrive 'wsroot'
        $p = Get-Compl8WorkspacePath -Environment nonprod -Path 'desired/resolved' -EnsureExists
        Test-Path -LiteralPath $p -PathType Container | Should -BeTrue
    }
}
