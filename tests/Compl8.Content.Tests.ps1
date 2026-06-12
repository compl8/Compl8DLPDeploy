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

Describe 'Import-ContentRelease' {
    BeforeAll {
        $script:MiniRelease = Join-Path $script:FixtureRoot 'mini-release'

        function Copy-MiniRelease {
            param([string]$Name)
            $dest = Join-Path $TestDrive $Name
            Copy-Item -LiteralPath $script:MiniRelease -Destination $dest -Recurse
            $dest
        }
    }

    It 'loads the mini release with items in release order' {
        $r = Import-ContentRelease -Path $script:MiniRelease
        $r.Version | Should -Be '2026.06-test.1'
        @($r.Items.Keys) | Should -Be @('bail-note', 'name-dict', 'shared-a', 'shared-b')
        $r.Items['bail-note'].Sections.Entity |
            Should -Match '^<Entity id="11111111-aaaa-4bbb-8ccc-000000000001"'
        $r.Items['bail-note'].Sections.Keywords.Count | Should -Be 2
        $r.Items['name-dict'].DictionaryRefs | Should -Contain '{{DICT_AU_FORENAMES}}'
        $r.ContentHash | Should -Match '^sha256:'
        @($r.Dictionaries).Count | Should -Be 2
    }

    It 'rejects a directory without release.json' {
        $empty = Join-Path $TestDrive 'not-a-release'
        New-Item -ItemType Directory -Path $empty | Out-Null
        { Import-ContentRelease -Path $empty } | Should -Throw '*release.json*'
    }

    It 'rejects an unknown schemaVersion' {
        $dir = Copy-MiniRelease 'rel-badschema'
        $manifestPath = Join-Path $dir 'release.json'
        $json = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $json.schemaVersion = 'compl8.release/v999'
        $json | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath
        { Import-ContentRelease -Path $dir } | Should -Throw '*schemaVersion*'
    }

    It 'rejects a release item whose fragment file is missing' {
        $dir = Copy-MiniRelease 'rel-nofragment'
        Remove-Item -LiteralPath (Join-Path $dir 'fragments' 'shared-b.json') -Confirm:$false
        { Import-ContentRelease -Path $dir } | Should -Throw '*fragment*'
    }

    It 'rejects an entityId mismatch between release item and fragment (corruption guard)' {
        $dir = Copy-MiniRelease 'rel-idmismatch'
        $fragPath = Join-Path $dir 'fragments' 'name-dict.json'
        $frag = Get-Content -LiteralPath $fragPath -Raw | ConvertFrom-Json
        $frag.entityId = '99999999-aaaa-4bbb-8ccc-999999999999'
        $frag | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $fragPath
        { Import-ContentRelease -Path $dir } | Should -Throw '*entityId*'
    }

    It 'rejects a dictionaryRef absent from the dictionaries manifest' {
        $dir = Copy-MiniRelease 'rel-baddictref'
        $manifestPath = Join-Path $dir 'release.json'
        $json = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $json.items[1].dictionaryRefs = @('{{DICT_DOES_NOT_EXIST}}')
        $json | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath
        { Import-ContentRelease -Path $dir } | Should -Throw '*DICT_DOES_NOT_EXIST*'
    }
}
