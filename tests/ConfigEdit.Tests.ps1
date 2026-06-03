#Requires -Modules Pester

BeforeAll {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'DLP-Deploy.psm1'
    Import-Module $ModulePath -Force
}

Describe 'ConvertTo-ConfigValue' {
    It 'parses integers'  { ConvertTo-ConfigValue -Raw '42'   | Should -Be 42 }
    It 'parses booleans'  { ConvertTo-ConfigValue -Raw 'true' | Should -BeTrue }
    It 'parses null'      { ConvertTo-ConfigValue -Raw 'null' | Should -Be $null }
    It 'keeps plain text' { ConvertTo-ConfigValue -Raw 'large' | Should -Be 'large' }
    It 'parses JSON arrays' {
        $v = ConvertTo-ConfigValue -Raw '[1,2,3]'
        @($v).Count | Should -Be 3
    }
}

Describe 'Set-JsonValue' {
    It 'sets an existing top-level key' {
        $o = '{"a":1}' | ConvertFrom-Json
        $r = Set-JsonValue -InputObject $o -Path 'a' -Value 5
        $r.a | Should -Be 5
    }
    It 'creates a nested key' {
        $o = [pscustomobject]@{}
        $r = Set-JsonValue -InputObject $o -Path 'x.y.z' -Value 'hi'
        $r.x.y.z | Should -Be 'hi'
    }
    It 'updates a nested key without dropping siblings' {
        $o = '{"x":{"keep":1,"z":2}}' | ConvertFrom-Json
        $r = Set-JsonValue -InputObject $o -Path 'x.z' -Value 9
        $r.x.z | Should -Be 9
        $r.x.keep | Should -Be 1
    }
}

Describe 'Set-ConfigValue' {
    It 'writes a value into a config file and round-trips' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("cedit-{0}" -f ([guid]::NewGuid().ToString('N')))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        '{"namingPrefix":"X"}' | Set-Content -LiteralPath (Join-Path $dir 'settings.json') -Encoding UTF8
        Set-ConfigValue -ConfigDir $dir -File 'settings.json' -Path 'namingPrefix' -Value 'ECQ' | Out-Null
        (Get-Content -Raw (Join-Path $dir 'settings.json') | ConvertFrom-Json).namingPrefix | Should -Be 'ECQ'
        Remove-Item $dir -Recurse -Force
    }
}

Describe 'Copy-GlobalConfigToTenant' {
    It 'overwrites the tenant file with the global one' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ("cpull-{0}" -f ([guid]::NewGuid().ToString('N')))
        $cfg = Join-Path $root 'config'
        $tenant = Join-Path $cfg 'tenants/ecq'
        New-Item -ItemType Directory -Path $tenant -Force | Out-Null
        '{"v":"GLOBAL"}' | Set-Content -LiteralPath (Join-Path $cfg 'labels.json') -Encoding UTF8
        '{"v":"OLD"}'    | Set-Content -LiteralPath (Join-Path $tenant 'labels.json') -Encoding UTF8
        Copy-GlobalConfigToTenant -ProjectRoot $root -Environment 'ecq' -File 'labels.json' | Out-Null
        (Get-Content -Raw (Join-Path $tenant 'labels.json') | ConvertFrom-Json).v | Should -Be 'GLOBAL'
        Remove-Item $root -Recurse -Force
    }

    It 'throws when the tenant dir does not exist' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ("cpull2-{0}" -f ([guid]::NewGuid().ToString('N')))
        New-Item -ItemType Directory -Path (Join-Path $root 'config') -Force | Out-Null
        '{"v":1}' | Set-Content -LiteralPath (Join-Path $root 'config/labels.json') -Encoding UTF8
        { Copy-GlobalConfigToTenant -ProjectRoot $root -Environment 'ecq' -File 'labels.json' -ErrorAction Stop } | Should -Throw
        Remove-Item $root -Recurse -Force
    }
}
