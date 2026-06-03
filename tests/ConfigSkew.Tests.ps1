#Requires -Modules Pester

BeforeAll {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'DLP-Deploy.psm1'
    Import-Module $ModulePath -Force
    function J([string]$s) { $s | ConvertFrom-Json }
}

Describe 'Compare-JsonStructure' {
    It 'returns nothing for identical objects' {
        $a = J '{"x":1,"y":{"z":2}}'
        $b = J '{"x":1,"y":{"z":2}}'
        @(Compare-JsonStructure -Left $a -Right $b).Count | Should -Be 0
    }

    It 'detects a changed scalar with a dotted path' {
        $a = J '{"y":{"z":2}}'
        $b = J '{"y":{"z":9}}'
        $d = @(Compare-JsonStructure -Left $a -Right $b)
        $d.Count | Should -Be 1
        $d[0].path | Should -Be 'y.z'
        $d[0].kind | Should -Be 'changed'
        $d[0].global | Should -Be 2
        $d[0].tenant | Should -Be 9
    }

    It 'detects a key added in tenant (Right)' {
        $a = J '{"x":1}'
        $b = J '{"x":1,"new":5}'
        $d = @(Compare-JsonStructure -Left $a -Right $b)
        $d.Count | Should -Be 1
        $d[0].path | Should -Be 'new'
        $d[0].kind | Should -Be 'added'
    }

    It 'detects a key removed in tenant' {
        $a = J '{"x":1,"gone":7}'
        $b = J '{"x":1}'
        $d = @(Compare-JsonStructure -Left $a -Right $b)
        $d.Count | Should -Be 1
        $d[0].path | Should -Be 'gone'
        $d[0].kind | Should -Be 'removed'
    }

    It 'treats a differing array as a single changed leaf' {
        $a = J '{"list":[1,2,3]}'
        $b = J '{"list":[1,2,4]}'
        $d = @(Compare-JsonStructure -Left $a -Right $b)
        $d.Count | Should -Be 1
        $d[0].path | Should -Be 'list'
        $d[0].kind | Should -Be 'changed'
    }
}

Describe 'Compare-TenantConfigSkew' {
    BeforeAll {
        function New-SkewRoot {
            $root = Join-Path ([System.IO.Path]::GetTempPath()) ("skew-{0}" -f ([guid]::NewGuid().ToString('N')))
            New-Item -ItemType Directory -Path (Join-Path $root 'config') -Force | Out-Null
            return $root
        }
    }

    It 'returns empty when no tenant dir exists' {
        $root = New-SkewRoot
        '{"a":1}' | Set-Content -LiteralPath (Join-Path $root 'config/classifiers.json') -Encoding UTF8
        @(Compare-TenantConfigSkew -ProjectRoot $root -Environment 'ecq').Count | Should -Be 0
        Remove-Item $root -Recurse -Force
    }

    It 'reports a changed value in a tenant override' {
        $root = New-SkewRoot
        $cfg = Join-Path $root 'config'
        $tenant = Join-Path $cfg 'tenants/ecq'
        New-Item -ItemType Directory -Path $tenant -Force | Out-Null
        '{"namingPrefix":"GLOBAL"}' | Set-Content -LiteralPath (Join-Path $cfg 'settings.json') -Encoding UTF8
        '{"namingPrefix":"ECQ"}'    | Set-Content -LiteralPath (Join-Path $tenant 'settings.json') -Encoding UTF8

        $skew = @(Compare-TenantConfigSkew -ProjectRoot $root -Environment 'ecq')
        $skew.Count | Should -Be 1
        $skew[0].file | Should -Be 'settings.json'
        $skew[0].path | Should -Be 'namingPrefix'
        $skew[0].kind | Should -Be 'changed'
        Remove-Item $root -Recurse -Force
    }

    It 'ignores files the tenant does not override' {
        $root = New-SkewRoot
        $cfg = Join-Path $root 'config'
        $tenant = Join-Path $cfg 'tenants/ecq'
        New-Item -ItemType Directory -Path $tenant -Force | Out-Null
        '{"a":1}' | Set-Content -LiteralPath (Join-Path $cfg 'labels.json') -Encoding UTF8
        '{"namingPrefix":"GLOBAL"}' | Set-Content -LiteralPath (Join-Path $cfg 'settings.json') -Encoding UTF8
        '{"namingPrefix":"GLOBAL"}' | Set-Content -LiteralPath (Join-Path $tenant 'settings.json') -Encoding UTF8

        @(Compare-TenantConfigSkew -ProjectRoot $root -Environment 'ecq').Count | Should -Be 0
        Remove-Item $root -Recurse -Force
    }
}
