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
