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
