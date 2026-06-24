#Requires -Modules Pester
BeforeAll {
    $repo = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $repo 'modules' 'Compl8.Content') -Force
}
Describe 'ConvertTo-RulePackageXml UTF-16 sizing' {
    BeforeAll {
        $script:items = @([pscustomobject]@{
            Slug = 'x-test'; EntityId = '11111111-1111-1111-1111-111111111111'
            Sections = [pscustomobject]@{
                Entity = '<Entity id="11111111-1111-1111-1111-111111111111"><Pattern confidenceLevel="75"><IdMatch idRef="Regex_x" /></Pattern></Entity>'
                Regexes = @('<Regex id="Regex_x">abc</Regex>'); Keywords=@(); Filters=@(); Validators=@()
                Resources = @('<Resource idRef="11111111-1111-1111-1111-111111111111"><Name default="true" langcode="en-us">X</Name></Resource>')
            }
            AttrPatches = @{}
        })
        $script:ledger = [pscustomobject]@{ Path='(mem)'; Entries=@([pscustomobject]@{ slug='x-test'; entityId='11111111-1111-1111-1111-111111111111'; state='active'; source='release' }) }
    }
    It 'reports Utf16SizeBytes ~2x the UTF-8 size, with Bytes still UTF-8' {
        $c = ConvertTo-RulePackageXml -Name 'P-test-01' -Items $script:items -Ledger $script:ledger -Publisher 'Pub' -RulePackId '22222222-2222-2222-2222-222222222222'
        $c.SizeBytes | Should -Be $c.Bytes.Length            # UTF-8 file unchanged
        $c.Utf16SizeBytes | Should -BeGreaterThan $c.SizeBytes
        $c.Utf16SizeBytes | Should -Be ([System.Text.Encoding]::Unicode.GetByteCount($c.Text))
    }
}
