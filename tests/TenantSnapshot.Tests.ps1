#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'modules/DLP-Deploy.psm1') -Force
}

Describe 'Write-TenantConfigSnapshot' {
    BeforeAll {
        $script:Root = Join-Path ([IO.Path]::GetTempPath()) "snap-$([guid]::NewGuid().Guid)"
        New-Item -ItemType Directory -Path $script:Root -Force | Out-Null
        $script:Src = Join-Path $script:Root 'srcconfig'
        New-Item -ItemType Directory -Path $script:Src -Force | Out-Null
        '{"namingPrefix":"QGISCF"}' | Set-Content -LiteralPath (Join-Path $script:Src 'settings.json') -Encoding UTF8
        '{"a":1}'                   | Set-Content -LiteralPath (Join-Path $script:Src 'policies.json') -Encoding UTF8
        $script:Dest = Join-Path $script:Root 'dest'
    }
    AfterAll { if (Test-Path $script:Root) { Remove-Item $script:Root -Recurse -Force } }

    It 'captures classifier XML, all live sections, copied config files, and a manifest' {
        $xmlBytes = [System.Text.Encoding]::Unicode.GetBytes('<RulePack><x/></RulePack>')
        $packages = @(
            [pscustomobject]@{ Name = 'QGISCF-medium-01'; Identity = 'abc-123'; SerializedClassificationRuleCollection = $xmlBytes }
            [pscustomobject]@{ Name = 'NoXmlPkg';        Identity = 'def-456'; SerializedClassificationRuleCollection = $null }
        )
        # rebuild-grade: dlp + labels + dictionaries + sit inventory (IRM later = another section)
        $sections = [ordered]@{
            'dlp-policies'        = @([pscustomobject]@{ Name = 'P01' })
            'dlp-rules'           = @([pscustomobject]@{ Name = 'R01' }, [pscustomobject]@{ Name = 'R02' })
            'labels'              = @([pscustomobject]@{ Name = 'OFFICIAL'; EncryptionEnabled = $true })
            'label-policies'      = @([pscustomobject]@{ Name = 'Label-Policy' })
            'keyword-dictionaries'= @([pscustomobject]@{ Name = 'AU Forenames' })
            'sit-inventory'       = @([pscustomobject]@{ Name = 'Legal Full Name' })
        }
        $info = [ordered]@{ name = 'Contoso'; tenantId = 'de93acc9-777c-4ac2-bbd6-262fe9063bf5' }
        $fileCopies = @(
            @{ Source = (Join-Path $script:Src 'settings.json'); Dest = 'config/settings.json' }
            @{ Source = (Join-Path $script:Src 'policies.json');  Dest = 'config/policies.json' }
            @{ Source = (Join-Path $script:Src 'missing.json');   Dest = 'config/missing.json' }   # absent -> skipped
        )

        $res = Write-TenantConfigSnapshot -DestinationRoot $script:Dest -Environment 'nonprod' -Timestamp '20260608_120000' `
            -Packages $packages -LiveSections $sections -TenantInfo $info -FileCopies $fileCopies

        $res.SnapshotPath    | Should -Exist
        $res.ClassifierCount | Should -Be 1
        $res.FileCount       | Should -Be 2          # missing.json skipped
        $res.Sections['dlp-rules'] | Should -Be 2
        $res.Sections['labels']    | Should -Be 1

        $snap = $res.SnapshotPath

        # classifier xml bytes preserved exactly
        $xmlFile = @(Get-ChildItem (Join-Path $snap 'classifiers') -Filter *.xml)
        $xmlFile.Count | Should -Be 1
        [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($xmlFile[0].FullName)) |
            Should -Be ([Convert]::ToBase64String($xmlBytes))

        # every live section is a parseable json array under live/
        @(Get-Content -Raw (Join-Path $snap 'live/dlp-rules.json')            | ConvertFrom-Json).Count | Should -Be 2
        @(Get-Content -Raw (Join-Path $snap 'live/labels.json')               | ConvertFrom-Json).Count | Should -Be 1
        @(Get-Content -Raw (Join-Path $snap 'live/keyword-dictionaries.json') | ConvertFrom-Json).Count | Should -Be 1
        # IRM/encryption fields survive the label dump
        (Get-Content -Raw (Join-Path $snap 'live/labels.json') | ConvertFrom-Json)[0].EncryptionEnabled | Should -BeTrue

        # config copied — only files that existed
        (Join-Path $snap 'config/settings.json') | Should -Exist
        (Join-Path $snap 'config/policies.json') | Should -Exist
        (Join-Path $snap 'config/missing.json')  | Should -Not -Exist

        # manifest
        $m = Get-Content -Raw (Join-Path $snap 'snapshot-manifest.json') | ConvertFrom-Json
        $m.tenant.tenantId             | Should -Be 'de93acc9-777c-4ac2-bbd6-262fe9063bf5'
        $m.generatedUtc                | Should -Be '20260608_120000'
        $m.counts.classifiersCaptured  | Should -Be 1
        $m.counts.filesCopied          | Should -Be 2
        $m.sections.'dlp-rules'        | Should -Be 2
        $m.sections.'labels'           | Should -Be 1
    }

    It 'handles empty packages, sections, and copies without error' {
        $res = Write-TenantConfigSnapshot -DestinationRoot $script:Dest -Environment '' -Timestamp '20260608_130000' `
            -Packages @() -LiveSections ([ordered]@{}) -TenantInfo $null -FileCopies @()

        $res.SnapshotPath    | Should -Exist
        $res.ClassifierCount | Should -Be 0
        $res.FileCount       | Should -Be 0
        (Split-Path $res.SnapshotPath -Leaf) | Should -BeLike 'default-*'   # blank env -> 'default'
    }
}
