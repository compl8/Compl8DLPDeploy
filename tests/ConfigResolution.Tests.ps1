#Requires -Modules Pester

BeforeAll {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'DLP-Deploy.psm1'
    Import-Module $ModulePath -Force

    function New-TempRoot {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ("cfg-{0}" -f ([guid]::NewGuid().ToString('N')))
        New-Item -ItemType Directory -Path (Join-Path $root 'config') -Force | Out-Null
        '{"namingPrefix":"GLOBAL"}' | Set-Content -LiteralPath (Join-Path $root 'config/settings.json') -Encoding UTF8
        return $root
    }
}

Describe 'Get-EffectiveConfigDir' {
    It 'returns global config when Environment is empty' {
        $root = New-TempRoot
        $r = Get-EffectiveConfigDir -ProjectRoot $root -Environment ''
        $r | Should -Be (Join-Path $root 'config')
        Remove-Item $root -Recurse -Force
    }

    It 'returns global config when no tenant dir exists' {
        $root = New-TempRoot
        $r = Get-EffectiveConfigDir -ProjectRoot $root -Environment 'ecq'
        $r | Should -Be (Join-Path $root 'config')
        Remove-Item $root -Recurse -Force
    }

    It 'returns the tenant dir when it exists' {
        $root = New-TempRoot
        $tenant = Join-Path $root 'config/tenants/ecq'
        New-Item -ItemType Directory -Path $tenant -Force | Out-Null
        $r = Get-EffectiveConfigDir -ProjectRoot $root -Environment 'ecq'
        $r | Should -Be $tenant
        Remove-Item $root -Recurse -Force
    }
}

Describe 'Resolve-ConfigFile' {
    It 'returns the tenant file when present' {
        $root = New-TempRoot
        $tenant = Join-Path $root 'config/tenants/ecq'
        New-Item -ItemType Directory -Path $tenant -Force | Out-Null
        '{"namingPrefix":"ECQ"}' | Set-Content -LiteralPath (Join-Path $tenant 'settings.json') -Encoding UTF8
        $r = Resolve-ConfigFile -ProjectRoot $root -Environment 'ecq' -Name 'settings.json'
        $r | Should -Be (Join-Path $tenant 'settings.json')
        Remove-Item $root -Recurse -Force
    }

    It 'falls back to global when the tenant dir lacks that file' {
        $root = New-TempRoot
        $tenant = Join-Path $root 'config/tenants/ecq'
        New-Item -ItemType Directory -Path $tenant -Force | Out-Null
        $r = Resolve-ConfigFile -ProjectRoot $root -Environment 'ecq' -Name 'labels.json'
        $r | Should -Be (Join-Path $root 'config/labels.json')
        Remove-Item $root -Recurse -Force
    }
}

Describe 'New-TenantConfig.ps1' {
    BeforeAll {
        $script:NewTenantScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts' 'New-TenantConfig.ps1'
    }

    It 'seeds a full copy of the scoped global files' {
        $root = New-TempRoot
        $cfg = Join-Path $root 'config'
        foreach ($f in @('classifiers.json','policies.json','labels.json','tier-assignments.json','rule-overrides.json','tenant-sits.json')) {
            '{}' | Set-Content -LiteralPath (Join-Path $cfg $f) -Encoding UTF8
        }
        '{}' | Set-Content -LiteralPath (Join-Path $cfg 'tenant-fingerprints.json') -Encoding UTF8
        '{}' | Set-Content -LiteralPath (Join-Path $cfg 'last-classifier-upload.json') -Encoding UTF8

        & $script:NewTenantScript -ProjectRoot $root -Environment 'ecq' | Out-Null

        $tenant = Join-Path $cfg 'tenants/ecq'
        (Test-Path (Join-Path $tenant 'classifiers.json')) | Should -BeTrue
        (Test-Path (Join-Path $tenant 'settings.json'))    | Should -BeTrue
        (Test-Path (Join-Path $tenant 'tenant-fingerprints.json'))   | Should -BeFalse
        (Test-Path (Join-Path $tenant 'last-classifier-upload.json')) | Should -BeFalse
        Remove-Item $root -Recurse -Force
    }

    It 'refuses to overwrite an existing tenant dir without -Force' {
        $root = New-TempRoot
        $tenant = Join-Path $root 'config/tenants/ecq'
        New-Item -ItemType Directory -Path $tenant -Force | Out-Null
        { & $script:NewTenantScript -ProjectRoot $root -Environment 'ecq' -ErrorAction Stop } | Should -Throw
        Remove-Item $root -Recurse -Force
    }
}
