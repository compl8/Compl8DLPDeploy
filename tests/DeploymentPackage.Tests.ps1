#Requires -Modules Pester

BeforeAll {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'DeploymentPackage.psm1'
    Import-Module $ModulePath -Force
}

Describe 'DeploymentPackage module loads' {
    It 'exports the lifecycle functions' {
        $expected = @(
            'New-DeploymentTargetSnapshot',
            'Get-TenantActualState',
            'Compare-DeploymentState',
            'Update-PendingPackage',
            'Get-PendingDeploymentPackage',
            'Read-DeploymentPackageManifest',
            'Add-DeploymentPlanAdjustment',
            'Add-DeploymentPhaseResult',
            'Move-DeploymentPackageToArchive'
        )
        $actual = (Get-Command -Module DeploymentPackage).Name
        foreach ($name in $expected) { $actual | Should -Contain $name }
        $actual.Count | Should -Be 9
    }
}

Describe 'Read-DeploymentPackageManifest' {
    BeforeAll {
        function New-TestSession {
            param([string]$Root, [hashtable]$Pin, [hashtable]$Target, [hashtable]$Adjustments, [hashtable]$Status)

            $sessionDir = Join-Path $Root ([guid]::NewGuid().Guid)
            $workingDir = Join-Path $sessionDir 'working'
            New-Item -ItemType Directory -Path $workingDir -Force | Out-Null

            if ($Pin)         { $Pin         | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $workingDir 'tenant-pin.json')         -Encoding UTF8 }
            if ($Target)      { $Target      | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $workingDir 'deployment-target.json') -Encoding UTF8 }
            if ($Adjustments) { $Adjustments | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $workingDir 'plan-adjustments.json')  -Encoding UTF8 }

            $zip = Join-Path $sessionDir 'pending.zip'
            Compress-Archive -Path (Join-Path $workingDir '*') -DestinationPath $zip -Force
            $sha = (Get-FileHash -Path $zip -Algorithm SHA256).Hash
            Set-Content -Path "$zip.sha256" -Value $sha -Encoding ASCII

            if (-not $Status) {
                $Status = @{
                    schemaVersion    = 1
                    state            = 'pending'
                    phasesCompleted  = @()
                    phasesPending    = @('classifiers','labels','dlprules')
                    pendingZipSha256 = $sha
                    lastUpdated      = (Get-Date).ToString('o')
                }
            }
            $Status | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $sessionDir 'status.json') -Encoding UTF8

            return $sessionDir
        }

        $script:TmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) "dp-read-$(([guid]::NewGuid()).Guid)"
        New-Item -ItemType Directory -Path $script:TmpRoot -Force | Out-Null
    }
    AfterAll {
        if (Test-Path $script:TmpRoot) { Remove-Item $script:TmpRoot -Recurse -Force }
    }

    It 'loads tenant-pin, target, adjustments, status into one record' {
        $sessionDir = New-TestSession -Root $script:TmpRoot `
            -Pin @{ schemaVersion=1; tenant='t.example'; tenantId='g'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId=([guid]::NewGuid().Guid) } `
            -Target @{ schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}}; classifierPackages=@(); dictionaries=@(); dlpPolicies=@(); dlpRules=@() } `
            -Adjustments @{ schemaVersion=1; entries=@() }

        $r = Read-DeploymentPackageManifest -SessionPath $sessionDir
        $r.TenantPin.tenant         | Should -Be 't.example'
        $r.Target.schemaVersion     | Should -Be 1
        $r.Adjustments.entries.Count | Should -Be 0
        $r.Status.state             | Should -Be 'pending'
        $r.SessionPath              | Should -Be $sessionDir
    }

    It 'throws when schemaVersion does not match' {
        $sessionDir = New-TestSession -Root $script:TmpRoot `
            -Pin @{ schemaVersion=99; tenant='t'; tenantId='g'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId='s' } `
            -Target @{ schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}}; classifierPackages=@(); dictionaries=@(); dlpPolicies=@(); dlpRules=@() } `
            -Adjustments @{ schemaVersion=1; entries=@() }

        { Read-DeploymentPackageManifest -SessionPath $sessionDir } | Should -Throw '*schemaVersion*'
    }

    It 'throws when pending.zip SHA does not match the sidecar' {
        $sessionDir = New-TestSession -Root $script:TmpRoot `
            -Pin @{ schemaVersion=1; tenant='t'; tenantId='g'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId='s' } `
            -Target @{ schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}}; classifierPackages=@(); dictionaries=@(); dlpPolicies=@(); dlpRules=@() } `
            -Adjustments @{ schemaVersion=1; entries=@() }
        Set-Content -Path (Join-Path $sessionDir 'pending.zip.sha256') -Value ('0' * 64)

        { Read-DeploymentPackageManifest -SessionPath $sessionDir } | Should -Throw '*SHA*'
    }
}
