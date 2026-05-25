#Requires -Modules Pester

BeforeAll {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'DeploymentPackage.psm1'
    Import-Module $ModulePath -Force

    # Shared helper used by Read-DeploymentPackageManifest tests and by upcoming Describes
    # for Tasks 4-11 (Initialize-DeploymentSession, Add-DeploymentPlanAdjustment, phase
    # results, archive move, etc.). Defined at file-scope so Pester v5 propagates it to
    # every child Describe automatically.
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

Describe 'Update-PendingPackage' {
    BeforeAll {
        $script:UpdRoot = Join-Path ([System.IO.Path]::GetTempPath()) "dp-upd-$([guid]::NewGuid().Guid)"
        New-Item -ItemType Directory -Path $script:UpdRoot -Force | Out-Null
    }
    AfterAll {
        if (Test-Path $script:UpdRoot) { Remove-Item $script:UpdRoot -Recurse -Force }
    }

    It 'extracts, runs the mutator, re-seals, updates SHA + status' {
        $sessionDir = New-TestSession -Root $script:UpdRoot `
            -Pin @{ schemaVersion=1; tenant='t'; tenantId='g'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId='s' } `
            -Target @{ schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}}; classifierPackages=@(); dictionaries=@(); dlpPolicies=@(); dlpRules=@() } `
            -Adjustments @{ schemaVersion=1; entries=@() }

        $origSha = (Get-Content -Raw -LiteralPath (Join-Path $sessionDir 'pending.zip.sha256')).Trim()

        Update-PendingPackage -SessionPath $sessionDir -Mutator {
            param($workingDir)
            New-Item -Path (Join-Path $workingDir 'evidence.txt') -ItemType File -Value 'hello' | Out-Null
        }

        $newSha = (Get-Content -Raw -LiteralPath (Join-Path $sessionDir 'pending.zip.sha256')).Trim()
        $newSha | Should -Not -Be $origSha

        $status = Get-Content -Raw -LiteralPath (Join-Path $sessionDir 'status.json') | ConvertFrom-Json -AsHashtable
        $status.pendingZipSha256 | Should -Be $newSha

        # The mutator's evidence.txt should now be inside pending.zip.
        $tempRead = Join-Path ([System.IO.Path]::GetTempPath()) "dp-verify-$([guid]::NewGuid().Guid)"
        try {
            Expand-Archive -LiteralPath (Join-Path $sessionDir 'pending.zip') -DestinationPath $tempRead -Force
            Test-Path (Join-Path $tempRead 'evidence.txt') | Should -BeTrue
        }
        finally { Remove-Item $tempRead -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'aborts cleanly when the lock cannot be acquired within the timeout' {
        $sessionDir = New-TestSession -Root $script:UpdRoot `
            -Pin @{ schemaVersion=1; tenant='t'; tenantId='g'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId='s' } `
            -Target @{ schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}}; classifierPackages=@(); dictionaries=@(); dlpPolicies=@(); dlpRules=@() } `
            -Adjustments @{ schemaVersion=1; entries=@() }

        # Hold the lock manually.
        $lockPath = Join-Path $sessionDir '.lock'
        $lockHandle = [System.IO.File]::Open($lockPath, 'CreateNew', 'Write', 'None')
        try {
            { Update-PendingPackage -SessionPath $sessionDir -Mutator { param($w) } -LockTimeoutSec 1 } |
                Should -Throw '*lock*'
        }
        finally { $lockHandle.Dispose(); Remove-Item $lockPath -Force -ErrorAction SilentlyContinue }
    }

    It 'leaves the prior pending.zip readable if the mutator throws' {
        $sessionDir = New-TestSession -Root $script:UpdRoot `
            -Pin @{ schemaVersion=1; tenant='t'; tenantId='g'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId='s' } `
            -Target @{ schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}}; classifierPackages=@(); dictionaries=@(); dlpPolicies=@(); dlpRules=@() } `
            -Adjustments @{ schemaVersion=1; entries=@() }

        $origSha = (Get-Content -Raw -LiteralPath (Join-Path $sessionDir 'pending.zip.sha256')).Trim()

        { Update-PendingPackage -SessionPath $sessionDir -Mutator { throw 'boom' } } | Should -Throw '*boom*'

        # SHA file unchanged, pending.zip still has the original content.
        $unchanged = (Get-Content -Raw -LiteralPath (Join-Path $sessionDir 'pending.zip.sha256')).Trim()
        $unchanged | Should -Be $origSha
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $sessionDir 'pending.zip')).Hash
        $actual | Should -Be $origSha
    }
}

Describe 'New-DeploymentTargetSnapshot' {
    BeforeAll {
        $script:FixturesDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'tests/fixtures/deployment-package/configs'
    }

    It 'produces the expected target for the fixture configs' {
        $target = New-DeploymentTargetSnapshot -ConfigDir $script:FixturesDir

        $target.schemaVersion | Should -Be 1
        $target.labels.Count  | Should -Be 1
        $target.labels[0].name | Should -Be 'QGISCF-OFFICIAL-OFFI'
        $target.labels[0].code | Should -Be 'OFFI'

        $target.labelPolicy.name | Should -Be 'QGISCF-Label-Policy'

        $target.dlpPolicies.Count | Should -Be 1
        $target.dlpPolicies[0].name | Should -Be 'P01-ECH-QGISCF-EXT-ADT'

        $target.dlpRules.Count | Should -Be 1
        $target.dlpRules[0].name   | Should -Be 'P01-R01-ECH-OFFI-EXT-ADT'
        $target.dlpRules[0].policy | Should -Be 'P01-ECH-QGISCF-EXT-ADT'
        $target.dlpRules[0].classifiers | Should -Contain '00000000-0000-0000-0000-000000000001'
    }

    It 'returns null rulePackId and null entity ids for classifier packages at init' {
        $target = New-DeploymentTargetSnapshot -ConfigDir $script:FixturesDir
        foreach ($pkg in $target.classifierPackages) {
            $pkg.rulePackId | Should -BeNullOrEmpty
            foreach ($e in $pkg.entities) { $e.id | Should -BeNullOrEmpty }
        }
    }
}

Describe 'Add-DeploymentPlanAdjustment' {
    BeforeAll {
        $script:AdjRoot = Join-Path ([System.IO.Path]::GetTempPath()) "dp-adj-$([guid]::NewGuid().Guid)"
        New-Item -ItemType Directory -Path $script:AdjRoot -Force | Out-Null
    }
    AfterAll {
        if (Test-Path $script:AdjRoot) { Remove-Item $script:AdjRoot -Recurse -Force }
    }

    It 'appends a refit classifier-package adjustment and mutates the target' {
        $sessionDir = New-TestSession -Root $script:AdjRoot `
            -Pin @{ schemaVersion=1; tenant='t'; tenantId='g'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId='s' } `
            -Target @{
                schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}};
                classifierPackages=@(@{name='QGISCF-medium-03'; rulePackId=$null; entities=@(); dictionaryRefs=@()});
                dictionaries=@(); dlpPolicies=@(); dlpRules=@() } `
            -Adjustments @{ schemaVersion=1; entries=@() }

        Add-DeploymentPlanAdjustment -SessionPath $sessionDir `
            -Source 'refit' -ArtifactType 'classifierPackage' -Key 'QGISCF-medium-03' -Action 'reuse-rulepackid' `
            -Before @{ rulePackId = $null } -After @{ rulePackId = 'abc-123' } -Reason 'preserved'

        $r = Read-DeploymentPackageManifest -SessionPath $sessionDir
        $r.Adjustments.entries.Count | Should -Be 1
        $r.Adjustments.entries[0].action | Should -Be 'reuse-rulepackid'
        ($r.Target.classifierPackages | Where-Object name -eq 'QGISCF-medium-03').rulePackId | Should -Be 'abc-123'
    }

    It 'is idempotent on identity key (re-emit updates ts/after, no duplicate)' {
        $sessionDir = New-TestSession -Root $script:AdjRoot `
            -Pin @{ schemaVersion=1; tenant='t'; tenantId='g'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId='s' } `
            -Target @{ schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}}; classifierPackages=@(@{name='P1';rulePackId=$null;entities=@();dictionaryRefs=@()}); dictionaries=@(); dlpPolicies=@(); dlpRules=@() } `
            -Adjustments @{ schemaVersion=1; entries=@() }

        Add-DeploymentPlanAdjustment -SessionPath $sessionDir -Source 'refit' -ArtifactType 'classifierPackage' -Key 'P1' -Action 'reuse-rulepackid' -Before @{ rulePackId=$null } -After @{ rulePackId='v1' } -Reason 'first'
        Add-DeploymentPlanAdjustment -SessionPath $sessionDir -Source 'refit' -ArtifactType 'classifierPackage' -Key 'P1' -Action 'reuse-rulepackid' -Before @{ rulePackId='v1' } -After @{ rulePackId='v2' } -Reason 'second'

        $r = Read-DeploymentPackageManifest -SessionPath $sessionDir
        $r.Adjustments.entries.Count | Should -Be 1
        $r.Adjustments.entries[0].after.rulePackId | Should -Be 'v2'
        $r.Adjustments.entries[0].reason | Should -Be 'second'
        ($r.Target.classifierPackages | Where-Object name -eq 'P1').rulePackId | Should -Be 'v2'
    }

    It 'rejects an adjustment whose Before does not match the current target value' {
        $sessionDir = New-TestSession -Root $script:AdjRoot `
            -Pin @{ schemaVersion=1; tenant='t'; tenantId='g'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId='s' } `
            -Target @{ schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}}; classifierPackages=@(@{name='P1';rulePackId='live-id';entities=@();dictionaryRefs=@()}); dictionaries=@(); dlpPolicies=@(); dlpRules=@() } `
            -Adjustments @{ schemaVersion=1; entries=@() }

        { Add-DeploymentPlanAdjustment -SessionPath $sessionDir -Source 'refit' -ArtifactType 'classifierPackage' -Key 'P1' -Action 'reuse-rulepackid' -Before @{ rulePackId=$null } -After @{ rulePackId='other' } -Reason 'stale plan' } |
            Should -Throw '*stale*'
    }

    It 'removes the target artifact when an operator-review skip is recorded' {
        $sessionDir = New-TestSession -Root $script:AdjRoot `
            -Pin @{ schemaVersion=1; tenant='t'; tenantId='g'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId='s' } `
            -Target @{
                schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}};
                classifierPackages=@(); dictionaries=@(); dlpPolicies=@();
                dlpRules=@(@{name='P04-R11-END-PROT_IT-EXT-ADT'; policy='P'; classifiers=@(); scopeParam=''; scopeValue=''}) } `
            -Adjustments @{ schemaVersion=1; entries=@() }

        Add-DeploymentPlanAdjustment -SessionPath $sessionDir -Source 'operator-review' -ArtifactType 'dlpRule' -Key 'P04-R11-END-PROT_IT-EXT-ADT' -Action 'skip' -Reason 'deferred'

        $r = Read-DeploymentPackageManifest -SessionPath $sessionDir
        $r.Target.dlpRules.Count | Should -Be 0
    }
}

Describe 'Add-DeploymentPhaseResult' {
    BeforeAll {
        $script:PhRoot = Join-Path ([System.IO.Path]::GetTempPath()) "dp-ph-$([guid]::NewGuid().Guid)"
        New-Item -ItemType Directory -Path $script:PhRoot -Force | Out-Null
    }
    AfterAll {
        if (Test-Path $script:PhRoot) { Remove-Item $script:PhRoot -Recurse -Force }
    }

    It 'writes phase file and moves status from pending to in-progress' {
        $sessionDir = New-TestSession -Root $script:PhRoot `
            -Pin @{ schemaVersion=1; tenant='t'; tenantId='g'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId='s' } `
            -Target @{ schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}}; classifierPackages=@(); dictionaries=@(); dlpPolicies=@(); dlpRules=@() } `
            -Adjustments @{ schemaVersion=1; entries=@() }

        Add-DeploymentPhaseResult -SessionPath $sessionDir -Phase 'classifiers' -Action 'Upload' -Status 'success' `
            -StartedAt (Get-Date).AddMinutes(-2).ToString('o') -CompletedAt (Get-Date).ToString('o') `
            -Artifacts @(@{name='QGISCF-medium-01'; action='created'}) -Errors @() -ReportPath 'reports/deployments/x/'

        $r = Read-DeploymentPackageManifest -SessionPath $sessionDir
        $r.Phases.classifiers.action | Should -Be 'Upload'
        $r.Phases.classifiers.status | Should -Be 'success'
        $r.Status.state              | Should -Be 'in-progress'
        $r.Status.phasesCompleted    | Should -Contain 'classifiers'
        $r.Status.phasesPending      | Should -Not -Contain 'classifiers'
    }

    It 'records a failed phase without moving state to terminal' {
        $sessionDir = New-TestSession -Root $script:PhRoot `
            -Pin @{ schemaVersion=1; tenant='t'; tenantId='g'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId='s' } `
            -Target @{ schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}}; classifierPackages=@(); dictionaries=@(); dlpPolicies=@(); dlpRules=@() } `
            -Adjustments @{ schemaVersion=1; entries=@() }

        Add-DeploymentPhaseResult -SessionPath $sessionDir -Phase 'labels' -Action 'Deploy' -Status 'failed' `
            -StartedAt (Get-Date).ToString('o') -CompletedAt (Get-Date).ToString('o') -Artifacts @() -Errors @('boom')

        $r = Read-DeploymentPackageManifest -SessionPath $sessionDir
        $r.Phases.labels.status   | Should -Be 'failed'
        $r.Status.state           | Should -Be 'in-progress'
        $r.Status.phasesCompleted | Should -Not -Contain 'labels'
    }
}

Describe 'Get-PendingDeploymentPackage' {
    BeforeAll {
        $script:LookRoot = Join-Path ([System.IO.Path]::GetTempPath()) "dp-look-$([guid]::NewGuid().Guid)"
        New-Item -ItemType Directory -Path $script:LookRoot -Force | Out-Null
    }
    AfterAll {
        if (Test-Path $script:LookRoot) { Remove-Item $script:LookRoot -Recurse -Force }
    }

    It 'returns the single matching pending session' {
        New-TestSession -Root $script:LookRoot `
            -Pin @{ schemaVersion=1; tenant='alpha.example'; tenantId='g1'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId='alpha' } `
            -Target @{ schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}}; classifierPackages=@(); dictionaries=@(); dlpPolicies=@(); dlpRules=@() } `
            -Adjustments @{ schemaVersion=1; entries=@() } | Out-Null

        $r = Get-PendingDeploymentPackage -DeploymentsRoot $script:LookRoot -Tenant 'alpha.example' -TargetEnvironment 'nonprod'
        $r.TenantPin.tenant | Should -Be 'alpha.example'
    }

    It 'throws a clear error when no match exists' {
        { Get-PendingDeploymentPackage -DeploymentsRoot $script:LookRoot -Tenant 'noone' -TargetEnvironment 'nowhere' } |
            Should -Throw '*No pending session*'
    }

    It 'throws with candidate list on multi-match' {
        New-TestSession -Root $script:LookRoot `
            -Pin @{ schemaVersion=1; tenant='dup.example'; tenantId='g2'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId='dup1' } `
            -Target @{ schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}}; classifierPackages=@(); dictionaries=@(); dlpPolicies=@(); dlpRules=@() } `
            -Adjustments @{ schemaVersion=1; entries=@() } | Out-Null
        New-TestSession -Root $script:LookRoot `
            -Pin @{ schemaVersion=1; tenant='dup.example'; tenantId='g2'; targetEnvironment='nonprod'; namingPrefix='X'; namingSuffix='Y'; deploymentTier='medium'; basePackage=@{name='b';version='v';sha256='s'}; createdAt=(Get-Date).ToString('o'); sessionId='dup2' } `
            -Target @{ schemaVersion=1; labels=@(); labelPolicy=@{name='';publishTo=@();labels=@();settings=@{}}; classifierPackages=@(); dictionaries=@(); dlpPolicies=@(); dlpRules=@() } `
            -Adjustments @{ schemaVersion=1; entries=@() } | Out-Null

        { Get-PendingDeploymentPackage -DeploymentsRoot $script:LookRoot -Tenant 'dup.example' -TargetEnvironment 'nonprod' } |
            Should -Throw '*multiple*'
    }
}

Describe 'Get-TenantActualState' {
    It 'is exported and accepts -NamingPrefix and -TargetEnvironment' {
        # End-to-end behaviour (provenance-scoped queries against the 6 Purview cmdlets) is
        # exercised in the Task 21 integration test via the -InjectActualState code path in
        # Finalize-DeploymentSession. Mocking ExchangeOnlineManagement cmdlets that aren't
        # loaded conflicts with Pester's module-scope resolution. We assert here only that
        # the exported function signature is correct.
        $cmd = Get-Command Get-TenantActualState -Module DeploymentPackage
        $cmd | Should -Not -BeNullOrEmpty
        $cmd.Parameters.Keys | Should -Contain 'NamingPrefix'
        $cmd.Parameters.Keys | Should -Contain 'TargetEnvironment'
    }
}
