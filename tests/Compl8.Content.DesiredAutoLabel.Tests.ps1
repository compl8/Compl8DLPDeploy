#Requires -Modules Pester

# Compl8.Content — Resolve-DesiredAutoLabel: the DESIRED auto-label POLICY projection (the
# autoLabelPolicy analogue of Resolve-DesiredDlpRules). It lifts Deploy-AutoLabeling.ps1's policy
# materialisation into a pure, config-driven set so assess can diff desired-vs-actual auto-label
# policies. These tests assert the projection shape, the deploy-faithful naming / mode / locations /
# applied-label, and the gating that keeps non-auto-label configs from synthesising policies.

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot   = Split-Path $PSScriptRoot -Parent
    $script:ContentDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Content'
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:ContentDir -Force

    function script:New-AutoLabelConfig {
        param([string]$Dir, [switch]$NoAutoLabelTemplate, [switch]$NoSupportedWorkloads)
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        $templates = if ($NoAutoLabelTemplate) {
            '"dlpPolicy":"P{policyNumber}-{policyCode}-{prefix}-{suffix}"'
        } else {
            '"label":"{prefix}-{name}","autoLabelPolicy":"AL{policyNumber}-{labelCode}-{prefix}-{suffix}","autoLabelRule":"AL{policyNumber}-R{ruleNumber}{chunkLetter}-{workloadCode}-{labelCode}-{suffix}","dlpPolicy":"P{policyNumber}-{policyCode}-{prefix}-{suffix}","dlpRule":"P{policyNumber}-R{ruleNumber}{chunkLetter}-{policyCode}-{labelCode}-{suffix}"'
        }
        Set-Content -Path (Join-Path $Dir 'settings.json') -Value "{ ""namingPrefix"":""QGISCF"",""namingSuffix"":""EXT-ADT"",""auditMode"":true,""notifyUser"":false,""nameTemplates"":{ $templates } }"
        # OFFI + SENS are DLP-eligible; GRP is a group (excluded); EXC is dlpExclude (excluded);
        # NOCLS has no classifiers (excluded).
        Set-Content -Path (Join-Path $Dir 'labels.json') -Value '[ { "code":"OFFI","name":"OFFICIAL","displayName":"OFFICIAL","isGroup":false }, { "code":"SENS","name":"SENSITIVE","displayName":"SENSITIVE","isGroup":false }, { "code":"GRP","name":"GROUP","displayName":"GROUP","isGroup":true }, { "code":"EXC","name":"EXCLUDED","displayName":"EXCLUDED","isGroup":false,"dlpExclude":true }, { "code":"NOCLS","name":"NOCLASS","displayName":"NOCLASS","isGroup":false } ]'
        $policies = if ($NoSupportedWorkloads) {
            '[ { "number":1,"code":"EPT","comment":"Endpoint","location":{"EndpointDlpLocation":"All"},"optional":false,"enabled":true } ]'
        } else {
            '[ { "number":1,"code":"ECH","comment":"Exchange policy","location":{"ExchangeLocation":"All"},"scopeParam":"AccessScope","scopeValue":"NotInOrganization","optional":false,"enabled":true }, { "number":2,"code":"ODB","comment":"OneDrive policy","location":{"OneDriveLocation":"All"},"scopeParam":"AccessScope","scopeValue":"NotInOrganization","optional":false,"enabled":true } ]'
        }
        Set-Content -Path (Join-Path $Dir 'policies.json') -Value $policies
        Set-Content -Path (Join-Path $Dir 'classifiers.json') -Value '{ "OFFI":[ {"name":"All Full Names","id":"50b8b56b-4ef8-44c2-a924-03374f5831ce","confidenceLevel":"Medium","minCount":1,"maxCount":-1} ], "SENS":[ {"name":"Credit Card Number","id":"50842eb7-edc8-4019-85dd-5a5c1f2bb085","confidenceLevel":"High","minCount":1,"maxCount":-1} ] }'
        Set-Content -Path (Join-Path $Dir 'rule-overrides.json') -Value '{}'
    }

    $script:ConfigDir = Join-Path ([System.IO.Path]::GetTempPath()) ("al-cfg-" + [guid]::NewGuid().ToString('N'))
    New-AutoLabelConfig -Dir $script:ConfigDir
    $script:Desired = Resolve-DesiredAutoLabel -ConfigPath $script:ConfigDir
    $script:Policies = @($script:Desired.Policies | Sort-Object policyName)
}

AfterAll {
    foreach ($d in $script:ConfigDir, $script:NoTplDir, $script:NoWlDir) {
        if ($d -and (Test-Path -LiteralPath $d)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Resolve-DesiredAutoLabel — module surface' {
    It 'is exported from Compl8.Content' {
        (Get-Command -Name Resolve-DesiredAutoLabel -Module Compl8.Content -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Resolve-DesiredAutoLabel — one policy per DLP-eligible label' {
    It 'emits exactly one policy per non-group, non-dlpExclude, classifier-bearing label' {
        # OFFI + SENS qualify; GRP (group), EXC (dlpExclude), NOCLS (no classifiers) are filtered out.
        $script:Policies.Count | Should -Be 2
        @($script:Policies | ForEach-Object { $_.labelCode }) | Should -Be @('OFFI', 'SENS')
    }

    It 'names policies with the AL-numbered template (sequential, prefix in the middle)' {
        $script:Policies[0].policyName | Should -Be 'AL01-OFFI-QGISCF-EXT-ADT'
        $script:Policies[1].policyName | Should -Be 'AL02-SENS-QGISCF-EXT-ADT'
    }

    It 'hard-codes Mode = TestWithoutNotifications (NOT the auditMode path)' {
        foreach ($p in $script:Policies) { $p.mode | Should -Be 'TestWithoutNotifications' }
    }

    It 'applies the deployed label NAME (Get-DeploymentObjectName label) as ApplySensitivityLabel' {
        ($script:Policies | Where-Object { $_.labelCode -eq 'OFFI' }).label | Should -Be 'QGISCF-OFFICIAL'
        ($script:Policies | Where-Object { $_.labelCode -eq 'SENS' }).label | Should -Be 'QGISCF-SENSITIVE'
    }

    It 'scopes to the UNION of enabled supported-workload locations (ECH + ODB)' {
        $loc = $script:Policies[0].locations
        @($loc.Keys) | Should -Contain 'ExchangeLocation'
        @($loc.Keys) | Should -Contain 'OneDriveLocation'
        $loc['ExchangeLocation'] | Should -Be 'All'
        $loc['OneDriveLocation'] | Should -Be 'All'
    }

    It 'carries the RAW (pre-stamp) comment' {
        ($script:Policies | Where-Object { $_.labelCode -eq 'OFFI' }).comment | Should -Be 'Auto-label OFFICIAL (OFFI)'
    }

    It 'is deterministic — identical output on repeated runs' {
        $a = (Resolve-DesiredAutoLabel -ConfigPath $script:ConfigDir | ConvertTo-Json -Depth 12)
        $b = (Resolve-DesiredAutoLabel -ConfigPath $script:ConfigDir | ConvertTo-Json -Depth 12)
        $a | Should -Be $b
    }
}

Describe 'Resolve-DesiredAutoLabel — config parity + gating' {
    It 'falls back to module-default name templates when settings.json omits them (deploy parity)' {
        # Deploy-AutoLabeling merges Get-ModuleDefaults under settings.json, so a config that omits the
        # auto-label templates STILL deploys policies. The resolver must match: produce them via the
        # default templates (codex review), not silently emit nothing.
        $script:NoTplDir = Join-Path ([System.IO.Path]::GetTempPath()) ("al-notpl-" + [guid]::NewGuid().ToString('N'))
        New-AutoLabelConfig -Dir $script:NoTplDir -NoAutoLabelTemplate
        $pols = @((Resolve-DesiredAutoLabel -ConfigPath $script:NoTplDir).Policies | Sort-Object policyName)
        $pols.Count | Should -Be 2
        $pols[0].policyName | Should -Be 'AL01-OFFI-QGISCF-EXT-ADT' -Because 'the module-default autoLabelPolicy template applies'
        $pols[0].label      | Should -Be 'QGISCF-OFFICIAL-OFFI'     -Because 'the module-default label template applies'
    }

    It 'returns no policies when no supported auto-label workload is enabled' {
        $script:NoWlDir = Join-Path ([System.IO.Path]::GetTempPath()) ("al-nowl-" + [guid]::NewGuid().ToString('N'))
        New-AutoLabelConfig -Dir $script:NoWlDir -NoSupportedWorkloads
        @((Resolve-DesiredAutoLabel -ConfigPath $script:NoWlDir).Policies).Count | Should -Be 0
    }
}
