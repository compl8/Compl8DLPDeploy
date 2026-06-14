#Requires -Modules Pester

# Compl8.Content — Resolve-DesiredDlpRules (DR-2): the DESIRED-rule resolver.
#
# It reads the config sources (-ConfigPath injectable; the Stage-5 re-point seam) and produces the
# DESIRED policy + rule set: for each enabled policy x each DLP-eligible label (non-group,
# non-dlpExclude, has classifiers for its code) x each classifier chunk, a record carrying
# { policyName (Get-PolicyName); ruleName (Get-RuleName w/ chunk letter); content; policy fields }.
#
# FIDELITY GATE — the SHADOW PARITY test (reuses the Stage-4 pattern): it runs the REAL
# scripts/Deploy-DLPRules.ps1 with -WhatIf against the committed config, capturing the policies/rules
# it WOULD deploy via PLAIN GLOBAL stubs for the connection/session/fingerprint boundary and GLOBAL
# RECORDING stubs for New-/Set-DlpComplianceRule|Policy (NOT Mock -ModuleName — module mocks drive
# ShouldProcess to $false so the recording cmdlets never fire). It then asserts Resolve-DesiredDlpRules
# produces the SAME rule/policy NAMES and the SAME content HASHES (via Get-DlpRuleContentHash) as the
# recorded real run, with a non-empty count guard so the pass is non-vacuous.

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot   = Split-Path $PSScriptRoot -Parent
    $script:ContentDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Content'
    $script:ModelDir   = Join-Path $script:RepoRoot 'modules' 'Compl8.Model'
    $script:DlpDeploy  = Join-Path $script:RepoRoot 'modules' 'DLP-Deploy.psm1'
    $script:ConfigDir  = Join-Path $script:RepoRoot 'config'
    Import-Module $script:ContentDir -Force

    # GENUINE old-side recorder: run the WHOLE real Deploy-DLPRules.ps1 -WhatIf against a committed
    # per-tenant config fixture, with the connection/session/fingerprint boundary + the SCC cmdlets
    # replaced by GLOBAL recording stubs. Records both the op NAME and (for rules) the full content
    # args so each side can be hashed with Get-DlpRuleContentHash.
    function Get-OldDlpDesiredState {
        param([Parameter(Mandatory)][string]$ConfigSourceDir)

        $envName = 'compl8-drshadow-' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
        $cfgRoot = Join-Path $script:RepoRoot 'config' 'tenants' $envName
        $policyOps = [System.Collections.Generic.List[object]]::new()
        $ruleOps   = [System.Collections.Generic.List[object]]::new()
        $global:Compl8DrPolicyOps = $policyOps
        $global:Compl8DrRuleOps   = $ruleOps
        try {
            New-Item -ItemType Directory -Path $cfgRoot -Force | Out-Null
            foreach ($f in 'labels.json', 'policies.json', 'classifiers.json', 'rule-overrides.json') {
                Copy-Item -LiteralPath (Join-Path $ConfigSourceDir $f) -Destination (Join-Path $cfgRoot $f) -Force
            }
            # Copy settings.json but neutralise the real-world inter-call sleep + retry delays so the
            # WhatIf-less run records instantly (the deploy loop's Start-Sleep is only WhatIf-guarded).
            # These knobs do NOT affect rule/policy NAMES or CONTENT, so parity is unchanged.
            $settings = Get-Content -LiteralPath (Join-Path $ConfigSourceDir 'settings.json') -Raw | ConvertFrom-Json
            $settings | Add-Member -NotePropertyName 'interCallDelaySec' -NotePropertyValue 0 -Force
            $settings | Add-Member -NotePropertyName 'maxRetries' -NotePropertyValue 2 -Force
            $settings | Add-Member -NotePropertyName 'baseDelaySec' -NotePropertyValue 1 -Force
            $settings | Add-Member -NotePropertyName 'skipSitValidation' -NotePropertyValue $true -Force
            $settings | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $cfgRoot 'settings.json')

            Import-Module $script:DlpDeploy -Force
            function global:Connect-DLPSession { param() $true }
            function global:Assert-DLPSession { param([string]$CommandToTest) $true }
            function global:Test-DeploymentTenantFingerprint { param() [pscustomobject]@{ passed = $true; environment = 'shadow'; mode = 'warn'; actual = @{ name = 's'; guid = 'g' }; messages = @(); mismatches = @(); configured = $true; matched = $true } }
            function global:Start-DeploymentLog { param([string]$ScriptName) $null }
            function global:Stop-Transcript { }
            function global:Get-DlpSensitiveInformationType { @() }
            function global:Get-DlpCompliancePolicy { param([string]$Identity) $null }
            function global:New-DlpCompliancePolicy { param([string]$Name, [string]$Comment, [string]$Mode, [string]$ExchangeLocation, [string]$OneDriveLocation, [string]$SharePointLocation, [string]$EndpointDlpLocation, [string]$TeamsLocation); $global:Compl8DrPolicyOps.Add([pscustomobject]@{ action = 'create'; name = $Name; mode = $Mode }) | Out-Null }
            function global:Set-DlpCompliancePolicy { param([string]$Identity, [string]$Comment, [string]$Mode); $global:Compl8DrPolicyOps.Add([pscustomobject]@{ action = 'update'; name = $Identity; mode = $Mode }) | Out-Null }
            function global:Get-DlpComplianceRule { param([string]$Identity, [string]$Policy) $null }
            function global:New-DlpComplianceRule {
                param([string]$Name, [string]$Policy, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled, [string]$AccessScope, [string]$GenerateIncidentReport, [string]$IncidentReportContent, [string]$NotifyUser)
                $global:Compl8DrRuleOps.Add([pscustomobject]@{
                    action = 'create'; name = $Name; policy = $Policy
                    params = @{
                        Name = $Name; Policy = $Policy
                        ContentContainsSensitiveInformation = $ContentContainsSensitiveInformation
                        AdvancedRule = $AdvancedRule; AccessScope = $AccessScope
                        ReportSeverityLevel = $ReportSeverityLevel; Disabled = $Disabled
                        GenerateIncidentReport = $GenerateIncidentReport; NotifyUser = $NotifyUser
                    }
                }) | Out-Null
            }
            function global:Set-DlpComplianceRule { param([string]$Identity, $ContentContainsSensitiveInformation) }
            function global:Remove-DlpComplianceRule { param([string]$Identity) }
            function global:Remove-DlpCompliancePolicy { param([string]$Identity) }

            & (Join-Path $script:RepoRoot 'scripts' 'Deploy-DLPRules.ps1') -TargetEnvironment $envName -SkipValidation -SkipVerification -AllowDirectRun *> $null

            [pscustomobject]@{
                Policies = @($policyOps)
                Rules    = @($ruleOps)
            }
        } finally {
            foreach ($fn in 'Connect-DLPSession', 'Assert-DLPSession', 'Test-DeploymentTenantFingerprint', 'Start-DeploymentLog', 'Stop-Transcript',
                'Get-DlpSensitiveInformationType', 'Get-DlpCompliancePolicy', 'New-DlpCompliancePolicy', 'Set-DlpCompliancePolicy', 'Remove-DlpCompliancePolicy',
                'Get-DlpComplianceRule', 'New-DlpComplianceRule', 'Set-DlpComplianceRule', 'Remove-DlpComplianceRule') {
                Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
            }
            Remove-Variable -Name Compl8DrPolicyOps, Compl8DrRuleOps -Scope Global -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $cfgRoot -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'module surface' {
    It 'exports Resolve-DesiredDlpRules from Compl8.Content' {
        (Get-Command -Name Resolve-DesiredDlpRules -Module Compl8.Content -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Resolve-DesiredDlpRules — shape + source injectability' {
    BeforeAll {
        $script:Desired = Resolve-DesiredDlpRules -ConfigPath $script:ConfigDir
    }

    It 'produces both policies and rules' {
        @($script:Desired.Policies).Count | Should -BeGreaterThan 0
        @($script:Desired.Rules).Count    | Should -BeGreaterThan 0
    }

    It 'each rule record carries policyName, ruleName, content, and policy fields' {
        $r = @($script:Desired.Rules)[0]
        $r.policyName | Should -Not -BeNullOrEmpty
        $r.ruleName   | Should -Not -BeNullOrEmpty
        $r.content    | Should -Not -BeNullOrEmpty
        $r.PSObject.Properties.Name | Should -Contain 'contentHash'
    }

    It 'every rule content hashes to a sha256 value (DR-1 comparable)' {
        foreach ($r in @($script:Desired.Rules)) {
            $r.contentHash | Should -Match '^sha256:[0-9a-f]{64}$'
        }
    }

    It 'only enabled policies x DLP-eligible labels (non-group, non-dlpExclude, with classifiers)' {
        # The committed config has 5 enabled policies; dlpExclude/group labels (SENS, PROT, PROT_Pvc,
        # PROT_Gov, group headers) must NOT appear. OFFI must appear.
        @($script:Desired.Rules | Where-Object { $_.labelCode -eq 'OFFI' }).Count | Should -BeGreaterThan 0
        @($script:Desired.Rules | Where-Object { $_.labelCode -in @('SENS', 'PROT', 'PROT_Pvc', 'PROT_Gov', 'SENSITIVE', 'PROTECTED') }).Count | Should -Be 0
    }

    It 'honours an injected -ConfigPath (Stage-5 re-point seam) over a separate dir' {
        $alt = Join-Path $TestDrive 'altcfg'
        New-Item -ItemType Directory -Path $alt -Force | Out-Null
        Set-Content -Path (Join-Path $alt 'settings.json') -Value '{ "namingPrefix":"ALTX","namingSuffix":"EXT-ADT","auditMode":true,"notifyUser":false,"generateIncidentReport":false,"sitPrefix":"ALTX","publisher":"ALTX","nameTemplates":{"dlpPolicy":"P{policyNumber}-{policyCode}-{prefix}-{suffix}","dlpRule":"P{policyNumber}-R{ruleNumber}{chunkLetter}-{policyCode}-{labelCode}-{suffix}"} }'
        Set-Content -Path (Join-Path $alt 'labels.json')   -Value '[ { "code":"OFFI","name":"OFFICIAL","displayName":"OFFICIAL","isGroup":false } ]'
        Set-Content -Path (Join-Path $alt 'policies.json') -Value '[ { "number":1,"code":"ECH","comment":"c","location":{"ExchangeLocation":"All"},"scopeParam":"AccessScope","scopeValue":"NotInOrganization","optional":false,"enabled":true } ]'
        Set-Content -Path (Join-Path $alt 'classifiers.json') -Value '{ "OFFI":[ {"name":"All Full Names","id":"50b8b56b-4ef8-44c2-a924-03374f5831ce","confidenceLevel":"Medium","minCount":1,"maxCount":-1} ] }'
        Set-Content -Path (Join-Path $alt 'rule-overrides.json') -Value '{}'

        $d = Resolve-DesiredDlpRules -ConfigPath $alt
        @($d.Policies).Count | Should -Be 1
        @($d.Policies)[0].policyName | Should -Be 'P01-ECH-ALTX-EXT-ADT'
        @($d.Rules).Count | Should -Be 1
        @($d.Rules)[0].ruleName | Should -Be 'P01-R01-ECH-OFFI-EXT-ADT'
    }

    It 'splits a >125-SIT label into chunks with a,b,... letters (chunk-letter parity)' {
        $alt = Join-Path $TestDrive 'chunkcfg'
        New-Item -ItemType Directory -Path $alt -Force | Out-Null
        Set-Content -Path (Join-Path $alt 'settings.json') -Value '{ "namingPrefix":"CHK","namingSuffix":"EXT-ADT","auditMode":true,"notifyUser":false,"generateIncidentReport":false,"sitPrefix":"CHK","publisher":"CHK","nameTemplates":{"dlpPolicy":"P{policyNumber}-{policyCode}-{prefix}-{suffix}","dlpRule":"P{policyNumber}-R{ruleNumber}{chunkLetter}-{policyCode}-{labelCode}-{suffix}"} }'
        Set-Content -Path (Join-Path $alt 'labels.json')   -Value '[ { "code":"OFFI","name":"OFFICIAL","displayName":"OFFICIAL","isGroup":false } ]'
        Set-Content -Path (Join-Path $alt 'policies.json') -Value '[ { "number":1,"code":"ECH","comment":"c","location":{"ExchangeLocation":"All"},"scopeParam":"AccessScope","scopeValue":"NotInOrganization","optional":false,"enabled":true } ]'
        # 130 synthetic SITs -> 2 chunks (a,b).
        $sits = 1..130 | ForEach-Object {
            $g = '{0:d8}-0000-0000-0000-000000000000' -f $_
            "{ `"name`": `"SIT $_`", `"id`": `"$g`", `"confidenceLevel`": `"Medium`", `"minCount`": 1, `"maxCount`": -1 }"
        }
        Set-Content -Path (Join-Path $alt 'classifiers.json') -Value "{ `"OFFI`": [ $($sits -join ',') ] }"
        Set-Content -Path (Join-Path $alt 'rule-overrides.json') -Value '{}'

        $d = Resolve-DesiredDlpRules -ConfigPath $alt
        $names = @($d.Rules | ForEach-Object { $_.ruleName })
        $names | Should -Contain 'P01-R01a-ECH-OFFI-EXT-ADT'
        $names | Should -Contain 'P01-R01b-ECH-OFFI-EXT-ADT'
    }
}

Describe 'Resolve-DesiredDlpRules — SHADOW PARITY vs Deploy-DLPRules.ps1 (GENUINE, committed config)' -Tag 'Slow' {
    BeforeAll {
        Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
        # OLD side: run the WHOLE real Deploy-DLPRules.ps1 against the committed config (empty tenant
        # => all create), recording the policies/rules it WOULD deploy + their full content args.
        $script:Old = Get-OldDlpDesiredState -ConfigSourceDir $script:ConfigDir
        # NEW side: the resolver against the SAME committed config.
        Import-Module $script:ContentDir -Force
        $script:New = Resolve-DesiredDlpRules -ConfigPath $script:ConfigDir
    }

    It 'NON-VACUOUS: the real Deploy-DLPRules.ps1 produced policies and rules' {
        @($script:Old.Policies).Count | Should -BeGreaterThan 0 -Because 'the committed config must drive real Deploy-DLPRules.ps1 operations'
        @($script:Old.Rules).Count    | Should -BeGreaterThan 0
    }

    It 'policy NAMES match exactly (same set, same count)' {
        $oldNames = @($script:Old.Policies | ForEach-Object { $_.name }) | Sort-Object
        $newNames = @($script:New.Policies | ForEach-Object { $_.policyName }) | Sort-Object
        $newNames | Should -Be $oldNames
    }

    It 'rule NAMES match exactly (same set, same count)' {
        $oldNames = @($script:Old.Rules | ForEach-Object { $_.name }) | Sort-Object
        $newNames = @($script:New.Rules | ForEach-Object { $_.ruleName }) | Sort-Object
        $newNames | Should -Be $oldNames
    }

    It 'rule CONTENT HASHES match per-name (DR-1 hash of old-side params == resolver content hash)' {
        # Hash each side with the SAME Get-DlpRuleContentHash, keyed by rule name.
        $oldHashByName = @{}
        foreach ($op in @($script:Old.Rules)) {
            $oldHashByName[$op.name] = Get-DlpRuleContentHash -DesiredParams $op.params
        }
        $newHashByName = @{}
        foreach ($r in @($script:New.Rules)) {
            $newHashByName[$r.ruleName] = $r.contentHash
        }

        $mismatches = [System.Collections.Generic.List[string]]::new()
        foreach ($name in $oldHashByName.Keys) {
            if (-not $newHashByName.ContainsKey($name)) { $mismatches.Add("missing-in-resolver:$name") | Out-Null; continue }
            if ($newHashByName[$name] -ne $oldHashByName[$name]) {
                $mismatches.Add("hash-differs:$name (old=$($oldHashByName[$name]); new=$($newHashByName[$name]))") | Out-Null
            }
        }
        @($mismatches).Count | Should -Be 0 -Because "every desired rule's content hash must match the real Deploy-DLPRules.ps1 content. Mismatches: $($mismatches -join ' | ')"
    }
}
