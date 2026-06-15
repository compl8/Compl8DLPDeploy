#Requires -Modules Pester

# =====================================================================================
# codex REVIEW findings on the auto-label assess feature (commit 06f2c34), fixed here:
#
#   [P2b] Resolve-DesiredAutoLabel must merge the deployment naming DEFAULTS (namingPrefix /
#         namingSuffix) the way Deploy-AutoLabeling.ps1 does (Get-ModuleDefaults under settings.json),
#         else a settings file that relies on those defaults yields names that DIVERGE from the deploy
#         path → false create/orphan drift.
#   [P2a] Invoke-Compl8Assess must treat a VALID auto-label config that resolves to ZERO desired
#         policies as MANAGED (not skipped), so existing stamped ours auto-label policies become
#         ORPHANS rather than being ignored.
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot   = Split-Path $PSScriptRoot -Parent
    $script:ContentDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Content'
    $script:TenantDir  = Join-Path $script:RepoRoot 'modules' 'Compl8.Tenant'
    $script:EngineDir  = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:ContentDir -Force
    Import-Module $script:TenantDir -Force
    Import-Module $script:EngineDir -Force

    # A VALID auto-label config. -OmitNaming drops namingPrefix/namingSuffix AND the nameTemplates so
    # the resolver must fall back to the module defaults (DLP / EXT-ADT + default templates) exactly as
    # the deploy path does. -NoSupportedWorkloads makes the desired set resolve to ZERO policies while
    # remaining a valid (parseable) config.
    function script:New-P2Config {
        param([string]$Dir, [switch]$OmitNaming, [switch]$NoSupportedWorkloads)
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        $settings = if ($OmitNaming) {
            '{ "auditMode":true, "notifyUser":false }'                      # relies entirely on defaults
        } else {
            '{ "namingPrefix":"QGISCF","namingSuffix":"EXT-ADT","auditMode":true,"notifyUser":false,"nameTemplates":{ "label":"{prefix}-{name}-{labelCode}","autoLabelPolicy":"AL{policyNumber}-{labelCode}-{prefix}-{suffix}" } }'
        }
        Set-Content -Path (Join-Path $Dir 'settings.json') -Value $settings
        Set-Content -Path (Join-Path $Dir 'labels.json') -Value '[ { "code":"OFFI","name":"OFFICIAL","displayName":"OFFICIAL","isGroup":false } ]'
        $policies = if ($NoSupportedWorkloads) {
            '[ { "number":1,"code":"EPT","comment":"Endpoint (unsupported for auto-label)","location":{"EndpointDlpLocation":"All"},"enabled":true } ]'
        } else {
            '[ { "number":1,"code":"ECH","comment":"Exchange","location":{"ExchangeLocation":"All"},"enabled":true } ]'
        }
        Set-Content -Path (Join-Path $Dir 'policies.json') -Value $policies
        Set-Content -Path (Join-Path $Dir 'classifiers.json') -Value '{ "OFFI":[ {"name":"All Full Names","id":"50b8b56b-4ef8-44c2-a924-03374f5831ce","confidenceLevel":"Medium","minCount":1,"maxCount":-1} ] }'
        Set-Content -Path (Join-Path $Dir 'rule-overrides.json') -Value '{}'
    }
}

Describe 'Resolve-DesiredAutoLabel — merges deployment naming defaults (codex P2b)' {
    BeforeAll {
        $script:Dir = Join-Path ([System.IO.Path]::GetTempPath()) ("al-p2b-" + [guid]::NewGuid().ToString('N'))
        New-P2Config -Dir $script:Dir -OmitNaming
        $script:Pols = @((Resolve-DesiredAutoLabel -ConfigPath $script:Dir).Policies | Sort-Object policyName)
    }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'names the policy with the DEFAULT namingPrefix (DLP) and suffix (EXT-ADT) when settings omits them' {
        # Deploy-AutoLabeling merges Get-ModuleDefaults (namingPrefix=DLP, namingSuffix=EXT-ADT) under
        # settings.json, so a settings file that omits naming STILL deploys AL01-OFFI-DLP-EXT-ADT. The
        # resolver must match — before the fix it produced an empty {prefix}/{suffix}, diverging.
        $script:Pols.Count | Should -Be 1
        $script:Pols[0].policyName | Should -Be 'AL01-OFFI-DLP-EXT-ADT'
    }
    It 'applies the deployed label NAME using the default prefix + label template' {
        $script:Pols[0].label | Should -Be 'DLP-OFFICIAL-OFFI'
    }
}

Describe 'Invoke-Compl8Assess — empty desired auto-label set still orphans ours policies (codex P2a)' {
    BeforeAll {
        # A workspace whose auto-label config is VALID but resolves to ZERO desired policies (no
        # supported workload). An existing OURS auto-label policy in the tenant must be an ORPHAN.
        $script:Ws = Join-Path ([System.IO.Path]::GetTempPath()) ("al-p2a-" + [guid]::NewGuid().ToString('N'))
        $resolvedDir = Join-Path $script:Ws 'desired' 'resolved'
        $script:ConfigDir = Join-Path $script:Ws 'config'
        New-Item -ItemType Directory -Path $resolvedDir -Force | Out-Null
        New-P2Config -Dir $script:ConfigDir -NoSupportedWorkloads
        ([ordered]@{ schemaVersion = 'compl8.resolve-manifest/v1'; generatedUtc = '2026-06-13T00:00:00Z'; packing = [ordered]@{ assignments = [ordered]@{} }; packages = @(); warnings = @() } |
            ConvertTo-Json -Depth 12) | Set-Content -LiteralPath (Join-Path $resolvedDir 'resolve-manifest.json') -Encoding UTF8

        # Precondition: the config genuinely resolves to ZERO desired auto-label policies.
        @((Resolve-DesiredAutoLabel -ConfigPath $script:ConfigDir).Policies).Count | Should -Be 0

        $stamp = '[[Compl8DLPDeploy:provenance:v1;prefix=QGISCF;component=AutoLabelPolicy;deploymentId=20260614;environment=nonprod]]'
        foreach ($fn in 'Get-DlpKeywordDictionary','Get-DlpSensitiveInformationTypeRulePackage','Get-DlpComplianceRule','Get-DlpCompliancePolicy','Get-Label','Get-LabelPolicy','Get-AutoSensitivityLabelPolicy','Get-AutoSensitivityLabelRule') {
            Set-Item "function:global:$fn" { } -Force
        }
        Mock -ModuleName Compl8.Tenant Get-DlpKeywordDictionary { @() }
        Mock -ModuleName Compl8.Tenant Get-DlpSensitiveInformationTypeRulePackage { @() }
        Mock -ModuleName Compl8.Tenant Get-DlpComplianceRule { @() }
        Mock -ModuleName Compl8.Tenant Get-DlpCompliancePolicy { @() }
        Mock -ModuleName Compl8.Tenant Get-Label { @() }
        Mock -ModuleName Compl8.Tenant Get-LabelPolicy { @() }
        Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelRule { @() }
        Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelPolicy {
            @([pscustomobject]@{
                Name = 'AL09-ARCH-QGISCF-EXT-ADT'; Identity = 'AL09-ARCH-QGISCF-EXT-ADT'; Mode = 'TestWithoutNotifications'
                ApplySensitivityLabel = 'QGISCF-ARCHIVE'; ExchangeLocation = @('All')
                Comment = "Auto-label ARCHIVE (ARCH)`n$stamp"
            })
        }

        $script:Inv = Get-TenantInventory -Prefix 'QGISCF' -GeneratedUtc '2026-06-13T00:00:00Z'
        $script:Assessment = Invoke-Compl8Assess -WorkspacePath $script:Ws -Inventory $script:Inv `
            -ConfigRoot $script:ConfigDir -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'
    }
    AfterAll {
        if ($script:Ws -and (Test-Path -LiteralPath $script:Ws)) { Remove-Item -LiteralPath $script:Ws -Recurse -Force -ErrorAction SilentlyContinue }
        foreach ($fn in 'Get-DlpKeywordDictionary','Get-DlpSensitiveInformationTypeRulePackage','Get-DlpComplianceRule','Get-DlpCompliancePolicy','Get-Label','Get-LabelPolicy','Get-AutoSensitivityLabelPolicy','Get-AutoSensitivityLabelRule') {
            Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
        }
    }

    It 'precondition: the actual inventory carries the ours auto-label policy' {
        $actual = @($script:Inv.objects.autoLabelPolicies | Where-Object { $_.name -eq 'AL09-ARCH-QGISCF-EXT-ADT' })[0]
        $actual          | Should -Not -BeNullOrEmpty
        $actual.ours     | Should -BeTrue
    }
    It 'buckets the ours policy as ORPHAN even though the desired set is empty' {
        $orphans = @($script:Assessment.buckets.orphan | Where-Object { $_.objectType -eq 'autoLabelPolicy' } | ForEach-Object { $_.ref })
        $orphans | Should -Contain 'AL09-ARCH-QGISCF-EXT-ADT'
    }
}
