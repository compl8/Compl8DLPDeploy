#Requires -Modules Pester

# Static wiring invariants for the per-tenant config feature. These guard the two
# bug classes found during review:
#   1. A tenant-aware script that forgets to route $ConfigPath through the resolver
#      (so it silently always reads global config).
#   2. A non-scoped file (legacy package registry, fingerprint registry, transient
#      upload state) read/written through the RESOLVED $ConfigPath, which would make
#      it follow the per-tenant dir instead of staying global -- a split read.
#
# NOTE: -ForEach data must be defined at discovery scope (top level), not in
# BeforeAll, or Pester v5 generates zero tests.

# Discovery-scope value for -ForEach below; runtime copies are set in BeforeAll.
$DiscoveryRoot = Split-Path $PSScriptRoot -Parent

# Scripts that resolve config per-tenant (declare/derive a scoped $ConfigPath).
$TenantAwareScripts = @(
    'scripts/Deploy-Labels.ps1'
    'scripts/Deploy-Classifiers.ps1'
    'scripts/Deploy-DLPRules.ps1'
    'scripts/Test-DeploymentReadiness.ps1'
    'scripts/full-deploy.ps1'
    'scripts/greenfield-deploy.ps1'
    'scripts/Generate-ChangePack.ps1'
    'scripts/Invoke-ChangePack.ps1'
)

Describe 'Per-tenant config resolution wiring' {
    BeforeAll {
        $script:ProjectRoot = Split-Path $PSScriptRoot -Parent
        $script:NonScopedFiles = @(
            'classifiers-registry.json'
            'tenant-fingerprints.json'
            'last-classifier-upload.json'
        )
    }

    It '<_> routes $ConfigPath through Get-EffectiveConfigDir (or a session working dir)' -ForEach $TenantAwareScripts {
        $content = Get-Content -LiteralPath (Join-Path $script:ProjectRoot $_) -Raw
        # Either resolver-routed, or session-aware (working/config) which is the
        # other legitimate scoped source.
        ($content -match 'Get-EffectiveConfigDir' -or $content -match 'working/config') |
            Should -BeTrue -Because "$_ must derive its scoped config dir from the resolver, not a hard-coded global path"
    }

    It '<_> never reads a non-scoped file through the resolved $ConfigPath' -ForEach $TenantAwareScripts {
        $path = $_
        $content = Get-Content -LiteralPath (Join-Path $script:ProjectRoot $path) -Raw
        foreach ($f in $script:NonScopedFiles) {
            $pattern = 'Join-Path\s+\$ConfigPath\s+["'']' + [regex]::Escape($f) + '["'']'
            ($content -match $pattern) |
                Should -BeFalse -Because "$path must read $f from the global config dir (`$GlobalConfigPath), not the per-tenant `$ConfigPath"
        }
    }
}
