#Requires -Modules Pester

# Static guard: every script that drives the tenant fingerprint gate must declare the two
# registration params AND forward them to Test-DeploymentTenantFingerprint, so the
# operator-asserted mode/GUID actually reach the module from every entry path.

$FingerprintAwareScripts = @(
    'scripts/Deploy-Labels.ps1'
    'scripts/Deploy-Classifiers.ps1'
    'scripts/Deploy-DLPRules.ps1'
    'scripts/Deploy-AutoLabeling.ps1'
    'scripts/Invoke-FullDeployment.ps1'
    'scripts/Invoke-GreenfieldDeployment.ps1'
    'scripts/Reset-DeploymentScope.ps1'
)

Describe 'Fingerprint registration param wiring' {
    BeforeAll { $script:ProjectRoot = Split-Path $PSScriptRoot -Parent }

    It '<_> declares -FingerprintMode and -ExpectedTenantId' -ForEach $FingerprintAwareScripts {
        $content = Get-Content -LiteralPath (Join-Path $script:ProjectRoot $_) -Raw
        ($content -match '\$FingerprintMode')  | Should -BeTrue -Because "$_ must accept -FingerprintMode"
        ($content -match '\$ExpectedTenantId') | Should -BeTrue -Because "$_ must accept -ExpectedTenantId"
    }

    It '<_> forwards both params to Test-DeploymentTenantFingerprint' -ForEach $FingerprintAwareScripts {
        $content = Get-Content -LiteralPath (Join-Path $script:ProjectRoot $_) -Raw
        ($content -match 'Test-DeploymentTenantFingerprint[^\r\n]*-RegisterMode\s+\$FingerprintMode')   | Should -BeTrue -Because "$_ must forward -RegisterMode"
        ($content -match 'Test-DeploymentTenantFingerprint[^\r\n]*-ExpectedTenantId\s+\$ExpectedTenantId') | Should -BeTrue -Because "$_ must forward -ExpectedTenantId"
    }
}
