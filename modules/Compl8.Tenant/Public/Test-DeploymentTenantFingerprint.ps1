function Test-DeploymentTenantFingerprint {
    <#
    .SYNOPSIS
        Compares the connected tenant against optional expected fingerprints.
    .PARAMETER ProjectRoot
        Repository root used to find config/tenant-fingerprints.json.
    .PARAMETER TargetEnvironment
        Environment key under the config file's environments object.
    .PARAMETER RegisterIfMissing
        When set, an unknown $TargetEnvironment is registered in tenant-fingerprints.json
        and then compared against the connected tenant. First-deploy bootstrap for a new tenant.
    .PARAMETER RegisterMode
        Mode (warn|block) written for a newly-registered entry. Default warn. Ignored if the
        entry already exists.
    .PARAMETER ExpectedTenantId
        Operator-asserted tenant GUID for a newly-registered entry. When supplied it is written
        verbatim (never overwritten by the connected tenant) and validated against the live
        tenant under RegisterMode. Ignored if the entry already exists.
    #>
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [string]$TargetEnvironment,
        [string]$FingerprintPath,
        [switch]$RegisterIfMissing,
        [string]$RegisterMode = 'warn',
        [string]$ExpectedTenantId
    )

    if (-not $FingerprintPath) {
        $FingerprintPath = Join-Path (Join-Path $ProjectRoot "config") "tenant-fingerprints.json"
    }

    $actual = Get-DeploymentTenantInfo
    $result = [ordered]@{
        checked     = $false
        configured  = $false
        passed      = $true
        matched     = $null
        mode        = "warn"
        environment = $TargetEnvironment
        configPath  = ConvertTo-DeploymentRelativePath -Path $FingerprintPath -ProjectRoot $ProjectRoot
        expected    = [ordered]@{}
        actual      = $actual
        messages    = @()
        mismatches  = @()
    }

    # Validate operator-supplied registration inputs eagerly so bad input never reaches a
    # file write. Non-default values only — absent/empty preserves legacy behavior.
    $RegisterMode = if ([string]::IsNullOrWhiteSpace($RegisterMode)) { 'warn' } else { $RegisterMode.ToLowerInvariant() }
    if ($RegisterMode -notin @('warn', 'block')) {
        $result.passed = $false
        $result.mode = 'block'
        $result.messages += "Invalid -RegisterMode '$RegisterMode'; expected 'warn' or 'block'."
        return [PSCustomObject]$result
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedTenantId)) {
        $parsedGuid = [guid]::Empty
        if (-not [guid]::TryParse($ExpectedTenantId, [ref]$parsedGuid)) {
            $result.passed = $false
            $result.mode = 'block'
            $result.messages += "Invalid -ExpectedTenantId '$ExpectedTenantId'; expected a tenant GUID."
            return [PSCustomObject]$result
        }
        $ExpectedTenantId = $parsedGuid.ToString()
    }

    if (-not (Test-Path -LiteralPath $FingerprintPath)) {
        $result.messages += "No tenant fingerprint config found. Create config/tenant-fingerprints.json to pin environments."
        return [PSCustomObject]$result
    }

    $result.checked = $true
    try {
        $config = Get-Content -LiteralPath $FingerprintPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        $result.passed = $false
        $result.mode = "block"
        $result.messages += "Tenant fingerprint config could not be parsed: $($_.Exception.Message)"
        return [PSCustomObject]$result
    }

    if (-not $TargetEnvironment) {
        $TargetEnvironment = if ($config.defaultEnvironment) { $config.defaultEnvironment } else { "default" }
        $result.environment = $TargetEnvironment
    }

    $envProp = $null
    if ($config.environments) {
        $envProp = $config.environments.PSObject.Properties | Where-Object { $_.Name -eq $TargetEnvironment } | Select-Object -First 1
    }
    if (-not $envProp) {
        $availableEnvs = if ($config.environments) {
            @($config.environments.PSObject.Properties.Name) -join ', '
        } else { '(none)' }

        if (-not $RegisterIfMissing) {
            $result.messages += "No fingerprint entry for environment '$TargetEnvironment'. Available: $availableEnvs. Re-run with -RegisterFingerprint to bootstrap a new entry (optionally -ExpectedTenantId <guid> -FingerprintMode block to assert the target up front)."
            return [PSCustomObject]$result
        }

        # Asserted GUID is authoritative; otherwise capture the connected tenant identity.
        $actualTenantId = $actual.tenantId
        if (-not $actualTenantId) { $actualTenantId = $actual.guid }
        if (-not $actualTenantId) { $actualTenantId = $actual.id }

        $tenantIdToWrite = if (-not [string]::IsNullOrWhiteSpace($ExpectedTenantId)) { $ExpectedTenantId } else { $actualTenantId }
        if ([string]::IsNullOrWhiteSpace($tenantIdToWrite)) {
            $result.messages += "No fingerprint entry for environment '$TargetEnvironment'. Available: $availableEnvs. Live tenant identity unavailable and no -ExpectedTenantId supplied; cannot register."
            return [PSCustomObject]$result
        }

        $newEntry = [ordered]@{ mode = $RegisterMode; tenantId = $tenantIdToWrite.ToString() }
        # Only record the connected tenant name when we captured it (not when the GUID was asserted blind).
        if ($actual.name -and [string]::IsNullOrWhiteSpace($ExpectedTenantId)) { $newEntry.name = $actual.name.ToString() }

        if (-not $config.environments) {
            $config | Add-Member -NotePropertyName 'environments' -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        $config.environments | Add-Member -NotePropertyName $TargetEnvironment -NotePropertyValue ([pscustomobject]$newEntry) -Force

        try {
            $config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $FingerprintPath -Encoding UTF8
        } catch {
            $result.passed = $false
            $result.mode   = 'block'
            $result.messages += "Failed to register fingerprint entry '$TargetEnvironment': $($_.Exception.Message)"
            return [PSCustomObject]$result
        }

        $idSource = if (-not [string]::IsNullOrWhiteSpace($ExpectedTenantId)) { 'operator-asserted' } else { 'captured from connected tenant' }
        $result.messages += "Registered new fingerprint entry '$TargetEnvironment' (tenantId=$tenantIdToWrite, mode=$RegisterMode, $idSource) at $($result.configPath)."

        # Fall through to the standard comparison so the chosen mode is honored against the
        # connected tenant: block + mismatch refuses, warn + mismatch warns, auto-capture matches.
        $envProp = $config.environments.PSObject.Properties | Where-Object { $_.Name -eq $TargetEnvironment } | Select-Object -First 1
    }

    $expectedConfig = $envProp.Value
    $mode = if ($expectedConfig.mode) { $expectedConfig.mode.ToString().ToLowerInvariant() } else { "warn" }
    if ($mode -notin @("warn", "block")) {
        $result.messages += "Fingerprint mode '$mode' is not valid; using warn."
        $mode = "warn"
    }
    $result.mode = $mode

    foreach ($field in @("name", "id", "guid", "tenantId", "organizationId")) {
        $value = $expectedConfig.$field
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $result.expected[$field] = $value.ToString()
        }
    }

    if ($result.expected.Count -eq 0) {
        $result.messages += "Fingerprint entry '$TargetEnvironment' has no expected tenant fields. Populate name, id, guid, or organizationId to enforce it."
        return [PSCustomObject]$result
    }

    $result.configured = $true
    $mismatches = @()
    foreach ($field in @($result.expected.Keys)) {
        $expectedValue = $result.expected[$field]
        $actualValue = $actual[$field]
        if ([string]::IsNullOrWhiteSpace($actualValue) -or $actualValue.ToString() -ne $expectedValue) {
            $mismatches += [ordered]@{
                field    = $field
                expected = $expectedValue
                actual   = $actualValue
            }
        }
    }

    if ($mismatches.Count -eq 0) {
        $result.matched = $true
        $result.messages += "Connected tenant matches fingerprint '$TargetEnvironment'."
        return [PSCustomObject]$result
    }

    $result.matched = $false
    $result.mismatches = @($mismatches)
    $result.messages += "Connected tenant does not match fingerprint '$TargetEnvironment'."
    if ($mode -eq "block") {
        $result.passed = $false
    }

    return [PSCustomObject]$result
}
