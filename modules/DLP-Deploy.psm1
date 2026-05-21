#==============================================================================
# DLP-Deploy Shared Module
# Consolidates all common functions for the DLP deployment toolkit.
# Import with: Import-Module .\modules\DLP-Deploy.psm1 -Force
#==============================================================================

#region Module Defaults
function Get-ModuleDefaults {
    return @{
        auditMode                = $true
        notifyUser               = $false
        generateIncidentReport   = $false
        incidentReportRecipient  = "SiteAdmin"
        incidentReportSeverity   = "Medium"
        namingPrefix             = "DLP"
        namingSuffix             = "EXT-ADT"
        skipSitValidation        = $false
        suppressRuleOutput       = $true
        # SIT field defaults
        sitMinCount              = 1
        sitMaxCount              = -1
        sitConfidenceLevel       = "High"
        # Retry defaults
        maxRetries               = 3
        baseDelaySec             = 300
        interCallDelaySec        = 10
        # Auto-labeling
        overwriteLabel           = $false
        # Classifier deployment
        deploymentTier           = "full"
        publisher                = ""
        labelPolicyName          = "DLP-Label-Policy"
        # Data pipeline
        inputSpreadsheet         = ""
        # External pattern registry — base URL for the dictionary manifest export API.
        # Override in config/settings.json to point at a different registry.
        dictionaryManifestUrl    = "https://testpattern.dev/api/export/dictionary-manifest"
        # SIT entity name prefix — replaces "TestPattern" in entity display names at deploy time
        sitPrefix                = ""
    }
}
#endregion

#region Connection

# Tracks whether the active SCC session was already live when Connect-DLPSession ran.
# When true, Disconnect-DLPSession leaves it open so we don't tear down a session the
# caller (or a prior step) established and may still want.
$script:DLPSessionReused = $false

function Test-DLPSessionMatch {
    <#
    .SYNOPSIS
        Decides whether an existing Get-ConnectionInformation connection satisfies the
        requested -UPN / -Tenant target. Pure (no cmdlet calls), so it is unit-testable.
    .DESCRIPTION
        With neither UPN nor Tenant supplied, any connection matches (caller just wants
        "a live SCC session"). A Tenant matches when it equals — or is a substring of, or
        contains — the connection's Organization, TenantId, or UserPrincipalName (covers
        GUID, *.onmicrosoft.com, and verified-domain forms). A UPN matches on exact user
        or shared email domain.
    #>
    param(
        [Parameter(Mandatory)]$Connection,
        [string]$UPN,
        [string]$Tenant
    )

    $org  = Get-DeploymentObjectProperty -InputObject $Connection -Names @("Organization", "Tenant", "TenantName", "DelegatedOrganization")
    $tid  = Get-DeploymentObjectProperty -InputObject $Connection -Names @("TenantID", "TenantId", "TenantGuid", "ExternalDirectoryOrganizationId")
    $cupn = Get-DeploymentObjectProperty -InputObject $Connection -Names @("UserPrincipalName", "UserName")

    if (-not $UPN -and -not $Tenant) { return $true }

    $norm = { param($s) if ($null -eq $s) { "" } else { $s.ToString().Trim().ToLowerInvariant() } }

    if ($Tenant) {
        $t = & $norm $Tenant
        foreach ($v in @($org, $tid, $cupn)) {
            $n = & $norm $v
            if ($n -and ($n -eq $t -or $n.Contains($t) -or $t.Contains($n))) { return $true }
        }
        return $false
    }

    if ($UPN) {
        $u  = & $norm $UPN
        $cu = & $norm $cupn
        if ($cu -and $cu -eq $u) { return $true }
        if ($u.Contains("@") -and $cu.Contains("@") -and (($u -split "@")[-1] -eq ($cu -split "@")[-1])) { return $true }
        $o = & $norm $org
        if ($u.Contains("@") -and $o -and $o -eq ($u -split "@")[-1]) { return $true }
    }

    return $false
}

function Get-LiveDLPSession {
    <#
    .SYNOPSIS
        Returns an existing, connected Security & Compliance session that matches the
        requested -UPN / -Tenant, or $null. Used to avoid a fresh login when one is live.
    .NOTES
        Sessions are per-process: this only finds a session established earlier in the
        SAME PowerShell process (e.g. an interactive session, or sub-scripts invoked with
        '& ./script.ps1'). A separate 'pwsh -File ...' launch starts a clean process with
        no session to reuse.
    #>
    param([string]$UPN, [string]$Tenant)

    if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue)) { return $null }
    try { $conns = @(Get-ConnectionInformation -ErrorAction Stop) } catch { return $null }

    $scc = @($conns | Where-Object {
        (Get-DeploymentObjectProperty -InputObject $_ -Names @("State")) -eq "Connected" -and
        ((Get-DeploymentObjectProperty -InputObject $_ -Names @("ConnectionUri")) -match "compliance|ps\.compliance|protection\.outlook")
    })
    foreach ($c in $scc) {
        if (Test-DLPSessionMatch -Connection $c -UPN $UPN -Tenant $Tenant) { return $c }
    }
    return $null
}

function Connect-DLPSession {
    <#
    .SYNOPSIS
        Connects to Security & Compliance Center (IPPS session).
    .PARAMETER UPN
        User principal name for authentication.
    .PARAMETER Tenant
        Target tenant for cross-tenant access. Accepts a tenant GUID, .onmicrosoft.com domain,
        or any verified domain. Forces the auth flow to the specified tenant so MFA and login
        happen in the correct context (guest account scenario), or uses DelegatedOrganization
        for CSP/GDAP scenarios.
    .PARAMETER Delegated
        Use CSP/GDAP delegated admin mode instead of guest-account auth. Requires -Tenant to
        be the target's primary .onmicrosoft.com domain.
    .PARAMETER ForceNewSession
        Skip reuse detection and always open a fresh login, even if a matching session is
        already live in this process.
    #>
    param(
        [string]$UPN,
        [string]$Tenant,
        [switch]$Delegated,
        [switch]$ForceNewSession
    )

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Error "ExchangeOnlineManagement module not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
        return $false
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    # Reuse an already-live SCC session for this tenant instead of forcing another login.
    $script:DLPSessionReused = $false
    if (-not $ForceNewSession) {
        $existing = Get-LiveDLPSession -UPN $UPN -Tenant $Tenant
        if ($existing) {
            $who = Get-DeploymentObjectProperty -InputObject $existing -Names @("UserPrincipalName", "UserName")
            $org = Get-DeploymentObjectProperty -InputObject $existing -Names @("Organization", "Tenant", "TenantName")
            $detail = @($org, $who | Where-Object { $_ }) -join ", "
            Write-Host "  Reusing existing Security & Compliance session ($detail). No login needed." -ForegroundColor Green
            Write-Host "  (Use -ForceNewSession to force a fresh login.)" -ForegroundColor DarkGray
            $script:DLPSessionReused = $true
            return $true
        }
    }

    $connectParams = @{}
    if ($UPN) { $connectParams["UserPrincipalName"] = $UPN }
    if ($Tenant) {
        if ($Delegated) {
            # CSP/GDAP: use DelegatedOrganization (requires .onmicrosoft.com domain)
            $connectParams["DelegatedOrganization"] = $Tenant
            $connectParams["AzureADAuthorizationEndpointUri"] = "https://login.microsoftonline.com/organizations"
            Write-Host "  Delegated admin to tenant: $Tenant" -ForegroundColor Gray
        } else {
            # Guest account: force auth flow to target tenant.
            # Drop UPN to avoid null-ref conflict between home-tenant UPN and cross-tenant auth endpoint.
            $connectParams.Remove("UserPrincipalName")
            $connectParams["ConnectionUri"] = "https://ps.compliance.protection.outlook.com/powershell-liveid/"
            $connectParams["AzureADAuthorizationEndpointUri"] = "https://login.microsoftonline.com/$Tenant"
            Write-Host "  Cross-tenant auth to: $Tenant (login prompt will appear)" -ForegroundColor Gray
        }
    }
    try {
        Connect-IPPSSession @connectParams -ErrorAction Stop
        Write-Host "  Connected to Security & Compliance Center." -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Connection failed: $($_.Exception.Message)"
        return $false
    }
}

function Assert-DLPSession {
    <#
    .SYNOPSIS
        Validates an active Security & Compliance session exists.
    .PARAMETER CommandToTest
        The cmdlet to probe. Defaults to Get-DlpCompliancePolicy.
    #>
    param([string]$CommandToTest = "Get-DlpCompliancePolicy")

    try {
        & $CommandToTest -ErrorAction Stop | Select-Object -First 1 | Out-Null
        return $true
    } catch {
        Write-Error "Not connected to Security & Compliance Center. Run with -Connect or Connect-IPPSSession first."
        return $false
    }
}

function Disconnect-DLPSession {
    <#
    .SYNOPSIS
        Disconnects the Exchange Online / IPPS session — unless Connect-DLPSession reused a
        session that was already live at start, in which case it is left open.
    .PARAMETER Force
        Disconnect even if the session was pre-existing/reused.
    #>
    param([switch]$Force)

    if ($script:DLPSessionReused -and -not $Force) {
        Write-Host "  Leaving the pre-existing session open (it was live before this run; use -Force to close)." -ForegroundColor Gray
        return
    }
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  Disconnected from Security & Compliance Center." -ForegroundColor Gray
}
#endregion

#region Config Loading
function Import-JsonConfig {
    <#
    .SYNOPSIS
        Loads and parses a JSON configuration file.
    #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string]$Description
    )
    if (-not (Test-Path $FilePath)) {
        Write-Error "Config file not found: $FilePath ($Description)"
        return $null
    }
    try {
        $content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
        $parsed = $content | ConvertFrom-Json -ErrorAction Stop
        Write-Host "  Loaded $Description from $(Split-Path $FilePath -Leaf)" -ForegroundColor Gray
        return $parsed
    } catch {
        Write-Error "Failed to parse $FilePath ($Description): $($_.Exception.Message)"
        return $null
    }
}

function Merge-GlobalConfig {
    <#
    .SYNOPSIS
        Merges a loaded global.json (or settings.json) over module defaults.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Defaults,
        [object]$GlobalJson
    )
    $merged = @{}
    foreach ($key in $Defaults.Keys) {
        $merged[$key] = $Defaults[$key]
    }
    if ($GlobalJson) {
        foreach ($prop in $GlobalJson.PSObject.Properties) {
            if ($merged.ContainsKey($prop.Name)) {
                $merged[$prop.Name] = $prop.Value
            }
        }
        # Warn on unrecognized keys (skip _comment-style keys)
        foreach ($prop in $GlobalJson.PSObject.Properties) {
            if (-not $Defaults.ContainsKey($prop.Name) -and $prop.Name -notlike '_*') {
                Write-Warning "Unrecognized setting: '$($prop.Name)' — check for typos in settings.json"
            }
        }
    }
    return $merged
}

function Set-DeploymentConfigPrefix {
    <#
    .SYNOPSIS
        Applies a command-line naming prefix override to a merged deployment config.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [string]$Prefix
    )

    if ([string]::IsNullOrWhiteSpace($Prefix)) {
        return $Config
    }

    $prefixValue = $Prefix.Trim()
    $oldPrefix = if ($Config.ContainsKey("namingPrefix")) { $Config["namingPrefix"] } else { $null }
    $oldLabelPolicy = if ($Config.ContainsKey("labelPolicyName")) { $Config["labelPolicyName"] } else { $null }

    $Config["namingPrefix"] = $prefixValue
    $Config["sitPrefix"] = $prefixValue

    if ([string]::IsNullOrWhiteSpace($oldLabelPolicy)) {
        $Config["labelPolicyName"] = "$prefixValue-Label-Policy"
    } elseif (-not [string]::IsNullOrWhiteSpace($oldPrefix) -and $oldLabelPolicy -match "^$([regex]::Escape($oldPrefix))(?=-|$)") {
        $Config["labelPolicyName"] = [regex]::Replace($oldLabelPolicy, "^$([regex]::Escape($oldPrefix))", $prefixValue, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    } elseif ($oldLabelPolicy -eq "DLP-Label-Policy") {
        $Config["labelPolicyName"] = "$prefixValue-Label-Policy"
    }

    Write-Host "  Prefix override: namingPrefix/sitPrefix = $prefixValue" -ForegroundColor Gray
    Write-Host "  Label policy:    $($Config["labelPolicyName"])" -ForegroundColor Gray
    return $Config
}

function Assert-ConfigCustomised {
    <#
    .SYNOPSIS
        Warns if critical settings are still at module defaults.
        Call after Merge-GlobalConfig to prompt users to customise settings.json.
    #>
    param([Parameter(Mandatory)][hashtable]$Config)

    $defaults = @{
        namingPrefix    = "DLP"
        publisher       = ""
        labelPolicyName = "DLP-Label-Policy"
    }
    $warnings = @()
    foreach ($key in $defaults.Keys) {
        if ($Config[$key] -eq $defaults[$key]) {
            $warnings += $key
        }
    }
    if ($warnings.Count -gt 0) {
        Write-Host ""
        Write-Host "  WARNING: The following settings in config/settings.json are still at defaults:" -ForegroundColor Red
        foreach ($w in $warnings) {
            $current = if ($Config[$w]) { $Config[$w] } else { "(empty)" }
            Write-Host "    $w = $current" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  These control how your policies, rules, and packages are named in the tenant." -ForegroundColor Yellow
        Write-Host "  Update config/settings.json before deploying to a customer environment." -ForegroundColor Yellow
        Write-Host ""

        $continue = Read-Host "  Continue with default settings? (yes/no)"
        if ($continue -ne "yes") {
            Write-Host "  Aborted. Edit config/settings.json and re-run." -ForegroundColor Red
            return $false
        }
    }
    return $true
}
#endregion

#region Config Resolution
function Resolve-PolicyConfig {
    <#
    .SYNOPSIS
        Converts policies.json array into structured hashtable array.
    #>
    param([Parameter(Mandatory)][array]$PoliciesJson)

    $policies = @()
    foreach ($p in $PoliciesJson) {
        $location = @{}
        foreach ($prop in $p.location.PSObject.Properties) {
            $location[$prop.Name] = $prop.Value
        }
        $policies += @{
            Number     = [int]$p.number
            Code       = $p.code
            Comment    = $p.comment
            Location   = $location
            ScopeParam = if ($null -eq $p.scopeParam -or $p.scopeParam -eq "") { $null } else { $p.scopeParam }
            ScopeValue = if ($null -eq $p.scopeValue -or $p.scopeValue -eq "") { "NotInOrganization" } else { $p.scopeValue }
            Optional   = [bool]$p.optional
            Enabled    = if ($null -eq $p.enabled) { $true } else { [bool]$p.enabled }
        }
    }
    return $policies
}

function Resolve-ClassifierConfig {
    <#
    .SYNOPSIS
        Converts classifiers.json into a hashtable of label-code → classifier-list.
        Each entry has Name, Id, and either SIT fields (minCount/maxCount/confidencelevel)
        or ClassifierType = "MLModel" for trainable classifiers.
    #>
    param(
        [Parameter(Mandatory)][object]$ClassifiersJson,
        [Parameter(Mandatory)][hashtable]$Defaults
    )
    $classifiers = @{}
    foreach ($prop in $ClassifiersJson.PSObject.Properties) {
        $labelCode = $prop.Name
        $entryList = @()
        foreach ($item in $prop.Value) {
            if ($item.classifierType -eq "MLModel") {
                $entryList += @{
                    Name           = $item.name
                    Id             = $item.id
                    ClassifierType = "MLModel"
                }
            } else {
                $entryList += @{
                    Name            = $item.name
                    Id              = $item.id
                    minCount        = if ($null -ne $item.minCount) { [int]$item.minCount } else { $Defaults.sitMinCount }
                    maxCount        = if ($null -ne $item.maxCount) { [int]$item.maxCount } else { $Defaults.sitMaxCount }
                    confidencelevel = if ($item.confidenceLevel) { $item.confidenceLevel } else { $Defaults.sitConfidenceLevel }
                }
            }
        }
        $classifiers[$labelCode] = $entryList
    }
    return $classifiers
}

function Resolve-LabelConfig {
    <#
    .SYNOPSIS
        Loads enriched labels.json and returns only non-group labels for DLP rule use.
        Returns objects with .code and .displayName properties.
    #>
    param([Parameter(Mandatory)][array]$LabelsJson)

    return $LabelsJson | Where-Object { -not $_.isGroup -and -not $_.dlpExclude } | ForEach-Object {
        [PSCustomObject]@{
            code     = $_.code
            fullName = if ($_.displayName) { $_.displayName } else { $_.name }
        }
    }
}

function Resolve-RuleOverrides {
    <#
    .SYNOPSIS
        Converts rule-overrides.json into structured hashtable.
    #>
    param([object]$OverridesJson)

    $overrides = @{
        byLabel  = @{}
        byPolicy = @{}
        byRule   = @{}
    }
    if (-not $OverridesJson) { return $overrides }

    foreach ($section in @("byLabel", "byPolicy", "byRule")) {
        $sectionObj = $OverridesJson.$section
        if ($sectionObj) {
            foreach ($prop in $sectionObj.PSObject.Properties) {
                $hash = @{}
                foreach ($innerProp in $prop.Value.PSObject.Properties) {
                    $hash[$innerProp.Name] = $innerProp.Value
                }
                $overrides[$section][$prop.Name] = $hash
            }
        }
    }
    return $overrides
}
#endregion

#region Naming
function Get-PolicyName {
    param(
        [int]$PolicyNumber,
        [string]$PolicyCode,
        [string]$Prefix,
        [string]$Suffix
    )
    return "P{0:D2}-{1}-{2}-{3}" -f $PolicyNumber, $PolicyCode, $Prefix, $Suffix
}

function Get-RuleName {
    param(
        [int]$PolicyNumber,
        [int]$RuleNumber,
        [string]$PolicyCode,
        [string]$LabelCode,
        [string]$Suffix
    )
    return "P{0:D2}-R{1:D2}-{2}-{3}-{4}" -f $PolicyNumber, $RuleNumber, $PolicyCode, $LabelCode, $Suffix
}

function Get-PurviewUnsafeNameCharacterSummary {
    param([AllowNull()][string]$Name)

    if ($null -eq $Name) { return @() }

    $seen = [ordered]@{}
    foreach ($char in $Name.ToCharArray()) {
        $value = [int][char]$char
        $charText = [string]$char
        $isAllowed = ($charText -cmatch '^[A-Za-z0-9_.-]$')
        if ($value -lt 32 -or $value -gt 126 -or -not $isAllowed) {
            $label = switch ($value) {
                9  { "tab"; break }
                10 { "line feed"; break }
                13 { "carriage return"; break }
                32 { "space"; break }
                default {
                    if ($value -lt 32 -or $value -gt 126) { "U+{0:X4}" -f $value }
                    else { "'$charText'" }
                }
            }
            if (-not $seen.Contains($label)) {
                $seen[$label] = $true
            }
        }
    }

    return @($seen.Keys)
}

function Test-PurviewObjectNameSafety {
    <#
    .SYNOPSIS
        Validates a generated Purview object identity against the deployment-safe
        naming policy.

    .DESCRIPTION
        Purview and Security & Compliance cmdlets can accept names that later
        become hard to query or remove. This guard intentionally uses a stricter
        deployment policy than a permissive service-side parser: ASCII letters,
        digits, underscore, dot, and hyphen only.
    #>
    param(
        [AllowNull()][AllowEmptyString()][string]$Name,
        [string]$ObjectType = "Purview object",
        [int]$MaxLength = 128
    )

    $reasons = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Name) {
        $reasons.Add("Name is null.")
    } elseif ([string]::IsNullOrWhiteSpace($Name)) {
        $reasons.Add("Name is empty or whitespace.")
    } else {
        if ($Name -ne $Name.Trim()) {
            $reasons.Add("Name has leading or trailing whitespace.")
        }
        if ($Name.Length -gt $MaxLength) {
            $reasons.Add("Name length $($Name.Length) exceeds max $MaxLength.")
        }
        if ($Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') {
            $unsafeChars = @(Get-PurviewUnsafeNameCharacterSummary -Name $Name)
            if ($unsafeChars.Count -gt 0) {
                $reasons.Add("Name contains unsupported character(s): $($unsafeChars -join ', ').")
            }
            $reasons.Add("Name must match ^[A-Za-z0-9][A-Za-z0-9_.-]*$.")
        }
    }

    return [PSCustomObject]@{
        IsSafe         = ($reasons.Count -eq 0)
        Name           = $Name
        ObjectType     = $ObjectType
        MaxLength      = $MaxLength
        AllowedPattern = '^[A-Za-z0-9][A-Za-z0-9_.-]*$'
        Reasons        = @($reasons)
    }
}

function Assert-PurviewObjectNameSafety {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Names,
        [string]$ObjectType = "Purview object",
        [int]$MaxLength = 128
    )

    $failures = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @($Names)) {
        $result = Test-PurviewObjectNameSafety -Name $name -ObjectType $ObjectType -MaxLength $MaxLength
        if (-not $result.IsSafe) {
            $displayName = if ($null -eq $result.Name) { "<null>" } else { "'$($result.Name)'" }
            $failures.Add("$ObjectType $displayName`: $($result.Reasons -join ' ')")
        }
    }

    if ($failures.Count -gt 0) {
        throw "Unsafe Purview object name(s) blocked before tenant submission:`n  - $($failures -join "`n  - ")"
    }

    return $true
}
#endregion

#region DLP Helpers
function New-DLPSITCondition {
    <#
    .SYNOPSIS
        Builds the classifier condition for New-DlpComplianceRule.
        Returns a hashtable with:
          .Format = "Simple" or "AdvancedRule"
          .Value  = hashtable (for -ContentContainsSensitiveInformation) or JSON string (for -AdvancedRule)

        If ANY classifier is a trainable classifier (ClassifierType=MLModel), the entire
        condition must use -AdvancedRule JSON format. Otherwise uses the simpler hashtable.
    .PARAMETER ClassifierList
        Array of classifier entries from Resolve-ClassifierConfig.
    .PARAMETER ScopeParam
        Optional. The scope parameter name (e.g. "AccessScope") for the policy.
    .PARAMETER ScopeValue
        Optional. The scope value (e.g. "NotInOrganization").
    #>
    param(
        [Parameter(Mandatory)][array]$ClassifierList,
        [string]$ScopeParam,
        [string]$ScopeValue
    )

    $hasTC = $false
    foreach ($entry in $ClassifierList) {
        if ($entry.ClassifierType -eq "MLModel") { $hasTC = $true; break }
    }

    if (-not $hasTC) {
        # Simple format — no trainable classifiers
        $sensitivetypes = @()
        foreach ($sit in $ClassifierList) {
            $sensitivetypes += @{
                name            = $sit.Name
                id              = $sit.Id
                mincount        = [int]$sit.minCount
                maxcount        = [int]$sit.maxCount
                confidencelevel = $sit.confidencelevel
            }
        }
        return @{
            Format = "Simple"
            Value  = @{
                operator = "And"
                groups   = @(
                    @{
                        operator       = "Or"
                        name           = "Default"
                        sensitivetypes = $sensitivetypes
                    }
                )
            }
        }
    }

    # AdvancedRule format — mix of SITs and TCs
    return @{
        Format = "AdvancedRule"
        Value  = New-AdvancedRuleJson -ClassifierList $ClassifierList -ScopeParam $ScopeParam -ScopeValue $ScopeValue
    }
}

function New-AdvancedRuleJson {
    <#
    .SYNOPSIS
        Builds the AdvancedRule JSON string for DLP rules containing trainable classifiers.
    #>
    param(
        [Parameter(Mandatory)][array]$ClassifierList,
        [string]$ScopeParam,
        [string]$ScopeValue
    )

    # Build Sensitivetypes array
    $sensitiveTypes = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $ClassifierList) {
        if ($entry.ClassifierType -eq "MLModel") {
            $sensitiveTypes.Add(@{
                Name           = $entry.Name
                Id             = $entry.Id
                Classifiertype = "MLModel"
            })
        } else {
            # AdvancedRule JSON schema requires numeric Minconfidence/Maxconfidence
            # (unlike Simple format which uses string confidencelevel: "Low"/"Medium"/"High").
            # Map the string confidencelevel to the appropriate numeric range.
            if ($entry.confidencelevel -match '^\d+$') {
                Write-Warning "Classifier '$($entry.Name)': confidencelevel should be 'Low', 'Medium', or 'High' — got numeric '$($entry.confidencelevel)'"
            }
            $minConfidence = switch ($entry.confidencelevel) {
                "Low"    { 65 }
                "Medium" { 75 }
                "High"   { 85 }
                default  { 75 }
            }
            $sensitiveTypes.Add(@{
                Name          = $entry.Name
                Id            = $entry.Id
                Mincount      = [int]$entry.minCount
                Maxcount      = [int]$entry.maxCount
                Minconfidence = $minConfidence
                Maxconfidence = 100
            })
        }
    }

    # Build the CCSI subcondition
    $ccsiSubCondition = @{
        ConditionName = "ContentContainsSensitiveInformation"
        Value         = @(
            @{
                Groups   = @(
                    @{
                        Name           = "Default"
                        Operator       = "Or"
                        Sensitivetypes = @($sensitiveTypes)
                    }
                )
                Operator = "And"
            }
        )
    }

    $subConditions = [System.Collections.Generic.List[object]]::new()
    $subConditions.Add($ccsiSubCondition)

    # Add AccessScope subcondition if applicable
    if ($ScopeParam -eq "AccessScope" -and $ScopeValue) {
        $subConditions.Add(@{
            ConditionName = "AccessScope"
            Value         = $ScopeValue
        })
    }

    $advancedRule = @{
        Version   = "1.0"
        Condition = @{
            Operator      = "And"
            SubConditions = @($subConditions)
        }
    }

    return ($advancedRule | ConvertTo-Json -Depth 20 -Compress)
}

function Resolve-PolicyMode {
    param(
        [bool]$AuditMode,
        [bool]$NotifyUser
    )
    if ($AuditMode) {
        if ($NotifyUser) { return "TestWithNotifications" }
        else { return "TestWithoutNotifications" }
    } else {
        return "Enable"
    }
}

function Get-MergedRuleParams {
    <#
    .SYNOPSIS
        Merges base rule parameters with overrides (byPolicy < byLabel < byRule).
    #>
    param(
        [hashtable]$BaseParams,
        [hashtable]$Overrides,
        [string]$LabelCode,
        [string]$PolicyCode,
        [string]$RuleName
    )
    $merged = @{}
    foreach ($key in $BaseParams.Keys) { $merged[$key] = $BaseParams[$key] }

    if ($Overrides.byPolicy.ContainsKey($PolicyCode)) {
        foreach ($key in $Overrides.byPolicy[$PolicyCode].Keys) {
            $merged[$key] = $Overrides.byPolicy[$PolicyCode][$key]
        }
    }
    if ($Overrides.byLabel.ContainsKey($LabelCode)) {
        foreach ($key in $Overrides.byLabel[$LabelCode].Keys) {
            $merged[$key] = $Overrides.byLabel[$LabelCode][$key]
        }
    }
    if ($Overrides.byRule.ContainsKey($RuleName)) {
        foreach ($key in $Overrides.byRule[$RuleName].Keys) {
            $merged[$key] = $Overrides.byRule[$RuleName][$key]
        }
    }
    return $merged
}
#endregion

#region Pre-flight Conflict Check
function Test-PurviewNameConflicts {
    <#
    .SYNOPSIS
        Checks a list of planned object names against existing tenant objects.
        Returns $true if safe to proceed, $false if user aborted.

        Classifies each existing object as:
        - "active"  — exists and is live, will need delete-and-recreate
        - "pending" — pending deletion, creation may fail
        - "clean"   — no conflict

        Prompts for confirmation when conflicts are found.
    .EXAMPLE
        $existingRules = Get-DlpComplianceRule -Policy $policyName
        $safe = Test-PurviewNameConflicts -PlannedNames @("P01-R01-ECH-OFFI") `
            -ExistingObjects $existingRules -ObjectType "DLP rule"
    #>
    param(
        [Parameter(Mandatory)][string[]]$PlannedNames,
        [array]$ExistingObjects = @(),
        [string]$ObjectType = "object",
        [string]$IdentityProperty = "Name"
    )

    # Build lookup of existing objects by name
    $existingLookup = @{}
    foreach ($obj in $ExistingObjects) {
        $name = $obj.$IdentityProperty
        if ($name) { $existingLookup[$name] = $obj }
    }

    # Classify conflicts
    $active = @()
    $pending = @()
    $clean = 0
    foreach ($name in $PlannedNames) {
        if (-not $existingLookup.ContainsKey($name)) {
            $clean++
            continue
        }
        $obj = $existingLookup[$name]
        $isPending = $false
        if ($obj.PSObject.Properties['Mode'] -and $obj.Mode -eq 'PendingDeletion') { $isPending = $true }
        if ($obj.PSObject.Properties['State'] -and $obj.State -eq 'PendingDeletion') { $isPending = $true }

        if ($isPending) { $pending += $name }
        else { $active += $name }
    }

    if ($active.Count -eq 0 -and $pending.Count -eq 0) {
        Write-Host "    No name conflicts detected ($clean new $($ObjectType)s)" -ForegroundColor Green
        return $true
    }

    Write-Host ""
    Write-Host "    Name conflict check:" -ForegroundColor Yellow
    Write-Host "      Clean (no conflict):  $clean" -ForegroundColor Green
    if ($active.Count -gt 0) {
        Write-Host "      Active (will delete and recreate): $($active.Count)" -ForegroundColor Red
        foreach ($n in $active | Select-Object -First 10) {
            Write-Host "        $n" -ForegroundColor Red
        }
        if ($active.Count -gt 10) { Write-Host "        ... and $($active.Count - 10) more" -ForegroundColor Red }
    }
    if ($pending.Count -gt 0) {
        Write-Host "      Pending deletion (creation may fail): $($pending.Count)" -ForegroundColor DarkYellow
        foreach ($n in $pending | Select-Object -First 10) {
            Write-Host "        $n" -ForegroundColor DarkYellow
        }
        if ($pending.Count -gt 10) { Write-Host "        ... and $($pending.Count - 10) more" -ForegroundColor DarkYellow }
        Write-Host ""
        Write-Host "      WARNING: Purview may reject creation of $($ObjectType)s that are still" -ForegroundColor DarkYellow
        Write-Host "      pending deletion. If this happens, wait for deletion to complete and re-run." -ForegroundColor DarkYellow
    }

    Write-Host ""
    $confirm = Read-Host "    Proceed? Active items will be deleted and recreated (yes/no)"
    if ($confirm -ne "yes") {
        Write-Host "    Aborted." -ForegroundColor Red
        return $false
    }

    # Delete active conflicts so creation can proceed
    if ($active.Count -gt 0) {
        Write-Host "    Removing $($active.Count) active $($ObjectType)(s) before deploy..." -ForegroundColor Yellow
        foreach ($name in $active) {
            $obj = $existingLookup[$name]
            Write-Host "      $name" -ForegroundColor Yellow -NoNewline
            # Determine remove command from object type
            $removeCmd = switch -Wildcard ($ObjectType) {
                "DLP rule"  { "Remove-DlpComplianceRule" }
                "DLP polic*" { "Remove-DlpCompliancePolicy" }
                "AL rule"   { "Remove-AutoSensitivityLabelRule" }
                "AL polic*" { "Remove-AutoSensitivityLabelPolicy" }
                default     { $null }
            }
            if ($removeCmd) {
                $null = Remove-PurviewObject -Identity $name -InputObject $obj `
                    -RemoveCommand $removeCmd -OperationName $ObjectType -MaxRetries 2 -BaseDelaySec 30
            }
        }
    }

    return $true
}
#endregion

#region Classifier Reference Guards
function Convert-DlpSerializedRulePackageToText {
    param([object]$Raw)

    if ($null -eq $Raw) { return $null }
    if ($Raw -is [byte[]]) {
        $bytes = [byte[]]$Raw
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
            return [System.Text.Encoding]::Unicode.GetString($bytes)
        }
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
            return [System.Text.Encoding]::BigEndianUnicode.GetString($bytes)
        }
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            return [System.Text.Encoding]::UTF8.GetString($bytes)
        }
        if ($bytes -contains 0) {
            return [System.Text.Encoding]::Unicode.GetString($bytes)
        }
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    }

    return $Raw.ToString()
}

function Get-DlpRulePackageEntityIds {
    param([Parameter(Mandatory)][object[]]$Packages)

    $results = @()
    foreach ($pkg in @($Packages)) {
        $entityIds = @()
        $rulePackId = $null
        $packageName = $null
        $parsed = $false
        $parseError = $null
        $rawText = Convert-DlpSerializedRulePackageToText -Raw $pkg.SerializedClassificationRuleCollection
        if ($rawText) {
            try {
                [xml]$xml = $rawText
                $parsed = $true
                $rulePack = $xml.RulePackage.RulePack
                if ($rulePack -and $rulePack.id) {
                    $rulePackId = $rulePack.id.ToString()
                }
                if ($rulePack -and $rulePack.Details -and $rulePack.Details.LocalizedDetails) {
                    $packageName = ($rulePack.Details.LocalizedDetails | Select-Object -First 1).Name
                }
                $rules = $xml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq "Rules" } | Select-Object -First 1
                if ($rules) {
                    $entityIds = @($rules.ChildNodes |
                        Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -eq "Entity" } |
                        ForEach-Object { $_.GetAttribute("id") } |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                        Sort-Object -Unique)
                }
            } catch {
                $parseError = $_.Exception.Message
                Write-Warning "Could not parse classifier package XML for '$($pkg.Identity)': $parseError"
            }
        } else {
            $parseError = "SerializedClassificationRuleCollection was empty."
        }

        $results += [pscustomobject]@{
            Identity   = if ($pkg.Identity) { $pkg.Identity.ToString() } else { $null }
            Name       = if ($packageName) { $packageName } elseif ($pkg.Name) { $pkg.Name.ToString() } else { $null }
            Publisher  = if ($pkg.Publisher) { $pkg.Publisher.ToString() } else { $null }
            RulePackId = $rulePackId
            EntityIds  = @($entityIds)
            Parsed     = [bool]$parsed
            ParseError  = $parseError
            Package    = $pkg
        }
    }

    return $results
}

function Get-DlpRulePolicyNames {
    param([Parameter(Mandatory)][object]$Rule)

    $names = New-Object System.Collections.Generic.List[string]
    if ($Rule.ParentPolicyName) {
        $names.Add($Rule.ParentPolicyName.ToString()) | Out-Null
    }
    foreach ($policy in @($Rule.Policy)) {
        if ($policy) {
            $names.Add($policy.ToString()) | Out-Null
        }
    }

    return @($names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
}

function Get-DlpRuleClassifierReferenceText {
    param([Parameter(Mandatory)][object]$Rule)

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($propertyName in @(
        "ContentContainsSensitiveInformation",
        "ExceptIfContentContainsSensitiveInformation",
        "AdvancedRule",
        "Conditions",
        "Exceptions"
    )) {
        $property = $Rule.PSObject.Properties[$propertyName]
        if (-not $property -or $null -eq $property.Value) { continue }
        try {
            $parts.Add(($property.Value | ConvertTo-Json -Depth 20 -Compress)) | Out-Null
        } catch {
            $parts.Add($property.Value.ToString()) | Out-Null
        }
    }

    return ($parts -join "`n")
}

function Get-DlpClassifierRuleReferences {
    param([Parameter(Mandatory)][string[]]$CandidateIds)

    $candidateLookup = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @($CandidateIds)) {
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $candidateLookup.Add($id.ToString()) | Out-Null
        }
    }

    $result = [pscustomobject]@{
        CandidateIdCount = $candidateLookup.Count
        RulesScanned     = 0
        MatchingRuleCount = 0
        References       = @()
    }
    if ($candidateLookup.Count -eq 0) { return $result }

    try {
        $rules = @(Get-DlpComplianceRule -ErrorAction Stop)
    } catch {
        Write-Warning "Could not retrieve DLP rules for classifier reference check: $($_.Exception.Message)"
        return $result
    }

    $guidPattern = '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
    $references = @()
    foreach ($rule in $rules) {
        $result.RulesScanned++
        $ruleText = Get-DlpRuleClassifierReferenceText -Rule $rule
        if (-not $ruleText) { continue }

        $matchedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($match in [regex]::Matches($ruleText, $guidPattern)) {
            if ($candidateLookup.Contains($match.Value)) {
                $matchedIds.Add($match.Value.ToLowerInvariant()) | Out-Null
            }
        }
        if ($matchedIds.Count -eq 0) { continue }

        $references += [pscustomobject]@{
            RuleName = if ($rule.Name) { $rule.Name.ToString() } elseif ($rule.Identity) { $rule.Identity.ToString() } else { "(unknown)" }
            PolicyNames = @(Get-DlpRulePolicyNames -Rule $rule)
            MatchedClassifierIds = @($matchedIds | Sort-Object)
        }
    }

    $result.MatchingRuleCount = @($references).Count
    $result.References = @($references)
    return $result
}

function Test-DlpRulePackageRemovalReferenceGuard {
    param(
        [Parameter(Mandatory)][object[]]$Packages,
        [string]$OperationName = "classifier package removal"
    )

    $packageEntityIndex = @(Get-DlpRulePackageEntityIds -Packages $Packages)
    $candidateIds = @($packageEntityIndex | ForEach-Object { $_.EntityIds } | Sort-Object -Unique)
    # When no entity IDs could be extracted (e.g. every package failed to parse), there is
    # nothing to scan for — skip the lookup so the mandatory parameter doesn't throw. The
    # unparsed-package check below still fails the guard closed.
    $referenceIndex = if ($candidateIds.Count -gt 0) {
        Get-DlpClassifierRuleReferences -CandidateIds $candidateIds
    } else {
        [pscustomobject]@{ CandidateIdCount = 0; RulesScanned = 0; MatchingRuleCount = 0; References = @() }
    }
    $referencedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ref in @($referenceIndex.References)) {
        foreach ($id in @($ref.MatchedClassifierIds)) {
            $referencedIds.Add($id) | Out-Null
        }
    }

    $referencedPackages = @($packageEntityIndex | Where-Object {
        $hit = $false
        foreach ($id in @($_.EntityIds)) {
            if ($referencedIds.Contains($id)) {
                $hit = $true
                break
            }
        }
        $hit
    })
    $unparsedPackages = @($packageEntityIndex | Where-Object { -not $_.Parsed })

    $safe = ($referenceIndex.MatchingRuleCount -eq 0 -and $unparsedPackages.Count -eq 0)
    Write-Host "`n=== Classifier Reference Guard ===" -ForegroundColor Cyan
    Write-Host "  Operation:          $OperationName" -ForegroundColor Gray
    Write-Host "  Packages checked:   $(@($Packages).Count)" -ForegroundColor Gray
    Write-Host "  Entity IDs checked: $($referenceIndex.CandidateIdCount)" -ForegroundColor Gray
    Write-Host "  DLP rules scanned:  $($referenceIndex.RulesScanned)" -ForegroundColor Gray
    if ($unparsedPackages.Count -gt 0) {
        Write-Host "  Unparsed packages:  $($unparsedPackages.Count)" -ForegroundColor Red
        foreach ($pkg in @($unparsedPackages | Select-Object -First 8)) {
            Write-Host "    - $($pkg.Identity): $($pkg.ParseError)" -ForegroundColor Red
        }
    }
    $color = if ($safe) { "Green" } else { "Red" }
    Write-Host "  Referencing rules:  $($referenceIndex.MatchingRuleCount)" -ForegroundColor $color

    if (-not $safe) {
        foreach ($ref in @($referenceIndex.References | Select-Object -First 12)) {
            Write-Host "    - $($ref.RuleName) [$(@($ref.PolicyNames) -join ', ')]" -ForegroundColor Red
        }
        if ($referenceIndex.MatchingRuleCount -gt 12) {
            Write-Host "    ... $($referenceIndex.MatchingRuleCount - 12) more referencing rule(s)" -ForegroundColor Red
        }
    }

    return [pscustomobject]@{
        Safe = [bool]$safe
        PackagesChecked = @($Packages).Count
        EntityIdsChecked = $referenceIndex.CandidateIdCount
        RulesScanned = $referenceIndex.RulesScanned
        ReferencingRuleCount = $referenceIndex.MatchingRuleCount
        References = @($referenceIndex.References)
        ReferencedPackages = @($referencedPackages)
        UnparsedPackages = @($unparsedPackages)
    }
}
#endregion

#region Deletion
function Remove-PurviewObject {
    <#
    .SYNOPSIS
        Checks state before deleting a Purview object. Returns a status string:
        "deleted", "pending", "not-found", or "failed".

        Pre-checks the object's state via -GetCommand before attempting deletion.
        Objects already pending deletion are skipped silently. Objects that don't
        exist are skipped. Only objects confirmed present and deletable are removed.
    .EXAMPLE
        Remove-PurviewObject -Identity "AL01-R01-ECH-OFFI-EXT-ADT" `
            -GetCommand "Get-AutoSensitivityLabelRule" `
            -RemoveCommand "Remove-AutoSensitivityLabelRule" `
            -OperationName "AL rule"
    #>
    param(
        [Parameter(Mandatory)][string]$Identity,
        [string]$GetCommand,
        [Parameter(Mandatory)][string]$RemoveCommand,
        [object]$InputObject,
        [string]$OperationName = "object",
        [int]$MaxRetries = 3,
        [int]$BaseDelaySec = 300,
        [switch]$WhatIf
    )

    # Step 1: Check if the object exists and inspect its state.
    # If caller already has the object (from a prior listing), skip the Get call.
    $obj = $InputObject
    if (-not $obj) {
        if (-not $GetCommand) {
            Write-Warning "  No -InputObject or -GetCommand provided for $OperationName ${Identity}"
            return "failed"
        }
        try {
            $obj = & $GetCommand -Identity $Identity -ErrorAction Stop
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match "couldn't be found" -or $msg -match "not found" -or $msg -match "does not exist") {
                Write-Host " -> not found, skipped" -ForegroundColor DarkGray
                return "not-found"
            }
            Write-Warning "  Could not query $OperationName ${Identity}: $msg"
            return "failed"
        }
    }

    if (-not $obj) {
        Write-Host "    (not found, skipping): $Identity" -ForegroundColor DarkGray
        return "not-found"
    }

    # Step 2: Check for pending deletion state
    # Purview objects may have Mode = "PendingDeletion" or similar state indicators
    $isPending = $false
    if ($obj.PSObject.Properties['Mode'] -and $obj.Mode -eq 'PendingDeletion') { $isPending = $true }
    if ($obj.PSObject.Properties['State'] -and $obj.State -eq 'PendingDeletion') { $isPending = $true }

    if ($isPending) {
        Write-Host " -> pending deletion, skipped" -ForegroundColor DarkGray
        return "pending"
    }

    # Step 3: Delete
    if ($WhatIf) {
        Write-Host " -> would remove (WhatIf)" -ForegroundColor Yellow
        return "deleted"
    }

    Write-Host " -> deleting..." -ForegroundColor Gray -NoNewline
    try {
        & $RemoveCommand -Identity $Identity -Confirm:$false -ErrorAction Stop
        Write-Host " done" -ForegroundColor Green
        return "deleted"
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "PendingDeletion" -or $msg -match "pending deletion") {
            Write-Host " -> pending deletion, skipped" -ForegroundColor DarkGray
            return "pending"
        }
        if ($msg -match "DeleteRetryInterval" -or $msg -match "retry after (\d+) min") {
            $waitMin = 60
            if ($msg -match "retry after (\d+) min") { $waitMin = [int]$Matches[1] + 1 }
            Write-Host " -> cooldown (${waitMin}m remaining)" -ForegroundColor DarkYellow
            return "cooldown:$waitMin"
        }
        if ($msg -match "server side error" -or $msg -match "try again after some time") {
            Write-Host " -> throttled, retrying..." -ForegroundColor DarkYellow
            # For throttle errors, do retry inline
            try {
                Invoke-WithRetry -OperationName "Remove $OperationName $Identity" -ScriptBlock {
                    & $RemoveCommand -Identity $Identity -Confirm:$false -ErrorAction Stop
                } -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec
                Write-Host " -> removed (after retry)" -ForegroundColor Green
                return "deleted"
            } catch {
                Write-Host " -> FAILED after retries: $($_.Exception.Message)" -ForegroundColor Red
                return "failed"
            }
        }
        Write-Host " -> FAILED: $msg" -ForegroundColor Red
        return "failed"
    }
}

function Remove-PurviewObjects {
    <#
    .SYNOPSIS
        Batch-removes Purview objects with cooldown-aware retry.
        First pass: attempt all deletions, collecting any in cooldown.
        If cooldowns found: wait once, then retry them all.
    #>
    param(
        [Parameter(Mandatory)][array]$Objects,
        [Parameter(Mandatory)][string]$RemoveCommand,
        [string]$GetCommand,
        [string]$OperationName = "object",
        [string]$IdentityProperty = "Name",
        [int]$MaxRetries = 3,
        [int]$BaseDelaySec = 300,
        [switch]$WhatIf
    )

    $total = $Objects.Count
    $deleted = 0
    $skipped = 0
    $cooldowns = @()
    $maxCooldownMin = 0

    # Pass 1: try all
    $idx = 0
    foreach ($obj in $Objects) {
        $idx++
        $identity = $obj.$IdentityProperty
        Write-Host "    [$idx/$total] $identity" -ForegroundColor Yellow -NoNewline
        $status = Remove-PurviewObject -Identity $identity -InputObject $obj `
            -RemoveCommand $RemoveCommand -GetCommand $GetCommand `
            -OperationName $OperationName -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -WhatIf:$WhatIf
        if ($status -eq "deleted") { $deleted++ }
        elseif ($status -like "cooldown:*") {
            $cooldowns += $obj
            $mins = [int]($status -replace 'cooldown:', '')
            if ($mins -gt $maxCooldownMin) { $maxCooldownMin = $mins }
        }
        else { $skipped++ }
    }

    # Pass 2: if any cooldowns, wait once then retry
    if ($cooldowns.Count -gt 0 -and -not $WhatIf) {
        $delaySec = $maxCooldownMin * 60
        $resumeTime = (Get-Date).AddSeconds($delaySec).ToString("HH:mm:ss")
        Write-Host ""
        Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkYellow
        Write-Host "  │  PAUSED — Purview delete cooldown                           │" -ForegroundColor DarkYellow
        Write-Host "  │  $($cooldowns.Count) $($OperationName)(s) in cooldown, waiting once for all    │" -ForegroundColor DarkYellow
        Write-Host "  │  Waiting:   $maxCooldownMin minutes                                      │" -ForegroundColor DarkYellow
        Write-Host "  │  Resuming:  $($resumeTime.PadRight(47))│" -ForegroundColor DarkYellow
        Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkYellow
        Write-Host ""
        Start-Sleep -Seconds $delaySec
        Write-Host "  Retrying $($cooldowns.Count) $($OperationName)(s)..." -ForegroundColor Cyan

        $retryIdx = 0
        foreach ($obj in $cooldowns) {
            $retryIdx++
            $identity = $obj.$IdentityProperty
            Write-Host "    [retry $retryIdx/$($cooldowns.Count)] $identity" -ForegroundColor Yellow -NoNewline
            $status = Remove-PurviewObject -Identity $identity `
                -RemoveCommand $RemoveCommand -GetCommand $GetCommand `
                -OperationName $OperationName -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec
            if ($status -eq "deleted") { $deleted++ }
        }
    }

    Write-Host "    Done: $total processed ($deleted deleted, $skipped skipped, $($cooldowns.Count) retried)" -ForegroundColor Green
    return $deleted
}

function Resolve-CleanupTargets {
    <#
    .SYNOPSIS
        Applies cleanup match rules to already-fetched tenant object lists and returns
        a concrete deletion manifest. Pure: callers fetch objects, this decides what
        would be deleted and records WHY each object matched.
    .PARAMETER Objects
        Hashtable keyed by category (AutoLabelPolicy, DlpPolicy, SitPackage,
        KeywordDictionary, LabelPolicy, Label) whose values are arrays of objects from
        the matching Get-* cmdlet.
    .PARAMETER IncludeLabels
        When set, label policies and labels are considered for removal.
    .OUTPUTS
        An array of target objects: Identity, Category, Type, MatchedBy, Risk
        ("scoped" = matched only by configured prefix/suffix/publisher;
        "broad" = matched by a heuristic that may hit objects this toolkit did not create),
        GetCommand, RemoveCommand, InputObject.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][hashtable]$Objects,
        [switch]$IncludeLabels
    )

    $prefix          = $Config.namingPrefix
    $suffix          = $Config.namingSuffix
    $publisher       = $Config.publisher
    $labelPolicyName = $Config.labelPolicyName
    $manifest        = [System.Collections.Generic.List[object]]::new()

    function New-CleanupTarget {
        param($Identity, $Category, $Type, $MatchedBy, $Risk, $GetCommand, $RemoveCommand, $InputObject)
        [pscustomobject]@{
            Identity      = $Identity
            Category      = $Category
            Type          = $Type
            MatchedBy     = $MatchedBy
            Risk          = $Risk
            GetCommand    = $GetCommand
            RemoveCommand = $RemoveCommand
            InputObject   = $InputObject
        }
    }

    foreach ($p in @($Objects['AutoLabelPolicy'])) {
        if (-not $p) { continue }
        if ($p.Name -like "AL*-$prefix-$suffix") {
            $manifest.Add((New-CleanupTarget $p.Name "AutoLabelPolicy" "Auto-labeling policy" "prefix '$prefix' + suffix '$suffix'" "scoped" "Get-AutoSensitivityLabelPolicy" "Remove-AutoSensitivityLabelPolicy" $p))
        }
    }

    foreach ($p in @($Objects['DlpPolicy'])) {
        if (-not $p) { continue }
        if ($p.Name -like "*$prefix*") {
            $manifest.Add((New-CleanupTarget $p.Name "DlpPolicy" "DLP policy" "prefix '$prefix'" "scoped" "Get-DlpCompliancePolicy" "Remove-DlpCompliancePolicy" $p))
        } elseif ($p.Name -like "P0*-*") {
            $manifest.Add((New-CleanupTarget $p.Name "DlpPolicy" "DLP policy" "heuristic 'P0*-*' (NOT prefix-scoped)" "broad" "Get-DlpCompliancePolicy" "Remove-DlpCompliancePolicy" $p))
        }
    }

    foreach ($pkg in @($Objects['SitPackage'])) {
        if (-not $pkg -or -not $pkg.Identity) { continue }
        if ($pkg.Publisher -eq "Microsoft Corporation" -or $pkg.Publisher -eq "Microsoft") { continue }
        if ($publisher -and $pkg.Publisher -eq $publisher) {
            $manifest.Add((New-CleanupTarget $pkg.Identity "SitPackage" "SIT rule package" "publisher '$publisher'" "scoped" "Get-DlpSensitiveInformationTypeRulePackage" "Remove-DlpSensitiveInformationTypeRulePackage" $pkg))
        }
    }

    foreach ($d in @($Objects['KeywordDictionary'])) {
        if (-not $d) { continue }
        if ($d.Name -like "$prefix*") {
            $manifest.Add((New-CleanupTarget $d.Identity "KeywordDictionary" "Keyword dictionary" "prefix '$prefix'" "scoped" "Get-DlpKeywordDictionary" "Remove-DlpKeywordDictionary" $d))
        }
    }

    if ($IncludeLabels) {
        foreach ($lp in @($Objects['LabelPolicy'])) {
            if (-not $lp) { continue }
            if ($lp.Name -like "*$prefix*") {
                $manifest.Add((New-CleanupTarget $lp.Name "LabelPolicy" "Label policy" "prefix '$prefix'" "scoped" "Get-LabelPolicy" "Remove-LabelPolicy" $lp))
            } elseif ($labelPolicyName -and $lp.Name -eq $labelPolicyName) {
                $manifest.Add((New-CleanupTarget $lp.Name "LabelPolicy" "Label policy" "configured labelPolicyName '$labelPolicyName'" "scoped" "Get-LabelPolicy" "Remove-LabelPolicy" $lp))
            }
        }
        foreach ($l in @($Objects['Label'])) {
            if (-not $l) { continue }
            if ($l.Name -like "*$prefix*") {
                $manifest.Add((New-CleanupTarget $l.Name "Label" "Sensitivity label" "prefix '$prefix'" "scoped" "Get-Label" "Remove-Label" $l))
            } elseif ($l.Name -match "^(OFFICIAL|SENSITIVE|PROTECTED)") {
                $manifest.Add((New-CleanupTarget $l.Name "Label" "Sensitivity label" "built-in classification regex (NOT prefix-scoped)" "broad" "Get-Label" "Remove-Label" $l))
            }
        }
    }

    return $manifest.ToArray()
}

function Get-CleanupConfirmationPhrase {
    <#
    .SYNOPSIS
        Builds the typed-confirmation phrase a user must enter to authorise cleanup.
    #>
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Tenant
    )
    return "DELETE $Prefix $Tenant"
}

function Show-CleanupPlan {
    <#
    .SYNOPSIS
        Renders the deletion manifest grouped by category, listing every object and the
        pattern that matched it. Broad (non-prefix-scoped) matches are highlighted.
        Returns a summary object. -Quiet suppresses console output (for tests).
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Targets,
        [Parameter(Mandatory)][string]$Tenant,
        [switch]$Quiet
    )

    $byCat = [ordered]@{}
    foreach ($t in $Targets) {
        if (-not $byCat.Contains($t.Category)) { $byCat[$t.Category] = [System.Collections.Generic.List[object]]::new() }
        $byCat[$t.Category].Add($t)
    }
    $broad = @($Targets | Where-Object { $_.Risk -eq "broad" })

    if (-not $Quiet) {
        Write-Host "`n=== Cleanup Plan: objects that WILL be deleted from $Tenant ===" -ForegroundColor Cyan
        if ($Targets.Count -eq 0) {
            Write-Host "  Nothing matched. No objects will be deleted." -ForegroundColor Green
        }
        foreach ($cat in $byCat.Keys) {
            $items = $byCat[$cat]
            Write-Host "`n  $cat ($($items.Count)):" -ForegroundColor Yellow
            foreach ($i in $items) {
                $color = if ($i.Risk -eq "broad") { "Red" } else { "Gray" }
                Write-Host "    - $($i.Identity)   [matched by: $($i.MatchedBy)]" -ForegroundColor $color
            }
        }
        if ($broad.Count -gt 0) {
            Write-Host "`n  WARNING: $($broad.Count) object(s) matched by BROAD heuristics that are not prefix-scoped." -ForegroundColor Red
            Write-Host "  These may include objects this toolkit did not create. Review each line above carefully." -ForegroundColor Red
        }
    }

    $catCounts = [ordered]@{}
    foreach ($cat in $byCat.Keys) { $catCounts[$cat] = $byCat[$cat].Count }
    return [pscustomobject]@{
        Total      = $Targets.Count
        BroadCount = $broad.Count
        Categories = $catCounts
    }
}

function Invoke-CleanupPlan {
    <#
    .SYNOPSIS
        Deletes exactly the objects in a manifest produced by Resolve-CleanupTargets.
        Honors -WhatIf. Applies the SIT rule-package reference guard before deleting
        any SitPackage targets. Never re-queries the tenant with broad patterns.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Targets,
        [switch]$AllowBreakingClassifierReferences,
        [int]$MaxRetries = 2,
        [int]$BaseDelaySec = 30
    )

    $order   = @("AutoLabelPolicy", "DlpPolicy", "SitPackage", "KeywordDictionary", "LabelPolicy", "Label")
    $results = [ordered]@{}

    # Reference guard before any SIT package deletion.
    $sitTargets = @($Targets | Where-Object { $_.Category -eq "SitPackage" })
    if ($sitTargets.Count -gt 0) {
        $guard = Test-DlpRulePackageRemovalReferenceGuard -Packages @($sitTargets.InputObject) -OperationName "cleanup SIT package removal"
        if (-not $guard.Safe -and -not $AllowBreakingClassifierReferences) {
            throw "SIT package cleanup blocked: live DLP rules still reference classifier IDs in these package(s). Rerun with -AllowBreakingClassifierReferences after explicit approval, or refit first."
        } elseif (-not $guard.Safe) {
            Write-Host "  WARNING: proceeding despite DLP rule references (-AllowBreakingClassifierReferences)." -ForegroundColor Red
        }
    }

    foreach ($cat in $order) {
        $items = @($Targets | Where-Object { $_.Category -eq $cat })
        if ($cat -eq "Label") {
            # Sublabels (have ParentId) first, then parents; highest priority first within each group.
            $items = @(@($items | Where-Object { $_.InputObject.ParentId }       | Sort-Object { $_.InputObject.Priority } -Descending) +
                       @($items | Where-Object { -not $_.InputObject.ParentId }   | Sort-Object { $_.InputObject.Priority } -Descending))
        }
        if ($items.Count -eq 0) { continue }

        $deleted = 0
        foreach ($t in $items) {
            Write-Host "    $($t.Type): $($t.Identity)" -ForegroundColor Yellow -NoNewline
            $status = Remove-PurviewObject -Identity $t.Identity -InputObject $t.InputObject `
                -GetCommand $t.GetCommand -RemoveCommand $t.RemoveCommand `
                -OperationName $t.Type -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -WhatIf:$WhatIfPreference
            if ($status -eq "deleted") { $deleted++ }
            if (-not $WhatIfPreference) { Start-Sleep 2 }
        }
        $results[$cat] = $deleted
    }

    return $results
}
#endregion

#region Retry
function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Retries a scriptblock on transient Purview API throttle errors.
        Default backoff: 5 min / 10 min / 15 min (Purview throttling is aggressive).
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [string]$OperationName = "operation",
        [int]$MaxRetries = 3,
        [int]$BaseDelaySec = 300
    )
    for ($attempt = 1; $attempt -le ($MaxRetries + 1); $attempt++) {
        try {
            return (& $ScriptBlock)
        } catch {
            $msg = $_.Exception.Message
            $isThrottle = $msg -match "server side error" -or
                          $msg -match "try again after some time"
            $isTransient = $msg -match "Object reference not set"
            $isDeleteCooldown = $msg -match "DeleteRetryInterval" -or
                                $msg -match "retry after (\d+) min"
            $isPendingDeletion = $msg -match "PendingDeletion" -or
                                 $msg -match "pending deletion"

            if ($isPendingDeletion) {
                # Already being deleted — treat as success, not an error
                Write-Host "    (already pending deletion, skipping)" -ForegroundColor DarkGray
                return
            } elseif ($isDeleteCooldown -and $attempt -le $MaxRetries) {
                # Purview enforces a 60-min cooldown between delete attempts on the same rule.
                # Extract the wait time from the message if possible.
                $waitMin = 60
                if ($msg -match "retry after (\d+) min") { $waitMin = [int]$Matches[1] + 1 }
                $delaySec = $waitMin * 60
                $resumeTime = (Get-Date).AddSeconds($delaySec).ToString("HH:mm:ss")
                Write-Host ""
                Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkYellow
                Write-Host "  │  PAUSED — Purview delete cooldown                           │" -ForegroundColor DarkYellow
                Write-Host "  │  Operation: $($OperationName.PadRight(47))│" -ForegroundColor DarkYellow
                Write-Host "  │  Waiting:   ${waitMin} minutes (Purview enforces 60-min gap)       │" -ForegroundColor DarkYellow
                Write-Host "  │  Resuming:  $($resumeTime.PadRight(47))│" -ForegroundColor DarkYellow
                Write-Host "  │  Attempt:   $attempt of $MaxRetries                                        │" -ForegroundColor DarkYellow
                Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkYellow
                Write-Host ""
                Start-Sleep -Seconds $delaySec
                Write-Host "  Resuming operations..." -ForegroundColor Cyan
            } elseif ($isThrottle -and $attempt -le $MaxRetries) {
                $delaySec = $BaseDelaySec * $attempt
                $delayMin = [math]::Round($delaySec / 60, 0)
                $resumeTime = (Get-Date).AddSeconds($delaySec).ToString("HH:mm:ss")
                Write-Host ""
                Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkYellow
                Write-Host "  │  PAUSED — Purview API throttle                              │" -ForegroundColor DarkYellow
                Write-Host "  │  Operation: $($OperationName.PadRight(47))│" -ForegroundColor DarkYellow
                Write-Host "  │  Waiting:   ${delayMin} min (${delaySec}s backoff)                           │" -ForegroundColor DarkYellow
                Write-Host "  │  Resuming:  $($resumeTime.PadRight(47))│" -ForegroundColor DarkYellow
                Write-Host "  │  Attempt:   $attempt of $MaxRetries                                        │" -ForegroundColor DarkYellow
                Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkYellow
                Write-Host ""
                Start-Sleep -Seconds $delaySec
                Write-Host "  Resuming operations..." -ForegroundColor Cyan
            } elseif ($isTransient -and $attempt -le 2) {
                $delaySec = 30 * $attempt
                $resumeTime = (Get-Date).AddSeconds($delaySec).ToString("HH:mm:ss")
                Write-Host ""
                Write-Host "  PAUSED — Transient server error on: $OperationName" -ForegroundColor DarkYellow
                Write-Host "  Waiting ${delaySec}s, resuming at $resumeTime (retry $attempt of 2)" -ForegroundColor DarkYellow
                Write-Host ""
                Start-Sleep -Seconds $delaySec
                Write-Host "  Resuming operations..." -ForegroundColor Cyan
            } else {
                throw
            }
        }
    }
}
#endregion

#region Logging
function Start-DeploymentLog {
    <#
    .SYNOPSIS
        Starts a transcript log in the logs/ directory relative to the module root.
    .PARAMETER ScriptName
        Name prefix for the log file (e.g. "Deploy-DLPRules").
    .PARAMETER LogDir
        Override log directory. Defaults to ../logs/ relative to module.
    #>
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [string]$LogDir
    )
    if (-not $LogDir) {
        $LogDir = Join-Path (Split-Path $PSScriptRoot -Parent) "logs"
    }
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    $transcriptPath = Join-Path $LogDir "${ScriptName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Start-Transcript -Path $transcriptPath -Append | Out-Null
    Write-Host "Logging to: $transcriptPath" -ForegroundColor Gray
    return $transcriptPath
}

function Stop-DeploymentLog {
    <#
    .SYNOPSIS
        Stops the active transcript even when the caller is running with -WhatIf.
    #>
    $previousWhatIf = $WhatIfPreference
    try {
        $WhatIfPreference = $false
        Stop-Transcript | Out-Null
    } catch {
    } finally {
        $WhatIfPreference = $previousWhatIf
    }
}

function Get-DeploymentObjectProperty {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string[]]$Names
    )

    foreach ($name in $Names) {
        $prop = $InputObject.PSObject.Properties[$name]
        if ($prop -and -not [string]::IsNullOrWhiteSpace($prop.Value)) {
            return $prop.Value.ToString()
        }
    }
    return $null
}

function Get-DeploymentTenantInfo {
    $tenant = [ordered]@{
        name           = $null
        id             = $null
        guid           = $null
        tenantId       = $null
        organizationId = $null
        userPrincipalName = $null
        connectionUri  = $null
        source         = $null
        status         = "Unknown"
    }

    try {
        $org = Get-OrganizationConfig -ErrorAction Stop
        if ($org) {
            $tenant.name = $org.Name
            $tenant.id = if ($org.Id) { $org.Id.ToString() } else { $null }
            $tenant.guid = if ($org.Guid) { $org.Guid.ToString() } else { $null }
            $tenant.organizationId = if ($org.OrganizationId) { $org.OrganizationId.ToString() } else { $null }
            $tenant.source = "Get-OrganizationConfig"
            $tenant.status = "Connected"
        }
    } catch {
        $tenant.status = "OrganizationConfigUnavailable"
    }

    try {
        if (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) {
            $connections = @(Get-ConnectionInformation -ErrorAction Stop)
            $connection = $connections |
                Where-Object {
                    (Get-DeploymentObjectProperty -InputObject $_ -Names @("State")) -eq "Connected" -and
                    ((Get-DeploymentObjectProperty -InputObject $_ -Names @("ConnectionUri")) -match "compliance|protection\.outlook|ps\.compliance")
                } |
                Select-Object -First 1

            if (-not $connection) {
                $connection = $connections |
                    Where-Object { (Get-DeploymentObjectProperty -InputObject $_ -Names @("State")) -eq "Connected" } |
                    Select-Object -First 1
            }
            if (-not $connection) {
                $connection = $connections | Select-Object -First 1
            }

            if ($connection) {
                $organization = Get-DeploymentObjectProperty -InputObject $connection -Names @("Organization", "Tenant", "TenantName")
                $tenantId = Get-DeploymentObjectProperty -InputObject $connection -Names @("TenantID", "TenantId", "TenantGuid", "ExternalDirectoryOrganizationId")

                if (-not $tenant.name -and $organization) { $tenant.name = $organization }
                if (-not $tenant.organizationId -and $organization) { $tenant.organizationId = $organization }
                if (-not $tenant.id -and $tenantId) { $tenant.id = $tenantId }
                if (-not $tenant.guid -and $tenantId) { $tenant.guid = $tenantId }
                if (-not $tenant.tenantId -and $tenantId) { $tenant.tenantId = $tenantId }
                $tenant.userPrincipalName = Get-DeploymentObjectProperty -InputObject $connection -Names @("UserPrincipalName", "UserName")
                $tenant.connectionUri = Get-DeploymentObjectProperty -InputObject $connection -Names @("ConnectionUri")
                $tenant.source = if ($tenant.source) { "$($tenant.source)+Get-ConnectionInformation" } else { "Get-ConnectionInformation" }
                $tenant.status = "Connected"
            }
        }
    } catch {
        if ($tenant.status -eq "Unknown") {
            $tenant.status = "Unavailable"
        }
    }

    return $tenant
}

function New-DeploymentManifest {
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][string]$ProjectRoot,
        [hashtable]$Parameters
    )

    $runId = [guid]::NewGuid().ToString()
    return [ordered]@{
        schemaVersion     = 1
        runId             = $runId
        scriptName        = $ScriptName
        operation         = $Operation
        startedUtc        = (Get-Date).ToUniversalTime().ToString("o")
        completedUtc      = $null
        status            = "Started"
        projectRoot       = $ProjectRoot
        operator          = [ordered]@{
            userName     = $env:USERNAME
            userDomain   = $env:USERDOMAIN
            computerName = $env:COMPUTERNAME
        }
        powershellVersion = $PSVersionTable.PSVersion.ToString()
        tenant            = Get-DeploymentTenantInfo
        tenantFingerprint = $null
        parameters        = if ($Parameters) { $Parameters } else { @{} }
        targets           = @()
        impact            = $null
        decisions         = @()
        artifacts         = @()
        flightRecorder    = $null
        results           = @()
        warnings          = @()
        errors            = @()
    }
}

function Add-DeploymentManifestEvent {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Manifest,
        [ValidateSet("Decision", "Result", "Warning", "Error", "Artifact")]
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][object]$Data
    )

    $entry = [ordered]@{
        timestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        data         = $Data
    }

    switch ($Type) {
        "Decision" { $Manifest.decisions += $entry }
        "Result"   { $Manifest.results += $entry }
        "Warning"  { $Manifest.warnings += $entry }
        "Error"    { $Manifest.errors += $entry }
        "Artifact" { $Manifest.artifacts += $entry }
    }
}

function Complete-DeploymentManifest {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Manifest,
        [Parameter(Mandatory)][string]$Status
    )

    $Manifest.completedUtc = (Get-Date).ToUniversalTime().ToString("o")
    $Manifest.status = $Status
    $Manifest.tenant = Get-DeploymentTenantInfo
    return $Manifest
}

function ConvertTo-DeploymentRelativePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ProjectRoot
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $resolvedRoot = [System.IO.Path]::GetFullPath($ProjectRoot)
    if ($resolvedPath.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return ($resolvedPath.Substring($resolvedRoot.Length).TrimStart('\', '/') -replace '\\', '/')
    }
    return ($resolvedPath -replace '\\', '/')
}

function Save-DeploymentManifest {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Manifest,
        [Parameter(Mandatory)][string]$ProjectRoot,
        [string]$ReportDir,
        [string]$TranscriptPath
    )

    if (-not $ReportDir) {
        $ReportDir = Join-Path (Join-Path $ProjectRoot "reports") "deployments"
    }
    if (-not (Test-Path -LiteralPath $ReportDir)) {
        New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeScript = $Manifest.scriptName -replace '[^a-zA-Z0-9\-]', ''
    $safeOperation = $Manifest.operation -replace '[^a-zA-Z0-9\-]', ''
    $runDir = Join-Path $ReportDir "${timestamp}_${safeScript}_${safeOperation}_$($Manifest.runId)"
    if (-not (Test-Path -LiteralPath $runDir)) {
        New-Item -ItemType Directory -Path $runDir -Force | Out-Null
    }

    $manifestPath = Join-Path $runDir "manifest.json"
    $Manifest.flightRecorder = [ordered]@{
        folder       = ConvertTo-DeploymentRelativePath -Path $runDir -ProjectRoot $ProjectRoot
        manifestPath = ConvertTo-DeploymentRelativePath -Path $manifestPath -ProjectRoot $ProjectRoot
        transcriptPath = $null
        artifactCopies = @()
    }

    $artifactCopyDir = Join-Path $runDir "artifacts"
    $artifactCopies = @()
    $copyEntries = @()
    $copyEntries += @($Manifest.artifacts)
    $copyEntries += @($Manifest.targets | Where-Object { $_.path })
    foreach ($entry in @($copyEntries)) {
        $artifact = if ($entry.data) { $entry.data } else { $entry }
        if (-not $artifact.path) { continue }
        $artifactRole = if ($artifact.role) { $artifact.role } elseif ($artifact.type) { $artifact.type } else { "artifact" }
        if ($artifactRole -in @("live-transcript", "transcript-log")) { continue }

        $artifactPath = $artifact.path.ToString()
        $sourcePath = if ([System.IO.Path]::IsPathRooted($artifactPath)) {
            $artifactPath
        } else {
            Join-Path $ProjectRoot ($artifactPath -replace '/', '\')
        }
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { continue }

        $resolvedSource = [System.IO.Path]::GetFullPath($sourcePath)
        if ($resolvedSource.StartsWith([System.IO.Path]::GetFullPath($runDir), [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        if (-not (Test-Path -LiteralPath $artifactCopyDir)) {
            New-Item -ItemType Directory -Path $artifactCopyDir -Force | Out-Null
        }

        $safeName = "$artifactRole`_$($artifactPath)" -replace '[\\/:*?"<>|]+', '_'
        $safeName = $safeName.Trim('_')
        $destPath = Join-Path $artifactCopyDir $safeName
        try {
            Copy-Item -LiteralPath $sourcePath -Destination $destPath -Force -ErrorAction Stop
            $copyArtifact = Get-DeploymentFileArtifact -Path $destPath -Role $artifactRole -ProjectRoot $ProjectRoot
            $artifactCopies += [ordered]@{
                role       = $artifactRole
                sourcePath = ($artifactPath -replace '\\', '/')
                copyPath   = $copyArtifact.path
                sha256     = $copyArtifact.sha256
                sizeBytes  = $copyArtifact.sizeBytes
            }
        } catch {
            Add-DeploymentManifestEvent -Manifest $Manifest -Type "Warning" -Data @{
                message = "Could not copy artifact into flight recorder"
                path    = $artifactPath
                error   = $_.Exception.Message
            }
        }
    }
    $Manifest.flightRecorder.artifactCopies = @($artifactCopies)

    if ($TranscriptPath -and (Test-Path -LiteralPath $TranscriptPath)) {
        $transcriptDest = Join-Path $runDir "transcript.log"
        try {
            Copy-Item -LiteralPath $TranscriptPath -Destination $transcriptDest -Force -ErrorAction Stop
            $transcriptArtifact = Get-DeploymentFileArtifact -Path $transcriptDest -Role "transcript-log" -ProjectRoot $ProjectRoot
            $Manifest.artifacts += $transcriptArtifact
            $Manifest.flightRecorder.transcriptPath = $transcriptArtifact.path
        } catch {
            Add-DeploymentManifestEvent -Manifest $Manifest -Type "Warning" -Data @{
                message = "Could not copy transcript into flight recorder"
                path    = $TranscriptPath
                error   = $_.Exception.Message
            }
        }
    }

    $Manifest | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Write-Host "Deployment flight recorder: $runDir" -ForegroundColor Gray
    return $manifestPath
}

function Get-DeploymentFileArtifact {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Role,
        [string]$ProjectRoot
    )

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    $relativePath = $item.FullName
    if ($ProjectRoot -and $item.FullName.StartsWith($ProjectRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        $relativePath = $item.FullName.Substring($ProjectRoot.Length).TrimStart('\', '/')
    }

    return [ordered]@{
        role         = $Role
        path         = $relativePath -replace '\\', '/'
        sizeBytes    = $item.Length
        sha256       = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        lastWriteUtc = $item.LastWriteTimeUtc.ToString("o")
    }
}

function Test-DeploymentTenantFingerprint {
    <#
    .SYNOPSIS
        Compares the connected tenant against optional expected fingerprints.
    .PARAMETER ProjectRoot
        Repository root used to find config/tenant-fingerprints.json.
    .PARAMETER TargetEnvironment
        Environment key under the config file's environments object.
    #>
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [string]$TargetEnvironment,
        [string]$FingerprintPath
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
        $result.messages += "No fingerprint entry found for environment '$TargetEnvironment'."
        return [PSCustomObject]$result
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
#endregion

#region Classifier Helpers
function Split-ClassifierChunks {
    <#
    .SYNOPSIS
        Splits a classifier list into even chunks of at most $MaxPerRule entries.
        When splitting is needed, divides evenly (not 125 + remainder) to balance rule sizes.
        Errors if the split would produce more than 26 chunks (a-z limit).
    .OUTPUTS
        Array of arrays. Each inner array is a chunk of classifier entries.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$ClassifierList,
        [int]$MaxPerRule = 125
    )
    $total = $ClassifierList.Count
    if ($total -eq 0) {
        return @(, @())
    }
    if ($total -le $MaxPerRule) {
        return @(, $ClassifierList)
    }
    $chunkCount = [math]::Ceiling($total / $MaxPerRule)
    if ($chunkCount -gt 26) {
        throw "Cannot split $total classifiers into chunks of $MaxPerRule — would need $chunkCount chunks but maximum is 26 (a-z). Reduce classifier count or increase MaxPerRule."
    }
    $chunkSize = [math]::Ceiling($total / $chunkCount)
    $chunks = @()
    for ($i = 0; $i -lt $total; $i += $chunkSize) {
        $end = [math]::Min($i + $chunkSize, $total)
        $chunks += , @($ClassifierList[$i..($end - 1)])
    }
    return $chunks
}

function Get-ChunkLetter {
    <#
    .SYNOPSIS
        Returns the chunk letter (a-z) for a 1-based chunk index.
        Throws if index is outside 1-26 range.
    #>
    param([Parameter(Mandatory)][int]$ChunkIndex)
    if ($ChunkIndex -lt 1 -or $ChunkIndex -gt 26) {
        throw "Chunk index $ChunkIndex is out of range (1-26). This indicates a bug in classifier splitting — rule names only support a-z suffixes."
    }
    return [char]([int][char]'a' + $ChunkIndex - 1)
}
#endregion

#region Dictionary Helpers
function Sync-DlpKeywordDictionaries {
    <#
    .SYNOPSIS
        Creates or reuses keyword dictionaries from a testpattern.dev manifest.
        Returns a hashtable mapping placeholder -> GUID.
    .PARAMETER ManifestUrl
        URL to the dictionary manifest endpoint.
    .PARAMETER NamePrefix
        Optional deployment naming prefix. When supplied, dictionaries are created and
        looked up as "<NamePrefix>-<manifest name>" so they are scoped to this deployment
        and discoverable by the prefix-based cleanup. Packages bind dictionaries by GUID,
        so the name change does not affect SIT references.
    .PARAMETER WhatIf
        If true, returns dummy GUIDs without making API calls.
    #>
    param(
        [Parameter(Mandatory)][string]$ManifestUrl,
        [string]$NamePrefix,
        [switch]$WhatIf
    )

    Write-Host "  Fetching dictionary manifest..."
    $manifest = Invoke-RestMethod -Uri $ManifestUrl
    Write-Host "  $($manifest.dictionaries.Count) dictionaries in manifest"

    $guidMap = @{}

    # Pre-fetch existing dictionaries (avoids N+1 API calls)
    $existingDicts = @{}
    if (-not $WhatIf) {
        Get-DlpKeywordDictionary -ErrorAction SilentlyContinue | ForEach-Object {
            $existingDicts[$_.Name] = $_.Identity
        }
    }

    foreach ($dict in $manifest.dictionaries) {
        # Scope the dictionary name to this deployment so prefix-based cleanup can find it.
        $name = if ($NamePrefix) { "$NamePrefix-$($dict.name)" } else { $dict.name }

        # Write terms to temp file and read back as bytes (includes UTF-16LE BOM).
        # Direct [System.Text.Encoding]::Unicode.GetBytes() produces BOM-less bytes
        # that are truncated to 1 char by the REST-based ExchangeOnlineManagement module.
        $tempFile = [System.IO.Path]::GetTempFileName()
        try {
            $dict.terms | Set-Content -Path $tempFile -Encoding Unicode
            $bytes = [System.IO.File]::ReadAllBytes($tempFile)
        } finally {
            Remove-Item $tempFile -ErrorAction SilentlyContinue
        }

        if ($WhatIf) {
            Write-Host "  [WHATIF] $name ($($dict.terms.Count) terms)"
            $guidMap[$dict.placeholder] = "00000000-0000-0000-0000-000000000000"
            continue
        }

        $guid = $null
        if ($existingDicts.ContainsKey($name)) {
            # Update existing dictionary with correct content
            $guid = $existingDicts[$name]
            try {
                Set-DlpKeywordDictionary -Identity $name -FileData $bytes -Confirm:$false -ErrorAction Stop
                Write-Host "  Updated: $name ($($dict.terms.Count) terms) [$guid]"
            } catch {
                Write-Warning "  Failed to update ${name}: $($_.Exception.Message)"
                Write-Host "  Exists: $name [$guid]"
            }
        } else {
            try {
                $result = Invoke-WithRetry -OperationName "New-Dictionary $name" -ScriptBlock {
                    New-DlpKeywordDictionary -Name $name -Description $dict.description -FileData $bytes -Confirm:$false -ErrorAction Stop
                } -MaxRetries 2 -BaseDelaySec 30
                $guid = $result.Identity
                Write-Host "  Created: $name ($($dict.terms.Count) terms)"
            } catch {
                if ($_.Exception.Message -match 'already exists') {
                    # Race condition: created between pre-fetch and now
                    $found = Get-DlpKeywordDictionary -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $name }
                    if ($found) {
                        $guid = $found.Identity
                        Write-Host "  Recovered: $name [$guid]"
                    } else {
                        Write-Warning "  Failed: $name - exists but could not retrieve"
                    }
                } else {
                    Write-Warning "  Failed: $name - $($_.Exception.Message)"
                }
            }
        }

        if ($guid) {
            $guidMap[$dict.placeholder] = $guid
        } else {
            Write-Warning "  No GUID for $name - packages using $($dict.placeholder) will be skipped"
        }
        if (-not $WhatIf) { Start-Sleep 2 }
    }

    Write-Host "  $($guidMap.Count) / $($manifest.dictionaries.Count) dictionary GUIDs resolved"
    return $guidMap
}
#endregion

#region Dictionary Lifecycle
function Get-NormalizedDictionaryTerms {
    <#
    .SYNOPSIS
        Returns the canonical comparison form of a term list: trimmed, lower-cased
        (invariant), de-duplicated, empty/whitespace dropped, sorted for determinism.
    #>
    param([string[]]$Terms)
    if (-not $Terms) { return @() }
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($t in $Terms) {
        if ($null -eq $t) { continue }
        $n = $t.Trim().ToLowerInvariant()
        if ($n) { [void]$seen.Add($n) }
    }
    return @($seen | Sort-Object)
}

function Get-DictionaryTermCoverage {
    <#
    .SYNOPSIS
        Coverage of OUR terms by an existing dictionary: |ours ∩ existing| / |ours|.
        Empty ours -> 1.0 (nothing required). Pure.
    #>
    param([string[]]$OurTerms, [string[]]$ExistingTerms)
    $ours = Get-NormalizedDictionaryTerms -Terms $OurTerms
    if ($ours.Count -eq 0) { return 1.0 }
    $existing = [System.Collections.Generic.HashSet[string]]::new([string[]](Get-NormalizedDictionaryTerms -Terms $ExistingTerms))
    $hit = 0
    foreach ($t in $ours) { if ($existing.Contains($t)) { $hit++ } }
    return [math]::Round($hit / $ours.Count, 4)
}

function Get-DictionaryCompressedSize {
    <#
    .SYNOPSIS
        Estimates the post-compression byte size of a dictionary's terms, to approximate
        Purview's tenant keyword-dictionary budget measurement. Normalises first, joins with
        newline as UTF-16LE (Purview stores Unicode), Deflate-compresses, returns byte count.
    #>
    param([string[]]$Terms)
    $norm = Get-NormalizedDictionaryTerms -Terms $Terms
    $blob = [System.Text.Encoding]::Unicode.GetBytes(($norm -join "`n"))
    $ms = [System.IO.MemoryStream]::new()
    try {
        $deflate = [System.IO.Compression.DeflateStream]::new($ms, [System.IO.Compression.CompressionLevel]::Optimal)
        $deflate.Write($blob, 0, $blob.Length)
        $deflate.Dispose()
        return $ms.ToArray().Length
    } finally {
        $ms.Dispose()
    }
}

function Get-DictionaryGuidReferences {
    <#
    .SYNOPSIS
        Returns the distinct GUID-valued idRef attribute values in a rule-package XML string.
        In SIT packages, a dictionary is referenced as <Match idRef="GUID"/>; named idRefs
        (Pattern_*/Evidence_*/Keyword_*) and entity id="GUID" definitions are not dictionary
        references, so only idRef attributes whose value is a GUID are returned.
    #>
    param([Parameter(Mandatory)][string]$PackageXmlText)
    $guid = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($m in [regex]::Matches($PackageXmlText, "idRef\s*=\s*`"($guid)`"")) {
        [void]$found.Add($m.Groups[1].Value.ToLowerInvariant())
    }
    return @($found | Sort-Object)
}

function Resolve-DictionarySyncDecision {
    <#
    .SYNOPSIS
        Decides the action for one dictionary. Pure — no tenant calls. Existing is $null
        (no match) or a hashtable/object with Guid and Terms (Terms = $null means the
        existing dictionary's terms could not be read = opaque).
    .OUTPUTS
        [pscustomobject] Action (Create|Reuse|Merge|OverBudgetKeep|OpaqueKeep),
        Guid (existing GUID when keeping/merging; $null for Create),
        Coverage, MergedTerms (for Merge), Reason.
    #>
    param(
        [string[]]$OurTerms,
        [object]$Existing,
        [Parameter(Mandatory)][long]$TenantHeadroomBytes,
        [double]$CoverageThreshold = 0.9
    )

    if (-not $Existing) {
        return [pscustomobject]@{ Action='Create'; Guid=$null; Coverage=$null; MergedTerms=$null; Reason='no existing dictionary matched' }
    }
    $existingGuid = $Existing.Guid
    if ($null -eq $Existing.Terms) {
        return [pscustomobject]@{ Action='OpaqueKeep'; Guid=$existingGuid; Coverage=$null; MergedTerms=$null; Reason='existing dictionary terms not readable; reusing without modification' }
    }

    $coverage = Get-DictionaryTermCoverage -OurTerms $OurTerms -ExistingTerms $Existing.Terms
    if ($coverage -ge $CoverageThreshold) {
        return [pscustomobject]@{ Action='Reuse'; Guid=$existingGuid; Coverage=$coverage; MergedTerms=$null; Reason="existing covers $([int]($coverage*100))% of required terms" }
    }

    $union = Get-NormalizedDictionaryTerms -Terms (@($Existing.Terms) + @($OurTerms))
    $unionSize = Get-DictionaryCompressedSize -Terms $union
    $existingSize = Get-DictionaryCompressedSize -Terms $Existing.Terms
    $delta = $unionSize - $existingSize
    if ($delta -le $TenantHeadroomBytes) {
        return [pscustomobject]@{ Action='Merge'; Guid=$existingGuid; Coverage=$coverage; MergedTerms=$union; Reason="coverage $([int]($coverage*100))%; merging adds $delta bytes (fits headroom)" }
    }
    return [pscustomobject]@{ Action='OverBudgetKeep'; Guid=$existingGuid; Coverage=$coverage; MergedTerms=$null; Reason="coverage $([int]($coverage*100))%; merge needs $delta bytes > headroom $TenantHeadroomBytes; keeping existing, SIT may under-match" }
}

function Test-DictionaryBudget {
    <#
    .SYNOPSIS
        Compares a projected total compressed dictionary size against the tenant caps.
        Defaults: warn 480 KB (AD-schema-conservative), hard 1 MB (documented ceiling).
    #>
    param(
        [Parameter(Mandatory)][long]$ProjectedBytes,
        [long]$WarnBytes = 491520,
        [long]$HardBytes = 1048576
    )
    [pscustomobject]@{
        ProjectedBytes = $ProjectedBytes
        WarnBytes      = $WarnBytes
        HardBytes      = $HardBytes
        WithinWarn     = ($ProjectedBytes -le $WarnBytes)
        WithinHard     = ($ProjectedBytes -le $HardBytes)
    }
}

function Test-DictionaryRemovalAllowed {
    <#
    .SYNOPSIS
        Pure decision: a dictionary may be removed only if it is ours AND no remaining
        package references its GUID.
    #>
    param(
        [Parameter(Mandatory)][bool]$IsOurs,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ReferencedByGuids,
        [Parameter(Mandatory)][string]$DictGuid
    )
    if (-not $IsOurs) {
        return [pscustomobject]@{ Allowed=$false; Reason='not created by this toolkit; keeping' }
    }
    $referenced = @($ReferencedByGuids) -contains $DictGuid
    if ($referenced) {
        return [pscustomobject]@{ Allowed=$false; Reason='still referenced by a remaining package; keeping' }
    }
    return [pscustomobject]@{ Allowed=$true; Reason='ours and unreferenced' }
}
#endregion

#region XML Validation
function Test-SITRulePackageXml {
    <#
    .SYNOPSIS
        Validates a SIT rule package XML file for Purview compliance.
    .OUTPUTS
        PSCustomObject with Valid (bool), Errors (string[]), Warnings (string[]), FileSize (int)
    #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [int]$MaxFileSizeBytes = 153600  # 150KB
    )

    $result = [PSCustomObject]@{
        Valid    = $true
        Errors   = [System.Collections.Generic.List[string]]::new()
        Warnings = [System.Collections.Generic.List[string]]::new()
        FileSize = 0
    }

    if (-not (Test-Path $FilePath)) {
        $result.Valid = $false
        $result.Errors.Add("File not found: $FilePath")
        return $result
    }

    $result.FileSize = (Get-Item $FilePath).Length

    if ($result.FileSize -gt $MaxFileSizeBytes) {
        $result.Valid = $false
        $result.Errors.Add("File exceeds 150KB limit: $([math]::Round($result.FileSize / 1KB, 1))KB")
    }

    if ($result.FileSize -eq 0) {
        $result.Valid = $false
        $result.Errors.Add("File is empty")
        return $result
    }

    # Parse XML (UTF-8 and UTF-16 both work; try UTF-8 first as it is the normal case)
    $xml = $null
    try {
        $xml = [xml](Get-Content $FilePath -Encoding UTF8 -ErrorAction SilentlyContinue)
        if (-not $xml) {
            $content = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::Unicode)
            $xml = [xml]$content
        }
    } catch {
        try {
            $content = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::Unicode)
            $xml = [xml]$content
        } catch {
            $result.Valid = $false
            $result.Errors.Add("XML parse error: $($_.Exception.Message)")
            return $result
        }
    }

    # Validate structure
    if ($xml.DocumentElement.LocalName -ne "RulePackage") {
        $result.Valid = $false
        $result.Errors.Add("Root element is '$($xml.DocumentElement.LocalName)', expected 'RulePackage'")
    }

    $rulePack = $xml.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq "RulePack" }
    if (-not $rulePack) {
        $result.Valid = $false
        $result.Errors.Add("Missing <RulePack> element")
    }

    $rules = $xml.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq "Rules" }
    if (-not $rules) {
        $result.Valid = $false
        $result.Errors.Add("Missing <Rules> element")
    } else {
        $entities = $rules.ChildNodes | Where-Object { $_.LocalName -eq "Entity" }
        $entityCount = @($entities).Count
        if ($entityCount -eq 0) {
            $result.Warnings.Add("No <Entity> elements found inside <Rules>")
        } elseif ($entityCount -gt 50) {
            $result.Valid = $false
            $result.Errors.Add("Contains $entityCount entities (max 50 per package)")
        }

        $localizedInRules = $rules.ChildNodes | Where-Object { $_.LocalName -eq "LocalizedStrings" }
        if (-not $localizedInRules) {
            $result.Warnings.Add("No <LocalizedStrings> found directly inside <Rules>")
        }

        foreach ($entity in @($entities)) {
            $badLocalized = $entity.ChildNodes | Where-Object { $_.LocalName -eq "LocalizedStrings" }
            if ($badLocalized) {
                $result.Valid = $false
                $result.Errors.Add("Entity '$($entity.GetAttribute('id'))' has <LocalizedStrings> inside it (must be in <Rules>)")
            }
        }
    }

    return $result
}
#endregion

# Export all public functions
Export-ModuleMember -Function @(
    'Get-ModuleDefaults'
    'Connect-DLPSession'
    'Assert-DLPSession'
    'Disconnect-DLPSession'
    'Get-LiveDLPSession'
    'Test-DLPSessionMatch'
    'Import-JsonConfig'
    'Merge-GlobalConfig'
    'Set-DeploymentConfigPrefix'
    'Assert-ConfigCustomised'
    'Resolve-PolicyConfig'
    'Resolve-ClassifierConfig'
    'Resolve-LabelConfig'
    'Resolve-RuleOverrides'
    'Get-PolicyName'
    'Get-RuleName'
    'New-DLPSITCondition'
    'New-AdvancedRuleJson'
    'Resolve-PolicyMode'
    'Get-MergedRuleParams'
    'Test-PurviewObjectNameSafety'
    'Assert-PurviewObjectNameSafety'
    'Test-PurviewNameConflicts'
    'Remove-PurviewObject'
    'Remove-PurviewObjects'
    'Resolve-CleanupTargets'
    'Get-CleanupConfirmationPhrase'
    'Show-CleanupPlan'
    'Invoke-CleanupPlan'
    'Invoke-WithRetry'
    'Start-DeploymentLog'
    'Stop-DeploymentLog'
    'Get-DeploymentTenantInfo'
    'New-DeploymentManifest'
    'Add-DeploymentManifestEvent'
    'Complete-DeploymentManifest'
    'Save-DeploymentManifest'
    'Get-DeploymentFileArtifact'
    'Test-DeploymentTenantFingerprint'
    'Convert-DlpSerializedRulePackageToText'
    'Get-DlpRulePackageEntityIds'
    'Get-DlpClassifierRuleReferences'
    'Test-DlpRulePackageRemovalReferenceGuard'
    'Test-SITRulePackageXml'
    'Split-ClassifierChunks'
    'Get-ChunkLetter'
    'Sync-DlpKeywordDictionaries'
    'Get-NormalizedDictionaryTerms'
    'Get-DictionaryTermCoverage'
    'Get-DictionaryCompressedSize'
    'Get-DictionaryGuidReferences'
    'Resolve-DictionarySyncDecision'
    'Test-DictionaryBudget'
    'Test-DictionaryRemovalAllowed'
)

