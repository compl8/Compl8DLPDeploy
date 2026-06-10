#==============================================================================
# DLP-Deploy Shared Module
# Consolidates all common functions for the DLP deployment toolkit.
# Import with: Import-Module .\modules\DLP-Deploy.psm1 -Force
#==============================================================================

# ---------------------------------------------------------------------------
# Layered-architecture facade (Stages 1-2 of
# docs/superpowers/specs/2026-06-10-config-mgmt-architecture-design.md).
# Moved functions are canonically defined one-per-file under
# modules/Compl8.Model and modules/Compl8.Tenant and dot-sourced here so every
# existing `Import-Module ...DLP-Deploy.psm1` site — and every Pester mock
# scoped `-ModuleName DLP-Deploy` — keeps working unchanged during migration.
# ---------------------------------------------------------------------------
foreach ($compl8Layer in @('Compl8.Model', 'Compl8.Tenant')) {
    $compl8LayerPublic = Join-Path $PSScriptRoot $compl8Layer 'Public'
    if (Test-Path -LiteralPath $compl8LayerPublic) {
        foreach ($compl8Fn in (Get-ChildItem -Path $compl8LayerPublic -Filter '*.ps1' -File | Sort-Object Name)) {
            . $compl8Fn.FullName
        }
    }
}

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
        labelPolicyName          = "Label-Policy"
        nameTemplates            = @{
            label             = "{prefix}-{name}-{labelCode}"
            labelPolicy       = "{prefix}-{name}"
            dlpPolicy         = "P{policyNumber}-{policyCode}-{prefix}-{suffix}"
            dlpRule           = "P{policyNumber}-R{ruleNumber}{chunkLetter}-{policyCode}-{labelCode}-{suffix}"
            classifierPackage = "{prefix}-{name}"
            classifierEntity  = "{prefix}-{name}"
            canaryPackage     = "{prefix}-DLPDeploy-Canary-{suffix}"
            canaryEntity      = "{prefix}-DLPDeploy-Canary-{name}"
            autoLabelPolicy   = "AL{policyNumber}-{labelCode}-{prefix}-{suffix}"
            autoLabelRule     = "AL{policyNumber}-R{ruleNumber}{chunkLetter}-{workloadCode}-{labelCode}-{suffix}"
        }
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
                if ($prop.Name -eq "nameTemplates") {
                    $templates = @{}
                    foreach ($templateKey in $Defaults.nameTemplates.Keys) {
                        $templates[$templateKey] = $Defaults.nameTemplates[$templateKey]
                    }
                    if ($prop.Value) {
                        foreach ($templateProp in $prop.Value.PSObject.Properties) {
                            $templates[$templateProp.Name] = $templateProp.Value
                        }
                    }
                    $merged[$prop.Name] = $templates
                } else {
                    $merged[$prop.Name] = $prop.Value
                }
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
        $Config["labelPolicyName"] = "Label-Policy"
    } elseif (-not [string]::IsNullOrWhiteSpace($oldPrefix) -and $oldLabelPolicy -match "^$([regex]::Escape($oldPrefix))(?=-|$)") {
        $Config["labelPolicyName"] = [regex]::Replace($oldLabelPolicy, "^$([regex]::Escape($oldPrefix))-?", "", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    } elseif ($oldLabelPolicy -eq "DLP-Label-Policy") {
        $Config["labelPolicyName"] = "Label-Policy"
    }

    Write-Host "  Prefix override: namingPrefix/sitPrefix = $prefixValue" -ForegroundColor Gray
    Write-Host "  Label policy:    $(Get-DeploymentObjectName -Config $Config -ObjectType "labelPolicy" -Name $Config["labelPolicyName"])" -ForegroundColor Gray
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
        labelPolicyName = "Label-Policy"
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
function ConvertTo-DeploymentNameTemplates {
    param([object]$Templates)

    $result = @{}
    if (-not $Templates) { return $result }

    if ($Templates -is [hashtable]) {
        foreach ($key in $Templates.Keys) {
            $result[$key] = $Templates[$key]
        }
        return $result
    }

    foreach ($prop in $Templates.PSObject.Properties) {
        $result[$prop.Name] = $prop.Value
    }
    return $result
}

function Remove-DeploymentNamePrefix {
    param(
        [string]$Name,
        [string]$Prefix
    )

    if ([string]::IsNullOrWhiteSpace($Name) -or [string]::IsNullOrWhiteSpace($Prefix)) {
        return $Name
    }

    $marker = "$Prefix-"
    if ($Name.StartsWith($marker, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Name.Substring($marker.Length)
    }
    return $Name
}

function Expand-DeploymentNameTemplate {
    param(
        [Parameter(Mandatory)][string]$Template,
        [Parameter(Mandatory)][hashtable]$Tokens
    )

    $expanded = $Template
    foreach ($key in @($Tokens.Keys | Sort-Object { $_.Length } -Descending)) {
        $value = if ($null -eq $Tokens[$key]) { "" } else { $Tokens[$key].ToString() }
        $expanded = $expanded.Replace("{$key}", $value)
    }

    # Drop any {placeholder} that no caller supplied so we never leak literal tokens into Purview names.
    $expanded = $expanded -replace '\{[^{}]+\}', ''

    return (($expanded -replace '-{2,}', '-').Trim('-').Trim())
}

function Get-DeploymentObjectName {
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][string]$ObjectType,
        [string]$Name,
        [string]$SourcePrefix,
        [hashtable]$Tokens = @{}
    )

    $prefix = if ($Config.ContainsKey("namingPrefix")) { $Config.namingPrefix } else { "" }
    $suffix = if ($Config.ContainsKey("namingSuffix")) { $Config.namingSuffix } else { "" }
    $templates = ConvertTo-DeploymentNameTemplates -Templates $Config.nameTemplates
    $template = if ($templates.ContainsKey($ObjectType)) { $templates[$ObjectType] } else { "{prefix}-{name}" }

    $baseName = Remove-DeploymentNamePrefix -Name $Name -Prefix $prefix
    if (-not [string]::IsNullOrWhiteSpace($SourcePrefix)) {
        $baseName = Remove-DeploymentNamePrefix -Name $baseName -Prefix $SourcePrefix
    }
    $allTokens = @{
        prefix      = $prefix
        suffix      = $suffix
        name        = $baseName
        rawName     = $Name
        chunkLetter = ""
    }
    foreach ($key in $Tokens.Keys) {
        $allTokens[$key] = $Tokens[$key]
    }

    return Expand-DeploymentNameTemplate -Template $template -Tokens $allTokens
}

function Get-PolicyName {
    param(
        [int]$PolicyNumber,
        [string]$PolicyCode,
        [string]$Prefix,
        [string]$Suffix,
        [hashtable]$Config
    )

    if (-not $Config) {
        return "P{0:D2}-{1}-{2}-{3}" -f $PolicyNumber, $PolicyCode, $Prefix, $Suffix
    }

    $resolvedSuffix = if ($Suffix) { $Suffix } else { $Config.namingSuffix }
    return Get-DeploymentObjectName -Config $Config -ObjectType "dlpPolicy" -Tokens @{
        policyNumber = ("{0:D2}" -f $PolicyNumber)
        policyCode   = $PolicyCode
        suffix       = $resolvedSuffix
    }
}

function Get-RuleName {
    param(
        [int]$PolicyNumber,
        [int]$RuleNumber,
        [string]$PolicyCode,
        [string]$LabelCode,
        [string]$Suffix,
        [string]$Prefix,
        [string]$ChunkLetter = "",
        [hashtable]$Config
    )

    if (-not $Config) {
        return "P{0:D2}-R{1:D2}{2}-{3}-{4}-{5}" -f $PolicyNumber, $RuleNumber, $ChunkLetter, $PolicyCode, $LabelCode, $Suffix
    }

    $resolvedSuffix = if ($Suffix) { $Suffix } else { $Config.namingSuffix }
    return Get-DeploymentObjectName -Config $Config -ObjectType "dlpRule" -Tokens @{
        policyNumber = ("{0:D2}" -f $PolicyNumber)
        ruleNumber   = ("{0:D2}" -f $RuleNumber)
        chunkLetter  = $ChunkLetter
        policyCode   = $PolicyCode
        labelCode    = $LabelCode
        suffix       = $resolvedSuffix
    }
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
        [object[]]$DlpRules,
        [string]$OperationName = "classifier package removal"
    )

    $packageEntityIndex = @(Get-DlpRulePackageEntityIds -Packages $Packages)
    $candidateIds = @($packageEntityIndex | ForEach-Object { $_.EntityIds } | Sort-Object -Unique)
    $referenceIndex = [pscustomobject]@{
        CandidateIdCount = $candidateIds.Count
        RulesScanned     = 0
        MatchingRuleCount = 0
        References       = @()
    }

    # When no entity IDs could be extracted (e.g. every package failed to parse), there is
    # nothing to scan for. The unparsed-package check below still fails the guard closed.
    if ($candidateIds.Count -gt 0) {
        $rules = @()
        if ($PSBoundParameters.ContainsKey("DlpRules")) {
            $rules = @($DlpRules)
        } else {
            try {
                $rules = @(Get-DlpComplianceRule -ErrorAction Stop)
            } catch {
                Write-Warning "Could not retrieve DLP rules for classifier reference check: $($_.Exception.Message)"
            }
        }

        $referenceIndex.RulesScanned = @($rules).Count
        if ($referenceIndex.RulesScanned -gt 0) {
            $candidateLookup = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($id in @($candidateIds)) {
                if (-not [string]::IsNullOrWhiteSpace($id)) {
                    $candidateLookup.Add($id.ToString()) | Out-Null
                }
            }

            $graph = Get-DeploymentReferenceGraph -SitPackages $Packages -DlpRules $rules
            $nodesById = @{}
            foreach ($node in @($graph.Nodes)) {
                $nodesById[$node.Id] = $node
            }

            $referencesByRule = @{}
            foreach ($edge in @($graph.Edges | Where-Object { $_.Type -eq "sitReferencedByRule" })) {
                if (-not $edge.From.StartsWith("sit:", [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                $matchedId = $edge.From.Substring(4)
                if (-not $candidateLookup.Contains($matchedId)) { continue }

                if (-not $referencesByRule.ContainsKey($edge.To)) {
                    $ruleNode = $nodesById[$edge.To]
                    $ruleName = if ($ruleNode -and $ruleNode.Name) { $ruleNode.Name } elseif ($edge.To -like "dlpRule:*") { $edge.To.Substring(8) } else { "(unknown)" }
                    $policyNames = @($graph.Edges |
                        Where-Object { $_.Type -eq "ruleBelongsToPolicy" -and $_.From -eq $edge.To } |
                        ForEach-Object {
                            if ($nodesById.ContainsKey($_.To) -and $nodesById[$_.To].Name) {
                                $nodesById[$_.To].Name
                            } elseif ($_.To -like "dlpPolicy:*") {
                                $_.To.Substring(10)
                            }
                        } |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                        Sort-Object -Unique)
                    $referencesByRule[$edge.To] = [pscustomobject]@{
                        RuleName = $ruleName
                        PolicyNames = @($policyNames)
                        MatchedClassifierIds = New-Object System.Collections.Generic.List[string]
                    }
                }
                $referencesByRule[$edge.To].MatchedClassifierIds.Add($matchedId.ToLowerInvariant()) | Out-Null
            }

            $references = @()
            foreach ($entry in @($referencesByRule.GetEnumerator() | Sort-Object { $_.Value.RuleName })) {
                $ids = @($entry.Value.MatchedClassifierIds | Sort-Object -Unique)
                $references += [pscustomobject]@{
                    RuleName = $entry.Value.RuleName
                    PolicyNames = @($entry.Value.PolicyNames)
                    MatchedClassifierIds = $ids
                }
            }
            $referenceIndex.MatchingRuleCount = @($references).Count
            $referenceIndex.References = @($references)
        }
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

function New-DeploymentGraphNodeId {
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Value
    )

    $cleanValue = $Value.Trim()
    if ($cleanValue -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        $cleanValue = $cleanValue.ToLowerInvariant()
    }
    return ("{0}:{1}" -f $Prefix, $cleanValue)
}

function Get-DeploymentGraphObjectValue {
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

function Get-DeploymentGraphRulePackageInfo {
    param([Parameter(Mandatory)][object]$Package)

    $identity = Get-DeploymentGraphObjectValue -InputObject $Package -Names @("Identity", "Id", "Guid")
    $name = Get-DeploymentGraphObjectValue -InputObject $Package -Names @("Name", "DisplayName")
    $publisher = Get-DeploymentGraphObjectValue -InputObject $Package -Names @("Publisher")
    $rawText = Convert-DlpSerializedRulePackageToText -Raw $Package.SerializedClassificationRuleCollection

    $result = [pscustomobject]@{
        Identity   = $identity
        Name       = $name
        Publisher  = $publisher
        RulePackId = $null
        Parsed     = $false
        ParseError  = $null
        Xml        = $null
        RawText    = $rawText
    }

    if (-not $rawText) {
        $result.ParseError = "SerializedClassificationRuleCollection was empty."
        return $result
    }

    try {
        [xml]$xml = $rawText
        $result.Xml = $xml
        $result.Parsed = $true
        $rulePack = $xml.RulePackage.RulePack
        if ($rulePack -and $rulePack.id) {
            $result.RulePackId = $rulePack.id.ToString()
        }
        if ($rulePack -and $rulePack.Details -and $rulePack.Details.LocalizedDetails) {
            $localized = $rulePack.Details.LocalizedDetails | Select-Object -First 1
            if ($localized -and $localized.Name) {
                $result.Name = $localized.Name.ToString()
            }
        }
    } catch {
        $result.ParseError = $_.Exception.Message
    }

    return $result
}

function Get-DeploymentReferenceGraph {
    <#
    .SYNOPSIS
        Builds a dependency graph across Purview deployment objects.
    .DESCRIPTION
        Produces stable node and edge records for the roadmap substrate:
        keyword dictionary -> sensitive information type -> DLP rule -> DLP policy -> label.
        The function is intentionally pure: callers pass already-fetched tenant/config
        objects so destructive guards can reuse the same parser without introducing new
        tenant calls in tests or plan-generation paths.
    #>
    param(
        [object[]]$Dictionaries = @(),
        [object[]]$SitPackages = @(),
        [object[]]$DlpRules = @(),
        [object[]]$DlpPolicies = @(),
        [object[]]$Labels = @()
    )

    $nodes = New-Object System.Collections.Generic.List[object]
    $edges = New-Object System.Collections.Generic.List[object]
    $nodesById = @{}
    $edgesByKey = @{}
    $knownSitIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $labelIdByCode = @{}
    $unparsedPackageCount = 0

    function Add-GraphNode {
        param(
            [Parameter(Mandatory)][string]$Id,
            [Parameter(Mandatory)][string]$Type,
            [string]$Name,
            [string]$Identity,
            [string]$Source,
            [hashtable]$Properties = @{}
        )

        if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
        if (-not $nodesById.ContainsKey($Id)) {
            $node = [pscustomobject]@{
                Id         = $Id
                Type       = $Type
                Name       = $Name
                Identity   = $Identity
                Source     = $Source
                Properties = [pscustomobject]$Properties
            }
            $nodesById[$Id] = $node
            $nodes.Add($node) | Out-Null
        } else {
            $node = $nodesById[$Id]
            if ([string]::IsNullOrWhiteSpace($node.Name) -and -not [string]::IsNullOrWhiteSpace($Name)) {
                $node.Name = $Name
            }
            if ([string]::IsNullOrWhiteSpace($node.Identity) -and -not [string]::IsNullOrWhiteSpace($Identity)) {
                $node.Identity = $Identity
            }
        }
        return $Id
    }

    function Add-GraphEdge {
        param(
            [Parameter(Mandatory)][string]$From,
            [Parameter(Mandatory)][string]$To,
            [Parameter(Mandatory)][string]$Type,
            [string]$Source,
            [hashtable]$Properties = @{}
        )

        if ([string]::IsNullOrWhiteSpace($From) -or [string]::IsNullOrWhiteSpace($To)) { return }
        $key = "{0}|{1}|{2}" -f $From, $To, $Type
        if ($edgesByKey.ContainsKey($key)) { return }
        $edge = [pscustomobject]@{
            From       = $From
            To         = $To
            Type       = $Type
            Source     = $Source
            Properties = [pscustomobject]$Properties
        }
        $edgesByKey[$key] = $true
        $edges.Add($edge) | Out-Null
    }

    foreach ($dictionary in @($Dictionaries)) {
        if (-not $dictionary) { continue }
        $identity = Get-DeploymentGraphObjectValue -InputObject $dictionary -Names @("Identity", "Guid", "Id")
        $name = Get-DeploymentGraphObjectValue -InputObject $dictionary -Names @("Name", "DisplayName")
        $nodeValue = if ($identity) { $identity } elseif ($name) { $name } else { $null }
        if (-not $nodeValue) { continue }
        $nodeId = New-DeploymentGraphNodeId -Prefix "dictionary" -Value $nodeValue
        Add-GraphNode -Id $nodeId -Type "KeywordDictionary" -Name $name -Identity $identity -Source "KeywordDictionary" -Properties @{ Missing = $false } | Out-Null
    }

    foreach ($label in @($Labels)) {
        if (-not $label) { continue }
        $code = Get-DeploymentGraphObjectValue -InputObject $label -Names @("code", "Code", "LabelCode")
        $name = Get-DeploymentGraphObjectValue -InputObject $label -Names @("name", "Name", "fullName", "displayName", "DisplayName")
        $identity = Get-DeploymentGraphObjectValue -InputObject $label -Names @("Identity", "Guid", "Id")
        $nodeValue = if ($identity) { $identity } elseif ($name) { $name } elseif ($code) { $code } else { $null }
        if (-not $nodeValue) { continue }
        $nodeId = New-DeploymentGraphNodeId -Prefix "label" -Value $nodeValue
        Add-GraphNode -Id $nodeId -Type "Label" -Name $name -Identity $identity -Source "LabelConfig" -Properties @{ Code = $code } | Out-Null
        if ($code -and -not $labelIdByCode.ContainsKey($code)) {
            $labelIdByCode[$code] = $nodeId
        }
    }

    foreach ($policy in @($DlpPolicies)) {
        if (-not $policy) { continue }
        $name = Get-DeploymentGraphObjectValue -InputObject $policy -Names @("Name", "Identity", "DisplayName")
        $identity = Get-DeploymentGraphObjectValue -InputObject $policy -Names @("Identity", "Id", "Guid")
        $nodeValue = if ($name) { $name } elseif ($identity) { $identity } else { $null }
        if (-not $nodeValue) { continue }
        $nodeId = New-DeploymentGraphNodeId -Prefix "dlpPolicy" -Value $nodeValue
        Add-GraphNode -Id $nodeId -Type "DlpPolicy" -Name $name -Identity $identity -Source "DlpPolicy" -Properties @{ Missing = $false } | Out-Null
    }

    foreach ($package in @($SitPackages)) {
        if (-not $package) { continue }
        $info = Get-DeploymentGraphRulePackageInfo -Package $package
        if (-not $info.Parsed) { $unparsedPackageCount++ }
        $packageValue = if ($info.RulePackId) { $info.RulePackId } elseif ($info.Identity) { $info.Identity } elseif ($info.Name) { $info.Name } else { $null }
        if (-not $packageValue) { continue }

        $packageNodeId = New-DeploymentGraphNodeId -Prefix "sitPackage" -Value $packageValue
        Add-GraphNode -Id $packageNodeId -Type "SitPackage" -Name $info.Name -Identity $info.Identity -Source "DlpRulePackage" -Properties @{
            RulePackId = $info.RulePackId
            Publisher = $info.Publisher
            Parsed = [bool]$info.Parsed
            ParseError = $info.ParseError
        } | Out-Null

        if (-not $info.Parsed -or -not $info.Xml) { continue }
        $rules = $info.Xml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq "Rules" } | Select-Object -First 1
        if (-not $rules) { continue }

        foreach ($entity in @($rules.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -eq "Entity" })) {
            $entityId = $entity.GetAttribute("id")
            if ([string]::IsNullOrWhiteSpace($entityId)) { continue }
            $entityId = $entityId.ToLowerInvariant()
            $sitNodeId = New-DeploymentGraphNodeId -Prefix "sit" -Value $entityId
            $knownSitIds.Add($entityId) | Out-Null
            Add-GraphNode -Id $sitNodeId -Type "SensitiveInformationType" -Name $null -Identity $entityId -Source "RulePackageEntity" -Properties @{
                RulePackId = $info.RulePackId
                PackageIdentity = $info.Identity
                PackageName = $info.Name
            } | Out-Null
            Add-GraphEdge -From $packageNodeId -To $sitNodeId -Type "packageContainsSit" -Source "RulePackageEntity" -Properties @{ RulePackId = $info.RulePackId } | Out-Null

            foreach ($dictionaryId in @(Get-DictionaryGuidReferences -PackageXmlText $entity.OuterXml)) {
                $dictionaryNodeId = New-DeploymentGraphNodeId -Prefix "dictionary" -Value $dictionaryId
                $missing = -not $nodesById.ContainsKey($dictionaryNodeId)
                Add-GraphNode -Id $dictionaryNodeId -Type "KeywordDictionary" -Name $null -Identity $dictionaryId -Source "RulePackageDictionaryReference" -Properties @{ Missing = $missing } | Out-Null
                Add-GraphEdge -From $dictionaryNodeId -To $sitNodeId -Type "dictionaryFeedsSit" -Source "RulePackageEntity" -Properties @{ RulePackId = $info.RulePackId } | Out-Null
            }
        }
    }

    $labelCodesByLength = @($labelIdByCode.Keys | Sort-Object { $_.Length } -Descending)
    $guidPattern = '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
    foreach ($rule in @($DlpRules)) {
        if (-not $rule) { continue }
        $ruleName = Get-DeploymentGraphObjectValue -InputObject $rule -Names @("Name", "Identity", "DisplayName")
        $ruleIdentity = Get-DeploymentGraphObjectValue -InputObject $rule -Names @("Identity", "Id", "Guid")
        $ruleValue = if ($ruleName) { $ruleName } elseif ($ruleIdentity) { $ruleIdentity } else { $null }
        if (-not $ruleValue) { continue }
        $ruleNodeId = New-DeploymentGraphNodeId -Prefix "dlpRule" -Value $ruleValue
        Add-GraphNode -Id $ruleNodeId -Type "DlpRule" -Name $ruleName -Identity $ruleIdentity -Source "DlpRule" -Properties @{} | Out-Null

        $ruleText = Get-DlpRuleClassifierReferenceText -Rule $rule
        if ($ruleText) {
            $matchedSitIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($match in [regex]::Matches($ruleText, $guidPattern)) {
                if ($knownSitIds.Contains($match.Value)) {
                    $matchedSitIds.Add($match.Value.ToLowerInvariant()) | Out-Null
                }
            }
            foreach ($sitId in @($matchedSitIds | Sort-Object)) {
                $sitNodeId = New-DeploymentGraphNodeId -Prefix "sit" -Value $sitId
                Add-GraphEdge -From $sitNodeId -To $ruleNodeId -Type "sitReferencedByRule" -Source "DlpRule" -Properties @{} | Out-Null
            }
        }

        $policyNames = @(Get-DlpRulePolicyNames -Rule $rule)
        foreach ($policyName in $policyNames) {
            if ([string]::IsNullOrWhiteSpace($policyName)) { continue }
            $policyNodeId = New-DeploymentGraphNodeId -Prefix "dlpPolicy" -Value $policyName
            Add-GraphNode -Id $policyNodeId -Type "DlpPolicy" -Name $policyName -Identity $policyName -Source "DlpRulePolicyReference" -Properties @{ Missing = -not $nodesById.ContainsKey($policyNodeId) } | Out-Null
            Add-GraphEdge -From $ruleNodeId -To $policyNodeId -Type "ruleBelongsToPolicy" -Source "DlpRule" -Properties @{} | Out-Null
        }

        foreach ($labelCode in $labelCodesByLength) {
            if ([string]::IsNullOrWhiteSpace($labelCode) -or [string]::IsNullOrWhiteSpace($ruleName)) { continue }
            $escapedCode = [regex]::Escape($labelCode)
            if (-not [regex]::IsMatch($ruleName, "(^|-)$escapedCode(-|$)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
                continue
            }
            $labelNodeId = $labelIdByCode[$labelCode]
            foreach ($policyName in $policyNames) {
                if ([string]::IsNullOrWhiteSpace($policyName)) { continue }
                $policyNodeId = New-DeploymentGraphNodeId -Prefix "dlpPolicy" -Value $policyName
                Add-GraphEdge -From $policyNodeId -To $labelNodeId -Type "policyTargetsLabel" -Source "DlpRuleName" -Properties @{ LabelCode = $labelCode; RuleName = $ruleName } | Out-Null
            }
            break
        }
    }

    $nodeArray = @($nodes.ToArray())
    $edgeArray = @($edges.ToArray())

    return [pscustomobject]@{
        Nodes   = $nodeArray
        Edges   = $edgeArray
        Summary = [pscustomobject]@{
            NodeCount            = $nodeArray.Count
            EdgeCount            = $edgeArray.Count
            DictionaryCount      = @($nodeArray | Where-Object { $_.Type -eq "KeywordDictionary" }).Count
            SitPackageCount      = @($nodeArray | Where-Object { $_.Type -eq "SitPackage" }).Count
            SitCount             = @($nodeArray | Where-Object { $_.Type -eq "SensitiveInformationType" }).Count
            DlpRuleCount         = @($nodeArray | Where-Object { $_.Type -eq "DlpRule" }).Count
            DlpPolicyCount       = @($nodeArray | Where-Object { $_.Type -eq "DlpPolicy" }).Count
            LabelCount           = @($nodeArray | Where-Object { $_.Type -eq "Label" }).Count
            UnparsedPackageCount = $unparsedPackageCount
        }
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
    $generatedLabelPolicyName = $null
    if ($labelPolicyName) {
        $generatedLabelPolicyName = Get-DeploymentObjectName -Config $Config -ObjectType "labelPolicy" -Name $labelPolicyName
    }
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

    function Get-ProvenanceMatchedBy {
        param(
            [Parameter(Mandatory)][object]$InputObject,
            [Parameter(Mandatory)][string]$Component
        )

        $ownership = Test-DeploymentProvenanceOwnership -InputObject $InputObject -Prefix $prefix -Component $Component
        if ($ownership.IsOwned) {
            return "provenance '$($ownership.Stamp.Prefix)'/$Component"
        }
        if ($ownership.Stamp) {
            return "__foreign_provenance__"
        }
        return $null
    }

    foreach ($p in @($Objects['AutoLabelPolicy'])) {
        if (-not $p) { continue }
        $provenance = Get-ProvenanceMatchedBy -InputObject $p -Component "AutoLabelPolicy"
        if ($provenance -eq "__foreign_provenance__") { continue }
        if ($provenance) {
            $manifest.Add((New-CleanupTarget $p.Name "AutoLabelPolicy" "Auto-labeling policy" $provenance "scoped" "Get-AutoSensitivityLabelPolicy" "Remove-AutoSensitivityLabelPolicy" $p))
        } elseif ($p.Name -like "AL*-$prefix-$suffix") {
            $manifest.Add((New-CleanupTarget $p.Name "AutoLabelPolicy" "Auto-labeling policy" "prefix '$prefix' + suffix '$suffix'" "scoped" "Get-AutoSensitivityLabelPolicy" "Remove-AutoSensitivityLabelPolicy" $p))
        }
    }

    foreach ($p in @($Objects['DlpPolicy'])) {
        if (-not $p) { continue }
        $provenance = Get-ProvenanceMatchedBy -InputObject $p -Component "DlpPolicy"
        if ($provenance -eq "__foreign_provenance__") { continue }
        if ($provenance) {
            $manifest.Add((New-CleanupTarget $p.Name "DlpPolicy" "DLP policy" $provenance "scoped" "Get-DlpCompliancePolicy" "Remove-DlpCompliancePolicy" $p))
        } elseif ($p.Name -like "*$prefix*") {
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
        $provenance = Get-ProvenanceMatchedBy -InputObject $d -Component "KeywordDictionary"
        if ($provenance -eq "__foreign_provenance__") { continue }
        if ($provenance) {
            $manifest.Add((New-CleanupTarget $d.Identity "KeywordDictionary" "Keyword dictionary" $provenance "scoped" "Get-DlpKeywordDictionary" "Remove-DlpKeywordDictionary" $d))
        } elseif ($d.Name -like "$prefix*") {
            $manifest.Add((New-CleanupTarget $d.Identity "KeywordDictionary" "Keyword dictionary" "prefix '$prefix'" "scoped" "Get-DlpKeywordDictionary" "Remove-DlpKeywordDictionary" $d))
        }
    }

    if ($IncludeLabels) {
        foreach ($lp in @($Objects['LabelPolicy'])) {
            if (-not $lp) { continue }
            $provenance = Get-ProvenanceMatchedBy -InputObject $lp -Component "LabelPolicy"
            if ($provenance -eq "__foreign_provenance__") { continue }
            if ($provenance) {
                $manifest.Add((New-CleanupTarget $lp.Name "LabelPolicy" "Label policy" $provenance "scoped" "Get-LabelPolicy" "Remove-LabelPolicy" $lp))
            } elseif ($lp.Name -like "*$prefix*") {
                $manifest.Add((New-CleanupTarget $lp.Name "LabelPolicy" "Label policy" "prefix '$prefix'" "scoped" "Get-LabelPolicy" "Remove-LabelPolicy" $lp))
            } elseif ($generatedLabelPolicyName -and $lp.Name -eq $generatedLabelPolicyName) {
                $manifest.Add((New-CleanupTarget $lp.Name "LabelPolicy" "Label policy" "configured labelPolicyName '$generatedLabelPolicyName'" "scoped" "Get-LabelPolicy" "Remove-LabelPolicy" $lp))
            } elseif ($labelPolicyName -and $lp.Name -eq $labelPolicyName) {
                $manifest.Add((New-CleanupTarget $lp.Name "LabelPolicy" "Label policy" "legacy configured labelPolicyName '$labelPolicyName'" "scoped" "Get-LabelPolicy" "Remove-LabelPolicy" $lp))
            }
        }
        foreach ($l in @($Objects['Label'])) {
            if (-not $l) { continue }
            $provenance = Get-ProvenanceMatchedBy -InputObject $l -Component "SensitivityLabel"
            if ($provenance -eq "__foreign_provenance__") { continue }
            if ($provenance) {
                $manifest.Add((New-CleanupTarget $l.Name "Label" "Sensitivity label" $provenance "scoped" "Get-Label" "Remove-Label" $l))
            } elseif ($l.Name -like "*$prefix*") {
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
        if ($cat -eq "KeywordDictionary" -and $items.Count -gt 0) {
            # Keep any dictionary still referenced by a package that will REMAIN after this run
            # (SIT packages are deleted earlier in $order, so only out-of-scope packages remain).
            $remaining = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction SilentlyContinue |
                Where-Object { $sitTargets.Identity -notcontains $_.Identity })
            $referenced = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($p in $remaining) {
                $txt = Convert-DlpSerializedRulePackageToText -Raw $p.SerializedClassificationRuleCollection
                if ($txt) { foreach ($g in Get-DictionaryGuidReferences -PackageXmlText $txt) { [void]$referenced.Add($g) } }
            }
            $items = @($items | Where-Object {
                $dictGuid = if ($_.InputObject.Identity) { $_.InputObject.Identity.ToString().ToLowerInvariant() } else { "" }
                $allow = Test-DictionaryRemovalAllowed -IsOurs $true -ReferencedByGuids @($referenced) -DictGuid $dictGuid
                if (-not $allow.Allowed) {
                    Write-Host "    KEPT dictionary $($_.Identity): $($allow.Reason)" -ForegroundColor DarkYellow
                    $false
                } else { $true }
            })
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

function ConvertTo-DeploymentProvenanceFieldValue {
    param([string]$Value)

    if ($null -eq $Value) { return "" }
    return [System.Uri]::EscapeDataString($Value)
}

function ConvertFrom-DeploymentProvenanceFieldValue {
    param([string]$Value)

    if ($null -eq $Value) { return $null }
    return [System.Uri]::UnescapeDataString($Value)
}

function Resolve-DeploymentProvenanceRegistryPath {
    <#
    .SYNOPSIS
        Resolves the provenance registry file path: explicit override > env var > repo default.
    #>
    param([string]$RegistryPath)

    if (-not [string]::IsNullOrWhiteSpace($RegistryPath)) { return $RegistryPath }
    if (-not [string]::IsNullOrWhiteSpace($env:COMPL8_PROVENANCE_REGISTRY)) { return $env:COMPL8_PROVENANCE_REGISTRY }
    return Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) "reports") "provenance-registry.json"
}

function New-DeploymentProvenanceId {
    <#
    .SYNOPSIS
        Deterministic 16-char hex id derived from the canonical provenance fields.
        Identical inputs always yield the same id, so re-deploys are idempotent.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Fields)

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $Fields.GetEnumerator()) {
        if ($null -eq $entry.Value -or [string]::IsNullOrWhiteSpace($entry.Value.ToString())) { continue }
        $parts.Add(("{0}={1}" -f $entry.Key, $entry.Value.ToString())) | Out-Null
    }
    $canonical = ($parts -join ';')

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canonical))
    } finally {
        $sha.Dispose()
    }
    $hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    return $hex.Substring(0, 16)
}

function Read-DeploymentProvenanceRegistry {
    <#
    .SYNOPSIS
        Loads the provenance registry as @{ version; entries=[ordered] }, tolerating missing/corrupt files.
    #>
    param([string]$RegistryPath)

    $path = Resolve-DeploymentProvenanceRegistryPath -RegistryPath $RegistryPath
    $empty = [ordered]@{ version = 1; entries = [ordered]@{} }
    if (-not (Test-Path -LiteralPath $path)) { return $empty }

    try {
        $raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $empty }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $empty
    }

    $entries = [ordered]@{}
    if ($obj.PSObject.Properties['entries'] -and $obj.entries) {
        foreach ($p in $obj.entries.PSObject.Properties) { $entries[$p.Name] = $p.Value }
    }
    return [ordered]@{ version = if ($obj.PSObject.Properties['version'] -and $obj.version) { $obj.version } else { 1 }; entries = $entries }
}

function Set-DeploymentProvenanceRegistryEntry {
    <#
    .SYNOPSIS
        Inserts or overwrites a single registry entry, creating the file/folder as needed.
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Entry,
        [string]$RegistryPath
    )

    $path = Resolve-DeploymentProvenanceRegistryPath -RegistryPath $RegistryPath
    $registry = Read-DeploymentProvenanceRegistry -RegistryPath $path
    $registry.entries[$Id] = $Entry

    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    ($registry | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $path -Encoding UTF8
}

function Get-DeploymentProvenanceRegistryEntry {
    <#
    .SYNOPSIS
        Returns the registry entry for a provenance id, or $null if absent.
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [string]$RegistryPath
    )

    $registry = Read-DeploymentProvenanceRegistry -RegistryPath $RegistryPath
    if ($registry.entries.Contains($Id)) { return $registry.entries[$Id] }
    return $null
}

function New-DeploymentProvenanceStamp {
    <#
    .SYNOPSIS
        Creates a short opaque ownership marker ([[Compl8:<16hex>]]) for Purview Comment/Description
        fields, recording the full field set in the local provenance registry.
    #>
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Component,
        [string]$DeploymentId,
        [string]$TargetEnvironment,
        [hashtable]$Metadata = @{}
    )

    if ([string]::IsNullOrWhiteSpace($DeploymentId)) {
        $DeploymentId = if ($env:COMPL8_DEPLOYMENT_ID) { $env:COMPL8_DEPLOYMENT_ID } else { Get-Date -Format "yyyyMMdd" }
    }

    $fields = [ordered]@{
        prefix       = $Prefix
        component    = $Component
        deploymentId = $DeploymentId
    }
    if (-not [string]::IsNullOrWhiteSpace($TargetEnvironment)) {
        $fields.environment = $TargetEnvironment
    }
    foreach ($key in @($Metadata.Keys | Sort-Object)) {
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        $safeKey = ($key.ToString() -replace '[^A-Za-z0-9_]', '')
        if ([string]::IsNullOrWhiteSpace($safeKey) -or $fields.Contains($safeKey)) { continue }
        $fields[$safeKey] = $Metadata[$key]
    }

    $id = New-DeploymentProvenanceId -Fields $fields

    $entry = [ordered]@{
        toolkit      = "Compl8DLPDeploy"
        version      = 1
        prefix       = $Prefix
        component    = $Component
        deploymentId = $fields.deploymentId
        environment  = if ($fields.Contains('environment')) { $fields.environment } else { $null }
        fields       = $fields
    }
    Set-DeploymentProvenanceRegistryEntry -Id $id -Entry $entry

    return "[[Compl8:$id]]"
}

function Get-DeploymentProvenanceStamp {
    <#
    .SYNOPSIS
        Reads a Compl8DLPDeploy provenance marker from text. Recognises both the short opaque
        form ([[Compl8:<16hex>]], resolved via the registry) and the legacy long form
        ([[Compl8DLPDeploy:provenance:v1;...]], parsed inline).
    #>
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    # Short opaque form — full fields live in the local registry.
    $shortMatch = [regex]::Match($Text, '\[\[Compl8:(?<id>[0-9a-f]{16})\]\]')
    if ($shortMatch.Success) {
        $id = $shortMatch.Groups["id"].Value
        $entry = Get-DeploymentProvenanceRegistryEntry -Id $id
        if ($null -eq $entry) {
            return [pscustomobject]@{
                Found             = $true
                Resolved          = $false
                Toolkit           = "Compl8DLPDeploy"
                Version           = $null
                Id                = $id
                Prefix            = $null
                Component         = $null
                DeploymentId      = $null
                TargetEnvironment = $null
                Fields            = $null
                Raw               = $shortMatch.Value
            }
        }
        return [pscustomobject]@{
            Found             = $true
            Resolved          = $true
            Toolkit           = if ($entry.toolkit) { $entry.toolkit } else { "Compl8DLPDeploy" }
            Version           = if ($entry.version) { [int]$entry.version } else { 1 }
            Id                = $id
            Prefix            = $entry.prefix
            Component         = $entry.component
            DeploymentId      = $entry.deploymentId
            TargetEnvironment = $entry.environment
            Fields            = $entry.fields
            Raw               = $shortMatch.Value
        }
    }

    # Legacy long form — self-contained, no registry needed.
    $pattern = '\[\[Compl8DLPDeploy:provenance:v(?<version>\d+)(?<fields>(?:;[A-Za-z][A-Za-z0-9_]*=[^\]\r\n;]*)*)\]\]'
    $match = [regex]::Match($Text, $pattern)
    if (-not $match.Success) { return $null }

    $fields = [ordered]@{}
    foreach ($fieldMatch in [regex]::Matches($match.Groups["fields"].Value, ';(?<key>[A-Za-z][A-Za-z0-9_]*)=(?<value>[^\]\r\n;]*)')) {
        $fields[$fieldMatch.Groups["key"].Value] = ConvertFrom-DeploymentProvenanceFieldValue -Value $fieldMatch.Groups["value"].Value
    }

    return [pscustomobject]@{
        Found             = $true
        Resolved          = $true
        Toolkit           = "Compl8DLPDeploy"
        Version           = [int]$match.Groups["version"].Value
        Id                = $null
        Prefix            = $fields["prefix"]
        Component         = $fields["component"]
        DeploymentId      = $fields["deploymentId"]
        TargetEnvironment = $fields["environment"]
        Fields            = [pscustomobject]$fields
        Raw               = $match.Value
    }
}

function Add-DeploymentProvenanceStamp {
    <#
    .SYNOPSIS
        Appends or replaces the provenance marker in a Comment/Description string. Strips any
        existing marker (short or legacy long form) before appending the current short marker.
    #>
    param(
        [string]$Text,
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Component,
        [string]$DeploymentId,
        [string]$TargetEnvironment,
        [hashtable]$Metadata = @{},
        [int]$MaxLength = 1000
    )

    $stamp = New-DeploymentProvenanceStamp -Prefix $Prefix -Component $Component -DeploymentId $DeploymentId -TargetEnvironment $TargetEnvironment -Metadata $Metadata
    $shortPattern = '\[\[Compl8:[0-9a-f]{16}\]\]'
    $longPattern  = '\[\[Compl8DLPDeploy:provenance:v\d+(?:;[A-Za-z][A-Za-z0-9_]*=[^\]\r\n;]*)*\]\]'
    $cleanText = ""
    if ($Text) {
        $cleanText = [regex]::Replace($Text, $longPattern, "")
        $cleanText = [regex]::Replace($cleanText, $shortPattern, "")
        $cleanText = $cleanText.Trim()
    }
    $combined = if ($cleanText) { "$cleanText`n$stamp" } else { $stamp }

    if ($MaxLength -gt 0 -and $combined.Length -gt $MaxLength -and $cleanText) {
        $available = $MaxLength - $stamp.Length - 1
        if ($available -gt 3) {
            $combined = "$($cleanText.Substring(0, $available - 3))...`n$stamp"
        } else {
            $combined = $stamp
        }
    }

    return $combined
}

function Test-DeploymentProvenanceOwnership {
    <#
    .SYNOPSIS
        Classifies an object as toolkit-owned only when a matching provenance marker exists.
        A short marker whose registry entry cannot be resolved is treated as NOT owned
        (fail-safe — never delete what cannot be confirmed).
    #>
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [string]$Prefix,
        [string]$Component
    )

    $stamp = $null
    foreach ($propertyName in @("Comment", "Description")) {
        $prop = $InputObject.PSObject.Properties[$propertyName]
        if (-not $prop -or [string]::IsNullOrWhiteSpace($prop.Value)) { continue }
        $stamp = Get-DeploymentProvenanceStamp -Text $prop.Value.ToString()
        if ($stamp) { break }
    }

    if (-not $stamp) {
        return [pscustomobject]@{ IsOwned = $false; Stamp = $null; Reason = "no provenance marker" }
    }
    if ($stamp.PSObject.Properties['Resolved'] -and -not $stamp.Resolved) {
        return [pscustomobject]@{ IsOwned = $false; Stamp = $stamp; Reason = "provenance id '$($stamp.Id)' not found in registry" }
    }
    if ($Prefix -and $stamp.Prefix -ne $Prefix) {
        return [pscustomobject]@{ IsOwned = $false; Stamp = $stamp; Reason = "provenance prefix '$($stamp.Prefix)' did not match '$Prefix'" }
    }
    if ($Component -and $stamp.Component -ne $Component) {
        return [pscustomobject]@{ IsOwned = $false; Stamp = $stamp; Reason = "provenance component '$($stamp.Component)' did not match '$Component'" }
    }

    return [pscustomobject]@{ IsOwned = $true; Stamp = $stamp; Reason = "matching provenance marker" }
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
#endregion

#region Orchestration Guard
function Test-IsInteractive {
    # Mockable seam: Pester cannot mock [Environment]::UserInteractive directly.
    # Interactive only when a console UI is present AND stdin is NOT redirected, so a
    # `pwsh -File ...` / CI run (stdin piped) is treated non-interactive and hits the
    # clean abort path instead of a Read-Host "NonInteractive mode" error.
    try {
        return ([Environment]::UserInteractive -and -not [System.Console]::IsInputRedirected)
    } catch {
        return $false
    }
}

function Assert-OrchestrationGate {
    <#
    .SYNOPSIS
        Guards a tenant-mutating leaf script against being run raw (bypassing the
        orchestrator's drift / config-skew gates). Returns silently when orchestrated
        (COMPL8_ORCHESTRATED env var), session-driven (-SessionPath), or explicitly
        acknowledged (-AllowDirectRun). Otherwise warns; if interactive, prompts to
        continue (throws on decline); non-interactive raw runs throw.
    #>
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [switch]$AllowDirectRun,
        [string]$SessionPath,
        [string]$RecommendedEntry = 'Start-DLPDeploy.ps1 (interactive) or Invoke-FullDeployment.ps1 (CLI)'
    )
    if (-not [string]::IsNullOrWhiteSpace($env:COMPL8_ORCHESTRATED)) { return }
    if ($AllowDirectRun) { return }
    if (-not [string]::IsNullOrWhiteSpace($SessionPath)) { return }

    Write-Warning "Direct run of $ScriptName -- the drift gate and config-skew confirm normally run by the orchestrator are SKIPPED."
    Write-Host "  Recommended entry: $RecommendedEntry" -ForegroundColor Yellow

    if (Test-IsInteractive) {
        $ans = (Read-Host "  Continue anyway? [y/N]").Trim()
        if ($ans -notmatch '^(y|yes)$') {
            throw "Aborted: direct run of $ScriptName declined."
        }
        return
    }
    throw "Aborted: non-interactive direct run of $ScriptName. Pass -AllowDirectRun to proceed."
}
#endregion

#region Config Resolution
function Get-EffectiveConfigDir {
    <#
    .SYNOPSIS
        Returns the effective config directory for an environment: the per-tenant
        directory config/tenants/<env> when it exists, otherwise the global config/.
        Empty/whitespace environment -> global. Zero-regression default.
    #>
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [string]$Environment
    )
    $globalDir = Join-Path $ProjectRoot 'config'
    if ([string]::IsNullOrWhiteSpace($Environment)) { return $globalDir }
    $tenantDir = Join-Path (Join-Path $globalDir 'tenants') $Environment
    if (Test-Path -LiteralPath $tenantDir -PathType Container) { return $tenantDir }
    return $globalDir
}

function Resolve-ConfigFile {
    <#
    .SYNOPSIS
        Returns the path to a named config file for an environment, preferring the
        tenant copy and falling back to the global file per-file.
    #>
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [string]$Environment,
        [Parameter(Mandatory)][string]$Name
    )
    $effective = Get-EffectiveConfigDir -ProjectRoot $ProjectRoot -Environment $Environment
    $candidate = Join-Path $effective $Name
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    return (Join-Path (Join-Path $ProjectRoot 'config') $Name)
}

function Compare-JsonStructure {
    <#
    .SYNOPSIS
        Recursively compares two parsed-JSON values (Left=global, Right=tenant).
        Returns an array of [pscustomobject]@{ path; kind; global; tenant } where
        kind is 'added' (present in tenant, not global), 'removed' (present in
        global, not tenant), or 'changed' (scalar/array value differs). Objects
        recurse by key; arrays and scalars are compared by normalized JSON.
    #>
    param($Left, $Right, [string]$Path = '')

    $diffs = [System.Collections.Generic.List[object]]::new()
    $leftIsObj  = $Left  -is [System.Management.Automation.PSCustomObject]
    $rightIsObj = $Right -is [System.Management.Automation.PSCustomObject]

    if ($leftIsObj -and $rightIsObj) {
        $leftKeys  = @($Left.PSObject.Properties.Name)
        $rightKeys = @($Right.PSObject.Properties.Name)
        $allKeys   = @($leftKeys + $rightKeys | Select-Object -Unique)
        foreach ($k in $allKeys) {
            $childPath = if ($Path) { "$Path.$k" } else { $k }
            $inLeft  = $leftKeys  -contains $k
            $inRight = $rightKeys -contains $k
            if ($inLeft -and -not $inRight) {
                $diffs.Add([pscustomobject]@{ path = $childPath; kind = 'removed'; global = $Left.$k; tenant = $null })
            } elseif ($inRight -and -not $inLeft) {
                $diffs.Add([pscustomobject]@{ path = $childPath; kind = 'added'; global = $null; tenant = $Right.$k })
            } else {
                foreach ($child in @(Compare-JsonStructure -Left $Left.$k -Right $Right.$k -Path $childPath)) {
                    $diffs.Add($child)
                }
            }
        }
        return $diffs.ToArray()
    }

    $ljson = $Left  | ConvertTo-Json -Depth 25 -Compress
    $rjson = $Right | ConvertTo-Json -Depth 25 -Compress
    if ($ljson -ne $rjson) {
        $diffs.Add([pscustomobject]@{ path = $Path; kind = 'changed'; global = $Left; tenant = $Right })
    }
    return $diffs.ToArray()
}

function Compare-TenantConfigSkew {
    <#
    .SYNOPSIS
        Compares each scoped config file in config/tenants/<env> against the global
        config/. Returns an array of [pscustomobject]@{ file; path; kind; global;
        tenant }. Files the tenant does not override are skipped. No tenant dir ->
        empty (no skew).
    #>
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$Environment
    )

    $scoped = @('classifiers.json','policies.json','labels.json','tier-assignments.json','rule-overrides.json','tenant-sits.json','settings.json')
    $globalDir = Join-Path $ProjectRoot 'config'
    $tenantDir = Join-Path (Join-Path $globalDir 'tenants') $Environment

    $results = [System.Collections.Generic.List[object]]::new()
    if (-not (Test-Path -LiteralPath $tenantDir -PathType Container)) { return @() }

    foreach ($name in $scoped) {
        $tPath = Join-Path $tenantDir $name
        if (-not (Test-Path -LiteralPath $tPath -PathType Leaf)) { continue }
        $gPath = Join-Path $globalDir $name
        if (-not (Test-Path -LiteralPath $gPath -PathType Leaf)) {
            $results.Add([pscustomobject]@{ file = $name; path = '(file)'; kind = 'added'; global = $null; tenant = '(tenant-only file)' })
            continue
        }
        try {
            $g = Get-Content -Raw -LiteralPath $gPath | ConvertFrom-Json
            $t = Get-Content -Raw -LiteralPath $tPath | ConvertFrom-Json
        } catch {
            $results.Add([pscustomobject]@{ file = $name; path = '(parse error)'; kind = 'changed'; global = '?'; tenant = $_.Exception.Message })
            continue
        }
        foreach ($d in @(Compare-JsonStructure -Left $g -Right $t)) {
            $results.Add([pscustomobject]@{ file = $name; path = $d.path; kind = $d.kind; global = $d.global; tenant = $d.tenant })
        }
    }
    return $results.ToArray()
}

function ConvertTo-ConfigValue {
    <#
    .SYNOPSIS
        Interprets a typed string as a JSON-ish value: integer/double -> number,
        true/false -> bool, null -> $null, {...}/[...] -> parsed JSON, else the
        literal string.
    #>
    param([AllowNull()][string]$Raw)
    if ($null -eq $Raw) { return $null }
    $t = $Raw.Trim()
    if ($t -eq 'null')  { return $null }
    if ($t -eq 'true')  { return $true }
    if ($t -eq 'false') { return $false }
    $intVal = 0
    if ([int]::TryParse($t, [ref]$intVal)) { return $intVal }
    $dblVal = 0.0
    if ([double]::TryParse($t, [ref]$dblVal)) { return $dblVal }
    if ($t.StartsWith('{') -or $t.StartsWith('[')) {
        try { return ($t | ConvertFrom-Json) } catch { return $Raw }
    }
    return $Raw
}

function Set-JsonValue {
    <#
    .SYNOPSIS
        Sets a dotted-path key on a parsed-JSON PSCustomObject (mutates and returns
        it). Creates intermediate objects as needed. Existing siblings are preserved.
    #>
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Path,
        $Value
    )
    $parts = $Path -split '\.'
    $cur = $InputObject
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        $p = $parts[$i]
        if (-not $cur.PSObject.Properties[$p] -or -not ($cur.$p -is [System.Management.Automation.PSCustomObject])) {
            $cur | Add-Member -NotePropertyName $p -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        $cur = $cur.$p
    }
    $cur | Add-Member -NotePropertyName $parts[-1] -NotePropertyValue $Value -Force
    return $InputObject
}

function Set-ConfigValue {
    <#
    .SYNOPSIS
        Reads <ConfigDir>/<File>, sets the dotted Path to Value, writes it back as
        pretty JSON. Creates the file as an empty object if missing.
    #>
    param(
        [Parameter(Mandatory)][string]$ConfigDir,
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)][string]$Path,
        $Value
    )
    $fp = Join-Path $ConfigDir $File
    $obj = if (Test-Path -LiteralPath $fp -PathType Leaf) {
        Get-Content -Raw -LiteralPath $fp | ConvertFrom-Json
    } else { [pscustomobject]@{} }
    $obj = Set-JsonValue -InputObject $obj -Path $Path -Value $Value
    ($obj | ConvertTo-Json -Depth 25) | Set-Content -LiteralPath $fp -Encoding UTF8
    return $fp
}

function Copy-GlobalConfigToTenant {
    <#
    .SYNOPSIS
        Pulls a single global config file into config/tenants/<env> (overwrite).
        The tenant dir must already exist (seed it with New-TenantConfig first).
    #>
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$Environment,
        [Parameter(Mandatory)][string]$File
    )
    $globalDir = Join-Path $ProjectRoot 'config'
    $tenantDir = Join-Path (Join-Path $globalDir 'tenants') $Environment
    if (-not (Test-Path -LiteralPath $tenantDir -PathType Container)) {
        throw "Tenant config not found: $tenantDir. Seed it first with scripts/New-TenantConfig.ps1 -Environment $Environment."
    }
    $src = Join-Path $globalDir $File
    if (-not (Test-Path -LiteralPath $src -PathType Leaf)) {
        throw "Global config file not found: $src"
    }
    Copy-Item -LiteralPath $src -Destination (Join-Path $tenantDir $File) -Force
    return (Join-Path $tenantDir $File)
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
    .PARAMETER ApproveDictionaryReplace
        Allow replacing an existing divergent dictionary's content with ours in the
        over-budget case. Without this, the existing (customer) dictionary is kept and the
        classifier references it as-is. Replacement backs up the existing terms first.
    .PARAMETER ReportDir
        Optional directory to write the per-dictionary decision log (dictionary-decisions.json)
        and any replacement backups.
    .PARAMETER WhatIf
        If true, returns dummy GUIDs without making API calls.
    #>
    param(
        [Parameter(Mandatory)][string]$ManifestUrl,
        [string]$NamePrefix,
        [switch]$ApproveDictionaryReplace,
        [string]$ReportDir,
        [switch]$WhatIf
    )

    Write-Host "  Fetching dictionary manifest..."
    $manifest = Invoke-RestMethod -Uri $ManifestUrl
    Write-Host "  $($manifest.dictionaries.Count) dictionaries in manifest"

    $guidMap = @{}
    $decisions = [System.Collections.Generic.List[object]]::new()

    # Convert a term list to Purview-safe bytes (UTF-16LE+BOM via temp file; direct
    # GetBytes() produces BOM-less bytes truncated to 1 char by the REST-based module).
    $toBytes = {
        param($terms)
        $tf = [System.IO.Path]::GetTempFileName()
        try { $terms | Set-Content -Path $tf -Encoding Unicode; [System.IO.File]::ReadAllBytes($tf) }
        finally { Remove-Item $tf -ErrorAction SilentlyContinue }
    }

    # Inventory (with terms) drives content-aware reuse/merge; empty under WhatIf/offline.
    $inventory = if ($WhatIf) { @() } else { @(Get-DlpDictionaryInventory) }
    $tenantBytes = [long](($inventory | Measure-Object -Property CompressedBytes -Sum).Sum)

    foreach ($dict in $manifest.dictionaries) {
        # Scope the dictionary name to this deployment so prefix-based cleanup can find it.
        # When the manifest name starts with "TestPattern - " (the canonical testpattern.dev prefix),
        # replace that prefix with "<NamePrefix> - " — matching the SIT entity rename in
        # Deploy-Classifiers.ps1. Result: "TestPattern - Noise Exclusion" -> "QGISCF - Noise Exclusion",
        # NOT "QGISCF-TestPattern - Noise Exclusion".
        $rawName = $dict.name
        $name = if ($NamePrefix) {
            if ($rawName.StartsWith('TestPattern - ', [System.StringComparison]::OrdinalIgnoreCase)) {
                "$NamePrefix - $($rawName.Substring('TestPattern - '.Length))"
            } else {
                "$NamePrefix-$rawName"
            }
        } else { $rawName }

        # Legacy name (pre-fix double-prefix format). Used for tenant-side lookup so dictionaries
        # already created under the old scheme are reused by GUID, not duplicated.
        $legacyName = if ($NamePrefix) { "$NamePrefix-$rawName" } else { $rawName }

        if ($WhatIf) {
            Write-Host "  [WHATIF] $name ($($dict.terms.Count) terms)"
            $guidMap[$dict.placeholder] = "00000000-0000-0000-0000-000000000000"
            continue
        }

        $existing = $inventory | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if (-not $existing -and $legacyName -ne $name) {
            $existing = $inventory | Where-Object { $_.Name -eq $legacyName } | Select-Object -First 1
            if ($existing) {
                Write-Host "  LEGACY NAME: '$($existing.Name)' will be reused; on a fresh tenant it would be created as '$name'." -ForegroundColor DarkYellow
            }
        }
        $existingForDecision = if ($existing) { @{ Guid = $existing.Guid; Terms = $existing.Terms } } else { $null }
        $headroom = [long]([long]1048576 - $tenantBytes)
        $decision = Resolve-DictionarySyncDecision -OurTerms $dict.terms -Existing $existingForDecision -TenantHeadroomBytes $headroom

        $guid = $null
        switch ($decision.Action) {
            'Create' {
                # Pre-create budget guard: fail loudly rather than let Purview silently reject.
                $newSize = Get-DictionaryCompressedSize -Terms $dict.terms
                $projected = Test-DictionaryBudget -ProjectedBytes ($tenantBytes + $newSize)
                if (-not $projected.WithinHard) {
                    Write-Warning "  BUDGET: creating '$name' (+$newSize bytes) would exceed the tenant hard cap ($($projected.HardBytes) bytes). Skipping; classifiers using $($dict.placeholder) will be flagged by the upload guard."
                    break
                }
                try {
                    $description = Add-DeploymentProvenanceStamp `
                        -Text $dict.description `
                        -Prefix $(if ($NamePrefix) { $NamePrefix } else { "UNSCOPED" }) `
                        -Component "KeywordDictionary" `
                        -Metadata @{ Placeholder = $dict.placeholder }
                    $result = Invoke-WithRetry -OperationName "New-Dictionary $name" -ScriptBlock {
                        New-DlpKeywordDictionary -Name $name -Description $description -FileData (& $toBytes $dict.terms) -Confirm:$false -ErrorAction Stop
                    } -MaxRetries 2 -BaseDelaySec 30
                    $guid = $result.Identity
                    $tenantBytes += Get-DictionaryCompressedSize -Terms $dict.terms
                    Write-Host "  CREATED: $name ($($dict.terms.Count) terms)" -ForegroundColor Green
                } catch {
                    if ($_.Exception.Message -match 'already exists') {
                        $found = Get-DlpKeywordDictionary -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $name }
                        if ($found) { $guid = $found.Identity; Write-Host "  RECOVERED: $name [$guid]" -ForegroundColor DarkYellow }
                        else { Write-Warning "  Failed: $name - exists but could not retrieve" }
                    } else { Write-Warning "  Failed: $name - $($_.Exception.Message)" }
                }
            }
            'Reuse' {
                $guid = $decision.Guid
                Write-Host "  REUSED: $name ($($decision.Reason)) [$guid]" -ForegroundColor Green
            }
            'Merge' {
                $guid = $decision.Guid
                try {
                    Set-DlpKeywordDictionary -Identity $name -FileData (& $toBytes $decision.MergedTerms) -Confirm:$false -ErrorAction Stop
                    $added = @($decision.MergedTerms).Count - @($existing.Terms).Count
                    $tenantBytes += (Get-DictionaryCompressedSize -Terms $decision.MergedTerms) - $existing.CompressedBytes
                    Write-Host "  MERGED: $name (+$added terms, additive) [$guid]" -ForegroundColor Yellow
                } catch {
                    Write-Warning "  Merge failed for ${name}: $($_.Exception.Message); reusing existing as-is."
                }
            }
            'OverBudgetKeep' {
                $guid = $decision.Guid
                Write-Warning "  OVER-BUDGET DIVERGENT: $name - $($decision.Reason)"
                if ($ApproveDictionaryReplace) {
                    if ($ReportDir -and (Test-Path $ReportDir)) {
                        @($existing.Terms) | Set-Content -Path (Join-Path $ReportDir "dict-backup-$name.txt") -Encoding Unicode
                    }
                    try {
                        Set-DlpKeywordDictionary -Identity $name -FileData (& $toBytes $dict.terms) -Confirm:$false -ErrorAction Stop
                        Write-Host "  REPLACED (approved, existing backed up): $name [$guid]" -ForegroundColor Red
                    } catch { Write-Warning "  Replace failed for ${name}: $($_.Exception.Message); kept existing." }
                } else {
                    Write-Host "  KEPT existing (replace not approved): $name [$guid]" -ForegroundColor DarkYellow
                }
            }
            'OpaqueKeep' {
                $guid = $decision.Guid
                Write-Host "  OPAQUE: $name (cannot compare terms; reusing existing unmodified) [$guid]" -ForegroundColor DarkYellow
            }
        }

        $decisions.Add([pscustomobject]@{ Name = $name; Action = $decision.Action; Coverage = $decision.Coverage; Guid = $guid; Reason = $decision.Reason })
        if ($guid) {
            $guidMap[$dict.placeholder] = $guid
        } else {
            Write-Warning "  No GUID for $name - packages using $($dict.placeholder) will be skipped"
        }
        Start-Sleep 2
    }

    if (-not $WhatIf) {
        $budget = Test-DictionaryBudget -ProjectedBytes $tenantBytes
        $color = if ($budget.WithinWarn) { "Green" } elseif ($budget.WithinHard) { "Yellow" } else { "Red" }
        Write-Host "  Tenant keyword-dictionary total: $tenantBytes bytes (warn $($budget.WarnBytes) / hard $($budget.HardBytes))" -ForegroundColor $color
        if (-not $budget.WithinWarn -and $budget.WithinHard) {
            Write-Warning "  Dictionary total exceeds the conservative 480 KB AD-schema limit; uploads may fail on some tenants."
        } elseif (-not $budget.WithinHard) {
            Write-Warning "  Dictionary total exceeds the 1 MB hard cap; further dictionary uploads will fail."
        }
    }

    if ($ReportDir -and (Test-Path $ReportDir) -and $decisions.Count -gt 0) {
        $decisions | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $ReportDir "dictionary-decisions.json") -Encoding UTF8
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
        Returns the distinct GUID-valued idRef attribute values that are real dictionary
        references in a resolved rule-package XML string. In SIT packages, a dictionary is
        referenced as <Match idRef="GUID"/> (or <ExcludedMatch.../>) inside a <Pattern>.
        Other GUID-valued idRefs are NOT dictionary references:
          - <Resource idRef="GUID"> inside <LocalizedStrings> links a <Resource> to an
            <Entity id="GUID"> (display-name plumbing)
          - <Entity id="GUID"> itself is the entity declaration
        Named idRefs (Pattern_*/Evidence_*/Keyword_*) are also not dictionary refs but they
        do not match the GUID pattern.
    #>
    param([Parameter(Mandatory)][string]$PackageXmlText)
    $guid = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    # Only Match / ExcludedMatch / IdMatch elements carry dictionary refs. Anchoring to the
    # element name keeps Resource/LocalizedStrings entity-display links out of the result.
    $pattern = "<(?:Match|ExcludedMatch|IdMatch)\b[^>]*\bidRef\s*=\s*`"($guid)`""
    $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($m in [regex]::Matches($PackageXmlText, $pattern)) {
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

function ConvertFrom-DlpDictionaryTermProperty {
    <#
    .SYNOPSIS
        Normalises the raw value of a Get-DlpKeywordDictionary term property into a string[].
        Purview returns terms in the 'KeywordDictionary' property as a single delimited
        string (comma and/or newline separated); some module versions return a collection.
        Returns @() for null/empty so callers treat it as opaque rather than mis-parsing.
    #>
    param([object]$Raw)
    if ($null -eq $Raw) { return @() }
    if ($Raw -is [string]) {
        return @($Raw -split "[`r`n,]+" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    if ($Raw -is [System.Collections.IEnumerable]) {
        return @($Raw | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    }
    return @("$Raw".Trim() | Where-Object { $_ })
}

function Get-DlpDictionaryInventory {
    <#
    .SYNOPSIS
        Snapshot of tenant keyword dictionaries: Name, Guid, Terms (or $null if unreadable),
        CompressedBytes. Returns @() if the cmdlet is unavailable / not connected.
    .NOTES
        The property holding the term list varies across ExchangeOnlineManagement versions;
        the probe list below is best-effort. If terms can't be read, the dictionary is
        treated as opaque (Terms=$null) and is therefore never modified or deleted.
        Confirm the property on your tenant with:
          Get-DlpKeywordDictionary | Select-Object -First 1 | Get-Member -MemberType Property
    #>
    if (-not (Get-Command Get-DlpKeywordDictionary -ErrorAction SilentlyContinue)) { return @() }
    try { $dicts = @(Get-DlpKeywordDictionary -ErrorAction Stop) } catch {
        Write-Warning "Could not enumerate keyword dictionaries: $($_.Exception.Message)"; return @()
    }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($d in $dicts) {
        $terms = $null
        foreach ($p in @('KeywordDictionary', 'Keywords', 'Entries', 'Terms')) {
            if ($d.PSObject.Properties[$p] -and $d.$p) {
                $parsed = ConvertFrom-DlpDictionaryTermProperty -Raw $d.$p
                if ($parsed.Count -gt 0) { $terms = $parsed }
                break
            }
        }
        $out.Add([pscustomobject]@{
            Name            = $d.Name
            Guid            = if ($d.Identity) { $d.Identity.ToString().ToLowerInvariant() } else { $null }
            Terms           = $terms
            CompressedBytes = if ($terms) { Get-DictionaryCompressedSize -Terms $terms } else { 0 }
        })
    }
    return $out.ToArray()
}

function Assert-PackageDictionaryReferencesExist {
    <#
    .SYNOPSIS
        Throws if the resolved package content references a dictionary GUID not present in the
        tenant. Prevents uploading a classifier that points at a non-existent dictionary
        (e.g. after a dictionary sync failure) — the silent-failure case.
    #>
    param(
        [Parameter(Mandatory)][string]$PackageName,
        [Parameter(Mandatory)][string]$ResolvedXmlText,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Inventory
    )
    $referenced = Get-DictionaryGuidReferences -PackageXmlText $ResolvedXmlText
    if ($referenced.Count -eq 0) { return }
    $present = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($d in @($Inventory)) { if ($d.Guid) { [void]$present.Add($d.Guid) } }
    $missing = @($referenced | Where-Object { -not $present.Contains($_) })
    if ($missing.Count -gt 0) {
        throw "Package '$PackageName' references dictionary GUID(s) not present in the tenant: $($missing -join ', '). Dictionary sync may have failed. Upload aborted."
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
        [int]$MaxFileSizeBytes = (Get-DeploymentLimits).MaxRulePackageBytes
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
#region Tenant Snapshot
function Write-TenantConfigSnapshot {
    <#
    .SYNOPSIS
        Writes a read-only "old config" snapshot bundle: deployed classifier package XML,
        named live-data sections (DLP, labels, dictionaries, SIT inventory, ... ), and copies
        of the redeployable deploy config. Pure file I/O — the caller fetches the live data.
    .PARAMETER Packages
        Deployed classifier rule packages (objects with SerializedClassificationRuleCollection
        bytes). Each is written to classifiers/<name>_<id>.xml.
    .PARAMETER LiveSections
        Ordered name -> object[] map. Each entry is written to live/<name>.json as a JSON array
        (so labels carry their IRM/encryption fields, rules carry conditions, etc.). Extensible:
        add a section (e.g. protection-templates) without changing this function.
    .PARAMETER FileCopies
        Array of @{ Source = <abs path>; Dest = <relative path under the snapshot> }. Missing
        sources are skipped. Use for the deploy config json, xml/deploy/*.xml, and registries.
    #>
    param(
        [Parameter(Mandatory)][string]$DestinationRoot,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Environment,
        [Parameter(Mandatory)][string]$Timestamp,
        [object[]]$Packages = @(),
        [System.Collections.IDictionary]$LiveSections = @{},
        [object]$TenantInfo,
        [object[]]$FileCopies = @()
    )

    $envSafe = if ([string]::IsNullOrWhiteSpace($Environment)) { 'default' } else { ($Environment -replace '[^a-zA-Z0-9\-_.]', '_') }
    $snapshotDir = Join-Path $DestinationRoot ("{0}-{1}" -f $envSafe, $Timestamp)
    $classDir = Join-Path $snapshotDir 'classifiers'
    $liveDir  = Join-Path $snapshotDir 'live'
    foreach ($d in @($snapshotDir, $classDir, $liveDir)) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }

    # Deployed classifier package XML (full rebuild-grade definition).
    $classifiers = @()
    foreach ($pkg in @($Packages)) {
        if (-not $pkg) { continue }
        $bytes = $pkg.SerializedClassificationRuleCollection
        $name = if ($pkg.Name) { [string]$pkg.Name } elseif ($pkg.Identity) { [string]$pkg.Identity } else { 'package' }
        $identity = if ($pkg.Identity) { [string]$pkg.Identity } else { $name }
        if (-not $bytes) {
            $classifiers += [ordered]@{ name = $name; identity = $identity; file = $null; captured = $false; reason = 'no SerializedClassificationRuleCollection' }
            continue
        }
        $safeName = ($name -replace '[^a-zA-Z0-9\-]', '_')
        $safeId   = ($identity -replace '[^a-zA-Z0-9\-]', '')
        $file = Join-Path $classDir ("{0}_{1}.xml" -f $safeName, $safeId)
        [System.IO.File]::WriteAllBytes($file, [byte[]]$bytes)
        $classifiers += [ordered]@{ name = $name; identity = $identity; file = (Split-Path $file -Leaf); captured = $true; sizeBytes = ([byte[]]$bytes).Length }
    }

    # Named live-data sections -> live/<name>.json (always a JSON array via -AsArray-equivalent).
    $sectionCounts = [ordered]@{}
    foreach ($key in @($LiveSections.Keys)) {
        $items = @($LiveSections[$key])
        $json = if ($items.Count -eq 0) { '[]' } else { $items | ConvertTo-Json -Depth 25 -AsArray }
        Set-Content -LiteralPath (Join-Path $liveDir ("{0}.json" -f $key)) -Value $json -Encoding UTF8
        $sectionCounts[$key] = $items.Count
    }

    # Copy redeployable config / source artifacts.
    $copied = @()
    foreach ($entry in @($FileCopies)) {
        if (-not $entry) { continue }
        $source = [string]$entry.Source
        $dest   = [string]$entry.Dest
        if ([string]::IsNullOrWhiteSpace($source) -or [string]::IsNullOrWhiteSpace($dest)) { continue }
        if (-not (Test-Path -LiteralPath $source)) { continue }
        $destPath = Join-Path $snapshotDir $dest
        $destParent = Split-Path $destPath -Parent
        if ($destParent -and -not (Test-Path -LiteralPath $destParent)) { New-Item -ItemType Directory -Path $destParent -Force | Out-Null }
        Copy-Item -LiteralPath $source -Destination $destPath -Force
        $copied += $dest
    }

    $tid   = if ($TenantInfo) { $TenantInfo.tenantId } else { $null }
    $tname = if ($TenantInfo) { $TenantInfo.name } else { $null }
    $capturedCount = @($classifiers | Where-Object { $_.captured }).Count
    $manifest = [ordered]@{
        generatedUtc = $Timestamp
        environment  = $Environment
        tenant       = [ordered]@{ name = $tname; tenantId = $tid }
        counts       = [ordered]@{
            classifierPackages  = @($Packages).Count
            classifiersCaptured = $capturedCount
            filesCopied         = @($copied).Count
        }
        sections     = $sectionCounts
        classifiers  = @($classifiers)
        configFiles  = @($copied)
        note = 'Read-only snapshot. classifiers/*.xml are deployed RulePack XML; live/*.json are raw live dumps (labels include IRM/encryption fields); config/* are the redeployable deploy config and source packages.'
    }
    $manifestPath = Join-Path $snapshotDir 'snapshot-manifest.json'
    Set-Content -LiteralPath $manifestPath -Value ($manifest | ConvertTo-Json -Depth 25) -Encoding UTF8

    return [pscustomobject]@{
        SnapshotPath    = $snapshotDir
        ManifestPath    = $manifestPath
        ClassifierCount = $capturedCount
        FileCount       = @($copied).Count
        Sections        = $sectionCounts
    }
}
#endregion

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
    'Get-DeploymentObjectName'
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
    'New-DeploymentProvenanceStamp'
    'Add-DeploymentProvenanceStamp'
    'Get-DeploymentProvenanceStamp'
    'Get-DeploymentProvenanceRegistryEntry'
    'Test-DeploymentProvenanceOwnership'
    'Get-DeploymentTenantInfo'
    'New-DeploymentManifest'
    'Add-DeploymentManifestEvent'
    'Complete-DeploymentManifest'
    'Save-DeploymentManifest'
    'Get-DeploymentFileArtifact'
    'Get-DeploymentLimits'
    'Test-DeploymentTenantFingerprint'
    'Convert-DlpSerializedRulePackageToText'
    'Get-DlpRulePackageEntityIds'
    'Get-DeploymentReferenceGraph'
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
    'Get-DlpDictionaryInventory'
    'ConvertFrom-DlpDictionaryTermProperty'
    'Assert-PackageDictionaryReferencesExist'
    'Assert-OrchestrationGate'
    'Get-EffectiveConfigDir'
    'Resolve-ConfigFile'
    'Compare-JsonStructure'
    'Compare-TenantConfigSkew'
    'ConvertTo-ConfigValue'
    'Set-JsonValue'
    'Set-ConfigValue'
    'Copy-GlobalConfigToTenant'
    'Write-TenantConfigSnapshot'
)

