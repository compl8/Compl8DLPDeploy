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
    }
}
#endregion

#region Connection
function Connect-DLPSession {
    <#
    .SYNOPSIS
        Connects to Security & Compliance Center (IPPS session).
    .PARAMETER UPN
        User principal name for authentication.
    #>
    param([string]$UPN)

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Error "ExchangeOnlineManagement module not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
        return $false
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    $connectParams = @{}
    if ($UPN) { $connectParams["UserPrincipalName"] = $UPN }
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
        Disconnects the Exchange Online / IPPS session.
    #>
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
        [Parameter(Mandatory)][string]$GetCommand,
        [Parameter(Mandatory)][string]$RemoveCommand,
        [string]$OperationName = "object",
        [int]$MaxRetries = 3,
        [int]$BaseDelaySec = 300,
        [switch]$WhatIf
    )

    # Step 1: Check if the object exists and inspect its state
    $obj = $null
    try {
        $obj = & $GetCommand -Identity $Identity -ErrorAction Stop
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "couldn't be found" -or $msg -match "not found" -or $msg -match "does not exist") {
            Write-Host "    (not found, skipping): $Identity" -ForegroundColor DarkGray
            return "not-found"
        }
        # If the Get itself failed for another reason, log and skip
        Write-Warning "  Could not query $OperationName ${Identity}: $msg"
        return "failed"
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
        Write-Host "    (pending deletion, skipping): $Identity" -ForegroundColor DarkGray
        return "pending"
    }

    # Step 3: Delete
    if ($WhatIf) {
        Write-Host "    WhatIf: Would remove $OperationName $Identity" -ForegroundColor Yellow
        return "deleted"
    }

    try {
        Invoke-WithRetry -OperationName "Remove $OperationName $Identity" -ScriptBlock {
            & $RemoveCommand -Identity $Identity -Confirm:$false -ErrorAction Stop
        } -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec
        Write-Host "    Removed: $Identity" -ForegroundColor Green
        return "deleted"
    } catch {
        Write-Warning "  Could not remove $OperationName ${Identity}: $($_.Exception.Message)"
        return "failed"
    }
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
                Write-Warning "Purview delete cooldown on: $OperationName"
                Write-Warning "  Error: $msg"
                Write-Warning "  Retry $attempt of $MaxRetries - waiting ${waitMin} min - resuming at $resumeTime"
                Write-Host ""
                Start-Sleep -Seconds $delaySec
            } elseif ($isThrottle -and $attempt -le $MaxRetries) {
                $delaySec = $BaseDelaySec * $attempt
                $delayMin = [math]::Round($delaySec / 60, 0)
                $resumeTime = (Get-Date).AddSeconds($delaySec).ToString("HH:mm:ss")
                Write-Host ""
                Write-Warning "Purview API throttle detected on: $OperationName"
                Write-Warning "  Error: $msg"
                Write-Warning "  Retry $attempt of $MaxRetries - waiting ${delayMin} min (${delaySec}s) - resuming at $resumeTime"
                Write-Host ""
                Start-Sleep -Seconds $delaySec
            } elseif ($isTransient -and $attempt -le 2) {
                $delaySec = 30 * $attempt
                Write-Host ""
                Write-Warning "Transient server error on: $OperationName"
                Write-Warning "  Error: $msg"
                Write-Warning "  Retry $attempt of 2 - waiting ${delaySec}s"
                Write-Host ""
                Start-Sleep -Seconds $delaySec
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
    Start-Transcript -Path $transcriptPath -Append
    Write-Host "Logging to: $transcriptPath" -ForegroundColor Gray
    return $transcriptPath
}
#endregion

#region Classifier Helpers
function Split-ClassifierChunks {
    <#
    .SYNOPSIS
        Splits a classifier list into even chunks of at most $MaxPerRule entries.
        When splitting is needed, divides evenly (not 125 + remainder) to balance rule sizes.
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
    $chunkSize = [math]::Ceiling($total / $chunkCount)
    $chunks = @()
    for ($i = 0; $i -lt $total; $i += $chunkSize) {
        $end = [math]::Min($i + $chunkSize, $total)
        $chunks += , @($ClassifierList[$i..($end - 1)])
    }
    return $chunks
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
    .PARAMETER WhatIf
        If true, returns dummy GUIDs without making API calls.
    #>
    param(
        [Parameter(Mandatory)][string]$ManifestUrl,
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
            Write-Host "  [WHATIF] $($dict.name) ($($dict.terms.Count) terms)"
            $guidMap[$dict.placeholder] = "00000000-0000-0000-0000-000000000000"
            continue
        }

        $guid = $null
        if ($existingDicts.ContainsKey($dict.name)) {
            # Update existing dictionary with correct content
            $guid = $existingDicts[$dict.name]
            try {
                Set-DlpKeywordDictionary -Identity $dict.name -FileData $bytes -Confirm:$false -ErrorAction Stop
                Write-Host "  Updated: $($dict.name) ($($dict.terms.Count) terms) [$guid]"
            } catch {
                Write-Warning "  Failed to update $($dict.name): $($_.Exception.Message)"
                Write-Host "  Exists: $($dict.name) [$guid]"
            }
        } else {
            try {
                $result = Invoke-WithRetry -OperationName "New-Dictionary $($dict.name)" -ScriptBlock {
                    New-DlpKeywordDictionary -Name $dict.name -Description $dict.description -FileData $bytes -Confirm:$false -ErrorAction Stop
                } -MaxRetries 2 -BaseDelaySec 30
                $guid = $result.Identity
                Write-Host "  Created: $($dict.name) ($($dict.terms.Count) terms)"
            } catch {
                if ($_.Exception.Message -match 'already exists') {
                    # Race condition: created between pre-fetch and now
                    $found = Get-DlpKeywordDictionary -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $dict.name }
                    if ($found) {
                        $guid = $found.Identity
                        Write-Host "  Recovered: $($dict.name) [$guid]"
                    } else {
                        Write-Warning "  Failed: $($dict.name) - exists but could not retrieve"
                    }
                } else {
                    Write-Warning "  Failed: $($dict.name) - $($_.Exception.Message)"
                }
            }
        }

        if ($guid) {
            $guidMap[$dict.placeholder] = $guid
        } else {
            Write-Warning "  No GUID for $($dict.name) - packages using $($dict.placeholder) will be skipped"
        }
        if (-not $WhatIf) { Start-Sleep 2 }
    }

    Write-Host "  $($guidMap.Count) / $($manifest.dictionaries.Count) dictionary GUIDs resolved"
    return $guidMap
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
    'Import-JsonConfig'
    'Merge-GlobalConfig'
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
    'Remove-PurviewObject'
    'Invoke-WithRetry'
    'Start-DeploymentLog'
    'Test-SITRulePackageXml'
    'Split-ClassifierChunks'
    'Sync-DlpKeywordDictionaries'
)
