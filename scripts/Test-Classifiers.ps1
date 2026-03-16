#==============================================================================
# Test-Classifiers.ps1
# Validates tenant SIT availability against config/classifiers.json
#
# Usage:
#   .\scripts\Test-Classifiers.ps1 -Connect                     # Validate all
#   .\scripts\Test-Classifiers.ps1 -Connect -UPN admin@tenant.onmicrosoft.com
#   .\scripts\Test-Classifiers.ps1 -Connect -Label SENS_Pvc     # Single label
#   .\scripts\Test-Classifiers.ps1 -Connect -ShowAll             # Verbose
#==============================================================================

[CmdletBinding()]
param(
    [switch]$Connect,
    [string]$UPN,
    [string]$Label,
    [switch]$ShowAll
)

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "config"

# Import shared module
Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

#region Connection
if ($Connect) {
    $connected = Connect-DLPSession -UPN $UPN
    if (-not $connected) { return }
}

if (-not (Assert-DLPSession -CommandToTest "Get-DlpSensitiveInformationType")) { return }
#endregion

#region Load Config
Write-Host "`n=== Loading Configuration ===" -ForegroundColor Cyan

$classifiersJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "classifiers.json") -Description "classifier definitions"
$labelsJson      = Import-JsonConfig -FilePath (Join-Path $ConfigPath "labels.json")       -Description "label definitions"

if (-not $classifiersJson) {
    Write-Error "classifiers.json not found or invalid. Aborting."
    return
}

# Build label code -> display name lookup (filter non-group labels)
$labelNames = @{}
if ($labelsJson) {
    foreach ($l in $labelsJson) {
        if ($l.code) {
            $labelNames[$l.code] = if ($l.displayName) { $l.displayName } else { $l.name }
        }
    }
}

# Determine which labels to validate
$labelCodes = @()
if ($Label) {
    if (-not ($classifiersJson.PSObject.Properties.Name -contains $Label)) {
        Write-Error "Label code '$Label' not found in classifiers.json. Available: $($classifiersJson.PSObject.Properties.Name -join ', ')"
        return
    }
    $labelCodes = @($Label)
} else {
    $labelCodes = $classifiersJson.PSObject.Properties.Name
}

$totalConfigSITs = 0
foreach ($code in $labelCodes) {
    $totalConfigSITs += $classifiersJson.$code.Count
}

Write-Host "  Labels to validate: $($labelCodes.Count)" -ForegroundColor Gray
Write-Host "  SITs to validate:   $totalConfigSITs" -ForegroundColor Gray
#endregion

#region Fetch Tenant SITs
Write-Host "`n=== Retrieving Tenant SITs ===" -ForegroundColor Cyan

$tenantSITs = Get-DlpSensitiveInformationType -ErrorAction Stop
Write-Host "  Tenant has $($tenantSITs.Count) SITs available." -ForegroundColor Gray

$tenantLookup = @{}
foreach ($sit in $tenantSITs) {
    $tenantLookup[$sit.Id.ToString().ToLower()] = $sit.Name
}
#endregion

#region Validate
Write-Host "`n=== Validation Results ===" -ForegroundColor Cyan

$totalMatched    = 0
$totalMissing    = 0
$totalMismatched = 0
$missingDetails  = @()
$mismatchDetails = @()

foreach ($code in $labelCodes) {
    $displayName = if ($labelNames.ContainsKey($code)) { $labelNames[$code] } else { $code }
    $sits = $classifiersJson.$code
    $matched    = 0
    $missing    = 0
    $mismatched = 0

    foreach ($sit in $sits) {
        $lookupId = $sit.id.ToLower()

        if (-not $tenantLookup.ContainsKey($lookupId)) {
            $missing++
            $missingDetails += [PSCustomObject]@{
                Label     = $code
                LabelName = $displayName
                SITName   = $sit.name
                GUID      = $sit.id
                Status    = "MISSING"
            }
        } elseif ($tenantLookup[$lookupId] -ne $sit.name) {
            $mismatched++
            $mismatchDetails += [PSCustomObject]@{
                Label      = $code
                LabelName  = $displayName
                ConfigName = $sit.name
                TenantName = $tenantLookup[$lookupId]
                GUID       = $sit.id
                Status     = "NAME MISMATCH"
            }
        } else {
            $matched++
        }
    }

    $totalMatched    += $matched
    $totalMissing    += $missing
    $totalMismatched += $mismatched

    $statusColor = if ($missing -gt 0) { "Red" } elseif ($mismatched -gt 0) { "Yellow" } else { "Green" }
    $statusIcon  = if ($missing -gt 0) { "FAIL" } elseif ($mismatched -gt 0) { "WARN" } else { "PASS" }

    $line = "  [{0}] {1,-10} {2,-35} {3,3} SITs: {4} matched" -f $statusIcon, $code, $displayName, $sits.Count, $matched
    if ($mismatched -gt 0) { $line += ", $mismatched name mismatch(es)" }
    if ($missing -gt 0)    { $line += ", $missing MISSING" }
    Write-Host $line -ForegroundColor $statusColor

    if ($ShowAll) {
        foreach ($sit in $sits) {
            $lookupId = $sit.id.ToLower()
            if (-not $tenantLookup.ContainsKey($lookupId)) {
                Write-Host "      MISSING  $($sit.name)  ($($sit.id))" -ForegroundColor Red
            } elseif ($tenantLookup[$lookupId] -ne $sit.name) {
                Write-Host "      RENAME   $($sit.name) -> $($tenantLookup[$lookupId])  ($($sit.id))" -ForegroundColor Yellow
            } else {
                Write-Host "      OK       $($sit.name)" -ForegroundColor DarkGray
            }
        }
    }
}
#endregion

#region Details
if ($missingDetails.Count -gt 0) {
    Write-Host "`n=== Missing SITs (not in tenant) ===" -ForegroundColor Red
    $missingDetails | Format-Table Label, SITName, GUID -AutoSize
    Write-Host "  These SITs are referenced in classifiers.json but do not exist in the tenant." -ForegroundColor Red
    Write-Host "  Action: Deploy SIT packages via Deploy-Classifiers.ps1 or remove from classifiers.json." -ForegroundColor Yellow
}

if ($mismatchDetails.Count -gt 0) {
    Write-Host "`n=== Name Mismatches (GUID matches, name differs) ===" -ForegroundColor Yellow
    $mismatchDetails | Format-Table Label, ConfigName, TenantName, GUID -AutoSize
    Write-Host "  Names do not affect DLP rule matching (GUID is authoritative)." -ForegroundColor Yellow
}
#endregion

#region Summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "  Total SITs checked:    $totalConfigSITs" -ForegroundColor Gray
Write-Host "  Matched:               $totalMatched" -ForegroundColor Green
Write-Host "  Name mismatches:       $totalMismatched" -ForegroundColor $(if ($totalMismatched -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Missing from tenant:   $totalMissing" -ForegroundColor $(if ($totalMissing -gt 0) { "Red" } else { "Green" })

$overallPass = $totalMissing -eq 0
if ($overallPass) {
    Write-Host "`n  RESULT: PASS — All SITs available in tenant. Safe to deploy." -ForegroundColor Green
} else {
    Write-Host "`n  RESULT: FAIL — $totalMissing SIT(s) missing. Resolve before deploying." -ForegroundColor Red
}

# Count trainable classifiers (MLModel) skipped during SIT validation
$tcSkipped = 0
foreach ($code in $labelCodes) {
    foreach ($sit in $classifiersJson.$code) {
        if ($sit.classifierType -eq 'MLModel') { $tcSkipped++ }
    }
}
if ($tcSkipped -gt 0) {
    Write-Host "`n  Note: Trainable classifiers are not validated by this script. Use Get-TrainableClassifiers.ps1 to verify TC availability. ($tcSkipped TCs skipped)" -ForegroundColor DarkYellow
}

exit $(if ($overallPass) { 0 } else { 1 })
#endregion
