#==============================================================================
# Test-MinimalKeywords.ps1
# Research experiment: Does Purview accept XML packages with minimal keyword
# definitions (1 term per group), and can they be expanded later via
# Set-DlpSensitiveInformationTypeRulePackage?
#
# Hypothesis: Purview validates XML structure on upload. If 1-term keyword
# groups pass validation, we can create SITs with stub keywords then update
# with full keywords in a second pass. This enables a two-phase deployment
# strategy that could bypass the 150KB package size limit by splitting
# keyword data across initial create + subsequent update.
#
# Usage:
#   .\scripts\Test-MinimalKeywords.ps1
#==============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent

$MinimalXml = Join-Path $ProjectRoot "xml\deploy\minimal-test.xml"
$FullXml    = Join-Path $ProjectRoot "xml\deploy\minimal-test-full.xml"
$UPN        = $env:DLP_DEPLOY_UPN  # Set via environment variable or edit this line

# The RulePack id from our test XMLs
$TestRulePackId = "86a6057b-9dfd-47ca-abef-d13cd3258764"

# Expected entity names for verification
$ExpectedEntities = @(
    "TestPattern - AWS Access Key",
    "TestPattern - General Password",
    "TestPattern - Slack Token"
)

#region Helpers
function Write-Phase {
    param([string]$Phase, [string]$Message)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  PHASE $Phase : $Message" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

function Write-Result {
    param([string]$Label, [string]$Value, [string]$Color = "White")
    Write-Host "  $($Label): " -NoNewline -ForegroundColor Gray
    Write-Host $Value -ForegroundColor $Color
}

function Get-PackageFromTenant {
    <#
    .SYNOPSIS
        Finds our test package in the tenant by RulePack ID.
        Returns the package object or $null.
    #>
    $allPkgs = Get-DlpSensitiveInformationTypeRulePackage
    foreach ($pkg in $allPkgs) {
        if (-not $pkg.SerializedClassificationRuleCollection) { continue }
        try {
            $xmlContent = $pkg.SerializedClassificationRuleCollection
            $xmlDoc = [xml]$xmlContent
            $rpId = $xmlDoc.RulePackage.RulePack.id
            if ($rpId -eq $TestRulePackId) {
                return $pkg
            }
        } catch {
            # Not parseable, skip
        }
    }
    return $null
}

function Get-PackageEntityCount {
    param([object]$Package)
    try {
        $xmlDoc = [xml]$Package.SerializedClassificationRuleCollection
        $ns = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable)
        $ns.AddNamespace("mce", "http://schemas.microsoft.com/office/2011/mce")
        $entities = $xmlDoc.SelectNodes("//mce:Entity", $ns)
        return $entities.Count
    } catch {
        return -1
    }
}

function Get-PackageTermCount {
    param([object]$Package)
    try {
        $xmlDoc = [xml]$Package.SerializedClassificationRuleCollection
        $ns = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable)
        $ns.AddNamespace("mce", "http://schemas.microsoft.com/office/2011/mce")
        $terms = $xmlDoc.SelectNodes("//mce:Term", $ns)
        return $terms.Count
    } catch {
        return -1
    }
}

function Get-PackageVersion {
    param([object]$Package)
    try {
        $xmlDoc = [xml]$Package.SerializedClassificationRuleCollection
        $v = $xmlDoc.RulePackage.RulePack.Version
        return "$($v.major).$($v.minor).$($v.build).$($v.revision)"
    } catch {
        return "(unknown)"
    }
}

function Upload-TestPackage {
    param(
        [string]$FilePath,
        [string]$Label,
        [bool]$IsUpdate = $false
    )

    Write-Host "  Uploading $Label..." -ForegroundColor Yellow
    Write-Host "    File: $FilePath" -ForegroundColor Gray
    Write-Host "    Size: $((Get-Item $FilePath).Length) bytes" -ForegroundColor Gray

    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)

    try {
        if ($IsUpdate) {
            Set-DlpSensitiveInformationTypeRulePackage -FileData $fileBytes -Confirm:$false
            Write-Host "    Set- completed successfully." -ForegroundColor Green
        } else {
            New-DlpSensitiveInformationTypeRulePackage -FileData $fileBytes
            Write-Host "    New- completed successfully." -ForegroundColor Green
        }
        return $true
    } catch {
        Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.InnerException) {
            Write-Host "    Inner: $($_.Exception.InnerException.Message)" -ForegroundColor Red
        }
        return $false
    }
}
#endregion

#region Main
$results = @{}
$startTime = Get-Date

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Magenta
Write-Host "  MINIMAL KEYWORD EXPERIMENT" -ForegroundColor Magenta
Write-Host "  Testing two-phase SIT deployment with stub keywords" -ForegroundColor Magenta
Write-Host "==========================================================" -ForegroundColor Magenta
Write-Host ""

# Validate files exist
if (-not (Test-Path $MinimalXml)) { Write-Error "Minimal XML not found: $MinimalXml" }
if (-not (Test-Path $FullXml))    { Write-Error "Full XML not found: $FullXml" }
Write-Result "Minimal XML" "$((Get-Item $MinimalXml).Length) bytes"
Write-Result "Full XML"    "$((Get-Item $FullXml).Length) bytes"

# ---- Connect ----
Write-Phase "0" "Connect to Security & Compliance"
Write-Host "  Connecting as $UPN ..." -ForegroundColor Yellow
Write-Host "  NOTE: A browser window should open for MFA. Please complete sign-in." -ForegroundColor Magenta
try {
    Connect-IPPSSession -UserPrincipalName $UPN -ShowBanner:$false -WarningAction SilentlyContinue -ErrorAction Stop
    Write-Host "  Connected." -ForegroundColor Green
} catch {
    Write-Host "  Connection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Aborting experiment." -ForegroundColor Red
    exit 1
}

# ---- Phase 0.5: Check for existing package ----
Write-Phase "0.5" "Check for existing test package"
$existing = Get-PackageFromTenant
if ($existing) {
    Write-Host "  Found existing package with RulePack ID $TestRulePackId" -ForegroundColor Yellow
    Write-Result "Identity" $existing.Identity
    Write-Result "Version" (Get-PackageVersion $existing)
    Write-Result "Entities" (Get-PackageEntityCount $existing)
    Write-Result "Terms" (Get-PackageTermCount $existing)
    Write-Host ""
    Write-Host "  Removing existing package first..." -ForegroundColor Yellow
    try {
        Remove-DlpSensitiveInformationTypeRulePackage -Identity $existing.Identity -Confirm:$false
        Write-Host "  Removed." -ForegroundColor Green
        # Brief pause for backend propagation
        Start-Sleep -Seconds 5
    } catch {
        Write-Host "  WARNING: Could not remove existing package: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Proceeding anyway - upload may act as update." -ForegroundColor Yellow
    }
} else {
    Write-Host "  No existing test package found. Clean slate." -ForegroundColor Green
}

# ---- Phase 1: Upload MINIMAL (stub) package ----
Write-Phase "1" "Upload MINIMAL package (1 term per keyword group)"
$minimalOk = Upload-TestPackage -FilePath $MinimalXml -Label "minimal-test (stub keywords)" -IsUpdate $false
$results["Phase1_MinimalUpload"] = $minimalOk

if ($minimalOk) {
    Start-Sleep -Seconds 3
    $pkg1 = Get-PackageFromTenant
    if ($pkg1) {
        Write-Host ""
        Write-Host "  VERIFICATION:" -ForegroundColor Green
        Write-Result "Identity" $pkg1.Identity "Green"
        Write-Result "Version" (Get-PackageVersion $pkg1) "Green"
        Write-Result "Entities" (Get-PackageEntityCount $pkg1) "Green"
        Write-Result "Terms" (Get-PackageTermCount $pkg1) "Green"
        $results["Phase1_EntityCount"] = Get-PackageEntityCount $pkg1
        $results["Phase1_TermCount"]   = Get-PackageTermCount $pkg1
        $results["Phase1_Identity"]    = $pkg1.Identity
    } else {
        Write-Host "  WARNING: Package uploaded but not found in tenant!" -ForegroundColor Red
        $results["Phase1_Verified"] = $false
    }
} else {
    Write-Host ""
    Write-Host "  MINIMAL UPLOAD FAILED - Purview rejected 1-term keyword groups." -ForegroundColor Red
    Write-Host "  This disproves the hypothesis." -ForegroundColor Red
}

# ---- Phase 2: Update with FULL keywords ----
if ($minimalOk) {
    Write-Phase "2" "Update with FULL package (all keyword terms)"

    # Need to bump version for update - read the full XML, bump version, rewrite
    # Actually, Set- replaces by RulePack ID, same version should work
    $fullOk = Upload-TestPackage -FilePath $FullXml -Label "minimal-test (full keywords)" -IsUpdate $true
    $results["Phase2_FullUpdate"] = $fullOk

    if ($fullOk) {
        Start-Sleep -Seconds 3
        $pkg2 = Get-PackageFromTenant
        if ($pkg2) {
            Write-Host ""
            Write-Host "  VERIFICATION:" -ForegroundColor Green
            Write-Result "Identity" $pkg2.Identity "Green"
            Write-Result "Version" (Get-PackageVersion $pkg2) "Green"
            Write-Result "Entities" (Get-PackageEntityCount $pkg2) "Green"
            Write-Result "Terms" (Get-PackageTermCount $pkg2) "Green"
            $results["Phase2_EntityCount"] = Get-PackageEntityCount $pkg2
            $results["Phase2_TermCount"]   = Get-PackageTermCount $pkg2

            # Compare term counts
            if ($results["Phase2_TermCount"] -gt $results["Phase1_TermCount"]) {
                Write-Host ""
                Write-Host "  TWO-PHASE DEPLOYMENT WORKS!" -ForegroundColor Green
                Write-Host "  Terms expanded from $($results['Phase1_TermCount']) -> $($results['Phase2_TermCount'])" -ForegroundColor Green
                $results["TwoPhaseWorks"] = $true
            } else {
                Write-Host ""
                Write-Host "  WARNING: Term count did not increase after update." -ForegroundColor Red
                $results["TwoPhaseWorks"] = $false
            }
        } else {
            Write-Host "  Package not found after update!" -ForegroundColor Red
        }
    } else {
        Write-Host ""
        Write-Host "  FULL UPDATE FAILED." -ForegroundColor Red
        Write-Host "  Set-DlpSensitiveInformationTypeRulePackage rejected the update." -ForegroundColor Red
    }
}

# ---- Phase 3: Cleanup ----
Write-Phase "3" "Cleanup - remove test package"
$pkgCleanup = Get-PackageFromTenant
if ($pkgCleanup) {
    try {
        Remove-DlpSensitiveInformationTypeRulePackage -Identity $pkgCleanup.Identity -Confirm:$false
        Write-Host "  Test package removed." -ForegroundColor Green
        $results["Cleanup"] = $true
    } catch {
        Write-Host "  WARNING: Cleanup failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Manual cleanup may be needed. RulePack ID: $TestRulePackId" -ForegroundColor Yellow
        $results["Cleanup"] = $false
    }
} else {
    Write-Host "  No package to clean up." -ForegroundColor Gray
    $results["Cleanup"] = $true
}

# ---- Disconnect ----
Write-Phase "4" "Disconnect"
try {
    Disconnect-ExchangeOnline -Confirm:$false
    Write-Host "  Disconnected." -ForegroundColor Green
} catch {
    Write-Host "  Disconnect warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---- Summary ----
$elapsed = (Get-Date) - $startTime
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Magenta
Write-Host "  EXPERIMENT RESULTS" -ForegroundColor Magenta
Write-Host ("=" * 70) -ForegroundColor Magenta
Write-Host ""

Write-Result "Duration" "$([math]::Round($elapsed.TotalSeconds))s"
Write-Result "Phase 1 - Minimal upload (1 term/group)" $(if ($results["Phase1_MinimalUpload"]) { "PASS" } else { "FAIL" }) $(if ($results["Phase1_MinimalUpload"]) { "Green" } else { "Red" })

if ($results["Phase1_MinimalUpload"]) {
    Write-Result "  Entities created" "$($results['Phase1_EntityCount'])"
    Write-Result "  Terms in tenant" "$($results['Phase1_TermCount'])"
}

if ($results.ContainsKey("Phase2_FullUpdate")) {
    Write-Result "Phase 2 - Full update (all terms)" $(if ($results["Phase2_FullUpdate"]) { "PASS" } else { "FAIL" }) $(if ($results["Phase2_FullUpdate"]) { "Green" } else { "Red" })
    if ($results["Phase2_FullUpdate"]) {
        Write-Result "  Terms after update" "$($results['Phase2_TermCount'])"
    }
}

if ($results.ContainsKey("TwoPhaseWorks")) {
    Write-Host ""
    if ($results["TwoPhaseWorks"]) {
        Write-Host "  CONCLUSION: Two-phase deployment is VIABLE." -ForegroundColor Green
        Write-Host "  Purview accepts minimal keyword stubs and allows expansion via Set-." -ForegroundColor Green
        Write-Host "  This could enable deploying oversized packages in two passes:" -ForegroundColor Green
        Write-Host "    1. New- with skeleton keywords (small payload)" -ForegroundColor Green
        Write-Host "    2. Set- with full keywords (can be larger)" -ForegroundColor Green
    } else {
        Write-Host "  CONCLUSION: Two-phase deployment does NOT work as hypothesized." -ForegroundColor Red
    }
}

if (-not $results["Phase1_MinimalUpload"]) {
    Write-Host ""
    Write-Host "  CONCLUSION: Purview rejects packages with 1-term keyword groups." -ForegroundColor Red
    Write-Host "  Minimum keyword term count may be > 1." -ForegroundColor Red
}

Write-Result "Cleanup" $(if ($results["Cleanup"]) { "OK" } else { "MANUAL NEEDED" }) $(if ($results["Cleanup"]) { "Green" } else { "Red" })
Write-Host ""
#endregion
