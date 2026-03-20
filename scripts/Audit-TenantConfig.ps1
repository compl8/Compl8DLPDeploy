#==============================================================================
# Audit-TenantConfig.ps1
# Connects to the SCC tenant and dumps a comprehensive audit report covering
# keyword dictionaries, SIT rule packages, auto-labeling policies, and DLP
# policies. Output goes to both the console and a log file.
#
# Usage:
#   .\scripts\Audit-TenantConfig.ps1 -Connect
#   .\scripts\Audit-TenantConfig.ps1 -Connect -UPN admin@tenant.com
#   .\scripts\Audit-TenantConfig.ps1                   # use existing session
#==============================================================================

[CmdletBinding()]
param(
    [switch]$Connect,
    [string]$UPN
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent

# Import shared module
Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

#region Connection
if ($Connect) {
    $connected = Connect-DLPSession -UPN $UPN
    if (-not $connected) { return }
}

# Verify session
if (-not (Assert-DLPSession)) { return }
#endregion

#region Logging setup
$LogDir = Join-Path $ProjectRoot "logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogPath = Join-Path $LogDir "tenant-audit.txt"

# Start transcript to capture all Write-Host and pipeline output
Start-Transcript -Path $LogPath -Force
Write-Host "Audit log: $LogPath" -ForegroundColor Gray
#endregion

$divider = "=" * 78
$subDivider = "-" * 78
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

Write-Host ""
Write-Host $divider
Write-Host "  TENANT CONFIGURATION AUDIT REPORT"
Write-Host "  Generated: $timestamp"
Write-Host $divider

#region 1. Keyword Dictionaries
Write-Host ""
Write-Host $divider
Write-Host "  SECTION 1: KEYWORD DICTIONARIES (TestPattern-*)"
Write-Host $divider

try {
    $allDicts = @(Get-DlpKeywordDictionary -ErrorAction Stop)
    $tpDicts = @($allDicts | Where-Object { $_.Name -like "TestPattern-*" } | Sort-Object Name)

    Write-Host ""
    Write-Host "  Total keyword dictionaries in tenant: $($allDicts.Count)"
    Write-Host "  TestPattern-* dictionaries:           $($tpDicts.Count)"

    if ($tpDicts.Count -eq 0) {
        Write-Host ""
        Write-Host "  (none found)" -ForegroundColor Yellow
    }

    foreach ($dict in $tpDicts) {
        Write-Host ""
        Write-Host "  $subDivider"
        Write-Host "  Dictionary: $($dict.Name)"
        Write-Host "  Identity:   $($dict.Identity)"

        # KeywordDictionary returns terms as a string with comma or newline delimiters
        $terms = @()
        if ($dict.KeywordDictionary) {
            # Terms may be comma-separated or newline-separated depending on API version
            $raw = $dict.KeywordDictionary
            if ($raw -is [string]) {
                $terms = @($raw -split "`r?`n|," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            } elseif ($raw -is [System.Collections.IList]) {
                $terms = @($raw)
            }
        }

        Write-Host "  Term count: $($terms.Count)"

        if ($terms.Count -gt 0) {
            $preview = $terms | Select-Object -First 5
            $idx = 0
            foreach ($t in $preview) {
                $idx++
                Write-Host "    $idx. $t"
            }
            if ($terms.Count -gt 5) {
                Write-Host "    ... ($($terms.Count - 5) more)"
            }
        }
    }
} catch {
    Write-Host "  ERROR retrieving keyword dictionaries: $($_.Exception.Message)" -ForegroundColor Red
}
#endregion

#region 2. SIT Rule Packages
Write-Host ""
Write-Host $divider
Write-Host "  SECTION 2: SIT RULE PACKAGES (custom, non-Microsoft)"
Write-Host $divider

try {
    $allPackages = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)

    # Filter to non-Microsoft packages
    $customPackages = @($allPackages | Where-Object {
        $_.Publisher -ne 'Microsoft Corporation' -and $_.Publisher -ne 'Microsoft'
    })

    Write-Host ""
    Write-Host "  Total rule packages in tenant:   $($allPackages.Count)"
    Write-Host "  Custom (non-Microsoft) packages:  $($customPackages.Count)"

    $totalFlags = 0

    foreach ($pkg in $customPackages) {
        Write-Host ""
        Write-Host "  $subDivider"
        Write-Host "  Package Identity: $($pkg.Identity)"
        Write-Host "  Publisher:        $($pkg.Publisher)"
        if ($pkg.WhenChangedUTC) {
            Write-Host "  Last modified:    $($pkg.WhenChangedUTC)"
        }

        if (-not $pkg.SerializedClassificationRuleCollection) {
            Write-Host "  WARNING: No SerializedClassificationRuleCollection data" -ForegroundColor Yellow
            continue
        }

        try {
            # IMPORTANT: SerializedClassificationRuleCollection is Byte[], decode with Unicode
            $bytes = $pkg.SerializedClassificationRuleCollection
            $xmlContent = [System.Text.Encoding]::Unicode.GetString($bytes)
            $xml = [xml]$xmlContent

            # Extract display name from localized details
            $displayName = $pkg.Identity
            $localized = $xml.RulePackage.RulePack.Details.LocalizedDetails
            if ($localized -and $localized.Name) { $displayName = $localized.Name }
            Write-Host "  Display name:     $displayName"

            # Extract version
            $rulePack = $xml.RulePackage.RulePack
            if ($rulePack -and $rulePack.Version) {
                $v = $rulePack.Version
                Write-Host "  Version:          $($v.major).$($v.minor).$($v.build).$($v.revision)"
            }

            # Parse rules section
            $rules = $xml.RulePackage.ChildNodes | Where-Object { $_.LocalName -eq "Rules" }
            if (-not $rules) {
                Write-Host "  WARNING: No Rules element found in package XML" -ForegroundColor Yellow
                continue
            }

            # Build name map from LocalizedStrings
            $nameMap = @{}
            $localizedStrings = $rules.ChildNodes | Where-Object { $_.LocalName -eq "LocalizedStrings" }
            if ($localizedStrings) {
                foreach ($resource in @($localizedStrings.ChildNodes)) {
                    if ($resource.LocalName -eq "Resource") {
                        $nameNode = $resource.ChildNodes | Where-Object { $_.LocalName -eq "Name" } | Select-Object -First 1
                        if ($nameNode) { $nameMap[$resource.idRef] = $nameNode.InnerText }
                    }
                }
            }

            # List entities
            $entities = @($rules.ChildNodes | Where-Object { $_.LocalName -eq "Entity" })
            Write-Host "  Entity count:     $($entities.Count)"
            Write-Host ""

            $entityIdx = 0
            foreach ($entity in $entities) {
                $entityIdx++
                $entityId = $entity.id
                $entityName = if ($nameMap.ContainsKey($entityId)) { $nameMap[$entityId] } else { "(unknown: $entityId)" }
                $patterns = @($entity.ChildNodes | Where-Object { $_.LocalName -eq "Pattern" })

                Write-Host "    Entity $entityIdx`: $entityName"
                Write-Host "      ID:       $entityId"
                Write-Host "      Patterns: $($patterns.Count)"

                # Flag Cabinet entities
                if ($entityName -like "*Cabinet*") {
                    Write-Host "      *** FLAG: Cabinet entity detected — dumping Pattern XML ***" -ForegroundColor Yellow
                    $totalFlags++
                    foreach ($pattern in $patterns) {
                        Write-Host "      --- Pattern (confidenceLevel=$($pattern.confidenceLevel)) ---" -ForegroundColor Yellow
                        Write-Host $pattern.OuterXml -ForegroundColor DarkYellow
                    }
                }
            }

            # List Keyword elements in the package
            $keywords = @($rules.ChildNodes | Where-Object { $_.LocalName -eq "Keyword" })
            Write-Host ""
            Write-Host "  Keyword elements: $($keywords.Count)"

            foreach ($kw in $keywords) {
                $kwId = $kw.id
                $kwTerms = @($kw.ChildNodes | Where-Object { $_.LocalName -eq "Term" })

                Write-Host ""
                Write-Host "    Keyword: $kwId"
                Write-Host "      Terms: $($kwTerms.Count)"

                # Show first 3 terms
                if ($kwTerms.Count -gt 0) {
                    $preview = $kwTerms | Select-Object -First 3
                    $tIdx = 0
                    foreach ($term in $preview) {
                        $tIdx++
                        Write-Host "        $tIdx. $($term.InnerText)"
                    }
                    if ($kwTerms.Count -gt 3) {
                        Write-Host "        ... ($($kwTerms.Count - 3) more)"
                    }
                }

                # Flag broken dictionaries (0 or 1 terms)
                if ($kwTerms.Count -le 1) {
                    Write-Host "      *** FLAG: Keyword has $($kwTerms.Count) term(s) — potential broken dictionary ***" -ForegroundColor Red
                    $totalFlags++
                }
            }
        } catch {
            Write-Host "  ERROR parsing package XML: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "  Total flags raised: $totalFlags"
} catch {
    Write-Host "  ERROR retrieving SIT rule packages: $($_.Exception.Message)" -ForegroundColor Red
}
#endregion

#region 3. Auto-Labeling Policies
Write-Host ""
Write-Host $divider
Write-Host "  SECTION 3: AUTO-LABELING POLICIES"
Write-Host $divider

try {
    $alPolicies = @(Get-AutoSensitivityLabelPolicy -ErrorAction Stop)

    Write-Host ""
    Write-Host "  Total auto-labeling policies: $($alPolicies.Count)"

    if ($alPolicies.Count -eq 0) {
        Write-Host ""
        Write-Host "  (none found)" -ForegroundColor Yellow
    }

    foreach ($alp in ($alPolicies | Sort-Object Name)) {
        Write-Host ""
        Write-Host "  $subDivider"
        Write-Host "  Policy: $($alp.Name)"
        Write-Host "  Mode:   $($alp.Mode)"

        if ($alp.ApplySensitivityLabel) {
            Write-Host "  Label:  $($alp.ApplySensitivityLabel)"
        }

        # Get rules for this policy
        $alRules = @()
        try {
            $alRules = @(Get-AutoSensitivityLabelRule -Policy $alp.Name -ErrorAction SilentlyContinue)
        } catch { }

        Write-Host "  Rules:  $($alRules.Count)"

        foreach ($alr in $alRules) {
            $workload = if ($alr.Workload) { $alr.Workload } else { "(not set)" }
            Write-Host "    - $($alr.Name)  [workload: $workload]"
        }
    }
} catch {
    Write-Host "  ERROR retrieving auto-labeling policies: $($_.Exception.Message)" -ForegroundColor Red
}
#endregion

#region 4. DLP Policies
Write-Host ""
Write-Host $divider
Write-Host "  SECTION 4: DLP COMPLIANCE POLICIES"
Write-Host $divider

try {
    $dlpPolicies = @(Get-DlpCompliancePolicy -ErrorAction Stop)

    Write-Host ""
    Write-Host "  Total DLP policies: $($dlpPolicies.Count)"

    if ($dlpPolicies.Count -eq 0) {
        Write-Host ""
        Write-Host "  (none found)" -ForegroundColor Yellow
    }

    foreach ($dlp in ($dlpPolicies | Sort-Object Name)) {
        Write-Host ""
        Write-Host "  $subDivider"
        Write-Host "  Policy: $($dlp.Name)"
        Write-Host "  Mode:   $($dlp.Mode)"

        if ($dlp.Comment) {
            $commentPreview = if ($dlp.Comment.Length -gt 120) { $dlp.Comment.Substring(0, 117) + "..." } else { $dlp.Comment }
            Write-Host "  Comment: $commentPreview"
        }

        # Get rules for this policy
        $dlpRules = @()
        try {
            $dlpRules = @(Get-DlpComplianceRule -Policy $dlp.Name -ErrorAction SilentlyContinue)
        } catch { }

        $enabledRules = @($dlpRules | Where-Object { -not $_.Disabled })
        $disabledRules = @($dlpRules | Where-Object { $_.Disabled })

        Write-Host "  Rules:  $($dlpRules.Count) total ($($enabledRules.Count) enabled, $($disabledRules.Count) disabled)"

        foreach ($rule in $dlpRules) {
            $state = if ($rule.Disabled) { " [DISABLED]" } else { "" }
            Write-Host "    - $($rule.Name)$state"
        }
    }
} catch {
    Write-Host "  ERROR retrieving DLP policies: $($_.Exception.Message)" -ForegroundColor Red
}
#endregion

#region Summary
Write-Host ""
Write-Host $divider
Write-Host "  AUDIT COMPLETE"
Write-Host "  $timestamp"
Write-Host $divider
Write-Host ""
#endregion

Stop-Transcript
Write-Host "Audit report written to: $LogPath" -ForegroundColor Green
