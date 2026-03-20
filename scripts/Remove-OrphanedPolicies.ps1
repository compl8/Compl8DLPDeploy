#==============================================================================
# Remove-OrphanedPolicies.ps1
# Targeted removal of orphaned auto-labeling policies and ghost DLP rules.
# Uses the shared DLP-Deploy.psm1 module for retry logic and session management.
#
# Usage:
#   .\scripts\Remove-OrphanedPolicies.ps1 -AutoLabelPolicies -Connect         # Remove old AL policies
#   .\scripts\Remove-OrphanedPolicies.ps1 -GhostDlpRules -DlpPolicy P01-ECH-QGISCF-EXT-ADT -Connect
#   .\scripts\Remove-OrphanedPolicies.ps1 -AutoLabelPolicies -GhostDlpRules -DlpPolicy P01-ECH-QGISCF-EXT-ADT -Connect
#   .\scripts\Remove-OrphanedPolicies.ps1 -AutoLabelPolicies -WhatIf -Connect # Dry run
#==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$AutoLabelPolicies,
    [switch]$GhostDlpRules,
    [string]$DlpPolicy,
    [switch]$Connect,
    [string]$UPN
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent

# Import shared module
Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

$Defaults = Get-ModuleDefaults
$interCallDelaySec = $Defaults.interCallDelaySec
$maxRetries        = $Defaults.maxRetries
$baseDelaySec      = $Defaults.baseDelaySec

if (-not $AutoLabelPolicies -and -not $GhostDlpRules) {
    Write-Error "Specify at least one of -AutoLabelPolicies or -GhostDlpRules."
    return
}

if ($GhostDlpRules -and -not $DlpPolicy) {
    Write-Error "-GhostDlpRules requires -DlpPolicy (e.g. 'P01-ECH-QGISCF-EXT-ADT')."
    return
}

#region Connection
if ($Connect) {
    $connected = Connect-DLPSession -UPN $UPN
    if (-not $connected) { return }
}
if (-not (Assert-DLPSession)) { return }
#endregion

$divider = "=" * 70

#region 1. Remove orphaned auto-labeling policies
if ($AutoLabelPolicies) {
    Write-Host ""
    Write-Host $divider
    Write-Host "  REMOVE ORPHANED AUTO-LABELING POLICIES"
    Write-Host "  (Old Deploy-AutoLabeling.ps1 set, superseded by converter)"
    Write-Host $divider

    # These are the old Deploy-AutoLabeling.ps1 policies that overlap in numbering
    # but NOT in name with the converter set. AL01-OFFI and AL02-SENS_Pvca are
    # shared (converter reused them) and must NOT be deleted.
    #
    # Old set numbering (labels with classifiers, sequential):
    #   AL01-OFFI          ← SHARED with converter, skip
    #   AL02-SENS_Pvca     ← SHARED with converter, skip
    #   AL03-SENS_Pvcb     ← converter merged Pvcb into AL02, this is orphaned
    #   AL04 through AL12  ← all orphaned (converter uses different numbering)

    $ConfigPath = Join-Path $ProjectRoot "config"
    $settingsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
    $Config = Merge-GlobalConfig -Defaults $Defaults -GlobalJson $settingsJson

    $labelsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "labels.json") -Description "label definitions"
    $classifiersJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "classifiers.json") -Description "classifier definitions"

    if (-not $labelsJson -or -not $classifiersJson) {
        Write-Error "Cannot load labels.json or classifiers.json."
        return
    }

    # Build classifier lookup
    $Classifiers = @{}
    if ($classifiersJson -is [System.Collections.IDictionary]) {
        foreach ($key in $classifiersJson.Keys) { $Classifiers[$key] = $classifiersJson[$key] }
    } else {
        foreach ($prop in $classifiersJson.PSObject.Properties) { $Classifiers[$prop.Name] = $prop.Value }
    }

    # Filter to non-group labels with classifiers (same logic as Deploy-AutoLabeling.ps1)
    $Labels = @($labelsJson | Where-Object { $_.code -and $Classifiers.ContainsKey($_.code) })

    # Build the full list of old policy names, then skip AL01 and AL02
    $policyNum = 0
    $policiesToRemove = @()
    foreach ($label in $Labels) {
        $policyNum++
        $policyName = "AL{0:D2}-{1}-{2}-{3}" -f $policyNum, $label.code, $Config.namingPrefix, $Config.namingSuffix
        if ($policyNum -le 2) {
            Write-Host "  SKIP (shared with converter): $policyName" -ForegroundColor DarkGray
            continue
        }
        $policiesToRemove += $policyName
    }

    Write-Host ""
    Write-Host "  Policies targeted for removal ($($policiesToRemove.Count)):" -ForegroundColor Yellow
    foreach ($p in $policiesToRemove) {
        Write-Host "    $p" -ForegroundColor Yellow
    }
    Write-Host ""

    $removedPolicies = 0
    $removedRules = 0

    foreach ($policyName in $policiesToRemove) {
        $existingPolicy = $null
        try { $existingPolicy = Get-AutoSensitivityLabelPolicy -Identity $policyName -ErrorAction Stop } catch { }

        if (-not $existingPolicy) {
            Write-Host "  Not found (already gone): $policyName" -ForegroundColor DarkGray
            continue
        }

        # Remove rules first
        $rules = @()
        try { $rules = @(Get-AutoSensitivityLabelRule -Policy $policyName -ErrorAction Stop) } catch { }

        $ruleIndex = 0
        foreach ($rule in $rules) {
            if ($PSCmdlet.ShouldProcess($rule.Name, "Remove-AutoSensitivityLabelRule")) {
                if ($ruleIndex -gt 0 -and -not $WhatIfPreference) { Start-Sleep -Seconds $interCallDelaySec }
                try {
                    Invoke-WithRetry -OperationName "Remove-ALRule $($rule.Name)" -ScriptBlock {
                        Remove-AutoSensitivityLabelRule -Identity $rule.Name -Confirm:$false -ErrorAction Stop
                    } -MaxRetries $maxRetries -BaseDelaySec $baseDelaySec
                    Write-Host "    Removed rule: $($rule.Name)" -ForegroundColor Yellow
                    $removedRules++
                } catch {
                    Write-Warning "    Failed to remove rule $($rule.Name): $($_.Exception.Message)"
                }
                $ruleIndex++
            }
        }

        # Remove policy
        if ($rules.Count -gt 0 -and -not $WhatIfPreference) { Start-Sleep -Seconds $interCallDelaySec }
        if ($PSCmdlet.ShouldProcess($policyName, "Remove-AutoSensitivityLabelPolicy")) {
            try {
                Invoke-WithRetry -OperationName "Remove-ALPolicy $policyName" -ScriptBlock {
                    Remove-AutoSensitivityLabelPolicy -Identity $policyName -Confirm:$false -ErrorAction Stop
                } -MaxRetries $maxRetries -BaseDelaySec $baseDelaySec
                Write-Host "  Removed policy: $policyName" -ForegroundColor Green
                $removedPolicies++
            } catch {
                Write-Warning "  Failed to remove policy ${policyName}: $($_.Exception.Message)"
            }
        }
    }

    Write-Host ""
    Write-Host "  Auto-labeling cleanup: $removedPolicies policies, $removedRules rules removed" -ForegroundColor Cyan
}
#endregion

#region 2. Remove ghost DLP rules
if ($GhostDlpRules) {
    Write-Host ""
    Write-Host $divider
    Write-Host "  REMOVE GHOST DLP RULES FROM: $DlpPolicy"
    Write-Host "  (Rules with no SIT conditions, from broken earlier deploys)"
    Write-Host $divider

    # Verify policy exists
    $policy = $null
    try { $policy = Get-DlpCompliancePolicy -Identity $DlpPolicy -ErrorAction Stop } catch { }
    if (-not $policy) {
        Write-Error "DLP policy not found: $DlpPolicy"
        return
    }

    # Get all rules
    $allRules = @()
    try { $allRules = @(Get-DlpComplianceRule -Policy $DlpPolicy -ErrorAction Stop) } catch {
        Write-Error "Failed to list rules for ${DlpPolicy}: $($_.Exception.Message)"
        return
    }

    # Identify ghost rules: no ContentContainsSensitiveInformation condition
    $ghostRules = @()
    $validRules = @()
    foreach ($rule in $allRules) {
        $hasSITs = $false
        if ($rule.ContentContainsSensitiveInformation -and $rule.ContentContainsSensitiveInformation.Count -gt 0) {
            $hasSITs = $true
        }
        if ($hasSITs) {
            $validRules += $rule
        } else {
            $ghostRules += $rule
        }
    }

    Write-Host ""
    Write-Host "  Total rules in policy:  $($allRules.Count)" -ForegroundColor Gray
    Write-Host "  Valid rules (with SITs): $($validRules.Count)" -ForegroundColor Green
    Write-Host "  Ghost rules (no SITs):   $($ghostRules.Count)" -ForegroundColor Yellow

    if ($ghostRules.Count -eq 0) {
        Write-Host "  No ghost rules found. Nothing to do." -ForegroundColor Green
        return
    }

    Write-Host ""
    Write-Host "  Ghost rules to remove:" -ForegroundColor Yellow
    foreach ($rule in $ghostRules) {
        $state = if ($rule.Disabled) { " [DISABLED]" } else { "" }
        Write-Host "    $($rule.Name)$state" -ForegroundColor Yellow
    }
    Write-Host ""

    $removedCount = 0
    $ruleIndex = 0
    foreach ($rule in $ghostRules) {
        if ($PSCmdlet.ShouldProcess($rule.Name, "Remove-DlpComplianceRule")) {
            if ($ruleIndex -gt 0 -and -not $WhatIfPreference) { Start-Sleep -Seconds $interCallDelaySec }
            try {
                Invoke-WithRetry -OperationName "Remove-DlpRule $($rule.Name)" -ScriptBlock {
                    Remove-DlpComplianceRule -Identity $rule.Name -Confirm:$false -ErrorAction Stop
                } -MaxRetries $maxRetries -BaseDelaySec $baseDelaySec
                Write-Host "    Removed: $($rule.Name)" -ForegroundColor Green
                $removedCount++
            } catch {
                Write-Warning "    Failed to remove $($rule.Name): $($_.Exception.Message)"
            }
            $ruleIndex++
        }
    }

    Write-Host ""
    Write-Host "  Ghost rule cleanup: $removedCount of $($ghostRules.Count) removed" -ForegroundColor Cyan
}
#endregion

Write-Host ""
Write-Host $divider
Write-Host "  CLEANUP COMPLETE"
Write-Host $divider
