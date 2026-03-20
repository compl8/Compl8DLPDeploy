#==============================================================================
# Remove-OrphanedPolicies.ps1
# Removes auto-labeling policies and DLP rules that are NOT in the current
# converter plan. Requires a -PlanFile to know what to keep (safety gate).
#
# How it works:
#   1. Reads the converter plan to build a "keep" list of policy names
#   2. Lists everything on the tenant
#   3. Shows what will be KEPT vs DELETED, with counts
#   4. Asks for confirmation before proceeding
#
# Usage:
#   # Remove orphaned auto-labeling policies (keeps converter set)
#   .\scripts\Remove-OrphanedPolicies.ps1 -PlanFile plans\conversion-plan-*.json -Connect
#
#   # Also remove ghost DLP rules (no SIT conditions) from a specific policy
#   .\scripts\Remove-OrphanedPolicies.ps1 -PlanFile plans\conversion-plan-*.json -GhostDlpRules -DlpPolicy P01-ECH-QGISCF-EXT-ADT -Connect
#
#   # Dry run
#   .\scripts\Remove-OrphanedPolicies.ps1 -PlanFile plans\conversion-plan-*.json -Connect -WhatIf
#==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$PlanFile,

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

if ($GhostDlpRules -and -not $DlpPolicy) {
    Write-Error "-GhostDlpRules requires -DlpPolicy (e.g. 'P01-ECH-QGISCF-EXT-ADT')."
    return
}

#region Load converter plan — build the "keep" list
$planPath = if ([System.IO.Path]::IsPathRooted($PlanFile)) { $PlanFile } else { Join-Path $ProjectRoot $PlanFile }
if (-not (Test-Path $planPath)) {
    Write-Error "Plan file not found: $planPath"
    return
}

$plan = Get-Content $planPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $plan.Entries -or -not $plan.ExecutionSummary) {
    Write-Error "Plan file does not look like a converter plan (missing Entries or ExecutionSummary)."
    return
}

# Extract policy names the converter created (from execution stamps)
$keepPolicies = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $plan.Entries) {
    foreach ($sr in $entry.sourceRules) {
        $ex = $sr.executed
        if ($ex -and $ex.policyName -and $ex.status -eq "success") {
            [void]$keepPolicies.Add($ex.policyName)
        }
    }
}

if ($keepPolicies.Count -eq 0) {
    Write-Error "No successfully executed policies found in plan. Has the converter been run?"
    return
}

Write-Host ""
Write-Host "  Converter plan: $planPath" -ForegroundColor Gray
Write-Host "  Policies to KEEP (from plan): $($keepPolicies.Count)" -ForegroundColor Green
foreach ($p in ($keepPolicies | Sort-Object)) {
    Write-Host "    $p" -ForegroundColor Green
}
#endregion

#region Connection
if ($Connect) {
    $connected = Connect-DLPSession -UPN $UPN
    if (-not $connected) { return }
}
if (-not (Assert-DLPSession)) { return }
#endregion

$divider = "=" * 70

#region 1. Auto-labeling policy cleanup
Write-Host ""
Write-Host $divider
Write-Host "  AUTO-LABELING POLICY CLEANUP"
Write-Host $divider

# List all auto-labeling policies on tenant
$allPolicies = @(Get-AutoSensitivityLabelPolicy -ErrorAction Stop)
Write-Host "  Total auto-labeling policies on tenant: $($allPolicies.Count)" -ForegroundColor Gray

# Classify: keep vs delete
$toKeep = @()
$toDelete = @()
foreach ($pol in ($allPolicies | Sort-Object Name)) {
    if ($keepPolicies.Contains($pol.Name)) {
        $toKeep += $pol
    } else {
        $toDelete += $pol
    }
}

# Display
Write-Host ""
Write-Host "  KEEP ($($toKeep.Count)):" -ForegroundColor Green
foreach ($pol in $toKeep) {
    $ruleCount = 0
    try { $ruleCount = @(Get-AutoSensitivityLabelRule -Policy $pol.Name -ErrorAction SilentlyContinue).Count } catch { }
    Write-Host "    $($pol.Name)  ($ruleCount rules, mode: $($pol.Mode))" -ForegroundColor Green
}

Write-Host ""
Write-Host "  DELETE ($($toDelete.Count)):" -ForegroundColor Red
foreach ($pol in $toDelete) {
    $ruleCount = 0
    try { $ruleCount = @(Get-AutoSensitivityLabelRule -Policy $pol.Name -ErrorAction SilentlyContinue).Count } catch { }
    Write-Host "    $($pol.Name)  ($ruleCount rules, mode: $($pol.Mode))" -ForegroundColor Red
}

if ($toDelete.Count -eq 0) {
    Write-Host "  Nothing to delete — tenant is clean." -ForegroundColor Green
} else {
    # Confirmation
    Write-Host ""
    if (-not $WhatIfPreference) {
        $confirm = Read-Host "  Delete $($toDelete.Count) policies and their rules? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Host "  Aborted." -ForegroundColor Yellow
            return
        }
    }

    $removedPolicies = 0
    $removedRules = 0

    foreach ($pol in $toDelete) {
        $policyName = $pol.Name

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

#region 2. Ghost DLP rules
if ($GhostDlpRules) {
    Write-Host ""
    Write-Host $divider
    Write-Host "  GHOST DLP RULE CLEANUP: $DlpPolicy"
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

    # Classify: valid (has SIT conditions) vs ghost (no SIT conditions)
    $validRules = @()
    $ghostRules = @()
    foreach ($rule in $allRules) {
        if ($rule.ContentContainsSensitiveInformation -and $rule.ContentContainsSensitiveInformation.Count -gt 0) {
            $validRules += $rule
        } else {
            $ghostRules += $rule
        }
    }

    Write-Host ""
    Write-Host "  Total rules:  $($allRules.Count)" -ForegroundColor Gray
    Write-Host "  KEEP (valid): $($validRules.Count)" -ForegroundColor Green
    foreach ($rule in $validRules) {
        Write-Host "    $($rule.Name)" -ForegroundColor Green
    }
    Write-Host "  DELETE (ghost, no SITs): $($ghostRules.Count)" -ForegroundColor Red
    if ($ghostRules.Count -le 20) {
        foreach ($rule in $ghostRules) {
            $state = if ($rule.Disabled) { " [DISABLED]" } else { "" }
            Write-Host "    $($rule.Name)$state" -ForegroundColor Red
        }
    } else {
        # Too many to list individually — show first 10 + count
        $ghostRules | Select-Object -First 10 | ForEach-Object {
            $state = if ($_.Disabled) { " [DISABLED]" } else { "" }
            Write-Host "    $($_.Name)$state" -ForegroundColor Red
        }
        Write-Host "    ... and $($ghostRules.Count - 10) more" -ForegroundColor Red
    }

    if ($ghostRules.Count -eq 0) {
        Write-Host "  No ghost rules found." -ForegroundColor Green
    } else {
        Write-Host ""
        if (-not $WhatIfPreference) {
            $confirm = Read-Host "  Delete $($ghostRules.Count) ghost rules from $DlpPolicy? (yes/no)"
            if ($confirm -ne "yes") {
                Write-Host "  Aborted." -ForegroundColor Yellow
                return
            }
        }

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
                    Write-Warning "    Failed: $($rule.Name): $($_.Exception.Message)"
                }
                $ruleIndex++
            }
        }

        Write-Host ""
        Write-Host "  Ghost rule cleanup: $removedCount of $($ghostRules.Count) removed" -ForegroundColor Cyan
    }
}
#endregion

Write-Host ""
Write-Host $divider
Write-Host "  CLEANUP COMPLETE"
Write-Host $divider
