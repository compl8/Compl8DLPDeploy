#==============================================================================
# Deploy-Labels.ps1
# Deploys sensitivity labels to Microsoft Purview.
# All label definitions loaded from config/labels.json (single source of truth).
#
# Usage:
#   .\scripts\Deploy-Labels.ps1 -Connect                                       # Deploy, prompt-free
#   .\scripts\Deploy-Labels.ps1 -Connect -PublishTo "DL-InfoSec@agency.gov"    # Publish to named group
#   .\scripts\Deploy-Labels.ps1 -Connect -PublishTo "All" -ApproveOpenPublish  # Publish to all (requires explicit approval)
#   .\scripts\Deploy-Labels.ps1 -Connect -SkipPublish                          # Create labels only
#   .\scripts\Deploy-Labels.ps1 -Connect -NoMarking              # Skip visual markings
#   .\scripts\Deploy-Labels.ps1 -Connect -Cleanup                # Remove all labels
#   .\scripts\Deploy-Labels.ps1 -Connect -WhatIf                 # Dry run
#==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PublishTo,
    [switch]$SkipPublish,
    [switch]$ApproveOpenPublish,
    [switch]$NoMarking,
    [switch]$Cleanup,
    [switch]$Connect,
    [string]$UPN
)

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath  = Join-Path $ProjectRoot "config"

# Import shared module
Import-Module (Join-Path $ProjectRoot "modules" "DLP-Deploy.psm1") -Force

$ErrorActionPreference = "Stop"

#region Config
$Defaults     = Get-ModuleDefaults
$settingsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "settings.json") -Description "deployment settings"
$Config       = Merge-GlobalConfig -Defaults $Defaults -GlobalJson $settingsJson

$labelsJson = Import-JsonConfig -FilePath (Join-Path $ConfigPath "labels.json") -Description "label definitions"
if (-not $labelsJson) {
    Write-Error "Failed to load labels.json. Aborting."
    return
}

$LabelDefinitions = $labelsJson
#endregion

#region Connection
if ($Connect) {
    $connected = Connect-DLPSession -UPN $UPN
    if (-not $connected) { return }
}

# Verify session
if (-not (Assert-DLPSession -CommandToTest "Get-Label")) { return }
#endregion

#region Logging
$null = Start-DeploymentLog -ScriptName "Deploy-Labels"
#endregion

#region Cleanup Mode
if ($Cleanup) {
    Write-Host "`n=== Cleanup Mode ===" -ForegroundColor Yellow

    # Remove sublabels before parent groups (reverse priority order)
    $sortedLabels = $LabelDefinitions | Sort-Object { $_.priority } -Descending

    # Remove label policy first
    $policyName = $Config.labelPolicyName
    $cleanupDelay = if ($Config.interCallDelaySec) { $Config.interCallDelaySec } else { 2 }
    Remove-PurviewObject -Identity $policyName `
        -GetCommand "Get-LabelPolicy" -RemoveCommand "Remove-LabelPolicy" `
        -OperationName "label policy" `
        -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec -WhatIf:$WhatIfPreference

    $labelIndex = 0
    foreach ($label in $sortedLabels) {
        if ($labelIndex -gt 0 -and -not $WhatIfPreference) { Start-Sleep -Seconds $cleanupDelay }
        $labelIndex++
        Remove-PurviewObject -Identity $label.name `
            -GetCommand "Get-Label" -RemoveCommand "Remove-Label" `
            -OperationName "label" `
            -MaxRetries $Config.maxRetries -BaseDelaySec $Config.baseDelaySec -WhatIf:$WhatIfPreference
    }

    Write-Host "`nCleanup complete." -ForegroundColor Green
    try { Stop-Transcript } catch { }
    return
}
#endregion

#region Deployment Plan
$groupLabels      = $LabelDefinitions | Where-Object { $_.isGroup }
$topLevelLeaves   = $LabelDefinitions | Where-Object { -not $_.isGroup -and -not $_.parentGroup }
$sublabels        = $LabelDefinitions | Where-Object { -not $_.isGroup -and $_.parentGroup }
$publishableCount = ($LabelDefinitions | Where-Object { -not $_.isGroup }).Count

Write-Host "`n=== Deployment Plan ===" -ForegroundColor Cyan
Write-Host "  Labels to deploy:       $($LabelDefinitions.Count) total" -ForegroundColor White
Write-Host "    Top-level labels:      $($topLevelLeaves.Count)  ($( ($topLevelLeaves.name) -join ', '))" -ForegroundColor Gray
Write-Host "    Label groups:          $($groupLabels.Count)  ($( ($groupLabels.name) -join ', '))" -ForegroundColor Gray
Write-Host "    Sublabels:             $($sublabels.Count)" -ForegroundColor Gray
foreach ($group in $groupLabels) {
    $children = $sublabels | Where-Object { $_.parentGroup -eq $group.name }
    Write-Host "      $($group.name):" -ForegroundColor Gray -NoNewline
    Write-Host "   $( ($children.displayName) -join ', ')" -ForegroundColor DarkGray
}
Write-Host "    Publishable labels:    $publishableCount" -ForegroundColor Gray
Write-Host "  Visual markings:         $(if ($NoMarking) { 'OFF (-NoMarking)' } else { 'Headers + Footers' })" -ForegroundColor White

# Resolve publish scope
if (-not $SkipPublish -and -not $PublishTo) {
    $SkipPublish = $true
    Write-Host "  No -PublishTo specified; publishing will be skipped. Use -PublishTo to publish." -ForegroundColor Yellow
}
if (-not $SkipPublish -and $PublishTo -eq "All" -and -not $ApproveOpenPublish) {
    Write-Error "Publishing to 'All' requires -ApproveOpenPublish. Specify a named user/group, or add -ApproveOpenPublish to confirm open publishing."
    return
}

if ($SkipPublish) {
    Write-Host "  Publish policy:          SKIP (labels only)" -ForegroundColor White
} else {
    Write-Host "  Publish policy:          $($Config.labelPolicyName) (scope: $PublishTo)" -ForegroundColor White
}
#endregion

#region Label Deployment
Write-Host "`n=== Deploying Sensitivity Labels ===" -ForegroundColor Cyan
Write-Host "Starting deployment at $(Get-Date)" -ForegroundColor Cyan

$successLabels = 0
$failLabels    = 0
$updatedLabels = 0
$parentGuids   = @{}
$deployDelay   = if ($Config.interCallDelaySec) { $Config.interCallDelaySec } else { 2 }

# Deploy in priority order (parents before children)
$sortedLabels = $LabelDefinitions | Sort-Object { $_.priority }

$labelIndex = 0
foreach ($label in $sortedLabels) {
    if ($labelIndex -gt 0 -and -not $WhatIfPreference) { Start-Sleep -Seconds $deployDelay }
    $labelIndex++
    $labelName = $label.name
    $labelType = if ($label.isGroup) { "Label Group" } else { "Label" }
    Write-Host "`n  Processing: $($label.displayName) ($labelType, Name: $labelName)" -ForegroundColor Cyan

    # Build base parameters
    $labelParams = @{
        DisplayName = $label.displayName
        Tooltip     = $label.tooltip
        Comment     = "$($Config.namingPrefix) label deployed $(Get-Date -Format 'yyyy-MM-dd'). Priority: $($label.priority)."
    }

    if ($label.isGroup) {
        $labelParams["IsLabelGroup"] = $true
    } else {
        $labelParams["ContentType"] = "File, Email"
    }

    # Set parent for sublabels
    if ($label.parentGroup) {
        if ($parentGuids.ContainsKey($label.parentGroup)) {
            $labelParams["ParentId"] = $parentGuids[$label.parentGroup]
        } else {
            try {
                $parentLabel = Get-Label -Identity $label.parentGroup -ErrorAction Stop
                $labelParams["ParentId"] = $parentLabel.Guid.ToString()
                $parentGuids[$label.parentGroup] = $parentLabel.Guid.ToString()
            } catch {
                Write-Warning "  Parent group '$($label.parentGroup)' not found. Skipping sublabel '$labelName'."
                $failLabels++
                continue
            }
        }
    }

    # Label tile colour
    $advancedSettings = @{}
    if ($label.colour) {
        $advancedSettings["color"] = $label.colour
    }

    # Visual markings
    if (-not $NoMarking) {
        if ($label.headerText) {
            $labelParams["ApplyContentMarkingHeaderEnabled"]   = $true
            $labelParams["ApplyContentMarkingHeaderText"]      = $label.headerText
            $labelParams["ApplyContentMarkingHeaderFontSize"]  = 10
            $labelParams["ApplyContentMarkingHeaderAlignment"] = "Center"
            if ($label.colour) {
                $labelParams["ApplyContentMarkingHeaderFontColor"] = $label.colour
            }
        }
        if ($label.footerText) {
            $labelParams["ApplyContentMarkingFooterEnabled"]   = $true
            $labelParams["ApplyContentMarkingFooterText"]      = $label.footerText
            $labelParams["ApplyContentMarkingFooterFontSize"]  = 8
            $labelParams["ApplyContentMarkingFooterAlignment"] = "Center"
            if ($label.colour) {
                $labelParams["ApplyContentMarkingFooterFontColor"] = $label.colour
            }
        }
    }

    # Check if label exists
    $existingLabel = $null
    try { $existingLabel = Get-Label -Identity $labelName -ErrorAction Stop } catch { }

    try {
        if ($existingLabel) {
            # Type mismatch guards
            $existingHasContentType = -not [string]::IsNullOrWhiteSpace($existingLabel.ContentType)
            if ($label.isGroup -and $existingHasContentType) {
                Write-Warning "  TYPE MISMATCH: '$labelName' exists as a leaf label but must be a label group. Delete in Purview and re-run. Skipping."
                $failLabels++
                continue
            }
            if (-not $label.isGroup -and -not $existingHasContentType -and -not $label.parentGroup) {
                Write-Warning "  TYPE MISMATCH: '$labelName' exists as a label group but must be a leaf label. Delete in Purview and re-run. Skipping."
                $failLabels++
                continue
            }

            Write-Host "    Label exists. Updating..." -ForegroundColor Yellow
            $skipOnUpdate = @("ParentId", "IsLabelGroup", "ContentType")
            $updateParams = @{ Identity = $labelName }
            foreach ($key in $labelParams.Keys) {
                if ($key -notin $skipOnUpdate) {
                    $updateParams[$key] = $labelParams[$key]
                }
            }
            if ($advancedSettings.Count -gt 0) {
                $updateParams["AdvancedSettings"] = $advancedSettings
            }
            if ($PSCmdlet.ShouldProcess($labelName, "Set-Label")) {
                Set-Label @updateParams -ErrorAction Stop
            }
            $parentGuids[$labelName] = $existingLabel.Guid.ToString()
            $updatedLabels++
        } else {
            Write-Host "    Creating new label..." -ForegroundColor Green
            $createParams = @{ Name = $labelName }
            foreach ($key in $labelParams.Keys) {
                $createParams[$key] = $labelParams[$key]
            }
            if ($advancedSettings.Count -gt 0) {
                $createParams["AdvancedSettings"] = $advancedSettings
            }
            if ($PSCmdlet.ShouldProcess($labelName, "New-Label")) {
                $newLabel = New-Label @createParams -ErrorAction Stop
                $parentGuids[$labelName] = $newLabel.Guid.ToString()
            }
            $successLabels++
        }
    } catch {
        Write-Error "    Failed: $($_.Exception.Message)"
        $failLabels++
    }
}
#endregion

#region Publish Label Policy
if ($SkipPublish) {
    Write-Host "`n=== Label Publishing Skipped ===" -ForegroundColor Yellow
} else {
    Write-Host "`n=== Publishing Label Policy ===" -ForegroundColor Cyan

    $policyName = $Config.labelPolicyName
    $publishableLabels = ($LabelDefinitions | Where-Object { -not $_.isGroup }).name | Select-Object -Unique

    $existingPolicy = $null
    try { $existingPolicy = Get-LabelPolicy -Identity $policyName -ErrorAction Stop } catch { }

    $locationParams = @{}
    if ($PublishTo -eq "All") {
        $locationParams["ExchangeLocation"] = "All"
    } else {
        $locationParams["ExchangeLocation"] = $PublishTo
    }

    try {
        if ($existingPolicy) {
            Write-Host "  Policy exists. Updating labels..." -ForegroundColor Yellow
            if ($PSCmdlet.ShouldProcess($policyName, "Set-LabelPolicy")) {
                try {
                    Invoke-WithRetry -OperationName "Set-LabelPolicy $policyName" -ScriptBlock {
                        Set-LabelPolicy -Identity $policyName `
                            -AddLabels $publishableLabels `
                            -Comment "$($Config.namingPrefix) labels published $(Get-Date -Format 'yyyy-MM-dd')" `
                            -ErrorAction Stop
                    } -MaxRetries 2 -BaseDelaySec 30
                } catch {
                    if ($_.Exception.Message -match 'LabelAlreadyPublished') {
                        Write-Host "  Labels already published to policy (no changes needed)." -ForegroundColor Green
                    } else {
                        throw
                    }
                }
            }
        } else {
            Write-Host "  Creating label policy (scope: $PublishTo)..." -ForegroundColor Green
            if ($PSCmdlet.ShouldProcess($policyName, "New-LabelPolicy")) {
                Invoke-WithRetry -OperationName "New-LabelPolicy $policyName" -ScriptBlock {
                    New-LabelPolicy -Name $policyName `
                        -Labels $publishableLabels `
                        @locationParams `
                        -Comment "$($Config.namingPrefix) label policy - scope: $PublishTo" `
                        -ErrorAction Stop
                } -MaxRetries 2 -BaseDelaySec 30
            }
        }
        Write-Host "  Label policy deployed: $policyName ($($publishableLabels.Count) labels, scope: $PublishTo)" -ForegroundColor Green
    } catch {
        Write-Error "  Failed to deploy label policy: $($_.Exception.Message)"
    }
}
#endregion

#region Summary
Write-Host "`n=== Deployment Summary ===" -ForegroundColor Cyan
Write-Host "  Labels created:  $successLabels" -ForegroundColor Green
Write-Host "  Labels updated:  $updatedLabels" -ForegroundColor Yellow
Write-Host "  Labels failed:   $failLabels" -ForegroundColor $(if ($failLabels -eq 0) { "Green" } else { "Red" })
if ($failLabels -eq $sortedLabels.Count) {
    Write-Error "ALL labels failed to deploy ($($failLabels) failures). Review warnings above."
}

Write-Host "`nDeployment complete at $(Get-Date)" -ForegroundColor Green

try { Stop-Transcript } catch { }
#endregion
