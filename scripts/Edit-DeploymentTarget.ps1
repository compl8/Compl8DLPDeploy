#==============================================================================
# Edit-DeploymentTarget.ps1
# Operator-review CLI: append skip adjustments to a pending deployment package.
#==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SessionPath,
    [Parameter(Mandatory)][string[]]$SkipArtifact,
    [Parameter(Mandatory)][string]$Reason
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $ProjectRoot 'modules/DeploymentPackage.psm1') -Force

foreach ($spec in $SkipArtifact) {
    $parts = $spec -split '/', 2
    if ($parts.Count -ne 2) { throw "Invalid -SkipArtifact value '$spec' (expected '<type>/<name>')" }
    $artifactType = $parts[0]
    $key          = $parts[1]
    Add-DeploymentPlanAdjustment -SessionPath $SessionPath -Source 'operator-review' `
        -ArtifactType $artifactType -Key $key -Action 'skip' -Reason $Reason
    Write-Host "  Skipped $artifactType/$key - $Reason" -ForegroundColor Yellow
}
