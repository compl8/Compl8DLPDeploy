#==============================================================================
# Finalize-DeploymentSession.ps1
# Verify a pending deployment session against the live tenant and archive it.
#==============================================================================

[CmdletBinding()]
param(
    [string]$SessionPath,
    [string]$Tenant,
    [string]$TargetEnvironment,
    [switch]$Connect,
    [string]$UPN,
    [switch]$AcceptIncomplete,
    [switch]$ReFinalize,
    [string]$ArchiveRoot,
    [hashtable]$InjectActualState  # test-only hook; bypasses tenant query
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $ProjectRoot 'modules/DeploymentPackage.psm1') -Force
Import-Module (Join-Path $ProjectRoot 'modules/DLP-Deploy.psm1') -Force

if (-not $SessionPath) {
    if (-not ($Tenant -and $TargetEnvironment)) { throw 'Provide -SessionPath or both -Tenant and -TargetEnvironment.' }
    $r = Get-PendingDeploymentPackage -DeploymentsRoot (Join-Path $ProjectRoot 'dist/deployments') -Tenant $Tenant -TargetEnvironment $TargetEnvironment
    $SessionPath = $r.SessionPath
}
if (-not $ArchiveRoot) { $ArchiveRoot = Join-Path $ProjectRoot 'dist/archive' }

$manifest = Read-DeploymentPackageManifest -SessionPath $SessionPath

$terminalStates = @('succeeded','partial','failed','rolledback')
if (($manifest.Status.state -in $terminalStates) -and -not $ReFinalize) {
    throw "Session is already in terminal state '$($manifest.Status.state)'. Pass -ReFinalize to refresh deployment-result.json without re-archiving."
}

if ($manifest.Status.phasesPending.Count -gt 0 -and -not $AcceptIncomplete) {
    throw "Session has pending phases: $($manifest.Status.phasesPending -join ', '). Pass -AcceptIncomplete to archive as 'partial'."
}

# Acquire actual state.
if ($InjectActualState) {
    $actual = $InjectActualState
} else {
    if ($Connect) { $null = Connect-DLPSession -UPN $UPN }
    if (-not (Assert-DLPSession)) { throw 'No live SCC session. Pass -Connect.' }
    $actual = Get-TenantActualState -NamingPrefix $manifest.TenantPin.namingPrefix -TargetEnvironment $manifest.TenantPin.targetEnvironment
}

$diff = Compare-DeploymentState -Target $manifest.Target -Actual $actual -Adjustments $manifest.Adjustments.entries

# Determine result status.
$result = if ($manifest.Status.phasesPending.Count -gt 0) {
    'partial'
} elseif ($diff.status -eq 'succeeded') {
    'succeeded'
} else {
    'failed'
}

$resultRecord = [ordered]@{
    schemaVersion = 1
    status        = $result
    verifiedAt    = (Get-Date).ToString('o')
    missing       = $diff.missing
    extras        = $diff.extras
    mismatches    = $diff.mismatches
    summary       = $diff.summary
}

$actualState = $actual
Update-PendingPackage -SessionPath $SessionPath -Mutator {
    param($workingDir)
    $actualState  | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $workingDir 'actual-state.json')        -Encoding UTF8
    $resultRecord | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $workingDir 'deployment-result.json')   -Encoding UTF8
}.GetNewClosure()

# Update status state to terminal before move.
$statusFp = Join-Path $SessionPath 'status.json'
$s = Get-Content -Raw -LiteralPath $statusFp | ConvertFrom-Json -AsHashtable
$s.state = $result
$s.lastUpdated = (Get-Date).ToString('o')
$s | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $statusFp -Encoding UTF8

if (-not $ReFinalize) {
    Move-DeploymentPackageToArchive -SessionPath $SessionPath -Result $result -ArchiveRoot $ArchiveRoot
}

$color = if ($result -eq 'succeeded') { 'Green' } else { 'Yellow' }
Write-Host "Deployment $result." -ForegroundColor $color
Write-Output $result
