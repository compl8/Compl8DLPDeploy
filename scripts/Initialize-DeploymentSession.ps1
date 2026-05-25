#==============================================================================
# Initialize-DeploymentSession.ps1
# Build a tenant-pinned pending deployment package from a base build zip.
#==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BasePackagePath,
    [Parameter(Mandatory)][string]$Tenant,
    [Parameter(Mandatory)][string]$TargetEnvironment,
    [string]$Prefix,
    [string]$OutputRoot,
    [switch]$NewSession
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $ProjectRoot 'modules/DeploymentPackage.psm1') -Force
Import-Module (Join-Path $ProjectRoot 'modules/DLP-Deploy.psm1') -Force

if (-not (Test-Path -LiteralPath $BasePackagePath)) { throw "Base package not found: $BasePackagePath" }
if (-not $OutputRoot) { $OutputRoot = Join-Path $ProjectRoot 'dist/deployments' }
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

$ts          = (Get-Date).ToString('yyyyMMdd-HHmmss')
$tenantSlug  = $Tenant -replace '[^a-zA-Z0-9.\-]','_'
$sessionDir  = Join-Path $OutputRoot "$tenantSlug-$ts"
$workingDir  = Join-Path $sessionDir 'working'

if ((Test-Path -LiteralPath $sessionDir) -and -not $NewSession) {
    throw "Session directory already exists: $sessionDir (use -NewSession to force a new one)"
}
New-Item -ItemType Directory -Path $workingDir -Force | Out-Null

# Extract base zip into working/
Expand-Archive -LiteralPath $BasePackagePath -DestinationPath $workingDir -Force

# Load resolved config from the extracted working/config/settings.json (+ optional Prefix override).
$settingsPath = Join-Path $workingDir 'config/settings.json'
if (-not (Test-Path -LiteralPath $settingsPath)) { throw "Base package missing config/settings.json" }
$settings = Get-Content -Raw -LiteralPath $settingsPath | ConvertFrom-Json
if ($Prefix) {
    $settings.namingPrefix = $Prefix
    if ($settings.PSObject.Properties['sitPrefix']) { $settings.sitPrefix = $Prefix } else { $settings | Add-Member -NotePropertyName sitPrefix -NotePropertyValue $Prefix -Force }
    $settings | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $settingsPath -Encoding UTF8
}

# Resolve tenantId from the base package's tenant-fingerprints (if present) or example file.
$tenantId = 'unresolved'
foreach ($fpName in @('tenant-fingerprints.json','tenant-fingerprints.example.json')) {
    $fpPath = Join-Path $workingDir "config/$fpName"
    if (Test-Path -LiteralPath $fpPath) {
        $fp = Get-Content -Raw -LiteralPath $fpPath | ConvertFrom-Json -AsHashtable
        if ($fp.environments -and $fp.environments.ContainsKey($TargetEnvironment)) {
            $env = $fp.environments[$TargetEnvironment]
            $tenantId = if ($env.tenantId) { $env.tenantId } elseif ($env.guid) { $env.guid } else { 'unresolved' }
            break
        }
    }
}

# Write tenant-pin.json
$baseSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $BasePackagePath).Hash
$baseName = 'Compl8DLPDeploy'
$baseVer  = if ($settings.PSObject.Properties['_packageVersion']) { $settings._packageVersion } else { (Get-Date).ToString('yyyy.MM.dd') }

$pin = [ordered]@{
    schemaVersion     = 1
    tenant            = $Tenant
    tenantId          = $tenantId
    targetEnvironment = $TargetEnvironment
    namingPrefix      = $settings.namingPrefix
    namingSuffix      = $settings.namingSuffix
    sitPrefix         = if ($settings.PSObject.Properties['sitPrefix']) { $settings.sitPrefix } else { $settings.namingPrefix }
    deploymentTier    = $settings.deploymentTier
    basePackage       = @{ name = $baseName; version = $baseVer; sha256 = $baseSha }
    createdBy         = ([Environment]::UserName + '@' + [Environment]::UserDomainName)
    createdAt         = (Get-Date).ToString('o')
    sessionId         = ([guid]::NewGuid().Guid)
}
$pin | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $workingDir 'tenant-pin.json') -Encoding UTF8

# Compute deployment-target.json from working configs.
$target = New-DeploymentTargetSnapshot -ConfigDir (Join-Path $workingDir 'config')
$target | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $workingDir 'deployment-target.json') -Encoding UTF8

# Empty plan-adjustments.json
@{ schemaVersion=1; entries=@() } | ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath (Join-Path $workingDir 'plan-adjustments.json') -Encoding UTF8

# Initial status.json (outside zip per spec amendment).
@{
    schemaVersion    = 1
    state            = 'pending'
    phasesCompleted  = @()
    phasesPending    = @('classifiers','labels','dlprules')
    pendingZipSha256 = ''
    lastUpdated      = (Get-Date).ToString('o')
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $sessionDir 'status.json') -Encoding UTF8

# Seal pending.zip via the standard atomic re-seal (mutator is a no-op since working/ is already populated).
Update-PendingPackage -SessionPath $sessionDir -Mutator { param($w) }

Write-Host "Initialised deployment session: $sessionDir" -ForegroundColor Green
Write-Host "  Tenant:            $Tenant"
Write-Host "  TargetEnvironment: $TargetEnvironment"
Write-Host "  Prefix:            $($pin.namingPrefix)"
Write-Output $sessionDir
