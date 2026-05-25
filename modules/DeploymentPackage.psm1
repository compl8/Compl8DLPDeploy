# Functions are added in subsequent tasks. Stubs throw so tests fail loudly if anyone calls them prematurely.

function New-DeploymentTargetSnapshot { throw 'Not implemented in module skeleton' }
function Get-TenantActualState { throw 'Not implemented in module skeleton' }
function Compare-DeploymentState { throw 'Not implemented in module skeleton' }
function Update-PendingPackage { throw 'Not implemented in module skeleton' }
function Get-PendingDeploymentPackage { throw 'Not implemented in module skeleton' }
function Read-DeploymentPackageManifest {
    param(
        [Parameter(Mandatory)][string]$SessionPath,
        [int]$ExpectedSchemaVersion = 1
    )

    if (-not (Test-Path -LiteralPath $SessionPath)) {
        throw "Session path not found: $SessionPath"
    }

    $zip       = Join-Path $SessionPath 'pending.zip'
    $shaFile   = Join-Path $SessionPath 'pending.zip.sha256'
    $statusFp  = Join-Path $SessionPath 'status.json'

    if ((Test-Path $zip) -and (Test-Path $shaFile)) {
        $expected = (Get-Content -Raw -LiteralPath $shaFile).Trim()
        $actual   = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash
        if ($expected -ne $actual) {
            throw "pending.zip SHA-256 mismatch (sidecar says $expected, file is $actual)"
        }
    }

    # Extract pending.zip to a temp working copy so we never mutate the on-disk working/ behind a phase script's back.
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("dp-read-$([guid]::NewGuid().Guid)")
    New-Item -ItemType Directory -Path $temp -Force | Out-Null
    try {
        if (Test-Path $zip) {
            Expand-Archive -LiteralPath $zip -DestinationPath $temp -Force
        } else {
            # Fall back to the live working dir if no zip is sealed yet (during Initialize-DeploymentSession).
            $working = Join-Path $SessionPath 'working'
            if (Test-Path $working) { Copy-Item -Path (Join-Path $working '*') -Destination $temp -Recurse -Force }
        }

        $pin = Get-Content -Raw -LiteralPath (Join-Path $temp 'tenant-pin.json')         | ConvertFrom-Json -AsHashtable
        $tgt = Get-Content -Raw -LiteralPath (Join-Path $temp 'deployment-target.json')  | ConvertFrom-Json -AsHashtable
        $adj = Get-Content -Raw -LiteralPath (Join-Path $temp 'plan-adjustments.json')   | ConvertFrom-Json -AsHashtable

        foreach ($pair in @(@('tenant-pin', $pin), @('deployment-target', $tgt), @('plan-adjustments', $adj))) {
            if ($pair[1].schemaVersion -ne $ExpectedSchemaVersion) {
                throw "$($pair[0]) schemaVersion is $($pair[1].schemaVersion); expected $ExpectedSchemaVersion"
            }
        }

        $status = if (Test-Path $statusFp) {
            Get-Content -Raw -LiteralPath $statusFp | ConvertFrom-Json -AsHashtable
        } else {
            @{ schemaVersion = 1; state = 'pending'; phasesCompleted = @(); phasesPending = @(); pendingZipSha256 = ''; lastUpdated = '' }
        }
        if ($status.schemaVersion -ne $ExpectedSchemaVersion) {
            throw "status schemaVersion is $($status.schemaVersion); expected $ExpectedSchemaVersion"
        }

        # Load phase-*.json files if any are present.
        $phases = @{}
        foreach ($file in Get-ChildItem -Path $temp -Filter 'phase-*.json' -ErrorAction SilentlyContinue) {
            $phaseRecord = Get-Content -Raw -LiteralPath $file.FullName | ConvertFrom-Json -AsHashtable
            $phases[$phaseRecord.phase] = $phaseRecord
        }

        return @{
            SessionPath = $SessionPath
            TenantPin   = $pin
            Target      = $tgt
            Adjustments = $adj
            Status      = $status
            Phases      = $phases
        }
    }
    finally {
        Remove-Item -Path $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
function Add-DeploymentPlanAdjustment { throw 'Not implemented in module skeleton' }
function Add-DeploymentPhaseResult { throw 'Not implemented in module skeleton' }
function Move-DeploymentPackageToArchive { throw 'Not implemented in module skeleton' }

Export-ModuleMember -Function @(
    'New-DeploymentTargetSnapshot',
    'Get-TenantActualState',
    'Compare-DeploymentState',
    'Update-PendingPackage',
    'Get-PendingDeploymentPackage',
    'Read-DeploymentPackageManifest',
    'Add-DeploymentPlanAdjustment',
    'Add-DeploymentPhaseResult',
    'Move-DeploymentPackageToArchive'
)
