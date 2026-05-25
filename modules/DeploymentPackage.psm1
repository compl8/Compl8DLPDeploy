# Functions are added in subsequent tasks. Stubs throw so tests fail loudly if anyone calls them prematurely.

function New-DeploymentTargetSnapshot { throw 'Not implemented in module skeleton' }
function Get-TenantActualState { throw 'Not implemented in module skeleton' }
function Compare-DeploymentState { throw 'Not implemented in module skeleton' }
function Update-PendingPackage { throw 'Not implemented in module skeleton' }
function Get-PendingDeploymentPackage { throw 'Not implemented in module skeleton' }
function Read-DeploymentPackageManifest { throw 'Not implemented in module skeleton' }
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
