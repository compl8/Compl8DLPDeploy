function Get-DeploymentTenantInfo {
    $tenant = [ordered]@{
        name           = $null
        id             = $null
        guid           = $null
        tenantId       = $null
        organizationId = $null
        userPrincipalName = $null
        connectionUri  = $null
        source         = $null
        status         = "Unknown"
    }

    try {
        $org = Get-OrganizationConfig -ErrorAction Stop
        if ($org) {
            $tenant.name = $org.Name
            $tenant.id = if ($org.Id) { $org.Id.ToString() } else { $null }
            $tenant.guid = if ($org.Guid) { $org.Guid.ToString() } else { $null }
            $tenant.organizationId = if ($org.OrganizationId) { $org.OrganizationId.ToString() } else { $null }
            $tenant.source = "Get-OrganizationConfig"
            $tenant.status = "Connected"
        }
    } catch {
        $tenant.status = "OrganizationConfigUnavailable"
    }

    try {
        if (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) {
            $connections = @(Get-ConnectionInformation -ErrorAction Stop)
            $connection = $connections |
                Where-Object {
                    (Get-DeploymentObjectProperty -InputObject $_ -Names @("State")) -eq "Connected" -and
                    ((Get-DeploymentObjectProperty -InputObject $_ -Names @("ConnectionUri")) -match "compliance|protection\.outlook|ps\.compliance")
                } |
                Select-Object -First 1

            if (-not $connection) {
                $connection = $connections |
                    Where-Object { (Get-DeploymentObjectProperty -InputObject $_ -Names @("State")) -eq "Connected" } |
                    Select-Object -First 1
            }
            if (-not $connection) {
                $connection = $connections | Select-Object -First 1
            }

            if ($connection) {
                $organization = Get-DeploymentObjectProperty -InputObject $connection -Names @("Organization", "Tenant", "TenantName")
                $tenantId = Get-DeploymentObjectProperty -InputObject $connection -Names @("TenantID", "TenantId", "TenantGuid", "ExternalDirectoryOrganizationId")

                if (-not $tenant.name -and $organization) { $tenant.name = $organization }
                if (-not $tenant.organizationId -and $organization) { $tenant.organizationId = $organization }
                if (-not $tenant.id -and $tenantId) { $tenant.id = $tenantId }
                if (-not $tenant.guid -and $tenantId) { $tenant.guid = $tenantId }
                if (-not $tenant.tenantId -and $tenantId) { $tenant.tenantId = $tenantId }
                $tenant.userPrincipalName = Get-DeploymentObjectProperty -InputObject $connection -Names @("UserPrincipalName", "UserName")
                $tenant.connectionUri = Get-DeploymentObjectProperty -InputObject $connection -Names @("ConnectionUri")
                $tenant.source = if ($tenant.source) { "$($tenant.source)+Get-ConnectionInformation" } else { "Get-ConnectionInformation" }
                $tenant.status = "Connected"
            }
        }
    } catch {
        if ($tenant.status -eq "Unknown") {
            $tenant.status = "Unavailable"
        }
    }

    return $tenant
}
