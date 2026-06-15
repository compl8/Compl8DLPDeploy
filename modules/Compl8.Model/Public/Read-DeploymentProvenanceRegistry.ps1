function Read-DeploymentProvenanceRegistry {
    <#
    .SYNOPSIS
        Loads the provenance registry as @{ version; entries=[ordered] }, tolerating missing/corrupt files.
    #>
    param([string]$RegistryPath)

    $path = Resolve-DeploymentProvenanceRegistryPath -RegistryPath $RegistryPath
    $empty = [ordered]@{ version = 1; entries = [ordered]@{} }
    if (-not (Test-Path -LiteralPath $path)) { return $empty }

    try {
        $raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $empty }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $empty
    }

    $entries = [ordered]@{}
    if ($obj.PSObject.Properties['entries'] -and $obj.entries) {
        foreach ($p in $obj.entries.PSObject.Properties) { $entries[$p.Name] = $p.Value }
    }
    return [ordered]@{ version = if ($obj.PSObject.Properties['version'] -and $obj.version) { $obj.version } else { 1 }; entries = $entries }
}
