function Get-DeploymentObjectName {
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][string]$ObjectType,
        [string]$Name,
        [string]$SourcePrefix,
        [hashtable]$Tokens = @{}
    )

    $prefix = if ($Config.ContainsKey("namingPrefix")) { $Config.namingPrefix } else { "" }
    $suffix = if ($Config.ContainsKey("namingSuffix")) { $Config.namingSuffix } else { "" }
    $templates = ConvertTo-DeploymentNameTemplates -Templates $Config.nameTemplates
    $template = if ($templates.ContainsKey($ObjectType)) { $templates[$ObjectType] } else { "{prefix}-{name}" }

    $baseName = Remove-DeploymentNamePrefix -Name $Name -Prefix $prefix
    if (-not [string]::IsNullOrWhiteSpace($SourcePrefix)) {
        $baseName = Remove-DeploymentNamePrefix -Name $baseName -Prefix $SourcePrefix
    }
    $allTokens = @{
        prefix      = $prefix
        suffix      = $suffix
        name        = $baseName
        rawName     = $Name
        chunkLetter = ""
    }
    foreach ($key in $Tokens.Keys) {
        $allTokens[$key] = $Tokens[$key]
    }

    return Expand-DeploymentNameTemplate -Template $template -Tokens $allTokens
}
