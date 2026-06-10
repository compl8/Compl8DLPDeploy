function Get-PolicyName {
    param(
        [int]$PolicyNumber,
        [string]$PolicyCode,
        [string]$Prefix,
        [string]$Suffix,
        [hashtable]$Config
    )

    if (-not $Config) {
        return "P{0:D2}-{1}-{2}-{3}" -f $PolicyNumber, $PolicyCode, $Prefix, $Suffix
    }

    $resolvedSuffix = if ($Suffix) { $Suffix } else { $Config.namingSuffix }
    return Get-DeploymentObjectName -Config $Config -ObjectType "dlpPolicy" -Tokens @{
        policyNumber = ("{0:D2}" -f $PolicyNumber)
        policyCode   = $PolicyCode
        suffix       = $resolvedSuffix
    }
}
