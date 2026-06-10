function Get-RuleName {
    param(
        [int]$PolicyNumber,
        [int]$RuleNumber,
        [string]$PolicyCode,
        [string]$LabelCode,
        [string]$Suffix,
        [string]$Prefix,
        [string]$ChunkLetter = "",
        [hashtable]$Config
    )

    if (-not $Config) {
        return "P{0:D2}-R{1:D2}{2}-{3}-{4}-{5}" -f $PolicyNumber, $RuleNumber, $ChunkLetter, $PolicyCode, $LabelCode, $Suffix
    }

    $resolvedSuffix = if ($Suffix) { $Suffix } else { $Config.namingSuffix }
    return Get-DeploymentObjectName -Config $Config -ObjectType "dlpRule" -Tokens @{
        policyNumber = ("{0:D2}" -f $PolicyNumber)
        ruleNumber   = ("{0:D2}" -f $RuleNumber)
        chunkLetter  = $ChunkLetter
        policyCode   = $PolicyCode
        labelCode    = $LabelCode
        suffix       = $resolvedSuffix
    }
}
