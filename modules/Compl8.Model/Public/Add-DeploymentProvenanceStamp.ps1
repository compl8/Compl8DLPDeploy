function Add-DeploymentProvenanceStamp {
    <#
    .SYNOPSIS
        Appends or replaces the provenance marker in a Comment/Description string. Strips any
        existing marker (short or legacy long form) before appending the current short marker.
    #>
    param(
        [string]$Text,
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Component,
        [string]$DeploymentId,
        [string]$TargetEnvironment,
        [hashtable]$Metadata = @{},
        [int]$MaxLength = 1000
    )

    $stamp = New-DeploymentProvenanceStamp -Prefix $Prefix -Component $Component -DeploymentId $DeploymentId -TargetEnvironment $TargetEnvironment -Metadata $Metadata
    $shortPattern = '\[\[Compl8:[0-9a-f]{16}\]\]'
    $longPattern  = '\[\[Compl8DLPDeploy:provenance:v\d+(?:;[A-Za-z][A-Za-z0-9_]*=[^\]\r\n;]*)*\]\]'
    $cleanText = ""
    if ($Text) {
        $cleanText = [regex]::Replace($Text, $longPattern, "")
        $cleanText = [regex]::Replace($cleanText, $shortPattern, "")
        $cleanText = $cleanText.Trim()
    }
    $combined = if ($cleanText) { "$cleanText`n$stamp" } else { $stamp }

    if ($MaxLength -gt 0 -and $combined.Length -gt $MaxLength -and $cleanText) {
        $available = $MaxLength - $stamp.Length - 1
        if ($available -gt 3) {
            $combined = "$($cleanText.Substring(0, $available - 3))...`n$stamp"
        } else {
            $combined = $stamp
        }
    }

    return $combined
}
