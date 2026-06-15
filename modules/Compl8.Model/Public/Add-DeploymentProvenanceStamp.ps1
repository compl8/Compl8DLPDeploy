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
        [int]$MaxLength = 1000,

        # Optional explicit provenance registry path. When supplied it is threaded to
        # New-DeploymentProvenanceStamp -> Set-DeploymentProvenanceRegistryEntry so the entry is written
        # to THIS registry (e.g. a workspace's <ws>/history/applies/provenance.json). When ABSENT the
        # behaviour is UNCHANGED — the registry resolves to $env:COMPL8_PROVENANCE_REGISTRY else the repo
        # default — so every existing caller is unaffected. (Stage 5 D8 workspace re-point; codex 5A review.)
        [string]$RegistryPath
    )

    $newStampArgs = @{
        Prefix            = $Prefix
        Component         = $Component
        DeploymentId      = $DeploymentId
        TargetEnvironment = $TargetEnvironment
        Metadata          = $Metadata
    }
    if (-not [string]::IsNullOrWhiteSpace($RegistryPath)) { $newStampArgs['RegistryPath'] = $RegistryPath }
    $stamp = New-DeploymentProvenanceStamp @newStampArgs
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
