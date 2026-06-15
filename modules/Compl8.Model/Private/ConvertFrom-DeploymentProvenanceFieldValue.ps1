function ConvertFrom-DeploymentProvenanceFieldValue {
    <#
    .SYNOPSIS
        URL-decodes a provenance field value parsed from a legacy long-form marker.
    .NOTES
        Private to Compl8.Model. Verbatim copy of the DLP-Deploy.psm1 helper of the same name,
        needed so Get-DeploymentProvenanceStamp can decode legacy long-form markers when
        Compl8.Model is imported standalone (without the DLP-Deploy facade).
    #>
    param([string]$Value)

    if ($null -eq $Value) { return $null }
    return [System.Uri]::UnescapeDataString($Value)
}
