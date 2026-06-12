function Test-ContentDictionaryBudget {
    <#
    .SYNOPSIS
        Dictionary byte-budget gate: warn early, stop hard.
    .DESCRIPTION
        Thresholds are single-sourced from Get-DeploymentLimits (Compl8.Model):
        DictionaryBudgetWarnBytes (480 KB, docs-conservative) and DictionaryBudgetMaxBytes
        (1 MB hard cap). Checks each dictionary's termsBytes; with -UsedPlaceholders only the
        dictionaries the desired item set actually references are gated.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Dictionaries,

        [string[]]$UsedPlaceholders
    )

    $limits = Get-DeploymentLimits
    $warnings = @()
    $errors = @()

    foreach ($dictionary in $Dictionaries) {
        if ($PSBoundParameters.ContainsKey('UsedPlaceholders') -and
            $UsedPlaceholders -notcontains $dictionary.placeholder) {
            continue
        }
        $bytes = [long]$dictionary.termsBytes
        if ($bytes -ge $limits.DictionaryBudgetMaxBytes) {
            $errors += "$($dictionary.placeholder): $bytes bytes exceeds the $($limits.DictionaryBudgetMaxBytes)-byte hard cap."
        } elseif ($bytes -ge $limits.DictionaryBudgetWarnBytes) {
            $warnings += "$($dictionary.placeholder): $bytes bytes exceeds the $($limits.DictionaryBudgetWarnBytes)-byte warn threshold."
        }
    }

    [pscustomobject]@{
        Warnings = $warnings
        Errors   = $errors
    }
}
