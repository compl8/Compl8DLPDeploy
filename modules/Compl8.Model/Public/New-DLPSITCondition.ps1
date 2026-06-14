function New-DLPSITCondition {
    <#
    .SYNOPSIS
        Builds the classifier condition for New-DlpComplianceRule.
        Returns a hashtable with:
          .Format = "Simple" or "AdvancedRule"
          .Value  = hashtable (for -ContentContainsSensitiveInformation) or JSON string (for -AdvancedRule)

        If ANY classifier is a trainable classifier (ClassifierType=MLModel), the entire
        condition must use -AdvancedRule JSON format. Otherwise uses the simpler hashtable.
    .PARAMETER ClassifierList
        Array of classifier entries from Resolve-ClassifierConfig.
    .PARAMETER ScopeParam
        Optional. The scope parameter name (e.g. "AccessScope") for the policy.
    .PARAMETER ScopeValue
        Optional. The scope value (e.g. "NotInOrganization").
    #>
    param(
        [Parameter(Mandatory)][array]$ClassifierList,
        [string]$ScopeParam,
        [string]$ScopeValue
    )

    $hasTC = $false
    foreach ($entry in $ClassifierList) {
        if ($entry.ClassifierType -eq "MLModel") { $hasTC = $true; break }
    }

    if (-not $hasTC) {
        # Simple format — no trainable classifiers
        $sensitivetypes = @()
        foreach ($sit in $ClassifierList) {
            $sensitivetypes += @{
                name            = $sit.Name
                id              = $sit.Id
                mincount        = [int]$sit.minCount
                maxcount        = [int]$sit.maxCount
                confidencelevel = $sit.confidencelevel
            }
        }
        return @{
            Format = "Simple"
            Value  = @{
                operator = "And"
                groups   = @(
                    @{
                        operator       = "Or"
                        name           = "Default"
                        sensitivetypes = $sensitivetypes
                    }
                )
            }
        }
    }

    # AdvancedRule format — mix of SITs and TCs
    return @{
        Format = "AdvancedRule"
        Value  = New-AdvancedRuleJson -ClassifierList $ClassifierList -ScopeParam $ScopeParam -ScopeValue $ScopeValue
    }
}
