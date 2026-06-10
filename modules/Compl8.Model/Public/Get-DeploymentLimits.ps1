function Get-DeploymentLimits {
    <#
    .SYNOPSIS
        Single source of truth for Microsoft Purview SIT/dictionary limits.
    .DESCRIPTION
        AUTHORING-class limits (custom SIT rule packages, per
        https://learn.microsoft.com/purview/sit-limits, verified 2026-06-10) are a
        DIFFERENT limit class from auto-labeling CONSUMPTION limits. Do not conflate:
        the authoring cap is 50 SITs per rule package; 125 is the max SITs referenced
        by a single auto-labeling rule.
        PreferredRulePackageBytes is the toolkit's self-imposed safety margin under
        the hard 150 KB package cap (kept at the historical 148 KB).
    #>
    [CmdletBinding()]
    param()

    [pscustomobject]@{
        # Authoring class — custom SIT rule packages
        MaxSitsPerRulePackage     = 50
        MaxRulePackageBytes       = 150KB    # 153600 — hard Purview cap
        PreferredRulePackageBytes = 148KB    # 151552 — toolkit margin under the cap
        MaxRulePackagesPerTenant  = 10
        # Keyword dictionary budget (docs conflict 480 KB vs 1 MB; warn early, stop hard)
        DictionaryBudgetWarnBytes = 480KB    # 491520
        DictionaryBudgetMaxBytes  = 1MB      # 1048576
        # Consumption class — auto-labeling (kept here so the two classes are never conflated)
        AutoLabelMaxSitsPerRule   = 125
    }
}
