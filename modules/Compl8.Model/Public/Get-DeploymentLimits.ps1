function Get-DeploymentLimits {
    <#
    .SYNOPSIS
        Single source of truth for Microsoft Purview SIT/dictionary limits.
    .DESCRIPTION
        AUTHORING-class limits (custom SIT rule packages) are a DIFFERENT limit class
        from auto-labeling CONSUMPTION limits. Do not conflate: the authoring cap is
        50 SITs per rule package; 125 is the max SITs referenced by a single
        auto-labeling rule.

        MaxRulePackageBytes is the PRACTICAL per-package upload cap: 770 KB UTF-16.
        The sit-limits page (https://learn.microsoft.com/purview/sit-limits) quotes
        "150 KB", but that is NOT the real upload limit — it was empirically falsified
        LIVE on compl8.dev (EXO 3.9.2), where New-DlpSensitiveInformationTypeRulePackage
        accepted packages up to at least 1000 KB UTF-16. The MS PowerShell authoring
        page (sit-create-a-custom-sensitive-information-type-in-scc-powershell, item 13)
        documents the real guidance: "keep the uploaded file limited to a 770 KB maximum"
        (tied to a ~1 MB deserialized-data limit). The uploaded file is Unicode/UTF-16.
        PreferredRulePackageBytes is the toolkit's self-imposed safety margin (760 KB)
        under that 770 KB cap.
        All *Bytes limits are measured UTF-16LE (Purview enforces the cap on the
        uploaded UTF-16 file).
    #>
    [CmdletBinding()]
    param()

    [pscustomobject]@{
        # Authoring class — custom SIT rule packages
        MaxSitsPerRulePackage     = 50
        MaxRulePackageBytes       = 770KB    # 788480 — practical Purview upload cap (UTF-16), empirically verified on compl8.dev
        PreferredRulePackageBytes = 760KB    # 778240 — toolkit margin under the cap
        MaxRulePackagesPerTenant  = 10
        ReservedManualPackages    = 1        # automated build uses MaxRulePackagesPerTenant - this; 10th left for manual adds
        # Keyword dictionary budget (docs conflict 480 KB vs 1 MB; warn early, stop hard)
        DictionaryBudgetWarnBytes = 480KB    # 491520
        DictionaryBudgetMaxBytes  = 1MB      # 1048576
        # Consumption class — auto-labeling (kept here so the two classes are never conflated)
        AutoLabelMaxSitsPerRule   = 125
    }
}
