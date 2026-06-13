function Get-TenantInventory {
    <#
    .SYNOPSIS
        Reads the six SCC object families and returns a normalised tenant inventory.
    .DESCRIPTION
        Shells the read-only SCC cmdlets — Get-DlpKeywordDictionary,
        Get-DlpSensitiveInformationTypeRulePackage, Get-DlpComplianceRule,
        Get-DlpCompliancePolicy, Get-Label, Get-LabelPolicy,
        Get-AutoSensitivityLabelPolicy, Get-AutoSensitivityLabelRule — and folds their
        output into one normalised inventory object (compl8.inventory/v1). One record list
        per object type; every record carries the ours/foreign discriminator so the Engine's
        assess pass can bucket it without re-reading the tenant. Read-only: no mutating cmdlet.

        Offline-first (D7): in CI every read cmdlet is mocked -ModuleName Compl8.Tenant.
        The single real network touch is an operator-run recording into actual/.

    .OUTPUTS
        A compl8.inventory/v1 object:

            schemaVersion : 'compl8.inventory/v1'
            prefix        : the naming prefix used for the ours-discriminator
            generatedUtc  : caller-supplied stamp (or $null — Get-Date is NOT called here)
            tenant        : Get-DeploymentTenantInfo header (name/id/guid/...), or $null
            objects       : an object with one array property per type, each a list of records:
                dictionaries      : { name, identity, ours }
                sitPackages       : { name, identity, ours, publisher, rulePackId }
                dlpRules          : { name, identity, ours, policy, priority, disabled }
                dlpPolicies       : { name, identity, ours, mode }
                labels            : { name, identity, ours, guid }
                labelPolicies     : { name, identity, ours, guid }
                autoLabelPolicies : { name, identity, ours, mode, label }
                autoLabelRules    : { name, identity, ours, policy, workload }

        Every record has at minimum name, identity and ours (boolean). `ours` is true when
        the object name carries the '<Prefix>-' marker (D6: prefix is the primary signal,
        corroborated by the provenance stamp; here the prefix is authoritative). Microsoft /
        foreign objects have ours=$false and are NEVER touched by later layers.

    .PARAMETER Prefix
        Naming prefix (e.g. 'QGISCF') driving the ours-discriminator via Remove-DeploymentNamePrefix.
    .PARAMETER GeneratedUtc
        Optional stamp written verbatim to .generatedUtc. Supplied by the caller so the reader
        stays deterministic in tests (Get-Date is banned here).
    .PARAMETER OutFile
        Optional path. When set, the inventory is also written as JSON to this path.
    .PARAMETER IncludeTenantHeader
        When set, embeds the Get-DeploymentTenantInfo header under .tenant.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Prefix,

        [string]$GeneratedUtc,

        [string]$OutFile,

        [switch]$IncludeTenantHeader
    )

    # --- Discriminator: an object is 'ours' when its name starts with '<Prefix>-' (D6). ---
    # Remove-DeploymentNamePrefix strips the marker; if the name changed, it carried the prefix.
    function Test-Ours {
        param([string]$Name)
        if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
        return (Remove-DeploymentNamePrefix -Name $Name -Prefix $Prefix) -ne $Name
    }

    function Get-Prop {
        param($Object, [string[]]$Names)
        Get-DeploymentObjectProperty -InputObject $Object -Names $Names
    }

    # --- Read the six SCC families. Direct calls (no Get-Command guard) so each is mockable. ---
    $rawDictionaries = @(Get-DlpKeywordDictionary -ErrorAction Stop)
    $rawSitPackages  = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)
    $rawDlpRules     = @(Get-DlpComplianceRule -ErrorAction Stop)
    $rawDlpPolicies  = @(Get-DlpCompliancePolicy -ErrorAction Stop)
    $rawLabels       = @(Get-Label -ErrorAction Stop)
    $rawLabelPols    = @(Get-LabelPolicy -ErrorAction Stop)
    $rawAlPolicies   = @(Get-AutoSensitivityLabelPolicy -ErrorAction Stop)
    $rawAlRules      = @(Get-AutoSensitivityLabelRule -ErrorAction Stop)

    function ConvertTo-Record {
        param(
            $Object,
            [hashtable]$Extra = @{}
        )
        $name = Get-Prop -Object $Object -Names @('Name')
        $identity = Get-Prop -Object $Object -Names @('Identity', 'Name')
        if ([string]::IsNullOrWhiteSpace($name)) { $name = $identity }

        $record = [ordered]@{
            name     = if ($null -ne $name) { [string]$name } else { $null }
            identity = if ($null -ne $identity) { [string]$identity } else { $null }
            ours     = [bool](Test-Ours -Name $name)
        }
        foreach ($key in $Extra.Keys) { $record[$key] = $Extra[$key] }
        [pscustomobject]$record
    }

    $dictionaries = @($rawDictionaries | ForEach-Object { ConvertTo-Record -Object $_ })

    $sitPackages = @($rawSitPackages | ForEach-Object {
        ConvertTo-Record -Object $_ -Extra @{
            publisher  = [string](Get-Prop -Object $_ -Names @('Publisher'))
            rulePackId = [string](Get-Prop -Object $_ -Names @('RulePackId', 'Id'))
        }
    })

    $dlpRules = @($rawDlpRules | ForEach-Object {
        ConvertTo-Record -Object $_ -Extra @{
            policy   = [string](Get-Prop -Object $_ -Names @('Policy', 'ParentPolicyName'))
            priority = Get-Prop -Object $_ -Names @('Priority')
            disabled = [bool](Get-Prop -Object $_ -Names @('Disabled'))
        }
    })

    $dlpPolicies = @($rawDlpPolicies | ForEach-Object {
        ConvertTo-Record -Object $_ -Extra @{
            mode = [string](Get-Prop -Object $_ -Names @('Mode'))
        }
    })

    $labels = @($rawLabels | ForEach-Object {
        ConvertTo-Record -Object $_ -Extra @{
            guid = [string](Get-Prop -Object $_ -Names @('Guid', 'ImmutableId'))
        }
    })

    $labelPolicies = @($rawLabelPols | ForEach-Object {
        ConvertTo-Record -Object $_ -Extra @{
            guid = [string](Get-Prop -Object $_ -Names @('Guid', 'ImmutableId'))
        }
    })

    $autoLabelPolicies = @($rawAlPolicies | ForEach-Object {
        ConvertTo-Record -Object $_ -Extra @{
            mode  = [string](Get-Prop -Object $_ -Names @('Mode'))
            label = [string](Get-Prop -Object $_ -Names @('ApplySensitivityLabel'))
        }
    })

    $autoLabelRules = @($rawAlRules | ForEach-Object {
        ConvertTo-Record -Object $_ -Extra @{
            policy   = [string](Get-Prop -Object $_ -Names @('Policy', 'ParentPolicyName'))
            workload = [string](Get-Prop -Object $_ -Names @('Workload'))
        }
    })

    $tenantHeader = $null
    if ($IncludeTenantHeader) {
        try { $tenantHeader = Get-DeploymentTenantInfo } catch { $tenantHeader = $null }
    }

    $inventory = [pscustomobject][ordered]@{
        schemaVersion = 'compl8.inventory/v1'
        prefix        = $Prefix
        generatedUtc  = if ($GeneratedUtc) { $GeneratedUtc } else { $null }
        tenant        = $tenantHeader
        objects       = [pscustomobject][ordered]@{
            dictionaries      = $dictionaries
            sitPackages       = $sitPackages
            dlpRules          = $dlpRules
            dlpPolicies       = $dlpPolicies
            labels            = $labels
            labelPolicies     = $labelPolicies
            autoLabelPolicies = $autoLabelPolicies
            autoLabelRules    = $autoLabelRules
        }
    }

    if ($OutFile) {
        $dir = Split-Path -Parent $OutFile
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $inventory | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $OutFile -Encoding UTF8
    }

    return $inventory
}
