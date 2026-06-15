function ConvertFrom-LegacyTenantSits {
    <#
    .SYNOPSIS
        Adapts the flat legacy config/tenant-sits.json SIT array into a compl8.inventory/v1 PARTIAL
        seed (the Get-TenantInventory shape), for Convert-ToWorkspace to write as actual/inventory.json.
    .DESCRIPTION
        Stage 5 / Task 5A-2 helper. Pure transform — no file IO, no live tenant call, no Get-Date.

        The legacy file is a flat array: [{ Name; Id; Publisher }]. That carries ONLY SIT identity
        (name + GUID + publisher) — it has none of the rich rule/package/dictionary/label content a
        real Get-TenantInventory recording captures. So this is a deliberate PARTIAL SEED:

          * objects.sits[]        — one record per legacy SIT { name; identity (Id); ours; package(null);
                                     contentHash(null) }. (No package membership or content hash is
                                     recoverable from the flat list.)
          * objects.sitPackages[] — one lightweight record per SIT { name; identity; ours; publisher;
                                     rulePackId(Id); entityIds([Id]); sits([name]); sha256(null);
                                     contentHash(null) }. The flat list has no notion of multi-entity
                                     packages, so each SIT is surfaced as its own one-entity stand-in.
          * every other family    — dictionaries / dlpRules / dlpPolicies / labels / labelPolicies /
                                     autoLabelPolicies / autoLabelRules — EMPTY arrays. A later real
                                     Get-TenantInventory recording (operator-run, against the tenant)
                                     fills these in; this seed exists only so the workspace VALIDATES
                                     and assess has the SIT identities to join on in the meantime.

        The record is stamped .partialSeed = $true so downstream readers (and the operator) know it
        is identity-only and a real recording is still owed. The discriminator matches
        Get-TenantInventory: a name carrying the prefix START marker ('<Prefix>-') is ours.
    .PARAMETER Sits
        The deserialized flat SIT array ([{ Name; Id; Publisher }, ...]). $null/empty => empty seed.
    .PARAMETER Prefix
        The naming prefix used for the ours-discriminator and stamped on the inventory.
    .PARAMETER GeneratedUtc
        Caller-supplied stamp written verbatim to .generatedUtc (Get-Date is banned here).
    .OUTPUTS
        A compl8.inventory/v1 pscustomobject (with an extra .partialSeed flag), ready to ConvertTo-Json.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [object[]]$Sits,

        [Parameter(Mandatory)]
        [string]$Prefix,

        [string]$GeneratedUtc
    )

    # ours when the name starts with '<Prefix>-' (mirrors Get-TenantInventory's discriminator for
    # SITs/packages). Kept inline so the helper has no hard dependency on a Model cmdlet signature.
    $prefixMarker = if ([string]::IsNullOrWhiteSpace($Prefix)) { $null } else { "$Prefix-" }
    function Test-OursName {
        param([string]$Name)
        if ([string]::IsNullOrWhiteSpace($Name) -or -not $prefixMarker) { return $false }
        return $Name.StartsWith($prefixMarker, [System.StringComparison]::OrdinalIgnoreCase)
    }

    $sitRecords = [System.Collections.Generic.List[object]]::new()
    $pkgRecords = [System.Collections.Generic.List[object]]::new()

    foreach ($sit in @($Sits)) {
        if ($null -eq $sit) { continue }
        $name = if ($sit.PSObject.Properties['Name']) { [string]$sit.Name } else { $null }
        $id   = if ($sit.PSObject.Properties['Id'])   { [string]$sit.Id }   else { $null }
        $pub  = if ($sit.PSObject.Properties['Publisher']) { [string]$sit.Publisher } else { $null }
        $ours = [bool](Test-OursName -Name $name)

        $sitRecords.Add([pscustomobject][ordered]@{
            name        = $name
            identity    = $id
            ours        = $ours
            package     = $null
            contentHash = $null
        }) | Out-Null

        $pkgRecords.Add([pscustomobject][ordered]@{
            name        = $name
            identity    = $id
            ours        = $ours
            publisher   = $pub
            rulePackId  = $id
            entityIds   = @($id | Where-Object { $_ })
            sits        = @($name | Where-Object { $_ })
            sha256      = $null
            contentHash = $null
        }) | Out-Null
    }

    [pscustomobject]([ordered]@{
        schemaVersion = 'compl8.inventory/v1'
        prefix        = $Prefix
        generatedUtc  = if ($GeneratedUtc) { $GeneratedUtc } else { $null }
        partialSeed   = $true
        tenant        = $null
        objects       = [pscustomobject]([ordered]@{
            dictionaries      = @()
            sitPackages       = @($pkgRecords)
            sits              = @($sitRecords)
            dlpRules          = @()
            dlpPolicies       = @()
            labels            = @()
            labelPolicies     = @()
            autoLabelPolicies = @()
            autoLabelRules    = @()
        })
    })
}
