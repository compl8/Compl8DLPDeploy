function Get-Compl8ReferenceGraph {
    <#
    .SYNOPSIS
        Builds the engine reference graph for a workspace from its DESIRED packages + an inventory's ACTUAL
        rules — the single source of graph-building shared by the deploy verb, the reconcile walk and the
        risk strategist, so they all reason over the same edges.

    .DESCRIPTION
        Reads the desired packages (real XML, carrying entity GUIDs + dictionary idRefs) from
        <ResolvedDir>/resolve-manifest.json and feeds them with the inventory's actual DLP rules /
        dictionaries / policies (and labels from the workspace config) to Get-DeploymentReferenceGraph —
        identically to Invoke-Compl8Assess, so ordering / impact roll-up / dereference generation see the
        same graph.

        -IncludeActualSits additionally makes every ACTUAL sit GUID known via synthetic entity-only
        packages built from the inventory's sitPackages.entityIds — INCLUDING retired sits no longer in any
        desired package. This is required for risk/blast-radius analysis of a removal: without it a removal
        of a retired sit still referenced by a foreign rule would show no downstream impact. (The desired
        XML still supplies the dictionary->sit edges; a dictionary feeding ONLY a retired sit is the one
        relationship not reconstructable from recorded state — see Get-Compl8ChangeRisk's dictionary
        hand-back.)

    .PARAMETER ResolvedDir
        The workspace's desired/resolved directory (contains resolve-manifest.json + the package XML).

    .PARAMETER Inventory
        A parsed compl8.inventory/v1 object (actual rules / sits / dictionaries / policies / packages).

    .PARAMETER IncludeActualSits
        Also register actual (incl. retired) sit GUIDs from the inventory so removal blast-radius sees
        their referencing rules.

    .OUTPUTS
        A Get-DeploymentReferenceGraph result (Nodes / Edges / Summary).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResolvedDir,
        [Parameter(Mandatory)][pscustomobject]$Inventory,
        [switch]$IncludeActualSits
    )

    $manifest = Get-Content -LiteralPath (Join-Path $ResolvedDir 'resolve-manifest.json') -Raw | ConvertFrom-Json
    $graphPackages = @(foreach ($pkg in @($manifest.packages)) {
        $pkgFile = Join-Path $ResolvedDir ([string]$pkg.file)
        if (-not $pkg.file -or -not (Test-Path -LiteralPath $pkgFile -PathType Leaf)) { continue }
        [pscustomobject]@{
            Identity = [string]$pkg.name; Name = [string]$pkg.name; Publisher = 'Compl8'
            SerializedClassificationRuleCollection = (Get-Content -LiteralPath $pkgFile -Raw)
        }
    })
    if ($IncludeActualSits) {
        foreach ($pk in @($Inventory.objects.sitPackages)) {
            $ents = (@($pk.entityIds) | Where-Object { $_ } | ForEach-Object { "<Entity id=`"$([string]$_)`" />" }) -join ''
            if (-not $ents) { continue }
            $graphPackages += [pscustomobject]@{
                Identity = [string]$pk.identity; Name = [string]$pk.name; Publisher = [string]$pk.publisher
                SerializedClassificationRuleCollection = "<RulePackage xmlns=`"http://schemas.microsoft.com/office/2011/mce`"><Rules>$ents</Rules></RulePackage>"
            }
        }
    }
    $graphRules = @(foreach ($rule in @($Inventory.objects.dlpRules)) {
        [pscustomobject]@{
            Name = [string]$rule.name; Identity = [string]$rule.identity; Policy = [string]$rule.policy
            ContentContainsSensitiveInformation = $rule.contentContainsSensitiveInformation
        }
    })
    $wsRoot = Split-Path (Split-Path $ResolvedDir -Parent) -Parent
    $graphLabels = @()
    foreach ($cand in @((Join-Path (Join-Path $wsRoot 'desired') 'config'), (Join-Path $wsRoot 'config'))) {
        $labelsPath = Join-Path $cand 'labels.json'
        if (Test-Path -LiteralPath $labelsPath -PathType Leaf) {
            try { $graphLabels = @(Get-Content -LiteralPath $labelsPath -Raw | ConvertFrom-Json) } catch { $graphLabels = @() }
            break
        }
    }
    Get-DeploymentReferenceGraph -Dictionaries @($Inventory.objects.dictionaries) -SitPackages $graphPackages `
        -DlpRules $graphRules -DlpPolicies @($Inventory.objects.dlpPolicies) -Labels $graphLabels
}
