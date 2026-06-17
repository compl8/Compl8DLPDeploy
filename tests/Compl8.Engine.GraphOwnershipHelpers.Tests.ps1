#Requires -Modules Pester

# =====================================================================================
# Shared helpers extracted for the reconcile-walk risk surfacing:
#   Get-Compl8OwnershipMap     — inventory -> { identifier -> ours } (for the risk strategist).
#   Get-Compl8ReferenceGraph   — workspace desired packages + actual rules -> graph; -IncludeActualSits
#                                registers actual (incl. retired) sit GUIDs so removal blast-radius works.
# Both are reused by Invoke-Compl8Deploy, the reconcile verb and the [M] walk so they reason over the
# same graph + ownership.
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $script:RepoRoot 'modules' 'Compl8.Engine') -Force
    $script:ResolvedDir = Join-Path $script:RepoRoot 'tests' 'fixtures' 'engine' 'e2e' 'desired' 'resolved'
    $script:Inv = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'tests' 'fixtures' 'engine' 'e2e' 'actual' 'inventory.json') -Raw | ConvertFrom-Json
}

Describe 'Get-Compl8OwnershipMap' {
    It 'maps rules/sits by identifier to their ours flag (sits by GUID lowercased + by name)' {
        $inv = [pscustomobject]@{ objects = [pscustomobject]@{
            dlpRules     = @([pscustomobject]@{ name = 'Our-Rule'; ours = $true }, [pscustomobject]@{ name = 'Foreign-Rule'; ours = $false })
            dlpPolicies  = @()
            sits         = @([pscustomobject]@{ name = 'sit-a'; identity = 'AAAA-GUID'; ours = $true })
            sitPackages  = @([pscustomobject]@{ name = 'OurPkg'; ours = $true })
            dictionaries = @([pscustomobject]@{ name = 'D1'; ours = $false })
        } }
        $map = Get-Compl8OwnershipMap -Inventory $inv
        $map['Our-Rule']      | Should -BeTrue
        $map['Foreign-Rule']  | Should -BeFalse
        $map['aaaa-guid']     | Should -BeTrue   # sit keyed by GUID, lowercased
        $map['sit-a']         | Should -BeTrue
        $map['OurPkg']        | Should -BeTrue
        $map['D1']            | Should -BeFalse
    }
    It 'is robust to a minimal inventory' {
        (Get-Compl8OwnershipMap -Inventory ([pscustomobject]@{ objects = [pscustomobject]@{} })) | Should -BeOfType ([hashtable])
    }
}

Describe 'Get-Compl8ReferenceGraph' {
    It 'is exported and builds a graph from the workspace desired packages + inventory rules' {
        (Get-Command -Name Get-Compl8ReferenceGraph -Module Compl8.Engine -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        $g = Get-Compl8ReferenceGraph -ResolvedDir $script:ResolvedDir -Inventory $script:Inv
        @($g.Nodes).Count | Should -BeGreaterThan 0
    }
    It 'resolves labels from -ConfigRoot first (mirroring assess''s chain) so the graph matches the assessment' {
        # A temp config root with a labels.json; the graph should pick up the label node from it.
        $cfg = Join-Path ([System.IO.Path]::GetTempPath()) ("compl8cfg-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $cfg -Force | Out-Null
        try {
            @([pscustomobject]@{ code = 'ZZZ'; name = 'ZZZ-FromConfigRoot' }) | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $cfg 'labels.json') -Encoding UTF8
            $g = Get-Compl8ReferenceGraph -ResolvedDir $script:ResolvedDir -Inventory $script:Inv -ConfigRoot $cfg
            @($g.Nodes | Where-Object { $_.Type -eq 'Label' -and $_.Name -eq 'ZZZ-FromConfigRoot' }).Count | Should -Be 1
        } finally { Remove-Item -LiteralPath $cfg -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It '-IncludeActualSits registers the actual sit GUIDs as nodes (so removal blast-radius sees them)' {
        $g = Get-Compl8ReferenceGraph -ResolvedDir $script:ResolvedDir -Inventory $script:Inv -IncludeActualSits
        $sitNodes = @($g.Nodes | Where-Object { $_.Type -eq 'SensitiveInformationType' })
        # every actual sit GUID from the inventory is present as a sit node
        foreach ($s in @($script:Inv.objects.sits)) {
            if (-not $s.identity) { continue }
            @($sitNodes | Where-Object { ([string]$_.Identity).ToLowerInvariant() -eq ([string]$s.identity).ToLowerInvariant() }).Count |
                Should -BeGreaterThan 0 -Because "actual sit $($s.identity) must be a graph node under -IncludeActualSits"
        }
    }
}
