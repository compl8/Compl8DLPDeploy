#Requires -Modules Pester

# =====================================================================================
# Invoke-Compl8Assess — NAME-COLLISION conflict detection.
#
# A desired object whose NAME is held by a NOT-OURS (foreign) actual is a silent deploy
# blocker: the engine will neither overwrite the foreign object (opacity-as-safety) nor
# create a duplicate name — so the desired object never deploys, and prior to this the
# assessment said nothing (no create, no conflict). Assess now emits it natively as an
# upgradeConflicts entry { slug; kind='name-collision'; detail } so the plan/report shows
# it. (Surfaced from a real compl8.dev recording: 48 desired DLP rules were silently
# blocked by an older deployment's rules squatting the same names.)
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot  = Split-Path $PSScriptRoot -Parent
    $script:EngineDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:EngineDir -Force

    # A minimal self-contained workspace: an empty-package resolve manifest + a persisted desired
    # dlp-rules.json (the Stage-5 re-point source assess reads directly), so the desired rule set is
    # known without resolving config. The actual side is injected per-test.
    function script:New-CollisionWorkspace {
        $ws = Join-Path ([System.IO.Path]::GetTempPath()) ("nc-ws-" + [guid]::NewGuid().ToString('N'))
        $resolved = Join-Path $ws 'desired' 'resolved'
        New-Item -ItemType Directory -Path $resolved -Force | Out-Null
        ([ordered]@{ schemaVersion = 'compl8.resolve-manifest/v1'; generatedUtc = '2026-06-13T00:00:00Z'; packing = [ordered]@{ assignments = [ordered]@{} }; packages = @(); warnings = @() } |
            ConvertTo-Json -Depth 12) | Set-Content -LiteralPath (Join-Path $resolved 'resolve-manifest.json') -Encoding UTF8
        ([ordered]@{ schemaVersion = 'compl8.dlp-rules/v1'; rules = @([ordered]@{ ruleName = 'P01-R01-ECH-OFFI'; contentHash = 'sha256:desired1' }); policies = @() } |
            ConvertTo-Json -Depth 12) | Set-Content -LiteralPath (Join-Path $resolved 'dlp-rules.json') -Encoding UTF8
        $ws
    }
    function script:New-Inv {
        param([object[]]$DlpRules = @())
        [pscustomobject]@{ schemaVersion = 'compl8.inventory/v1'; objects = [pscustomobject]@{
            sitPackages = @(); sits = @(); dictionaries = @(); dlpRules = @($DlpRules); dlpPolicies = @(); autoLabelPolicies = @() } }
    }
    function script:Conflicts { param($A, [string]$Kind) @($A.upgradeConflicts | Where-Object { $_.kind -eq $Kind }) }
    function script:Refs { param($A, [string]$Bucket) @($A.buckets.$Bucket | Where-Object { $_.objectType -eq 'dlpRule' } | ForEach-Object { $_.ref }) }
}

Describe 'Invoke-Compl8Assess — name-collision against a foreign object' {
    AfterEach { if ($script:ws -and (Test-Path -LiteralPath $script:ws)) { Remove-Item -LiteralPath $script:ws -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'emits a name-collision conflict when a FOREIGN actual holds a desired name (and does NOT create it)' {
        $script:ws = New-CollisionWorkspace
        $inv = New-Inv -DlpRules @([pscustomobject]@{ name = 'P01-R01-ECH-OFFI'; identity = 'r1'; ours = $false; contentHash = 'sha256:other' })
        $a = Invoke-Compl8Assess -WorkspacePath $script:ws -Inventory $inv -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'

        $nc = Conflicts $a 'name-collision'
        $nc.Count           | Should -Be 1
        $nc[0].slug         | Should -Be 'P01-R01-ECH-OFFI'
        $nc[0].detail       | Should -Match 'foreign'
        # It must NOT appear as a create (the name is taken)...
        (Refs $a 'create')  | Should -Not -Contain 'P01-R01-ECH-OFFI'
        # ...and the foreign object is still reported foreign.
        (Refs $a 'foreign') | Should -Contain 'P01-R01-ECH-OFFI'
    }

    It 'does NOT flag a collision when the actual holding the name is OURS (it is drift, reconciled in place)' {
        $script:ws = New-CollisionWorkspace
        $inv = New-Inv -DlpRules @([pscustomobject]@{ name = 'P01-R01-ECH-OFFI'; identity = 'r1'; ours = $true; contentHash = 'sha256:other' })
        $a = Invoke-Compl8Assess -WorkspacePath $script:ws -Inventory $inv -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'

        (Conflicts $a 'name-collision') | Should -BeNullOrEmpty
        (Refs $a 'drift')               | Should -Contain 'P01-R01-ECH-OFFI'
    }

    It 'does NOT flag a collision when no actual holds the name (it is a clean create)' {
        $script:ws = New-CollisionWorkspace
        $inv = New-Inv -DlpRules @()
        $a = Invoke-Compl8Assess -WorkspacePath $script:ws -Inventory $inv -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z'

        (Conflicts $a 'name-collision') | Should -BeNullOrEmpty
        (Refs $a 'create')              | Should -Contain 'P01-R01-ECH-OFFI'
    }

    It 'runs under Set-StrictMode against a persisted dlp-rules.json (SOURCE 1) workspace without throwing (R1 graph-label lookup)' {
        # codex R1 review: the R1 graph-label lookup reads $configSource, which is only assigned in the
        # SOURCE 2/3 fallback. On a SOURCE-1 (dlp-rules.json) workspace a Set-StrictMode caller would throw
        # on the unassigned variable. This guards the hoisted initialisation.
        $script:ws = New-CollisionWorkspace
        $inv = New-Inv -DlpRules @()
        { & { Set-StrictMode -Version Latest
              Invoke-Compl8Assess -WorkspacePath $script:ws -Inventory $inv -Workspace 'nonprod' -GeneratedUtc '2026-06-13T00:00:00Z' | Out-Null } } |
            Should -Not -Throw
    }
}
