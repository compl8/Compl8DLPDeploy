#Requires -Modules Pester

# Task 5A-2 (Stage 5 / D2 non-destructive, D3 overlay auto-diff): Convert-ToWorkspace —
# a one-off NON-DESTRUCTIVE migration that reads today's scattered legacy state and writes a
# per-environment workspace (workspaces/<env>/) in the Stage-3+ model, WITHOUT moving or
# deleting any original. Precious files are COPIED and SHA-256 verified.
#
# These tests run entirely on a small hand-built legacy-state fixture under
# tests/fixtures/migration/ copied into TestDrive — they NEVER touch the repo's real config/.

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0

    $script:RepoRoot   = Split-Path $PSScriptRoot -Parent
    $script:ScriptPath = Join-Path $script:RepoRoot 'scripts' 'Convert-ToWorkspace.ps1'
    $script:TenantDir  = Join-Path $script:RepoRoot 'modules' 'Compl8.Tenant'
    $script:FixtureSrc = Join-Path $PSScriptRoot 'fixtures' 'migration'

    # New-Compl8Context (Task 5A-1) must be able to resolve the produced tenant.json.
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:TenantDir -Force

    # Stamp the migration deterministically (Get-Date is banned in deterministic paths).
    $script:Stamp = '2026-06-14T00:00:00Z'

    # Lay down a throwaway copy of the legacy-state fixture and run the migration into it.
    # Returns @{ RepoRoot; WorkspaceRoot; WorkspacePath; Report }.
    function script:Invoke-FixtureMigration {
        param(
            [Parameter(Mandatory)][string]$Dest,
            [string]$Environment = 'nonprod',
            [switch]$WhatIf,
            [switch]$Force,
            [switch]$Verify
        )
        $repo = Join-Path $Dest 'repo'
        Copy-Item -LiteralPath $script:FixtureSrc -Destination $repo -Recurse -Force
        $wsRoot = Join-Path $Dest 'workspaces'
        $params = @{
            Environment   = $Environment
            RepoRoot      = $repo
            WorkspaceRoot = $wsRoot
            GeneratedUtc  = $script:Stamp
        }
        if ($WhatIf)  { $params['WhatIf']  = $true }
        if ($Force)   { $params['Force']   = $true }
        if ($Verify)  { $params['Verify']  = $true }
        $report = & $script:ScriptPath @params
        [pscustomobject]@{
            RepoRoot      = $repo
            WorkspaceRoot = $wsRoot
            WorkspacePath = Join-Path $wsRoot $Environment
            Report        = $report
        }
    }
}

Describe 'Convert-ToWorkspace — fixture sanity' {
    It 'the legacy-state fixture exists and is well-formed' {
        Test-Path -LiteralPath (Join-Path $script:FixtureSrc 'config' 'tenant-fingerprints.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:FixtureSrc 'config' 'tenant-sits.json')         | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:FixtureSrc 'xml' 'deploy' 'deploy-registry.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:FixtureSrc 'reports' 'provenance-registry.json')  | Should -BeTrue
    }
    It 'the migration script exists' {
        Test-Path -LiteralPath $script:ScriptPath | Should -BeTrue
    }
}

Describe 'Convert-ToWorkspace — round-trip workspace tree' {
    BeforeAll {
        $script:RT  = Join-Path $TestDrive 'roundtrip'
        $script:Mig = Invoke-FixtureMigration -Dest $script:RT -Environment 'nonprod'
        $script:Ws  = $script:Mig.WorkspacePath
    }

    It 'writes tenant.json (compl8.tenant/v1) at the workspace root' {
        $tj = Join-Path $script:Ws 'tenant.json'
        Test-Path -LiteralPath $tj | Should -BeTrue
        $doc = Get-Content -LiteralPath $tj -Raw | ConvertFrom-Json
        $doc.schemaVersion       | Should -Be 'compl8.tenant/v1'
        $doc.environment         | Should -Be 'nonprod'
        $doc.identity.tenantId   | Should -Be 'de93acc9-777c-4ac2-bbd6-262fe9063bf5'
        $doc.identity.prefix     | Should -Be 'QGISCF'
        $doc.fingerprint.mode    | Should -Be 'block'
    }

    It 'writes actual/inventory.json adapted to compl8.inventory/v1 from the flat SIT list' {
        $inv = Join-Path $script:Ws 'actual' 'inventory.json'
        Test-Path -LiteralPath $inv | Should -BeTrue
        $raw = Get-Content -LiteralPath $inv -Raw
        # -DateKind String keeps the ISO stamp a verbatim string (default coercion turns it into a
        # [datetime], which restringifies as ...0000000Z — the ON-DISK value is the exact string).
        $doc = $raw | ConvertFrom-Json -DateKind String
        $doc.schemaVersion | Should -Be 'compl8.inventory/v1'
        $doc.prefix        | Should -Be 'QGISCF'
        $doc.generatedUtc  | Should -Be $script:Stamp
        # The inventory carries every required object family (seeded or empty).
        foreach ($fam in 'dictionaries','sitPackages','sits','dlpRules','dlpPolicies','labels','labelPolicies','autoLabelPolicies','autoLabelRules') {
            $doc.objects.PSObject.Properties.Name | Should -Contain $fam
        }
        # 3 SITs from the fixture seed the sits family.
        @($doc.objects.sits).Count | Should -Be 3
        ($doc.objects.sits | Where-Object { $_.name -eq 'ABA Routing Number' }).identity | Should -Be 'cb353f78-2b72-4c3c-8827-92ebe4f69fdf'
    }

    It 'marks the inventory as a partial seed' {
        $doc = Get-Content -LiteralPath (Join-Path $script:Ws 'actual' 'inventory.json') -Raw | ConvertFrom-Json
        $doc.partialSeed | Should -BeTrue
    }

    It 'copies the package XML into desired/resolved and synthesizes resolve-manifest.json' {
        $resolved = Join-Path $script:Ws 'desired' 'resolved'
        Test-Path -LiteralPath (Join-Path $resolved 'QGISCF-medium-08.xml') | Should -BeTrue
        $mf = Join-Path $resolved 'resolve-manifest.json'
        Test-Path -LiteralPath $mf | Should -BeTrue
        $doc = Get-Content -LiteralPath $mf -Raw | ConvertFrom-Json
        $doc.schemaVersion | Should -Be 'compl8.resolve-manifest/v1'
        @($doc.packages).Count | Should -Be 1
        $doc.packages[0].name   | Should -Be 'QGISCF-medium-08'
        $doc.packages[0].file   | Should -Be 'QGISCF-medium-08.xml'
        $doc.packages[0].sha256 | Should -Not -BeNullOrEmpty
    }

    It 'copies the provenance registry VERBATIM into history/applies/provenance.json' {
        Test-Path -LiteralPath (Join-Path $script:Ws 'history' 'applies' 'provenance.json') | Should -BeTrue
    }

    It 'copies backups → history/snapshots, plans → history/plans, logs → history/logs' {
        Test-Path -LiteralPath (Join-Path $script:Ws 'history' 'snapshots') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Ws 'history' 'plans')     | Should -BeTrue
        # the fixture has a backups file and a plans file
        (Get-ChildItem -LiteralPath (Join-Path $script:Ws 'history' 'snapshots') -Recurse -File).Count | Should -BeGreaterThan 0
        (Get-ChildItem -LiteralPath (Join-Path $script:Ws 'history' 'plans')     -Recurse -File).Count | Should -BeGreaterThan 0
    }

    It 'writes history/metadata.json from last-classifier-upload.json' {
        Test-Path -LiteralPath (Join-Path $script:Ws 'history' 'metadata.json') | Should -BeTrue
    }

    It 'writes an EMPTY overlay.json (compl8.overlay/v1) when per-tenant config is an identity-copy of global' {
        $ov = Join-Path $script:Ws 'desired' 'overlay' 'overlay.json'
        Test-Path -LiteralPath $ov | Should -BeTrue
        $doc = Get-Content -LiteralPath $ov -Raw | ConvertFrom-Json
        $doc.schemaVersion | Should -Be 'compl8.overlay/v1'
        @($doc.add).Count      | Should -Be 0
        @($doc.override).Count | Should -Be 0
        @($doc.disable).Count  | Should -Be 0
    }

    It 'writes an empty entity-ledger.json stub (compl8.entity-ledger/v1)' {
        $led = Join-Path $script:Ws 'entity-ledger.json'
        Test-Path -LiteralPath $led | Should -BeTrue
        $doc = Get-Content -LiteralPath $led -Raw | ConvertFrom-Json
        $doc.schemaVersion | Should -Be 'compl8.entity-ledger/v1'
        @($doc.entries).Count  | Should -Be 0
        @($doc.packages).Count | Should -Be 0
    }

    It 'returns a structured migration report' {
        $rpt = $script:Mig.Report
        $rpt.workspace | Should -Be $script:Ws
        $rpt.PSObject.Properties.Name | Should -Contain 'copied'
        $rpt.PSObject.Properties.Name | Should -Contain 'warnings'
        $rpt.PSObject.Properties.Name | Should -Contain 'skipped'
        @($rpt.copied).Count | Should -BeGreaterThan 0
        # every copied entry carries source/target/sha256/bytes
        foreach ($c in $rpt.copied) {
            $c.PSObject.Properties.Name | Should -Contain 'source'
            $c.PSObject.Properties.Name | Should -Contain 'target'
            $c.PSObject.Properties.Name | Should -Contain 'sha256'
            $c.PSObject.Properties.Name | Should -Contain 'bytes'
        }
    }
}

Describe 'Convert-ToWorkspace — non-destructiveness + hash verification' {
    BeforeAll {
        $script:ND  = Join-Path $TestDrive 'nondestructive'
        $script:Mig = Invoke-FixtureMigration -Dest $script:ND -Environment 'nonprod' -Verify
        $script:Ws  = $script:Mig.WorkspacePath
        $script:Repo = $script:Mig.RepoRoot
    }

    It 'leaves the legacy originals untouched (config/, xml/, reports/, backups/, plans/ all still present)' {
        Test-Path -LiteralPath (Join-Path $script:Repo 'config' 'tenant-fingerprints.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Repo 'config' 'tenant-sits.json')         | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Repo 'xml' 'deploy' 'QGISCF-medium-08.xml') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Repo 'reports' 'provenance-registry.json')  | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Repo 'backups')                             | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Repo 'plans')                               | Should -BeTrue
    }

    It 'the provenance registry copy is BYTE-IDENTICAL to the source (Get-FileHash)' {
        $src = Join-Path $script:Repo 'reports' 'provenance-registry.json'
        $dst = Join-Path $script:Ws 'history' 'applies' 'provenance.json'
        (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash | Should -Be (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash
    }

    It 'the copied package XML is BYTE-IDENTICAL to the source' {
        $src = Join-Path $script:Repo 'xml' 'deploy' 'QGISCF-medium-08.xml'
        $dst = Join-Path $script:Ws 'desired' 'resolved' 'QGISCF-medium-08.xml'
        (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash | Should -Be (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash
    }

    It 'the report records the package sha256 matching the on-disk source hash' {
        $src = Join-Path $script:Repo 'xml' 'deploy' 'QGISCF-medium-08.xml'
        $srcHash = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash.ToLowerInvariant()
        $entry = $script:Mig.Report.copied | Where-Object { $_.target -like '*QGISCF-medium-08.xml' } | Select-Object -First 1
        $entry | Should -Not -BeNullOrEmpty
        $entry.sha256 | Should -Be $srcHash
    }
}

Describe 'Convert-ToWorkspace — -WhatIf writes nothing' {
    It 'creates no workspace directory and returns a plan' {
        $wf = Join-Path $TestDrive 'whatif'
        $mig = Invoke-FixtureMigration -Dest $wf -Environment 'nonprod' -WhatIf
        Test-Path -LiteralPath $mig.WorkspacePath | Should -BeFalse
        # the plan still enumerates the intended copies
        @($mig.Report.copied).Count | Should -BeGreaterThan 0
        $mig.Report.PSObject.Properties.Name | Should -Contain 'whatIf'
        $mig.Report.whatIf | Should -BeTrue
    }
}

Describe 'Convert-ToWorkspace — idempotency / re-run policy' {
    It 'refuses to overwrite an existing workspace without -Force' {
        $ir = Join-Path $TestDrive 'idem-refuse'
        $first = Invoke-FixtureMigration -Dest $ir -Environment 'nonprod'
        Test-Path -LiteralPath $first.WorkspacePath | Should -BeTrue
        # second run, same dest repo+ws, no -Force: must throw rather than corrupt.
        $wsRoot = $first.WorkspaceRoot
        { & $script:ScriptPath -Environment 'nonprod' -RepoRoot $first.RepoRoot -WorkspaceRoot $wsRoot -GeneratedUtc $script:Stamp } |
            Should -Throw '*already exists*'
    }

    It 're-running with -Force does not corrupt the workspace (precious files stay byte-identical)' {
        $if = Join-Path $TestDrive 'idem-force'
        $first = Invoke-FixtureMigration -Dest $if -Environment 'nonprod'
        $provBefore = (Get-FileHash -LiteralPath (Join-Path $first.WorkspacePath 'history' 'applies' 'provenance.json') -Algorithm SHA256).Hash
        # re-run with -Force over the SAME repo + ws root
        $report = & $script:ScriptPath -Environment 'nonprod' -RepoRoot $first.RepoRoot -WorkspaceRoot $first.WorkspaceRoot -GeneratedUtc $script:Stamp -Force -Verify
        $provAfter = (Get-FileHash -LiteralPath (Join-Path $first.WorkspacePath 'history' 'applies' 'provenance.json') -Algorithm SHA256).Hash
        $provAfter | Should -Be $provBefore
        $srcHash = (Get-FileHash -LiteralPath (Join-Path $first.RepoRoot 'reports' 'provenance-registry.json') -Algorithm SHA256).Hash
        $provAfter | Should -Be $srcHash
    }
}

Describe 'Convert-ToWorkspace — overlay auto-diff (D3)' {
    It 'a per-tenant config file that DIFFERS from global lands in overlay/_unmapped + a warning' {
        $od = Join-Path $TestDrive 'overlay-diff'
        $repo = Join-Path $od 'repo'
        Copy-Item -LiteralPath $script:FixtureSrc -Destination $repo -Recurse -Force
        # Make the per-tenant labels.json DIFFER from the global one.
        $perTenant = Join-Path $repo 'config' 'tenants' 'nonprod' 'labels.json'
        Set-Content -LiteralPath $perTenant -Value '{"labels":[{"name":"CUSTOM-DIVERGENT"}]}' -Encoding UTF8
        $wsRoot = Join-Path $od 'workspaces'
        $report = & $script:ScriptPath -Environment 'nonprod' -RepoRoot $repo -WorkspaceRoot $wsRoot -GeneratedUtc $script:Stamp
        $ws = Join-Path $wsRoot 'nonprod'
        Test-Path -LiteralPath (Join-Path $ws 'desired' 'overlay' '_unmapped' 'labels.json') | Should -BeTrue
        @($report.warnings | Where-Object { $_ -like '*labels.json*' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Convert-ToWorkspace — missing sources are skipped not errors' {
    It 'skips a missing backups/ directory with a note, not an error' {
        $ms = Join-Path $TestDrive 'missing-src'
        $repo = Join-Path $ms 'repo'
        Copy-Item -LiteralPath $script:FixtureSrc -Destination $repo -Recurse -Force
        Remove-Item -LiteralPath (Join-Path $repo 'backups') -Recurse -Force
        $wsRoot = Join-Path $ms 'workspaces'
        $report = & $script:ScriptPath -Environment 'nonprod' -RepoRoot $repo -WorkspaceRoot $wsRoot -GeneratedUtc $script:Stamp
        @($report.skipped | Where-Object { $_ -like '*backups*' }).Count | Should -BeGreaterThan 0
        # the rest of the migration still succeeded
        Test-Path -LiteralPath (Join-Path $wsRoot 'nonprod' 'tenant.json') | Should -BeTrue
    }
}

Describe 'Convert-ToWorkspace — New-Compl8Context resolves the produced tenant.json (round-trip with 5A-1)' {
    It 'New-Compl8Context reads the migrated tenant.json back' {
        $rt = Join-Path $TestDrive 'ctx-roundtrip'
        $mig = Invoke-FixtureMigration -Dest $rt -Environment 'nonprod'
        $ctx = New-Compl8Context -TargetEnvironment 'nonprod' -WorkspaceRoot $mig.WorkspaceRoot
        $ctx.Environment     | Should -Be 'nonprod'
        $ctx.TenantId        | Should -Be 'de93acc9-777c-4ac2-bbd6-262fe9063bf5'
        $ctx.Prefix          | Should -Be 'QGISCF'
        $ctx.FingerprintMode | Should -Be 'block'
        $ctx.WorkspacePath   | Should -Be $mig.WorkspacePath
    }
}

Describe 'Convert-ToWorkspace — helper: ConvertFrom-LegacyTenantSits' {
    BeforeAll {
        Import-Module $script:TenantDir -Force
    }
    It 'adapts a flat SIT array into a compl8.inventory/v1 partial seed' {
        $sits = @(
            [pscustomobject]@{ Name = 'Alpha'; Id = '11111111-1111-1111-1111-111111111111'; Publisher = 'Microsoft Corporation' }
            [pscustomobject]@{ Name = 'Beta';  Id = '22222222-2222-2222-2222-222222222222'; Publisher = 'QGISCF' }
        )
        $inv = ConvertFrom-LegacyTenantSits -Sits $sits -Prefix 'QGISCF' -GeneratedUtc $script:Stamp
        $inv.schemaVersion | Should -Be 'compl8.inventory/v1'
        $inv.prefix        | Should -Be 'QGISCF'
        $inv.generatedUtc  | Should -Be $script:Stamp
        $inv.partialSeed   | Should -BeTrue
        @($inv.objects.sits).Count        | Should -Be 2
        @($inv.objects.sitPackages).Count | Should -Be 2
        # ours-discriminator: a SIT carrying the prefix as a name token is ours; Microsoft is not.
        ($inv.objects.sits | Where-Object { $_.name -eq 'Alpha' }).ours | Should -BeFalse
    }
}

Describe 'Convert-ToWorkspace — -Environment validation (P1 safety: reject unsafe keys BEFORE any destructive op)' {
    # An unsafe -Environment must be rejected at the TOP of the script — before the workspace path is
    # computed or the -Force recursive delete is reachable. A `..` or a path separator could otherwise
    # make Join-Path $WorkspaceRoot $Environment resolve OUTSIDE the intended workspace and let -Force
    # delete an unrelated directory. The no-delete proof plants a SENTINEL dir a traversal env would
    # reach and asserts it (and the real workspace) survive a throwing run with -Force.

    It 'rejects -Environment ".." with a clear error naming the bad value and DELETES NOTHING' {
        $base   = Join-Path $TestDrive 'p1-dotdot'
        $repo   = Join-Path $base 'repo'
        Copy-Item -LiteralPath $script:FixtureSrc -Destination $repo -Recurse -Force
        $wsRoot = Join-Path $base 'workspaces'

        # SENTINEL: a dir SIBLING to the workspace root that `..` traversal (Join-Path $wsRoot '..')
        # resolves into — it MUST survive.
        $sentinel = Join-Path $base 'sentinel-keepme'
        New-Item -ItemType Directory -Path $sentinel -Force | Out-Null
        $sentinelFile = Join-Path $sentinel 'precious.txt'
        Set-Content -LiteralPath $sentinelFile -Value 'do-not-delete' -Encoding UTF8

        # Even WITH -Force the validation must fire first; the message must flag the env as unsafe AND
        # echo the bad value. (The distinctive 'unsafe' marker proves it is the SAFETY rejection, not an
        # incidental downstream error such as 'no entry for environment ..'.)
        { & $script:ScriptPath -Environment '..' -RepoRoot $repo -WorkspaceRoot $wsRoot -GeneratedUtc $script:Stamp -Force } |
            Should -Throw "*'..' is unsafe*"

        # NO delete happened: the sentinel and its file are untouched.
        Test-Path -LiteralPath $sentinelFile | Should -BeTrue
        (Get-Content -LiteralPath $sentinelFile -Raw).Trim() | Should -Be 'do-not-delete'
    }

    It 'rejects -Environment "a/b" (path separator) with the VALIDATION error and DELETES NOTHING' {
        $base   = Join-Path $TestDrive 'p1-slash'
        $repo   = Join-Path $base 'repo'
        Copy-Item -LiteralPath $script:FixtureSrc -Destination $repo -Recurse -Force
        $wsRoot = Join-Path $base 'workspaces'
        $sentinel = Join-Path $wsRoot 'a'
        New-Item -ItemType Directory -Path $sentinel -Force | Out-Null
        $sentinelFile = Join-Path $sentinel 'keep.txt'
        Set-Content -LiteralPath $sentinelFile -Value 'keep' -Encoding UTF8

        # Must be the explicit SAFETY rejection (the 'unsafe' marker + the bad value), NOT an incidental
        # downstream error such as 'no entry for environment a/b'.
        { & $script:ScriptPath -Environment 'a/b' -RepoRoot $repo -WorkspaceRoot $wsRoot -GeneratedUtc $script:Stamp -Force } |
            Should -Throw "*'a/b' is unsafe*"

        Test-Path -LiteralPath $sentinelFile | Should -BeTrue
    }

    It 'rejects -Environment "a\b" (backslash separator) with the VALIDATION error before any work' {
        $base   = Join-Path $TestDrive 'p1-backslash'
        $repo   = Join-Path $base 'repo'
        Copy-Item -LiteralPath $script:FixtureSrc -Destination $repo -Recurse -Force
        $wsRoot = Join-Path $base 'workspaces'
        { & $script:ScriptPath -Environment 'a\b' -RepoRoot $repo -WorkspaceRoot $wsRoot -GeneratedUtc $script:Stamp -Force } |
            Should -Throw "*is unsafe*path separator*"
    }

    It 'rejects an empty -Environment with the VALIDATION error' {
        $base   = Join-Path $TestDrive 'p1-empty'
        $repo   = Join-Path $base 'repo'
        Copy-Item -LiteralPath $script:FixtureSrc -Destination $repo -Recurse -Force
        $wsRoot = Join-Path $base 'workspaces'
        { & $script:ScriptPath -Environment '   ' -RepoRoot $repo -WorkspaceRoot $wsRoot -GeneratedUtc $script:Stamp -Force } |
            Should -Throw "*unsafe*"
    }

    It 'still accepts a normal safe environment key (regression guard)' {
        $base = Join-Path $TestDrive 'p1-ok'
        $mig  = Invoke-FixtureMigration -Dest $base -Environment 'nonprod'
        Test-Path -LiteralPath (Join-Path $mig.WorkspacePath 'tenant.json') | Should -BeTrue
    }
}

Describe 'Convert-ToWorkspace — helper: New-WorkspaceTenantJson' {
    BeforeAll {
        Import-Module $script:TenantDir -Force
    }
    It 'maps a fingerprint env entry + prefix into the compl8.tenant/v1 shape' {
        $tj = New-WorkspaceTenantJson -Environment 'nonprod' `
            -FingerprintEntry ([pscustomobject]@{ mode = 'block'; tenantId = 'de93acc9-777c-4ac2-bbd6-262fe9063bf5'; name = 'Contoso' }) `
            -Prefix 'QGISCF' -Settings ([pscustomobject]@{ namingSuffix = 'EXT-ADT' })
        $tj.schemaVersion     | Should -Be 'compl8.tenant/v1'
        $tj.environment       | Should -Be 'nonprod'
        $tj.identity.tenantId | Should -Be 'de93acc9-777c-4ac2-bbd6-262fe9063bf5'
        $tj.identity.prefix   | Should -Be 'QGISCF'
        $tj.fingerprint.mode  | Should -Be 'block'
        $tj.settings.namingSuffix | Should -Be 'EXT-ADT'
    }
}
