#Requires -Modules Pester

BeforeAll {
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    $script:ContentDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Content'
    $script:FixtureRoot = Join-Path $PSScriptRoot 'fixtures' 'content'
    Import-Module $script:ContentDir -Force
}

Describe 'Get-Compl8WorkspacePath' {
    BeforeEach {
        $script:SavedRoot = $env:COMPL8_WORKSPACE_ROOT
    }
    AfterEach {
        if ($null -ne $script:SavedRoot) { $env:COMPL8_WORKSPACE_ROOT = $script:SavedRoot }
        else { Remove-Item Env:\COMPL8_WORKSPACE_ROOT -ErrorAction SilentlyContinue }
    }

    It 'defaults to <repo>\workspaces when COMPL8_WORKSPACE_ROOT is unset' {
        Remove-Item Env:\COMPL8_WORKSPACE_ROOT -ErrorAction SilentlyContinue
        $expected = Join-Path $script:RepoRoot 'workspaces' 'nonprod'
        Get-Compl8WorkspacePath -Environment nonprod | Should -Be $expected
    }

    It 'honours COMPL8_WORKSPACE_ROOT when set' {
        $env:COMPL8_WORKSPACE_ROOT = Join-Path $TestDrive 'wsroot'
        Get-Compl8WorkspacePath -Environment nonprod |
            Should -Be (Join-Path $TestDrive 'wsroot' 'nonprod')
    }

    It 'joins a forward-slash subpath under the environment' {
        $env:COMPL8_WORKSPACE_ROOT = Join-Path $TestDrive 'wsroot'
        Get-Compl8WorkspacePath -Environment nonprod -Path 'desired/release' |
            Should -Be (Join-Path $TestDrive 'wsroot' 'nonprod' 'desired' 'release')
    }

    It 'creates the directory tree with -EnsureExists' {
        $env:COMPL8_WORKSPACE_ROOT = Join-Path $TestDrive 'wsroot'
        $p = Get-Compl8WorkspacePath -Environment nonprod -Path 'desired/resolved' -EnsureExists
        Test-Path -LiteralPath $p -PathType Container | Should -BeTrue
    }
}

Describe 'Import-ContentRelease' {
    BeforeAll {
        $script:MiniRelease = Join-Path $script:FixtureRoot 'mini-release'

        function Copy-MiniRelease {
            param([string]$Name)
            $dest = Join-Path $TestDrive $Name
            Copy-Item -LiteralPath $script:MiniRelease -Destination $dest -Recurse
            $dest
        }
    }

    It 'loads the mini release with items in release order' {
        $r = Import-ContentRelease -Path $script:MiniRelease
        $r.Version | Should -Be '2026.06-test.1'
        @($r.Items.Keys) | Should -Be @('bail-note', 'name-dict', 'shared-a', 'shared-b')
        $r.Items['bail-note'].Sections.Entity |
            Should -Match '^<Entity id="11111111-aaaa-4bbb-8ccc-000000000001"'
        $r.Items['bail-note'].Sections.Keywords.Count | Should -Be 2
        $r.Items['name-dict'].DictionaryRefs | Should -Contain '{{DICT_AU_FORENAMES}}'
        $r.ContentHash | Should -Match '^sha256:'
        @($r.Dictionaries).Count | Should -Be 2
    }

    It 'rejects a directory without release.json' {
        $empty = Join-Path $TestDrive 'not-a-release'
        New-Item -ItemType Directory -Path $empty | Out-Null
        { Import-ContentRelease -Path $empty } | Should -Throw '*release.json*'
    }

    It 'rejects an unknown schemaVersion' {
        $dir = Copy-MiniRelease 'rel-badschema'
        $manifestPath = Join-Path $dir 'release.json'
        $json = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $json.schemaVersion = 'compl8.release/v999'
        $json | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath
        { Import-ContentRelease -Path $dir } | Should -Throw '*schemaVersion*'
    }

    It 'rejects a release item whose fragment file is missing' {
        $dir = Copy-MiniRelease 'rel-nofragment'
        Remove-Item -LiteralPath (Join-Path $dir 'fragments' 'shared-b.json') -Confirm:$false
        { Import-ContentRelease -Path $dir } | Should -Throw '*fragment*'
    }

    It 'rejects an entityId mismatch between release item and fragment (corruption guard)' {
        $dir = Copy-MiniRelease 'rel-idmismatch'
        $fragPath = Join-Path $dir 'fragments' 'name-dict.json'
        $frag = Get-Content -LiteralPath $fragPath -Raw | ConvertFrom-Json
        $frag.entityId = '99999999-aaaa-4bbb-8ccc-999999999999'
        $frag | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $fragPath
        { Import-ContentRelease -Path $dir } | Should -Throw '*entityId*'
    }

    It 'rejects a dictionaryRef absent from the dictionaries manifest' {
        $dir = Copy-MiniRelease 'rel-baddictref'
        $manifestPath = Join-Path $dir 'release.json'
        $json = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $json.items[1].dictionaryRefs = @('{{DICT_DOES_NOT_EXIST}}')
        $json | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath
        { Import-ContentRelease -Path $dir } | Should -Throw '*DICT_DOES_NOT_EXIST*'
    }
}

Describe 'Entity ledger' {
    BeforeAll {
        $script:Release = Import-ContentRelease -Path (Join-Path $script:FixtureRoot 'mini-release')
    }

    It 'seeds one active release entry per release item' {
        $path = Join-Path $TestDrive 'ledger1.json'
        $ledger = Initialize-EntityLedger -Release $script:Release -Path $path
        @($ledger.Entries).Count | Should -Be 4
        $e = $ledger.Entries | Where-Object slug -EQ 'bail-note'
        $e.entityId | Should -Be '11111111-aaaa-4bbb-8ccc-000000000001'
        $e.state | Should -Be 'active'
        $e.source | Should -Be 'release'
        Test-Path -LiteralPath $path | Should -BeTrue
    }

    It 'is idempotent: re-seeding never re-mints an existing binding' {
        $path = Join-Path $TestDrive 'ledger2.json'
        Initialize-EntityLedger -Release $script:Release -Path $path | Out-Null
        # Simulate an adopted binding that differs from the release default GUID.
        $raw = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        ($raw.entries | Where-Object slug -EQ 'shared-a').entityId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
        $raw | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path
        $ledger = Initialize-EntityLedger -Release $script:Release -Path $path
        ($ledger.Entries | Where-Object slug -EQ 'shared-a').entityId |
            Should -Be 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
        @($ledger.Entries).Count | Should -Be 4
    }

    It 'warns about GUIDs absent from a provided inventory but still seeds them' {
        $invPath = Join-Path $TestDrive 'inv.json'
        ConvertTo-Json @(
            @{ Name = 'Bail Note'; Id = '11111111-aaaa-4bbb-8ccc-000000000001'; Publisher = 'P' }
        ) | Set-Content -LiteralPath $invPath
        $path = Join-Path $TestDrive 'ledger3.json'
        $ledger = Initialize-EntityLedger -Release $script:Release -Path $path -InventoryPath $invPath `
            -WarningVariable warnings -WarningAction SilentlyContinue
        @($ledger.Entries).Count | Should -Be 4
        @($warnings).Count | Should -Be 3
    }

    It 'mints a custom GUID once and returns the same GUID on re-add' {
        $path = Join-Path $TestDrive 'ledger4.json'
        Initialize-EntityLedger -Release $script:Release -Path $path | Out-Null
        $first = Update-EntityLedger -Path $path -Add 'custom-foo'
        $second = Update-EntityLedger -Path $path -Add 'custom-foo'
        $first.entityId | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        $second.entityId | Should -Be $first.entityId
        $first.source | Should -Be 'custom'
    }

    It 'disable retains the entry; re-enable restores the same GUID' {
        $path = Join-Path $TestDrive 'ledger5.json'
        Initialize-EntityLedger -Release $script:Release -Path $path | Out-Null
        $before = (Get-EntityLedger -Path $path).Entries | Where-Object slug -EQ 'name-dict'
        Update-EntityLedger -Path $path -Disable 'name-dict' | Out-Null
        $mid = (Get-EntityLedger -Path $path).Entries | Where-Object slug -EQ 'name-dict'
        $mid.state | Should -Be 'disabled'
        Update-EntityLedger -Path $path -Enable 'name-dict' | Out-Null
        $after = (Get-EntityLedger -Path $path).Entries | Where-Object slug -EQ 'name-dict'
        $after.state | Should -Be 'active'
        $after.entityId | Should -Be $before.entityId
    }

    It 'Get-EntityLedger rejects a schemaVersion mismatch' {
        $path = Join-Path $TestDrive 'ledger6.json'
        '{"schemaVersion":"compl8.entity-ledger/v99","entries":[]}' | Set-Content -LiteralPath $path
        { Get-EntityLedger -Path $path } | Should -Throw '*schemaVersion*'
    }

    It 'Update-EntityLedger rejects -Add without the custom- prefix' {
        $path = Join-Path $TestDrive 'ledger7.json'
        Initialize-EntityLedger -Release $script:Release -Path $path | Out-Null
        { Update-EntityLedger -Path $path -Add 'not-custom' } | Should -Throw '*custom-*'
    }

    It 'Update-EntityLedger rejects disabling an unknown slug' {
        $path = Join-Path $TestDrive 'ledger8.json'
        Initialize-EntityLedger -Release $script:Release -Path $path | Out-Null
        { Update-EntityLedger -Path $path -Disable 'no-such-slug' } | Should -Throw '*no-such-slug*'
    }
}

Describe 'Import-ContentOverlay' {
    BeforeAll {
        $script:Release = Import-ContentRelease -Path (Join-Path $script:FixtureRoot 'mini-release')
        $script:MiniOverlay = Join-Path $script:FixtureRoot 'mini-overlay'

        function Copy-MiniOverlay {
            param([string]$Name)
            $dest = Join-Path $TestDrive $Name
            Copy-Item -LiteralPath $script:MiniOverlay -Destination $dest -Recurse
            $dest
        }
        function Set-OverlayJson {
            param([string]$Dir, [scriptblock]$Mutate)
            $p = Join-Path $Dir 'overlay.json'
            $json = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json
            & $Mutate $json
            $json | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $p
        }
    }

    It 'loads add, override and disable from the mini overlay' {
        $o = Import-ContentOverlay -Path $script:MiniOverlay -Release $script:Release
        @($o.Add).Count | Should -Be 1
        $o.Add[0].Slug | Should -Be 'custom-incident-ref'
        $o.Add[0].Definition.regex | Should -Not -BeNullOrEmpty
        @($o.Override).Count | Should -Be 1
        $o.Override[0].Set.patternsProximity | Should -Be 200
        @($o.Disable).Count | Should -Be 1
        $o.Disable[0].Slug | Should -Be 'shared-b'
    }

    It 'treats a missing overlay.json as a valid empty overlay' {
        $empty = Join-Path $TestDrive 'overlay-empty'
        New-Item -ItemType Directory -Path $empty | Out-Null
        $o = Import-ContentOverlay -Path $empty -Release $script:Release
        @($o.Add).Count | Should -Be 0
        @($o.Override).Count | Should -Be 0
        @($o.Disable).Count | Should -Be 0
    }

    It 'rejects an add slug outside the custom- namespace' {
        $dir = Copy-MiniOverlay 'ov-badns'
        Set-OverlayJson $dir { param($j) $j.add[0].slug = 'not-custom' }
        { Import-ContentOverlay -Path $dir -Release $script:Release } | Should -Throw '*custom-*'
    }

    It 'rejects an add slug colliding with a release slug' {
        # Defence in depth: craft a release that (illegally) contains a custom- slug.
        $items = [ordered]@{}
        $items['custom-incident-ref'] = [pscustomobject]@{ Slug = 'custom-incident-ref' }
        $fakeRelease = [pscustomobject]@{ Items = $items }
        { Import-ContentOverlay -Path $script:MiniOverlay -Release $fakeRelease } |
            Should -Throw '*collides*'
    }

    It 'rejects override.set keys outside the whitelist' {
        $dir = Copy-MiniOverlay 'ov-badkey'
        Set-OverlayJson $dir { param($j)
            $j.override[0].set = [pscustomobject]@{ regex = '(?i)\bhacked\b' } }
        { Import-ContentOverlay -Path $dir -Release $script:Release } | Should -Throw '*whitelist*'
    }

    It 'accepts override/disable targets absent from the release (orphan detection is merge''s job)' {
        $dir = Copy-MiniOverlay 'ov-orphan-ok'
        Set-OverlayJson $dir { param($j)
            $j.override[0].slug = 'never-released'
            $j.disable[0].slug = 'also-never-released' }
        $o = Import-ContentOverlay -Path $dir -Release $script:Release
        $o.Override[0].Slug | Should -Be 'never-released'
        $o.Disable[0].Slug | Should -Be 'also-never-released'
    }

    It 'rejects an add whose definition file is missing' {
        $dir = Copy-MiniOverlay 'ov-nodef'
        Remove-Item -LiteralPath (Join-Path $dir 'add' 'custom-incident-ref.json') -Confirm:$false
        { Import-ContentOverlay -Path $dir -Release $script:Release } | Should -Throw '*definition*'
    }
}

Describe 'Merge-DesiredContent' {
    BeforeAll {
        $script:Release = Import-ContentRelease -Path (Join-Path $script:FixtureRoot 'mini-release')
        $script:Overlay = Import-ContentOverlay -Path (Join-Path $script:FixtureRoot 'mini-overlay') -Release $script:Release
        $script:EmptyOverlay = Import-ContentOverlay -Path (Join-Path $TestDrive 'no-overlay-here') -Release $script:Release

        # Deep-copy the release and bump one item's sourceHash to simulate a release upgrade.
        function Get-UpgradedRelease {
            param([string[]]$ChangedSlugs, [string[]]$RemovedSlugs = @())
            $copy = Import-ContentRelease -Path (Join-Path $script:FixtureRoot 'mini-release')
            foreach ($slug in $ChangedSlugs) {
                $copy.Items[$slug].SourceHash = 'sha256:fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0'
            }
            foreach ($slug in $RemovedSlugs) { $copy.Items.Remove($slug) }
            $copy
        }
    }

    It 'case 1: unchanged release item with no customisation passes through as released' {
        $m = Merge-DesiredContent -Release $script:Release -Overlay $script:EmptyOverlay
        @($m.Items).Count | Should -Be 4
        @($m.Conflicts).Count | Should -Be 0
        $item = $m.Items | Where-Object Slug -EQ 'bail-note'
        $item.Source | Should -Be 'release'
        $item.AttrPatches.Count | Should -Be 0
    }

    It 'case 2: unchanged release item with override carries the attr patches, no conflict' {
        $m = Merge-DesiredContent -Release $script:Release -Overlay $script:Overlay
        $item = $m.Items | Where-Object Slug -EQ 'bail-note'
        $item.AttrPatches['patternsProximity'] | Should -Be 200
        $item.StaleOverride | Should -BeFalse
        @($m.Conflicts | Where-Object Slug -EQ 'bail-note').Count | Should -Be 0
    }

    It 'case 3: disable excludes the item without conflict' {
        $m = Merge-DesiredContent -Release $script:Release -Overlay $script:Overlay
        @($m.Items | Where-Object Slug -EQ 'shared-b').Count | Should -Be 0
        @($m.Conflicts | Where-Object Slug -EQ 'shared-b').Count | Should -Be 0
    }

    It 'case 4: release changed under an override -> conflict surfaced, override still applied flagged stale' {
        $upgraded = Get-UpgradedRelease -ChangedSlugs @('bail-note')
        $m = Merge-DesiredContent -Release $upgraded -Overlay $script:Overlay
        $conflict = $m.Conflicts | Where-Object Slug -EQ 'bail-note'
        $conflict.Kind | Should -Be 'override-base-changed'
        $item = $m.Items | Where-Object Slug -EQ 'bail-note'
        $item.AttrPatches['patternsProximity'] | Should -Be 200
        $item.StaleOverride | Should -BeTrue
    }

    It 'case 5: release changed while disabled -> conflict surfaced, item stays excluded' {
        $upgraded = Get-UpgradedRelease -ChangedSlugs @('shared-b')
        $m = Merge-DesiredContent -Release $upgraded -Overlay $script:Overlay
        ($m.Conflicts | Where-Object Slug -EQ 'shared-b').Kind | Should -Be 'disabled-item-changed'
        @($m.Items | Where-Object Slug -EQ 'shared-b').Count | Should -Be 0
    }

    It 'case 6: customisations orphaned by item removal -> orphan conflicts' {
        $upgraded = Get-UpgradedRelease -ChangedSlugs @() -RemovedSlugs @('bail-note', 'shared-b')
        $m = Merge-DesiredContent -Release $upgraded -Overlay $script:Overlay
        ($m.Conflicts | Where-Object Slug -EQ 'bail-note').Kind | Should -Be 'orphaned-override'
        ($m.Conflicts | Where-Object Slug -EQ 'shared-b').Kind | Should -Be 'orphaned-disable'
    }

    It 'case 7: custom add lands as a desired item with source custom, after release items' {
        $m = Merge-DesiredContent -Release $script:Release -Overlay $script:Overlay
        $last = @($m.Items)[-1]
        $last.Slug | Should -Be 'custom-incident-ref'
        $last.Source | Should -Be 'custom'
        $last.Definition.regex | Should -Not -BeNullOrEmpty
    }

    It 'is deterministic: identical inputs produce byte-identical serialised output' {
        $a = Merge-DesiredContent -Release $script:Release -Overlay $script:Overlay
        $b = Merge-DesiredContent -Release $script:Release -Overlay $script:Overlay
        ($a | ConvertTo-Json -Depth 10) | Should -Be ($b | ConvertTo-Json -Depth 10)
    }
}

Describe 'Get-RulePackageAssignment' {
    BeforeAll {
        function New-PackItem {
            param([string]$Slug, [int]$SizeBytes = 2000)
            [pscustomobject]@{ Slug = $Slug; SizeBytes = $SizeBytes }
        }
        function Invoke-Pack {
            param($Items, $Prior = $null)
            Get-RulePackageAssignment -Items $Items -Prior $Prior -Prefix 'P' -Tier 'test'
        }
        $script:Limits = Get-DeploymentLimits
    }

    It 'is deterministic: identical inputs produce identical output' {
        $items = 1..20 | ForEach-Object { New-PackItem "slug-$_" }
        $a = Invoke-Pack $items
        $b = Invoke-Pack $items
        ($a | ConvertTo-Json -Depth 10) | Should -Be ($b | ConvertTo-Json -Depth 10)
    }

    It 'greedy baseline without prior: 70 small items pack to the 50-entity cap -> 2 packages' {
        $items = 1..70 | ForEach-Object { New-PackItem "slug-$_" }
        $r = Invoke-Pack $items
        @($r.Packages).Count | Should -Be 2
        @($r.Packages[0].Slugs).Count | Should -Be 50
        @($r.Packages[1].Slugs).Count | Should -Be 20
        @($r.Dropped).Count | Should -Be 0
    }

    It 'opens a new package when the size cap binds before the entity cap' {
        # 60KB each: two fit under the 148KB preferred cap, the third must spill.
        $items = 1..3 | ForEach-Object { New-PackItem "big-$_" -SizeBytes 61440 }
        $r = Invoke-Pack $items
        @($r.Packages).Count | Should -Be 2
        @($r.Packages[0].Slugs) | Should -Be @('big-1', 'big-2')
        @($r.Packages[1].Slugs) | Should -Be @('big-3')
    }

    It 'prior assignments are sticky: removing one slug moves nothing else' {
        $items = @(
            New-PackItem 'a'; New-PackItem 'c'; New-PackItem 'd'  # 'b' departed
        )
        $prior = @{ a = 'P-test-01'; b = 'P-test-01'; c = 'P-test-01'; d = 'P-test-02' }
        $r = Invoke-Pack $items $prior
        $r.Assignments['a'] | Should -Be 'P-test-01'
        $r.Assignments['c'] | Should -Be 'P-test-01'
        $r.Assignments['d'] | Should -Be 'P-test-02'
    }

    It 'new slugs fill existing headroom in ascending package order before opening new packages' {
        $items = @(New-PackItem 'a'; New-PackItem 'b'; New-PackItem 'new-1')
        $prior = @{ a = 'P-test-01'; b = 'P-test-02' }
        $r = Invoke-Pack $items $prior
        $r.Assignments['new-1'] | Should -Be 'P-test-01'
        @($r.Packages).Count | Should -Be 2
    }

    It 'overflow evicts only the newest slugs of the oversized package' {
        # Prior package P-test-01 holds three items; release growth inflates them so only
        # two fit. The LAST in item order (c) must move; a and b stay.
        $items = @(
            New-PackItem 'a' -SizeBytes 61440
            New-PackItem 'b' -SizeBytes 61440
            New-PackItem 'c' -SizeBytes 61440
        )
        $prior = @{ a = 'P-test-01'; b = 'P-test-01'; c = 'P-test-01' }
        $r = Invoke-Pack $items $prior
        $r.Assignments['a'] | Should -Be 'P-test-01'
        $r.Assignments['b'] | Should -Be 'P-test-01'
        $r.Assignments['c'] | Should -Not -Be 'P-test-01'
    }

    It 'drops items beyond the tenant package cap with a reason, never throws' {
        # 70KB items: exactly two fit per package under the 148KB preferred cap, so 22
        # items need 11 packages. The automated build is capped at the EFFECTIVE cap
        # (tenant cap minus the reserved manual slot) = 9, so packages 10-11 (4 items) drop.
        $effectiveCap = $script:Limits.MaxRulePackagesPerTenant - $script:Limits.ReservedManualPackages
        $items = 1..22 | ForEach-Object { New-PackItem "cap-$_" -SizeBytes 71680 }
        $r = Invoke-Pack $items
        @($r.Packages).Count | Should -Be $effectiveCap
        @($r.Dropped).Count | Should -Be 4
        $r.Dropped[0].Reason | Should -Match 'package'
    }

    It 'preserves verbatim prior package names from an adopted layout' {
        $items = @(New-PackItem 'a'; New-PackItem 'b')
        $prior = @{ a = 'QGISCF-medium-07a'; b = 'QGISCF-medium-07a' }
        $r = Invoke-Pack $items $prior
        $r.Packages[0].Name | Should -Be 'QGISCF-medium-07a'
    }

    It 'caps the automated build at 9 packages (reserves the 10th)' {
        # 10 items each just under the preferred cap -> would be 10 packages, but cap is 9 -> 1 dropped.
        $big = [int]($script:Limits.PreferredRulePackageBytes - 1000)
        $items = 1..10 | ForEach-Object { New-PackItem "big-$_" $big }
        $r = Invoke-Pack $items
        @($r.Packages).Count | Should -Be 9
        @($r.Dropped).Count  | Should -Be 1
    }
    It 'places largest-first (FFD): a big item is not stranded behind small ones' {
        $cap = $script:Limits.PreferredRulePackageBytes
        # one near-cap item + many small; FFD must give the big item its own package first.
        $items = @(New-PackItem 'huge' ([int]($cap - 500))) + (1..40 | ForEach-Object { New-PackItem "s-$_" 2000 })
        $r = Invoke-Pack $items
        $hugePkg = $r.Packages | Where-Object { $_.Slugs -contains 'huge' }
        @($hugePkg.Slugs).Count | Should -Be 1   # big item alone; smalls fill OTHER packages
    }

    It 'P2-3: reservation cap is enforced when Prior already fills MaxRulePackagesPerTenant packages' {
        # Build a Prior mapping with MaxRulePackagesPerTenant (10) distinct packages,
        # each holding exactly one small item.  The effective cap is 9 (one slot reserved).
        # After Pass 1 all 10 items land in 10 prior groups; the reservation guard (Pass 2b)
        # must evict the highest-ordinal package so only 9 remain.
        $totalPkgs  = $script:Limits.MaxRulePackagesPerTenant      # 10
        $effectiveCap = $totalPkgs - $script:Limits.ReservedManualPackages  # 9
        $slugs = 1..$totalPkgs | ForEach-Object { "pkg$_-item" }
        $items = $slugs | ForEach-Object { New-PackItem $_ }
        $prior = @{}
        for ($i = 0; $i -lt $totalPkgs; $i++) {
            $prior[$slugs[$i]] = ('P-test-{0:d2}' -f ($i + 1))
        }
        $r = Invoke-Pack $items $prior
        @($r.Packages).Count | Should -BeLessOrEqual $effectiveCap
        # No item silently lost: placed + dropped must equal input count
        $placedCount = ($r.Packages | ForEach-Object { @($_.Slugs).Count } | Measure-Object -Sum).Sum
        ($placedCount + @($r.Dropped).Count) | Should -Be $totalPkgs
    }
}

Describe 'ConvertTo-RulePackageXml' {
    BeforeAll {
        $script:Release = Import-ContentRelease -Path (Join-Path $script:FixtureRoot 'mini-release')
        $script:EmptyOverlay = Import-ContentOverlay -Path (Join-Path $TestDrive 'no-overlay') -Release $script:Release
        $script:Merged = Merge-DesiredContent -Release $script:Release -Overlay $script:EmptyOverlay
        $script:LedgerPath = Join-Path $TestDrive 'compose-ledger.json'
        Initialize-EntityLedger -Release $script:Release -Path $script:LedgerPath | Out-Null
        $script:Ledger = Get-EntityLedger -Path $script:LedgerPath

        function Invoke-Compose {
            param($Items = $script:Merged.Items, $Ledger = $script:Ledger)
            ConvertTo-RulePackageXml -Name 'P-test-01' -Items $Items -Ledger $Ledger `
                -Publisher 'Test Pub' -RulePackId 'deadbeef-dead-4eef-8eef-deadbeefdead'
        }
    }

    It 'composes a package that passes Test-SITRulePackageXml' {
        $r = Invoke-Compose
        $out = Join-Path $TestDrive 'composed.xml'
        [System.IO.File]::WriteAllBytes($out, $r.Bytes)
        $v = Test-SITRulePackageXml -FilePath $out
        $v.Errors | Should -BeNullOrEmpty
        $v.Valid | Should -BeTrue
        $r.EntityCount | Should -Be 4
    }

    It 'orders sections Entities, Regexes, Keywords, then LocalizedStrings' {
        $t = (Invoke-Compose).Text
        $lastEntity = $t.LastIndexOf('<Entity ')
        $firstRegex = $t.IndexOf('<Regex ')
        $firstKeyword = $t.IndexOf('<Keyword ')
        $strings = $t.IndexOf('<LocalizedStrings>')
        $lastEntity | Should -BeLessThan $firstRegex
        $firstRegex | Should -BeLessThan $firstKeyword
        $firstKeyword | Should -BeLessThan $strings
    }

    It 'emits a shared keyword definition exactly once (id dedup, first occurrence wins)' {
        $t = (Invoke-Compose).Text
        ([regex]::Matches($t, '<Keyword id="Keyword_shared_noise_filter"')).Count | Should -Be 1
    }

    It 'rebinds a ledger GUID in Entity id and Resource idRef, changing nothing else' {
        $adopted = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
        $original = '33333333-aaaa-4bbb-8ccc-000000000003'
        $raw = Get-Content -LiteralPath $script:LedgerPath -Raw | ConvertFrom-Json
        ($raw.entries | Where-Object slug -EQ 'shared-a').entityId = $adopted
        $rebindPath = Join-Path $TestDrive 'rebind-ledger.json'
        $raw | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $rebindPath

        $identity = (Invoke-Compose).Text
        $rebound = (Invoke-Compose -Ledger (Get-EntityLedger -Path $rebindPath)).Text

        $rebound | Should -Match "<Entity id=`"$adopted`""
        $rebound | Should -Match "<Resource idRef=`"$adopted`""
        $rebound.Contains($original) | Should -BeFalse
        # Undoing the rebind must reproduce the identity composition byte-for-byte.
        $rebound.Replace($adopted, $original) | Should -Be $identity
    }

    It 'applies attr patches to the entity start tag only' {
        $items = @($script:Merged.Items | ForEach-Object { $_ })
        $patched = $items[0].PSObject.Copy()
        $patched.AttrPatches = @{ patternsProximity = 200 }
        $items[0] = $patched

        $identity = (Invoke-Compose).Text
        $t = (Invoke-Compose -Items $items).Text
        $t | Should -Match '<Entity id="11111111-aaaa-4bbb-8ccc-000000000001" patternsProximity="200"'
        $t.Replace('patternsProximity="200"', 'patternsProximity="300"') | Should -Be $identity
    }

    It 'honours the byte contract: no BOM, CRLF only, no comments, publisher and description patched' {
        $r = Invoke-Compose
        $r.Bytes[0] | Should -Be 60   # '<' — no BOM
        $r.Text | Should -Match '<PublisherName>Test Pub</PublisherName>'
        $r.Text | Should -Match '<Description>TestPattern bundle with 4 patterns</Description>'
        $r.Text.Contains('<!--') | Should -BeFalse
        ([regex]::Matches($r.Text, "(?<!`r)`n")).Count | Should -Be 0
        $r.Text | Should -Match '^<\?xml version="1\.0" encoding="utf-8"\?>'
    }

    It 'passes dictionary placeholders through verbatim' {
        (Invoke-Compose).Text | Should -Match '<Match idRef="\{\{DICT_AU_FORENAMES\}\}" />'
    }

    It 'throws when an item has no ledger binding' {
        $noLedger = [pscustomobject]@{ Path = 'x'; Entries = @() }
        { Invoke-Compose -Ledger $noLedger } | Should -Throw '*ledger*'
    }
}

Describe 'ConvertTo-CustomSitFragment' {
    BeforeAll {
        $script:Release = Import-ContentRelease -Path (Join-Path $script:FixtureRoot 'mini-release')
        $script:Overlay = Import-ContentOverlay -Path (Join-Path $script:FixtureRoot 'mini-overlay') -Release $script:Release
        $script:CustomDef = $script:Overlay.Add[0].Definition
        $script:CustomGuid = '55555555-aaaa-4bbb-8ccc-000000000005'
    }

    It 'renders a release-shaped fragment with the provided ledger GUID' {
        $f = ConvertTo-CustomSitFragment -Definition $script:CustomDef -EntityId $script:CustomGuid
        $f.Slug | Should -Be 'custom-incident-ref'
        $f.EntityId | Should -Be $script:CustomGuid
        $f.Sections.Entity | Should -Match "^<Entity id=`"$($script:CustomGuid)`""
        @($f.Sections.Regexes).Count | Should -Be 1
        @($f.Sections.Keywords).Count | Should -Be 2   # evidence + exclusion filter
        @($f.Sections.Resources).Count | Should -Be 1
        $f.Sections.Resources[0] | Should -Match "idRef=`"$($script:CustomGuid)`""
    }

    It 'is deterministic for the same inputs' {
        $a = ConvertTo-CustomSitFragment -Definition $script:CustomDef -EntityId $script:CustomGuid
        $b = ConvertTo-CustomSitFragment -Definition $script:CustomDef -EntityId $script:CustomGuid
        ($a | ConvertTo-Json -Depth 10) | Should -Be ($b | ConvertTo-Json -Depth 10)
    }

    It 'composes into a package that passes Test-SITRulePackageXml alongside release items' {
        $ledgerPath = Join-Path $TestDrive 'custom-ledger.json'
        Initialize-EntityLedger -Release $script:Release -Path $ledgerPath | Out-Null
        $entry = Update-EntityLedger -Path $ledgerPath -Add 'custom-incident-ref'
        $fragment = ConvertTo-CustomSitFragment -Definition $script:CustomDef -EntityId $entry.entityId

        $emptyOverlay = Import-ContentOverlay -Path (Join-Path $TestDrive 'no-ov2') -Release $script:Release
        $merged = Merge-DesiredContent -Release $script:Release -Overlay $emptyOverlay
        $items = @($merged.Items) + [pscustomobject]@{
            Slug        = $fragment.Slug
            Source      = 'custom'
            EntityId    = $fragment.EntityId
            Sections    = $fragment.Sections
            AttrPatches = @{}
        }
        $r = ConvertTo-RulePackageXml -Name 'P-test-01' -Items $items `
            -Ledger (Get-EntityLedger -Path $ledgerPath) -Publisher 'Test Pub' `
            -RulePackId 'deadbeef-dead-4eef-8eef-deadbeefdead'
        $out = Join-Path $TestDrive 'composed-custom.xml'
        [System.IO.File]::WriteAllBytes($out, $r.Bytes)
        $v = Test-SITRulePackageXml -FilePath $out
        $v.Errors | Should -BeNullOrEmpty
        $v.Valid | Should -BeTrue
        $r.EntityCount | Should -Be 5
    }

    It 'XML-escapes user-supplied text' {
        $def = [pscustomobject]@{
            slug = 'custom-esc'; name = 'A & B <Test>'; description = 'Uses "quotes" & <angles>'
            regex = '(?i)\bA&B\b'; keywords = @('a & b'); confidence = 'low'
        }
        $f = ConvertTo-CustomSitFragment -Definition $def -EntityId $script:CustomGuid
        $f.Sections.Resources[0] | Should -Match 'A &amp; B &lt;Test&gt;'
        $f.Sections.Keywords[0] | Should -Match 'a &amp; b'
        $f.Sections.Regexes[0] | Should -Match 'A&amp;B'
        $f.Sections.Entity | Should -Match 'recommendedConfidence="65"'
    }

    It 'rejects complex definitions with a pointer to testpattern curation' {
        $def = [pscustomobject]@{
            slug = 'custom-complex'; name = 'X'; description = 'Y'
            regex = 'a'; regexes = @('a', 'b')
        }
        { ConvertTo-CustomSitFragment -Definition $def -EntityId $script:CustomGuid } |
            Should -Throw '*testpattern*'
    }

    It 'rejects a definition missing the regex' {
        $def = [pscustomobject]@{ slug = 'custom-noregex'; name = 'X'; description = 'Y' }
        { ConvertTo-CustomSitFragment -Definition $def -EntityId $script:CustomGuid } |
            Should -Throw '*regex*'
    }
}

Describe 'Test-ContentDictionaryBudget' {
    BeforeAll { $script:Limits = Get-DeploymentLimits }

    It 'warns at the conservative threshold' {
        $r = Test-ContentDictionaryBudget -Dictionaries @(
            [pscustomobject]@{ placeholder = '{{DICT_BIG}}'; termsBytes = $script:Limits.DictionaryBudgetWarnBytes }
        )
        @($r.Warnings).Count | Should -Be 1
        @($r.Errors).Count | Should -Be 0
    }

    It 'errors at the hard cap' {
        $r = Test-ContentDictionaryBudget -Dictionaries @(
            [pscustomobject]@{ placeholder = '{{DICT_HUGE}}'; termsBytes = $script:Limits.DictionaryBudgetMaxBytes }
        )
        @($r.Errors).Count | Should -Be 1
    }

    It 'gates only the used placeholders when -UsedPlaceholders is given' {
        $r = Test-ContentDictionaryBudget -Dictionaries @(
            [pscustomobject]@{ placeholder = '{{DICT_HUGE}}'; termsBytes = $script:Limits.DictionaryBudgetMaxBytes }
        ) -UsedPlaceholders @('{{DICT_OTHER}}')
        @($r.Errors).Count | Should -Be 0
    }
}

Describe 'Resolve-DesiredContent pipeline' {
    BeforeAll {
        function New-ResolveWorkspace {
            param([string]$Name)
            $ws = Join-Path $TestDrive $Name
            New-Item -ItemType Directory -Path (Join-Path $ws 'desired') -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $script:FixtureRoot 'mini-release') `
                -Destination (Join-Path $ws 'desired' 'release') -Recurse
            Copy-Item -LiteralPath (Join-Path $script:FixtureRoot 'mini-overlay') `
                -Destination (Join-Path $ws 'desired' 'overlay') -Recurse
            # Fixed ledger (entities AND package GUID) so resolve output is fully deterministic.
            [pscustomobject]@{
                schemaVersion = 'compl8.entity-ledger/v1'
                entries       = @(
                    [pscustomobject]@{ slug = 'bail-note'; entityId = '11111111-aaaa-4bbb-8ccc-000000000001'; state = 'active'; source = 'release'; firstBound = '2026-06-13' }
                    [pscustomobject]@{ slug = 'name-dict'; entityId = '22222222-aaaa-4bbb-8ccc-000000000002'; state = 'active'; source = 'release'; firstBound = '2026-06-13' }
                    [pscustomobject]@{ slug = 'shared-a'; entityId = '33333333-aaaa-4bbb-8ccc-000000000003'; state = 'active'; source = 'release'; firstBound = '2026-06-13' }
                    [pscustomobject]@{ slug = 'shared-b'; entityId = '44444444-aaaa-4bbb-8ccc-000000000004'; state = 'active'; source = 'release'; firstBound = '2026-06-13' }
                    [pscustomobject]@{ slug = 'custom-incident-ref'; entityId = '55555555-aaaa-4bbb-8ccc-000000000005'; state = 'active'; source = 'custom'; firstBound = '2026-06-13' }
                )
                packages      = @(
                    [pscustomobject]@{ name = 'P-test-01'; rulePackId = 'cafebabe-cafe-4abe-8abe-cafebabecafe' }
                )
            } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $ws 'entity-ledger.json')
            $ws
        }
        function Invoke-Resolve {
            param([string]$Workspace)
            Resolve-DesiredContent -WorkspacePath $Workspace -Prefix 'P' -Publisher 'Test Pub'
        }

        # Helper: builds a workspace whose single composed package is well over 150 KB UTF-16
        # but well under 150 KB UTF-8, so the OLD UTF-8 cap check passes while the NEW UTF-16
        # cap check fires.
        #
        # Design: the regex content uses 1 000 LF-terminated lines of 74 ASCII chars each.
        #   sectionText (entity+regex+resource joined with LF) ≈ 75 372 chars
        #     UTF-16 SizeBytes ≈ 150 744  →  packer projection ≈ 151 344 ≤ 151 552 PREFERRED cap → PACKED
        #     UTF-8  SizeBytes ≈  75 372  →  packer projection ≈  75 972 ≤ 151 552                → PACKED
        #   After CRLF normalisation (each LF → CRLF adds 1 char per newline):
        #     composed body ≈ 77 061 chars  →  Utf16SizeBytes ≈ 154 122 > 153 600 HARD cap → THROW
        #     composed body UTF-8 ≈ 77 061 bytes                        < 153 600           → no old throw
        function New-OvercapWorkspace {
            param([string]$Name)
            $ws = Join-Path $TestDrive $Name
            $releasePath = Join-Path $ws 'desired' 'release'
            New-Item -ItemType Directory -Path (Join-Path $releasePath 'fragments') -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $releasePath 'definitions') -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $releasePath 'dictionaries') -Force | Out-Null

            # 1 000 lines of 74 "a"s, each terminated by LF.  When CRLF-normalised in
            # ConvertTo-RulePackageXml each LF becomes CRLF (+1 char), pushing Utf16SizeBytes
            # over 153 600 while UTF-8 SizeBytes stays well below it.
            $lineContent = 'a' * 74
            $bigRegexContent = ($lineContent + "`n") * 1000   # 75 000 chars: 74 000 a's + 1 000 LF
            $entityId = 'eeeeeeee-eeee-4eee-8eee-000000000001'
            $fragJson = [pscustomobject]@{
                schemaVersion = 'compl8.fragment/v1'
                slug          = 'big-item'
                entityId      = $entityId
                sections      = [pscustomobject]@{
                    entity   = "<Entity id=`"$entityId`" patternsProximity=`"300`" recommendedConfidence=`"85`"><Pattern confidenceLevel=`"85`"><IdMatch idRef=`"Pattern_big`" /></Pattern></Entity>"
                    regexes  = @("<Regex id=`"Pattern_big`">$bigRegexContent</Regex>")
                    keywords  = @()
                    filters   = @()
                    validators = @()
                    resources = @("<Resource idRef=`"$entityId`"><Name default=`"true`" langcode=`"en-us`">Big Item</Name><Description default=`"true`" langcode=`"en-us`">Oversized for UTF-16 cap test.</Description></Resource>")
                }
            } | ConvertTo-Json -Depth 6
            Set-Content -LiteralPath (Join-Path $releasePath 'fragments' 'big-item.json') -Value $fragJson -Encoding UTF8

            $defJson = '{"schemaVersion":"compl8.definition/v1","slug":"big-item","type":"sit","name":"Big Item","description":"Oversized test SIT"}'
            Set-Content -LiteralPath (Join-Path $releasePath 'definitions' 'big-item.json') -Value $defJson -Encoding UTF8

            [pscustomobject]@{
                schemaVersion = 'compl8.dictionaries/v1'
                dictionaries  = @()
            } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $releasePath 'dictionaries' 'manifest.json') -Encoding UTF8

            [pscustomobject]@{
                schemaVersion = 'compl8.release/v1'
                version       = '2026.06-test.overcap'
                generatedUtc  = '2026-06-13T00:00:00Z'
                tier          = 'test'
                items         = @(
                    [pscustomobject]@{
                        slug          = 'big-item'
                        type          = 'sit'
                        entityId      = $entityId
                        name          = 'Big Item'
                        fragment      = 'fragments/big-item.json'
                        definition    = 'definitions/big-item.json'
                        dictionaryRefs = @()
                        sourceHash    = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                    }
                )
                contentHash   = 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
            } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $releasePath 'release.json') -Encoding UTF8

            # Minimal empty overlay
            $overlayPath = Join-Path $ws 'desired' 'overlay'
            New-Item -ItemType Directory -Path $overlayPath -Force | Out-Null
            [pscustomobject]@{
                schemaVersion = 'compl8.overlay/v1'
                add           = @()
                override      = @()
                disable       = @()
            } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $overlayPath 'overlay.json') -Encoding UTF8

            # Ledger with one entry + one package binding
            [pscustomobject]@{
                schemaVersion = 'compl8.entity-ledger/v1'
                entries       = @(
                    [pscustomobject]@{ slug = 'big-item'; entityId = $entityId; state = 'active'; source = 'release'; firstBound = '2026-06-13' }
                )
                packages      = @(
                    [pscustomobject]@{ name = 'P-test-01'; rulePackId = 'deadbeef-dead-4eef-8eef-deadbeefcafe' }
                )
            } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $ws 'entity-ledger.json') -Encoding UTF8

            $ws
        }
    }

    It 'resolves end-to-end: package file, manifest, ledger-pinned RulePack id' {
        $ws = New-ResolveWorkspace 'ws-main'
        $m = Invoke-Resolve $ws
        $packageFile = Join-Path $ws 'desired' 'resolved' 'P-test-01.xml'
        Test-Path -LiteralPath $packageFile | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $ws 'desired' 'resolved' 'resolve-manifest.json') | Should -BeTrue
        $m.packages[0].name | Should -Be 'P-test-01'
        $m.packages[0].rulePackId | Should -Be 'cafebabe-cafe-4abe-8abe-cafebabecafe'
        # shared-b disabled by overlay: 3 release items + 1 custom add.
        $m.packages[0].entities | Should -Be 4
        $m.packing.assignments.'custom-incident-ref' | Should -Be 'P-test-01'
        @($m.warnings).Count | Should -Be 0
        $v = Test-SITRulePackageXml -FilePath $packageFile
        $v.Valid | Should -BeTrue
    }

    It 're-resolving unchanged inputs is byte-identical — reuses the prior generatedUtc, no plan churn [codex rescue P2]' {
        # generatedUtc was stamped with the current time on every resolve, so a no-op re-resolve rewrote
        # resolve-manifest.json with different bytes and staled every plan that hashes the manifest. The
        # fix reuses the prior stamp when the input hashes are unchanged -> byte-identical manifest.
        $ws = New-ResolveWorkspace 'ws-idempotent'
        Invoke-Resolve $ws | Out-Null
        $manifestPath = Join-Path $ws 'desired' 'resolved' 'resolve-manifest.json'
        $first = Get-Content -LiteralPath $manifestPath -Raw
        Invoke-Resolve $ws | Out-Null   # re-resolve; release/overlay/ledger unchanged
        (Get-Content -LiteralPath $manifestPath -Raw) | Should -Be $first
    }

    It 'honours an injected -GeneratedUtc (determinism)' {
        $ws = New-ResolveWorkspace 'ws-injected'
        $m = Resolve-DesiredContent -WorkspacePath $ws -Prefix 'P' -Publisher 'Test Pub' -GeneratedUtc '2026-01-01T00:00:00Z'
        $m.generatedUtc | Should -Be '2026-01-01T00:00:00Z'
    }

    It 'pins the golden package hash (recorded from the first green run)' {
        $ws = New-ResolveWorkspace 'ws-golden'
        $m = Invoke-Resolve $ws
        # Golden constant recorded 2026-06-13 from the first green run; regenerate ONLY by
        # deliberate fixture change (the regeneration-invariant test guards accidental drift).
        $m.packages[0].sha256 | Should -Be '94e516887ffb2670f9ab0051b23e0456ef806a4cdcc5af0484af394270d87bf4'
    }

    It 'regenerates identically after desired/resolved is deleted (pure-function invariant)' {
        $ws = New-ResolveWorkspace 'ws-regen'
        $first = Invoke-Resolve $ws
        Remove-Item -LiteralPath (Join-Path $ws 'desired' 'resolved') -Recurse -Force -Confirm:$false
        $second = Invoke-Resolve $ws
        $second.packages[0].sha256 | Should -Be $first.packages[0].sha256
        $second.packages[0].rulePackId | Should -Be $first.packages[0].rulePackId
    }

    It 'reports current after resolve and stale after an overlay edit' {
        $ws = New-ResolveWorkspace 'ws-stale'
        Invoke-Resolve $ws | Out-Null
        Test-ResolveManifestCurrent -WorkspacePath $ws | Should -BeTrue
        Set-Content -LiteralPath (Join-Path $ws 'desired' 'overlay' 'note.txt') -Value 'drift'
        Test-ResolveManifestCurrent -WorkspacePath $ws | Should -BeFalse
        (Test-ResolveManifestCurrent -WorkspacePath $ws -Detail).Stale | Should -Contain 'overlay'
    }

    It 'aborts on a dictionary budget error leaving no resolved output' {
        $ws = New-ResolveWorkspace 'ws-budget'
        $dictPath = Join-Path $ws 'desired' 'release' 'dictionaries' 'manifest.json'
        $dict = Get-Content -LiteralPath $dictPath -Raw | ConvertFrom-Json
        ($dict.dictionaries | Where-Object placeholder -EQ '{{DICT_AU_FORENAMES}}').termsBytes = 2097152
        $dict | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $dictPath
        { Invoke-Resolve $ws } | Should -Throw '*budget*'
        Test-Path -LiteralPath (Join-Path $ws 'desired' 'resolved') | Should -BeFalse
        @(Get-ChildItem -Path (Join-Path $ws 'desired') -Directory -Filter '.resolved-staging-*').Count | Should -Be 0
    }

    It 'records merge conflicts in the manifest warnings' {
        $ws = New-ResolveWorkspace 'ws-conflict'
        $ovPath = Join-Path $ws 'desired' 'overlay' 'overlay.json'
        $ov = Get-Content -LiteralPath $ovPath -Raw | ConvertFrom-Json
        $ov.override[0].baseSourceHash = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        $ov | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ovPath
        $m = Invoke-Resolve $ws
        @($m.warnings | Where-Object { $_ -like 'conflict:override-base-changed:bail-note*' }).Count | Should -Be 1
    }

    It 'rejects a package over the 150KB UTF-16 hard cap' {
        # Build a release whose one composed package is well over 150KB UTF-16 (but its UTF-8 size
        # alone would be under the old UTF-8 cap). Use the block's fixture helpers to write the release.
        $ws = New-OvercapWorkspace 'ws-over-utf16-cap'
        { Resolve-DesiredContent -WorkspacePath $ws -Prefix 'P' -Publisher 'Pub' } |
            Should -Throw -ExpectedMessage '*over the 153600-byte hard cap*'
    }
}
