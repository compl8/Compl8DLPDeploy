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
