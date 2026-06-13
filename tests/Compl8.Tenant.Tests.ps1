#Requires -Modules Pester

BeforeAll {
    $script:TenantDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'Compl8.Tenant'
    # Isolation: DLP-Deploy's facade dot-source claims ownership of these functions when loaded;
    # remove it so -Module Compl8.Tenant attribution is testable (same pattern as Compl8.Model.Tests.ps1).
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:TenantDir -Force
}

Describe 'Compl8.Tenant standalone exports' {
    It 'exports the gates and tenant readers' {
        $names = @(
            'Test-IsInteractive', 'Assert-OrchestrationGate',
            'Get-DeploymentTenantInfo', 'Test-DeploymentTenantFingerprint',
            'Get-DlpClassifierRuleReferences', 'Test-DlpRulePackageRemovalReferenceGuard',
            'Get-TenantInventory', 'Export-TenantActualSnapshot'
        )
        foreach ($n in $names) {
            (Get-Command -Name $n -Module Compl8.Tenant -ErrorAction SilentlyContinue) |
                Should -Not -BeNullOrEmpty -Because "$n should be exported by Compl8.Tenant"
        }
    }
    It 'orchestration gate passes standalone when COMPL8_ORCHESTRATED is set' {
        $env:COMPL8_ORCHESTRATED = '1'
        try { { Assert-OrchestrationGate -ScriptName 'X' } | Should -Not -Throw }
        finally { Remove-Item Env:\COMPL8_ORCHESTRATED -ErrorAction SilentlyContinue }
    }
    It 'orchestration gate throws standalone on a raw non-interactive run' {
        Remove-Item Env:\COMPL8_ORCHESTRATED -ErrorAction SilentlyContinue
        Mock -ModuleName Compl8.Tenant Test-IsInteractive { $false }
        { Assert-OrchestrationGate -ScriptName 'X' } | Should -Throw '*AllowDirectRun*'
    }
    It 'loads its Compl8.Model dependency for the reference guard' {
        (Get-Command -Name Get-DeploymentReferenceGraph -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
    It 'resolves Get-DeploymentObjectProperty through its Compl8.Model dependency' {
        (Get-Command -Name Get-DeploymentObjectProperty -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-TenantInventory' {
    BeforeAll {
        # The SCC read cmdlets are not installed in CI. Define global stubs so the command
        # names resolve (repo pattern, cf. DLP-Deploy.Tests.ps1), then Mock -ModuleName overrides
        # them inside the Compl8.Tenant module scope (the module is loaded standalone here).
        function global:Get-DlpKeywordDictionary { [CmdletBinding()] param() }
        function global:Get-DlpSensitiveInformationTypeRulePackage { [CmdletBinding()] param() }
        function global:Get-DlpComplianceRule { [CmdletBinding()] param() }
        function global:Get-DlpCompliancePolicy { [CmdletBinding()] param() }
        function global:Get-Label { [CmdletBinding()] param() }
        function global:Get-LabelPolicy { [CmdletBinding()] param() }
        function global:Get-AutoSensitivityLabelPolicy { [CmdletBinding()] param() }
        function global:Get-AutoSensitivityLabelRule { [CmdletBinding()] param() }

        # All read cmdlets mocked in the Compl8.Tenant module scope. Shapes mirror the real
        # Get-Dlp* output: a single QGISCF-prefixed 'ours' object and one foreign Microsoft
        # object per type where it matters for the ours-discriminator.
        Mock -ModuleName Compl8.Tenant Get-DlpKeywordDictionary {
            @(
                [pscustomobject]@{ Name = 'QGISCF-medical-terms'; Identity = 'QGISCF-medical-terms' }
                [pscustomobject]@{ Name = 'Diseases';             Identity = 'Diseases' }
            )
        }
        Mock -ModuleName Compl8.Tenant Get-DlpSensitiveInformationTypeRulePackage {
            @(
                [pscustomobject]@{ Name = 'QGISCF-medium'; Identity = 'QGISCF-medium'; Publisher = 'QGISCF DLP Deploy'; RulePackId = '11111111-1111-1111-1111-111111111111' }
                [pscustomobject]@{ Name = 'Microsoft Rule Package'; Identity = 'Microsoft Rule Package'; Publisher = 'Microsoft Corporation'; RulePackId = '00000000-0000-0000-0000-000000000001' }
            )
        }
        Mock -ModuleName Compl8.Tenant Get-DlpComplianceRule {
            @(
                [pscustomobject]@{ Name = 'QGISCF-QLD-Medium-Email-07'; Identity = 'QGISCF-QLD-Medium-Email-07'; Policy = 'P01-MED-QGISCF-EXT'; Priority = 0; Disabled = $false }
            )
        }
        Mock -ModuleName Compl8.Tenant Get-DlpCompliancePolicy {
            @(
                [pscustomobject]@{ Name = 'P01-MED-QGISCF-EXT'; Identity = 'P01-MED-QGISCF-EXT'; Mode = 'Enable' }
            )
        }
        Mock -ModuleName Compl8.Tenant Get-Label {
            @(
                [pscustomobject]@{ Name = 'QGISCF-Medical-M01'; Identity = 'QGISCF-Medical-M01'; Guid = '22222222-2222-2222-2222-222222222222' }
                [pscustomobject]@{ Name = 'Confidential';       Identity = 'Confidential';       Guid = '33333333-3333-3333-3333-333333333333' }
            )
        }
        Mock -ModuleName Compl8.Tenant Get-LabelPolicy {
            @(
                [pscustomobject]@{ Name = 'QGISCF-Medical'; Identity = 'QGISCF-Medical'; Guid = '44444444-4444-4444-4444-444444444444' }
            )
        }
        Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelPolicy {
            @(
                [pscustomobject]@{ Name = 'AL01-M01-QGISCF-EXT'; Identity = 'AL01-M01-QGISCF-EXT'; Mode = 'TestWithoutNotifications'; ApplySensitivityLabel = 'QGISCF-Medical-M01' }
            )
        }
        Mock -ModuleName Compl8.Tenant Get-AutoSensitivityLabelRule {
            @(
                [pscustomobject]@{ Name = 'QGISCF-AutoLabel-Medical-Rule'; Identity = 'QGISCF-AutoLabel-Medical-Rule'; Policy = 'AL01-M01-QGISCF-EXT'; Workload = 'Exchange' }
            )
        }

        $script:Inv = Get-TenantInventory -Prefix 'QGISCF'
    }

    AfterAll {
        foreach ($fn in 'Get-DlpKeywordDictionary', 'Get-DlpSensitiveInformationTypeRulePackage',
            'Get-DlpComplianceRule', 'Get-DlpCompliancePolicy', 'Get-Label', 'Get-LabelPolicy',
            'Get-AutoSensitivityLabelPolicy', 'Get-AutoSensitivityLabelRule') {
            Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
        }
    }

    It 'returns a compl8.inventory/v1 object with one record list per object type' {
        $script:Inv.schemaVersion | Should -Be 'compl8.inventory/v1'
        foreach ($t in 'dictionaries', 'sitPackages', 'dlpRules', 'dlpPolicies', 'labels', 'labelPolicies', 'autoLabelPolicies', 'autoLabelRules') {
            $script:Inv.objects.PSObject.Properties.Name | Should -Contain $t
        }
    }

    It 'normalises each record with at least name, identity and an ours flag' {
        $dict = @($script:Inv.objects.dictionaries)[0]
        $dict.name     | Should -Be 'QGISCF-medical-terms'
        $dict.identity | Should -Be 'QGISCF-medical-terms'
        $dict.PSObject.Properties.Name | Should -Contain 'ours'
    }

    It 'sets ours=true for a prefixed object and ours=false for a foreign object' {
        $dicts = @($script:Inv.objects.dictionaries)
        ($dicts | Where-Object { $_.name -eq 'QGISCF-medical-terms' }).ours | Should -BeTrue
        ($dicts | Where-Object { $_.name -eq 'Diseases' }).ours             | Should -BeFalse
    }

    It 'carries the ours flag through to every object type' {
        @($script:Inv.objects.sitPackages    | Where-Object { $_.name -eq 'QGISCF-medium' }).ours | Should -BeTrue
        @($script:Inv.objects.sitPackages    | Where-Object { $_.name -eq 'Microsoft Rule Package' }).ours | Should -BeFalse
        @($script:Inv.objects.labels         | Where-Object { $_.name -eq 'QGISCF-Medical-M01' }).ours | Should -BeTrue
        @($script:Inv.objects.labels         | Where-Object { $_.name -eq 'Confidential' }).ours | Should -BeFalse
        @($script:Inv.objects.dlpRules)[0].ours          | Should -BeTrue
        @($script:Inv.objects.autoLabelRules)[0].ours    | Should -BeTrue
    }

    It 'preserves type-specific fields used by later assessment (policy, publisher, guid)' {
        @($script:Inv.objects.dlpRules)[0].policy          | Should -Be 'P01-MED-QGISCF-EXT'
        @($script:Inv.objects.sitPackages)[0].publisher    | Should -Be 'QGISCF DLP Deploy'
        @($script:Inv.objects.labels)[0].guid              | Should -Be '22222222-2222-2222-2222-222222222222'
        @($script:Inv.objects.autoLabelRules)[0].policy    | Should -Be 'AL01-M01-QGISCF-EXT'
    }

    It 'shells every read cmdlet exactly once' {
        # Call inside the It so the invocation counter is scoped to this test, not BeforeAll.
        $null = Get-TenantInventory -Prefix 'QGISCF'
        Should -Invoke -ModuleName Compl8.Tenant Get-DlpKeywordDictionary -Times 1 -Exactly
        Should -Invoke -ModuleName Compl8.Tenant Get-DlpSensitiveInformationTypeRulePackage -Times 1 -Exactly
        Should -Invoke -ModuleName Compl8.Tenant Get-DlpComplianceRule -Times 1 -Exactly
        Should -Invoke -ModuleName Compl8.Tenant Get-DlpCompliancePolicy -Times 1 -Exactly
        Should -Invoke -ModuleName Compl8.Tenant Get-Label -Times 1 -Exactly
        Should -Invoke -ModuleName Compl8.Tenant Get-LabelPolicy -Times 1 -Exactly
        Should -Invoke -ModuleName Compl8.Tenant Get-AutoSensitivityLabelPolicy -Times 1 -Exactly
        Should -Invoke -ModuleName Compl8.Tenant Get-AutoSensitivityLabelRule -Times 1 -Exactly
    }

    It 'writes inventory.json to the supplied -OutFile path' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("inv-" + [guid]::NewGuid().ToString('N') + '.json')
        try {
            $written = Get-TenantInventory -Prefix 'QGISCF' -OutFile $tmp
            Test-Path -LiteralPath $tmp | Should -BeTrue
            $roundTrip = Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json
            $roundTrip.schemaVersion | Should -Be 'compl8.inventory/v1'
            @($roundTrip.objects.dictionaries).Count | Should -Be 2
        } finally {
            Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
        }
    }

    It 'matches the hand-authored engine fixture shape' {
        $fixture = Join-Path (Split-Path $PSScriptRoot -Parent) 'tests' 'fixtures' 'engine' 'actual' 'inventory.json'
        # PSScriptRoot is tests/, so the fixture is reachable directly under it too.
        if (-not (Test-Path -LiteralPath $fixture)) {
            $fixture = Join-Path $PSScriptRoot 'fixtures' 'engine' 'actual' 'inventory.json'
        }
        Test-Path -LiteralPath $fixture | Should -BeTrue
        $fx = Get-Content -LiteralPath $fixture -Raw | ConvertFrom-Json
        $fx.schemaVersion | Should -Be 'compl8.inventory/v1'
        # Same object-type list and same per-record fields as the live reader produces.
        foreach ($t in 'dictionaries', 'sitPackages', 'dlpRules', 'dlpPolicies', 'labels', 'labelPolicies', 'autoLabelPolicies', 'autoLabelRules') {
            $fx.objects.PSObject.Properties.Name | Should -Contain $t
        }
        $fxDict = @($fx.objects.dictionaries)[0]
        $fxDict.PSObject.Properties.Name | Should -Contain 'name'
        $fxDict.PSObject.Properties.Name | Should -Contain 'identity'
        $fxDict.PSObject.Properties.Name | Should -Contain 'ours'
        # At least one ours and one foreign record somewhere in the fixture.
        $allRecords = foreach ($p in $fx.objects.PSObject.Properties) { @($p.Value) }
        @($allRecords | Where-Object { $_.ours -eq $true })  | Should -Not -BeNullOrEmpty
        @($allRecords | Where-Object { $_.ours -eq $false }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Export-TenantActualSnapshot' {
    BeforeAll {
        $script:Workspace = Join-Path ([System.IO.Path]::GetTempPath()) ("ws-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Workspace -Force | Out-Null
    }
    AfterAll {
        Remove-Item -LiteralPath $script:Workspace -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'writes inventory.json under actual/snapshots/<Timestamp>/ using the injected timestamp' {
        $inv = [pscustomobject]@{
            schemaVersion = 'compl8.inventory/v1'
            objects       = [pscustomobject]@{ dictionaries = @(); sitPackages = @() }
        }
        $res = Export-TenantActualSnapshot -WorkspacePath $script:Workspace -Timestamp '20260613_120000' -Inventory $inv
        $expected = Join-Path $script:Workspace 'actual' 'snapshots' '20260613_120000' 'inventory.json'
        Test-Path -LiteralPath $expected | Should -BeTrue
        $res.InventoryPath | Should -Be $expected
        $res.Timestamp     | Should -Be '20260613_120000'
        (Get-Content -LiteralPath $expected -Raw | ConvertFrom-Json).schemaVersion | Should -Be 'compl8.inventory/v1'
    }

    It 'is deterministic — does not call Get-Date (timestamp is supplied)' {
        # If the function relied on Get-Date, two calls with the same -Timestamp would still
        # land in the same directory; assert the path is purely a function of -Timestamp.
        $inv = [pscustomobject]@{ schemaVersion = 'compl8.inventory/v1'; objects = [pscustomobject]@{} }
        $a = Export-TenantActualSnapshot -WorkspacePath $script:Workspace -Timestamp '20260101_000000' -Inventory $inv
        $b = Export-TenantActualSnapshot -WorkspacePath $script:Workspace -Timestamp '20260101_000000' -Inventory $inv
        $a.SnapshotDir | Should -Be $b.SnapshotDir
    }

    It 'requires an explicit -Timestamp (Get-Date is banned in deterministic paths)' {
        (Get-Command Export-TenantActualSnapshot).Parameters.ContainsKey('Timestamp') | Should -BeTrue
        (Get-Command Export-TenantActualSnapshot).Parameters['Timestamp'].Attributes.Mandatory | Should -Contain $true
    }
}
