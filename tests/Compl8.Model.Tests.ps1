#Requires -Modules Pester

BeforeAll {
    $script:ModuleDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'Compl8.Model'
    Import-Module $script:ModuleDir -Force
}

Describe 'Get-DeploymentLimits' {
    It 'returns the authoring-class rule package limits (sit-limits, MS-verified 2026-06-10)' {
        $l = Get-DeploymentLimits
        $l.MaxSitsPerRulePackage    | Should -Be 50
        $l.MaxRulePackageBytes      | Should -Be 153600   # 150 KB
        $l.PreferredRulePackageBytes | Should -Be 151552  # 148 KB self-imposed margin
        $l.MaxRulePackagesPerTenant | Should -Be 10
    }
    It 'returns dictionary budget thresholds' {
        $l = Get-DeploymentLimits
        $l.DictionaryBudgetWarnBytes | Should -Be 491520   # 480 KB conservative warn
        $l.DictionaryBudgetMaxBytes  | Should -Be 1048576  # 1 MB hard cap
    }
    It 'keeps the auto-label CONSUMPTION limit separate from the authoring cap' {
        (Get-DeploymentLimits).AutoLabelMaxSitsPerRule | Should -Be 125
    }
}

Describe 'DLP-Deploy facade' {
    It 'exposes Get-DeploymentLimits through the legacy module' {
        $facade = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'DLP-Deploy.psm1'
        Import-Module $facade -Force
        Get-Command Get-DeploymentLimits -Module DLP-Deploy | Should -Not -BeNullOrEmpty
    }
}

Describe 'Compl8.Model standalone exports (parsing/graph)' {
    BeforeAll {
        Remove-Module DLP-Deploy -ErrorAction SilentlyContinue
        $script:ModelDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'Compl8.Model'
        Import-Module $script:ModelDir -Force
    }
    It 'exports the parser and graph functions without loading DLP-Deploy' {
        $names = @(
            'Convert-DlpSerializedRulePackageToText', 'Get-DlpRulePackageEntityIds',
            'Get-DlpRulePolicyNames', 'Get-DlpRuleClassifierReferenceText',
            'New-DeploymentGraphNodeId', 'Get-DeploymentGraphObjectValue',
            'Get-DeploymentGraphRulePackageInfo', 'Get-DeploymentReferenceGraph',
            'ConvertTo-DeploymentRelativePath', 'Get-DictionaryGuidReferences',
            'Test-SITRulePackageXml'
        )
        foreach ($n in $names) {
            (Get-Command -Name $n -Module Compl8.Model -ErrorAction SilentlyContinue) |
                Should -Not -BeNullOrEmpty -Because "$n should be exported by Compl8.Model"
        }
    }
    It 'extracts entity ids from a minimal rule package standalone' {
        $xml = @'
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="aaaaaaaa-1111-2222-3333-444444444444">
    <Version major="1" minor="0" build="0" revision="0"/>
    <Publisher id="bbbbbbbb-1111-2222-3333-444444444444"/>
    <Details>
      <LocalizedDetails langcode="en-us">
        <PublisherName>Test</PublisherName>
        <Name>TestPkg</Name>
        <Description>Test</Description>
      </LocalizedDetails>
    </Details>
  </RulePack>
  <Rules>
    <Entity id="33333333-3333-3333-3333-333333333333" patternsProximity="300" recommendedConfidence="85">
      <Pattern confidenceLevel="85">
        <IdMatch idRef="Pattern_test"/>
      </Pattern>
    </Entity>
    <LocalizedStrings>
      <Resource idRef="33333333-3333-3333-3333-333333333333">
        <Name default="true" langcode="en-us">Test Entity</Name>
        <Description default="true" langcode="en-us">Test entity description</Description>
      </Resource>
    </LocalizedStrings>
  </Rules>
</RulePackage>
'@
        $pkg = [pscustomobject]@{
            Identity = 'test-pkg'
            Publisher = 'Test'
            Name = 'TestPkg'
            SerializedClassificationRuleCollection = $xml
        }
        $r = Get-DlpRulePackageEntityIds -Packages @($pkg)
        $r[0].Parsed | Should -BeTrue
        $r[0].EntityIds | Should -Contain '33333333-3333-3333-3333-333333333333'
        $r[0].RulePackId | Should -Be 'aaaaaaaa-1111-2222-3333-444444444444'
    }
}

Describe 'Get-DlpEntityContentHash — shared canonical SIT content hash' {
    BeforeAll {
        Remove-Module DLP-Deploy -ErrorAction SilentlyContinue
        $script:ModelDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'Compl8.Model'
        Import-Module $script:ModelDir -Force
    }

    It 'is exported by Compl8.Model' {
        (Get-Command -Name Get-DlpEntityContentHash -Module Compl8.Model -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty
    }

    It 'returns a sha256:-prefixed 64-hex-char hash' {
        $h = Get-DlpEntityContentHash -EntityXml '<Entity id="x"><Pattern confidenceLevel="85"/></Entity>'
        $h | Should -Match '^sha256:[0-9a-f]{64}$'
    }

    It 'hashes two serially-different-but-semantically-equal entities EQUAL (the comparability seam)' {
        # Same entity, three serialisations: compact, indented+xml-decl, and a UTF-16 decl.
        $compact = '<Entity id="22222222-aaaa-4bbb-8ccc-000000000002"><Pattern confidenceLevel="75"><IdMatch idRef="P"/></Pattern></Entity>'
        $indented = @"
<?xml version="1.0" encoding="utf-8"?>
<Entity id="22222222-aaaa-4bbb-8ccc-000000000002">
  <Pattern confidenceLevel="75">
    <IdMatch idRef="P" />
  </Pattern>
</Entity>
"@
        $utf16decl = "<?xml version='1.0' encoding='utf-16'?>`r`n<Entity id=`"22222222-aaaa-4bbb-8ccc-000000000002`">`r`n`t<Pattern confidenceLevel=`"75`"><IdMatch idRef=`"P`"></IdMatch></Pattern></Entity>"

        $a = Get-DlpEntityContentHash -EntityXml $compact
        $b = Get-DlpEntityContentHash -EntityXml $indented
        $c = Get-DlpEntityContentHash -EntityXml $utf16decl
        $a | Should -Be $b
        $a | Should -Be $c
    }

    It 'hashes a genuinely-changed entity DIFFERENTLY (real drift still surfaces)' {
        $base    = '<Entity id="x"><Pattern confidenceLevel="75"><IdMatch idRef="P"/></Pattern></Entity>'
        $changed = '<Entity id="x"><Pattern confidenceLevel="85"><IdMatch idRef="P"/></Pattern></Entity>'
        (Get-DlpEntityContentHash -EntityXml $base) | Should -Not -Be (Get-DlpEntityContentHash -EntityXml $changed)
    }

    It 'is stable across processes for the same input (deterministic)' {
        $x = '<Entity id="x"><Regex id="r">(?i)\bfoo\b</Regex></Entity>'
        Get-DlpEntityContentHash -EntityXml $x | Should -Be (Get-DlpEntityContentHash -EntityXml $x)
    }

    It 'preserves significant text — a changed Regex body changes the hash' {
        $a = '<Entity id="x"><Regex id="r">(?i)\bfoo\b</Regex></Entity>'
        $b = '<Entity id="x"><Regex id="r">(?i)\bbar\b</Regex></Entity>'
        (Get-DlpEntityContentHash -EntityXml $a) | Should -Not -Be (Get-DlpEntityContentHash -EntityXml $b)
    }

    It 'does not throw on null/empty/unparseable input' {
        { Get-DlpEntityContentHash -EntityXml $null } | Should -Not -Throw
        { Get-DlpEntityContentHash -EntityXml '' }    | Should -Not -Throw
        { Get-DlpEntityContentHash -EntityXml 'not xml <<<' } | Should -Not -Throw
    }
}

Describe 'Compl8.Model standalone exports (naming)' {
    BeforeAll {
        # Reload Compl8.Model in a clean state; the DLP-Deploy facade Describe above
        # dot-sources the same files into DLP-Deploy scope which can shift function
        # ownership away from Compl8.Model.  Re-importing ensures the module's own
        # Export-ModuleMember list is current for the -Module filter below.
        Remove-Module DLP-Deploy -ErrorAction SilentlyContinue
        $script:ModelDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules' 'Compl8.Model'
        Import-Module $script:ModelDir -Force
    }
    It 'exports the naming functions without loading DLP-Deploy' {
        $names = @(
            'ConvertTo-DeploymentNameTemplates', 'Remove-DeploymentNamePrefix',
            'Expand-DeploymentNameTemplate', 'Get-DeploymentObjectName',
            'Get-PolicyName', 'Get-RuleName',
            'Get-PurviewUnsafeNameCharacterSummary', 'Test-PurviewObjectNameSafety',
            'Assert-PurviewObjectNameSafety'
        )
        foreach ($n in $names) {
            (Get-Command -Name $n -Module Compl8.Model -ErrorAction SilentlyContinue) |
                Should -Not -BeNullOrEmpty -Because "$n should be exported by Compl8.Model"
        }
    }
    It 'expands a name template standalone' {
        # Exercises Expand-DeploymentNameTemplate directly — matches the DLP-Deploy.Tests.ps1
        # Get-PolicyName legacy-format assertion (P01-ECH-QGISCF-EXT-ADT) but via the
        # template engine so the test is independent of Get-ModuleDefaults.
        $result = Expand-DeploymentNameTemplate -Template 'P{policyNumber}-{policyCode}-{prefix}-{suffix}' `
            -Tokens @{ policyNumber = '01'; policyCode = 'ECH'; prefix = 'QGISCF'; suffix = 'EXT-ADT' }
        $result | Should -Be 'P01-ECH-QGISCF-EXT-ADT'
    }
}

Describe 'Layer scaffolds' {
    It 'all four layer modules import cleanly' {
        $root = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules'
        foreach ($layer in 'Compl8.Model', 'Compl8.Tenant', 'Compl8.Content', 'Compl8.Engine') {
            { Import-Module (Join-Path $root $layer) -Force -ErrorAction Stop } | Should -Not -Throw
        }
    }
}
