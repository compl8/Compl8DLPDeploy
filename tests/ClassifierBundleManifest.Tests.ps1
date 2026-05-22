#Requires -Modules Pester

BeforeAll {
    $script:RepoRoot = Split-Path $PSScriptRoot -Parent
    $script:ManifestScript = Join-Path $script:RepoRoot 'scripts' 'Update-ClassifierBundleManifest.ps1'

    function New-TestRulePackageXml {
        param(
            [string]$RulePackId = '11111111-1111-1111-1111-111111111111',
            [string]$Version = '1.0.0.0',
            [string]$EntityName = 'TestPattern - One'
        )

        $parts = $Version.Split('.')
        while ($parts.Count -lt 4) { $parts += '0' }
        return @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="$RulePackId">
    <Version major="$($parts[0])" minor="$($parts[1])" build="$($parts[2])" revision="$($parts[3])" />
    <Details>
      <LocalizedDetails langcode="en-us">
        <PublisherName>Compl8</PublisherName>
        <Name>TestPkg</Name>
        <Description>Test package</Description>
      </LocalizedDetails>
    </Details>
  </RulePack>
  <Rules>
    <Entity id="22222222-2222-2222-2222-222222222222">
      <Pattern confidenceLevel="85">
        <IdMatch idRef="Pattern_test" />
      </Pattern>
    </Entity>
    <LocalizedStrings>
      <Resource idRef="22222222-2222-2222-2222-222222222222">
        <Name default="true" langcode="en-us">$EntityName</Name>
        <Description default="true" langcode="en-us">Test entity</Description>
      </Resource>
    </LocalizedStrings>
  </Rules>
</RulePackage>
"@
    }

    function New-TestClassifierProject {
        param([Parameter(Mandatory)][string]$Root)

        $deployDir = Join-Path $Root 'xml/deploy'
        New-Item -ItemType Directory -Path $deployDir -Force | Out-Null
        [ordered]@{
            tier = 'medium'
            packages = @(
                [ordered]@{
                    key = 'TestPkg'
                    entities = 1
                    sizeKB = 1
                }
            )
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $deployDir 'deploy-registry.json') -Encoding UTF8
        New-TestRulePackageXml | Set-Content -LiteralPath (Join-Path $deployDir 'TestPkg.xml') -Encoding UTF8
    }

    function Invoke-TestManifestScript {
        param(
            [Parameter(Mandatory)][string]$ProjectRoot,
            [string[]]$Arguments = @()
        )

        $splat = @{
            ProjectRoot = $ProjectRoot
            NoExit = $true
        }
        if ($Arguments -contains '-CheckOnly') {
            $splat.CheckOnly = $true
        }
        $result = @(& $script:ManifestScript @splat)
        return $result[-1]
    }
}

Describe 'Update-ClassifierBundleManifest.ps1' {
    BeforeEach {
        $script:TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('n'))
        New-TestClassifierProject -Root $script:TempRoot
        $script:DeployDir = Join-Path $script:TempRoot 'xml/deploy'
        $script:ManifestPath = Join-Path $script:DeployDir 'classifier-bundle-manifest.json'
        $script:XmlPath = Join-Path $script:DeployDir 'TestPkg.xml'
    }

    AfterEach {
        Remove-Item -LiteralPath $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'creates a manifest and then passes CheckOnly' {
        Invoke-TestManifestScript -ProjectRoot $script:TempRoot | Should -BeTrue
        Test-Path -LiteralPath $script:ManifestPath | Should -BeTrue

        $manifest = Get-Content -Raw -LiteralPath $script:ManifestPath | ConvertFrom-Json
        $manifest.packages[0].key | Should -Be 'TestPkg'
        $manifest.packages[0].version | Should -Be '1.0.0.0'
        $manifest.packages[0].sha256 | Should -Match '^[0-9a-f]{64}$'

        Invoke-TestManifestScript -ProjectRoot $script:TempRoot -Arguments @('-CheckOnly') | Should -BeTrue
    }

    It 'rejects an XML update without a RulePack version increment' {
        Invoke-TestManifestScript -ProjectRoot $script:TempRoot | Should -BeTrue
        New-TestRulePackageXml -EntityName 'TestPattern - Changed' |
            Set-Content -LiteralPath $script:XmlPath -Encoding UTF8

        Invoke-TestManifestScript -ProjectRoot $script:TempRoot | Should -BeFalse
    }

    It 'allows the manifest to update after a RulePack version increment' {
        Invoke-TestManifestScript -ProjectRoot $script:TempRoot | Should -BeTrue
        New-TestRulePackageXml -Version '1.1.0.0' -EntityName 'TestPattern - Changed' |
            Set-Content -LiteralPath $script:XmlPath -Encoding UTF8

        Invoke-TestManifestScript -ProjectRoot $script:TempRoot | Should -BeTrue
        $manifest = Get-Content -Raw -LiteralPath $script:ManifestPath | ConvertFrom-Json
        $manifest.packages[0].version | Should -Be '1.1.0.0'
    }

    It 'fails CheckOnly when the XML hash differs from the manifest' {
        Invoke-TestManifestScript -ProjectRoot $script:TempRoot | Should -BeTrue
        New-TestRulePackageXml -Version '1.1.0.0' -EntityName 'TestPattern - Changed' |
            Set-Content -LiteralPath $script:XmlPath -Encoding UTF8

        Invoke-TestManifestScript -ProjectRoot $script:TempRoot -Arguments @('-CheckOnly') | Should -BeFalse
    }
}
