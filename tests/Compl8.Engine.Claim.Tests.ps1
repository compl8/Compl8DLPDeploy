#Requires -Modules Pester

# =====================================================================================
# Reconciliation R2 — the `claim`/adopt action + Invoke-Compl8ClaimExecutor.
#
# Claiming ADOPTS an existing not-ours object into management by re-stamping its provenance
# (Comment) — content untouched — so the next assess buckets it as drift and the ordinary
# update path reconciles it in place. This is the operator-gated exception to opacity-as-safety
# that lets the compl8.dev old-deployment (48 rules squatting the desired names) be migrated
# without delete-and-recreate.
# =====================================================================================

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot  = Split-Path $PSScriptRoot -Parent
    $script:EngineDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:EngineDir -Force

    $env:COMPL8_PROVENANCE_REGISTRY = Join-Path ([System.IO.Path]::GetTempPath()) ("compl8-claim-prov-{0}.json" -f ([guid]::NewGuid().ToString('N')))
    $env:COMPL8_DEPLOYMENT_ID = '20260616'
    $script:NoSleep = { param($s) }

    function global:Get-DlpComplianceRule   { [CmdletBinding()] param([string]$Identity, [string]$Policy) }
    function global:Set-DlpComplianceRule   { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled) }
    function global:New-DlpComplianceRule   { [CmdletBinding(SupportsShouldProcess)] param([string]$Name, [string]$Policy, [string]$Comment, $ContentContainsSensitiveInformation, $AdvancedRule, [string]$ReportSeverityLevel, [bool]$Disabled) }
    function global:Get-DlpCompliancePolicy { [CmdletBinding()] param([string]$Identity) }
    function global:Set-DlpCompliancePolicy { [CmdletBinding(SupportsShouldProcess)] param([string]$Identity, [string]$Comment, [string]$Mode) }

    function script:ClaimStep { param([string]$Type, [string]$Ref) [pscustomobject]@{ id = 's1'; action = 'claim'; objectType = $Type; objectRef = $Ref; dependsOn = @(); impact = @(); gate = $null } }
}

AfterAll {
    foreach ($fn in 'Get-DlpComplianceRule', 'Set-DlpComplianceRule', 'New-DlpComplianceRule', 'Get-DlpCompliancePolicy', 'Set-DlpCompliancePolicy') {
        Remove-Item "function:global:$fn" -ErrorAction SilentlyContinue
    }
}

Describe 'claim — schema' {
    It 'is a valid plan-step action' {
        (Get-Compl8EngineSchemaEnums).Actions | Should -Contain 'claim'
    }
    It 'a plan carrying a claim step passes Test-PlanSchema' {
        $plan = New-PlanObject -Workspace 'nonprod' -Id 'plan-claim' -GeneratedUtc '2026-06-16T00:00:00Z'
        $plan = Add-PlanStep -Plan $plan -Id 's1' -Action 'claim' -ObjectType 'dlpRule' -ObjectRef 'P01-R01-ECH-OFFI' -DependsOn @() -Impact @() -Gate $null
        (Test-PlanSchema -Plan $plan).Valid | Should -BeTrue
    }
    It 'is exported from Compl8.Engine' {
        (Get-Command -Name Invoke-Compl8ClaimExecutor -Module Compl8.Engine -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-Compl8ClaimExecutor — adopts by re-stamping the Comment only' {
    It 'claims a dlpRule: re-stamps the Comment, does NOT touch the rule content, status=claimed' {
        Mock -ModuleName Compl8.Engine Get-DlpComplianceRule { [pscustomobject]@{ Identity = 'P01-R01-ECH-OFFI'; Name = 'P01-R01-ECH-OFFI'; Comment = 'legacy rule comment' } }
        Mock -ModuleName Compl8.Engine Set-DlpComplianceRule { }
        $r = Invoke-Compl8ClaimExecutor -Step (ClaimStep 'dlpRule' 'P01-R01-ECH-OFFI') -Prefix 'QGISCF' -TargetEnvironment 'nonprod' -SleepAction $script:NoSleep
        $r.status            | Should -Be 'claimed'
        $r.stampedComment    | Should -Match '\[\[Compl8:[0-9a-f]{16}\]\]'
        $r.stampedComment    | Should -Match 'legacy rule comment'   # original comment preserved
        # Set was called with the stamped Comment and WITHOUT touching the content (CCSI).
        Should -Invoke -ModuleName Compl8.Engine Set-DlpComplianceRule -Times 1 -ParameterFilter {
            $Comment -match '\[\[Compl8:[0-9a-f]{16}\]\]' -and $null -eq $ContentContainsSensitiveInformation
        }
    }
    It 'claims a dlpPolicy: re-stamps via Set-DlpCompliancePolicy -Comment (no mode/location change)' {
        Mock -ModuleName Compl8.Engine Get-DlpCompliancePolicy { [pscustomobject]@{ Identity = 'P01-ECH-QGISCF-EXT-ADT'; Name = 'P01-ECH-QGISCF-EXT-ADT'; Comment = '' } }
        Mock -ModuleName Compl8.Engine Set-DlpCompliancePolicy { }
        $r = Invoke-Compl8ClaimExecutor -Step (ClaimStep 'dlpPolicy' 'P01-ECH-QGISCF-EXT-ADT') -Prefix 'QGISCF' -SleepAction $script:NoSleep
        $r.status | Should -Be 'claimed'
        Should -Invoke -ModuleName Compl8.Engine Set-DlpCompliancePolicy -Times 1 -ParameterFilter { $Comment -match '\[\[Compl8:[0-9a-f]{16}\]\]' -and $null -eq $Mode }
    }
    It '-WhatIf reports a planned claim WITHOUT mutating' {
        Mock -ModuleName Compl8.Engine Get-DlpComplianceRule { [pscustomobject]@{ Identity = 'r'; Comment = '' } }
        Mock -ModuleName Compl8.Engine Set-DlpComplianceRule { }
        $r = Invoke-Compl8ClaimExecutor -Step (ClaimStep 'dlpRule' 'r') -Prefix 'QGISCF' -SleepAction $script:NoSleep -WhatIf
        $r.status | Should -Be 'planned'
        Should -Invoke -ModuleName Compl8.Engine Set-DlpComplianceRule -Times 0
    }
    It 'reports not-found (no mutation) when the object is absent' {
        Mock -ModuleName Compl8.Engine Get-DlpComplianceRule { $null }
        Mock -ModuleName Compl8.Engine Set-DlpComplianceRule { }
        $r = Invoke-Compl8ClaimExecutor -Step (ClaimStep 'dlpRule' 'ghost') -Prefix 'QGISCF' -SleepAction $script:NoSleep
        $r.status | Should -Be 'not-found'
        Should -Invoke -ModuleName Compl8.Engine Set-DlpComplianceRule -Times 0
    }
    It 'throws for an unsupported objectType (only dlpRule/dlpPolicy are claimable in v1)' {
        { Invoke-Compl8ClaimExecutor -Step (ClaimStep 'dictionary' 'QGISCF - X') -Prefix 'QGISCF' -SleepAction $script:NoSleep } | Should -Throw
    }
}

Describe 'Get-Compl8ExecutorMap — routes a claim step to the claim executor' {
    It 'a dlpRule claim step is dispatched to Invoke-Compl8ClaimExecutor, not the create/update path' {
        Mock -ModuleName Compl8.Engine Get-DlpComplianceRule { [pscustomobject]@{ Identity = 'P01-R01-ECH-OFFI'; Comment = 'x' } }
        Mock -ModuleName Compl8.Engine Set-DlpComplianceRule { }
        Mock -ModuleName Compl8.Engine New-DlpComplianceRule { }
        $map = Get-Compl8ExecutorMap -StepContent @{} -Prefix 'QGISCF' -SleepAction $script:NoSleep
        $result = & $map['dlpRule'] (ClaimStep 'dlpRule' 'P01-R01-ECH-OFFI')
        $result.status | Should -Be 'claimed'
        Should -Invoke -ModuleName Compl8.Engine Set-DlpComplianceRule -Times 1
        Should -Invoke -ModuleName Compl8.Engine New-DlpComplianceRule -Times 0
    }
}
