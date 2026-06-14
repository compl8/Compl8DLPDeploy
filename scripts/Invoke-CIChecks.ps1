#==============================================================================
# Invoke-CIChecks.ps1
# Local verification entrypoint for generated DLP deployment content.
#==============================================================================

[CmdletBinding()]
param(
    [switch]$SkipPester,
    # Fast dev loop: exclude the slow "shadow parity" tests (Describe blocks tagged 'Slow'
    # that run the real Deploy-*.ps1 leaf scripts). DEFAULT (no switch) runs EVERYTHING so
    # CI stays unchanged.
    [switch]$Fast
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$failures = [System.Collections.Generic.List[string]]::new()

function Invoke-Check {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )

    Write-Host "`n=== $Name ===" -ForegroundColor Cyan
    try {
        & $ScriptBlock
        Write-Host "PASS: $Name" -ForegroundColor Green
    } catch {
        $failures.Add("$Name`: $($_.Exception.Message)")
        Write-Host "FAIL: $Name" -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    }
}

Invoke-Check -Name "PowerShell parser" -ScriptBlock {
    $files = @(
        Get-ChildItem -LiteralPath (Join-Path $ProjectRoot "scripts") -Recurse -File -Include *.ps1
        Get-ChildItem -LiteralPath (Join-Path $ProjectRoot "modules") -Recurse -File -Include *.psm1,*.psd1
    )
    foreach ($file in $files) {
        $errors = $null
        [System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw -LiteralPath $file.FullName), [ref]$errors) | Out-Null
        if ($errors.Count -gt 0) {
            throw "$($file.FullName): $($errors[0].Message)"
        }
    }
}

Invoke-Check -Name "Deployment readiness" -ScriptBlock {
    $ok = @(& (Join-Path $ProjectRoot "scripts\Test-DeploymentReadiness.ps1") -Scope All -NoExit)
    if ($ok.Count -eq 0 -or $ok[-1] -ne $true) {
        throw "Deployment readiness failed"
    }
}

Invoke-Check -Name "TestPattern drift fixtures" -ScriptBlock {
    $ok = @(& (Join-Path $ProjectRoot "scripts\Test-TestPatternDrift.ps1") -NoExit)
    if ($ok.Count -eq 0 -or $ok[-1] -ne $true) {
        throw "TestPattern drift fixture validation failed"
    }
}

Invoke-Check -Name "Classifier XML validation" -ScriptBlock {
    # Offline validation with no orchestrator: acknowledge the direct run so the
    # orchestration gate doesn't abort CI (Validate does not mutate the tenant).
    & (Join-Path $ProjectRoot "scripts\Deploy-Classifiers.ps1") -Action Validate -AllowDirectRun
}

if (-not $SkipPester) {
    Invoke-Check -Name "Pester" -ScriptBlock {
        if (-not (Get-Module -ListAvailable -Name Pester)) {
            throw "Pester is not installed"
        }
        $testPath = Join-Path $ProjectRoot "tests"
        if (-not (Test-Path -LiteralPath $testPath)) {
            throw "No tests directory found"
        }
        # Ensure Pester 5+ (the inbox v3 ships alongside on Windows).
        Import-Module Pester -MinimumVersion 5.0
        $pesterConfig = New-PesterConfiguration
        $pesterConfig.Run.Path = $testPath
        $pesterConfig.Run.PassThru = $true
        if ($Fast) {
            # Fast dev loop: skip the slow shadow-parity Describes. DEFAULT leaves the filter
            # empty so every test still runs (CI behaviour is unchanged).
            $pesterConfig.Filter.ExcludeTag = 'Slow'
            Write-Host "  (-Fast) excluding tests tagged 'Slow'" -ForegroundColor Yellow
        }
        $result = Invoke-Pester -Configuration $pesterConfig
        if ($result.FailedCount -gt 0) {
            throw "$($result.FailedCount) Pester test(s) failed"
        }
    }
}

if ($failures.Count -gt 0) {
    Write-Host "`n=== CI Check Failures ===" -ForegroundColor Red
    foreach ($failure in $failures) { Write-Host "  - $failure" -ForegroundColor Red }
    exit 1
}

Write-Host "`nAll CI checks passed." -ForegroundColor Green
