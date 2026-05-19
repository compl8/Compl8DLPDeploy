#==============================================================================
# Invoke-CIChecks.ps1
# Local verification entrypoint for generated DLP deployment content.
#==============================================================================

[CmdletBinding()]
param(
    [switch]$SkipPester
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

Invoke-Check -Name "Classifier XML validation" -ScriptBlock {
    & (Join-Path $ProjectRoot "scripts\Deploy-Classifiers.ps1") -Action Validate
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
        $result = Invoke-Pester -Path $testPath -PassThru
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
