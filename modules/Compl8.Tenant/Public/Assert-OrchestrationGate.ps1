function Assert-OrchestrationGate {
    <#
    .SYNOPSIS
        Guards a tenant-mutating leaf script against being run raw (bypassing the
        orchestrator's drift / config-skew gates). Returns silently when orchestrated
        (COMPL8_ORCHESTRATED env var), session-driven (-SessionPath), or explicitly
        acknowledged (-AllowDirectRun). Otherwise warns; if interactive, prompts to
        continue (throws on decline); non-interactive raw runs throw.
    #>
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [switch]$AllowDirectRun,
        [string]$SessionPath,
        [string]$RecommendedEntry = 'Start-DLPDeploy.ps1 (interactive) or Invoke-FullDeployment.ps1 (CLI)'
    )
    if (-not [string]::IsNullOrWhiteSpace($env:COMPL8_ORCHESTRATED)) { return }
    if ($AllowDirectRun) { return }
    if (-not [string]::IsNullOrWhiteSpace($SessionPath)) { return }

    Write-Warning "Direct run of $ScriptName -- the drift gate and config-skew confirm normally run by the orchestrator are SKIPPED."
    Write-Host "  Recommended entry: $RecommendedEntry" -ForegroundColor Yellow

    if (Test-IsInteractive) {
        $ans = (Read-Host "  Continue anyway? [y/N]").Trim()
        if ($ans -notmatch '^(y|yes)$') {
            throw "Aborted: direct run of $ScriptName declined."
        }
        return
    }
    throw "Aborted: non-interactive direct run of $ScriptName. Pass -AllowDirectRun to proceed."
}
