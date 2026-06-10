function Test-IsInteractive {
    # Mockable seam: Pester cannot mock [Environment]::UserInteractive directly.
    # Interactive only when a console UI is present AND stdin is NOT redirected, so a
    # `pwsh -File ...` / CI run (stdin piped) is treated non-interactive and hits the
    # clean abort path instead of a Read-Host "NonInteractive mode" error.
    try {
        return ([Environment]::UserInteractive -and -not [System.Console]::IsInputRedirected)
    } catch {
        return $false
    }
}
