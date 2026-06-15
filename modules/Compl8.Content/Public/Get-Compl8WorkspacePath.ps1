function Get-Compl8WorkspacePath {
    <#
    .SYNOPSIS
        Resolves a path inside a tenant-environment workspace.
    .DESCRIPTION
        Workspace root resolution: $env:COMPL8_WORKSPACE_ROOT if set, else <repo>\workspaces
        (the transitional default per the 2026-06-10 architecture design §3; moving the root
        out of the repo entirely is the Stage 5 end state).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Environment,

        [string]$Path,

        [switch]$EnsureExists
    )

    $root = if ($env:COMPL8_WORKSPACE_ROOT) {
        $env:COMPL8_WORKSPACE_ROOT
    } else {
        # This file lives at modules/Compl8.Content/Public/ — repo root is three levels up.
        $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
        Join-Path $repoRoot 'workspaces'
    }

    $resolved = Join-Path $root $Environment
    if ($Path) {
        foreach ($segment in ($Path -split '[/\\]' | Where-Object { $_ })) {
            $resolved = Join-Path $resolved $segment
        }
    }

    if ($EnsureExists -and -not (Test-Path -LiteralPath $resolved)) {
        New-Item -ItemType Directory -Path $resolved -Force | Out-Null
    }

    $resolved
}
