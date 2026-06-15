function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Retries a scriptblock on transient Purview API errors (throttle / delete-cooldown), treats
        a pending-deletion error as success, and otherwise rethrows. (PHASE 4C, Task 7.)

    .DESCRIPTION
        FRESH PORT of DLP-Deploy.psm1's Invoke-WithRetry into Compl8.Engine scope (decision D1 — the
        Engine is the only tenant-mutating layer, D3; the DLP-Deploy original stays live and
        unmodified, this is a deliberate second copy). Behaviour is IDENTICAL to the original with one
        determinism change: the real Start-Sleep is INJECTABLE via -SleepAction so tests assert retry
        COUNTS instantly without wall-clock waiting (and Get-Date / a real Start-Sleep never run).

        Recognised conditions (matched on the exception message), in priority order:
          * pending-deletion ("PendingDeletion" / "pending deletion") — the object is ALREADY being
            deleted, so this is treated as SUCCESS (returns, no retry, no throw).
          * delete-cooldown ("DeleteRetryInterval" / "retry after N min") — Purview enforces a ~60-min
            cooldown between delete attempts on the same object. Waits the stated minutes (N+1, default
            60) and retries while attempts remain.
          * throttle ("server side error" / "try again after some time") — backs off BaseDelaySec *
            attempt seconds and retries while attempts remain.
          * transient ("Object reference not set") — short 30s * attempt backoff, retried up to twice.
        Anything else (or exhausting the retry budget) rethrows the original error.

        The original used Start-Sleep + Get-Date for the resume-time banner; here the SLEEP is the only
        side effect that matters for control flow and it is injected. The Get-Date-based banner text is
        dropped (it was cosmetic Write-Host only); the retry/backoff logic is preserved exactly.

    .PARAMETER ScriptBlock
        The operation to run (and retry on a recognised transient error).

    .PARAMETER OperationName
        Label used in progress messages.

    .PARAMETER MaxRetries
        Maximum number of RETRIES (the operation runs up to MaxRetries+1 times). Default 3.

    .PARAMETER BaseDelaySec
        Base backoff for throttle errors (delay = BaseDelaySec * attempt). Default 300.

    .PARAMETER SleepAction
        Injectable sleep. A scriptblock taking one positional arg (seconds). Defaults to a real
        Start-Sleep; tests pass a no-op/recording scriptblock so retries are instant and assertable.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [string]$OperationName = "operation",
        [int]$MaxRetries = 3,
        [int]$BaseDelaySec = 300,
        [scriptblock]$SleepAction = { param($s) Start-Sleep -Seconds $s }
    )

    for ($attempt = 1; $attempt -le ($MaxRetries + 1); $attempt++) {
        try {
            return (& $ScriptBlock)
        } catch {
            $msg = $_.Exception.Message
            $isThrottle = $msg -match "server side error" -or
                          $msg -match "try again after some time"
            $isTransient = $msg -match "Object reference not set"
            $isDeleteCooldown = $msg -match "DeleteRetryInterval" -or
                                $msg -match "retry after (\d+) min"
            $isPendingDeletion = $msg -match "PendingDeletion" -or
                                 $msg -match "pending deletion"

            if ($isPendingDeletion) {
                # Already being deleted — treat as success, not an error
                Write-Host "    (already pending deletion, skipping)" -ForegroundColor DarkGray
                return
            } elseif ($isDeleteCooldown -and $attempt -le $MaxRetries) {
                # Purview enforces a 60-min cooldown between delete attempts on the same rule.
                # Extract the wait time from the message if possible.
                $waitMin = 60
                if ($msg -match "retry after (\d+) min") { $waitMin = [int]$Matches[1] + 1 }
                $delaySec = $waitMin * 60
                Write-Host "  PAUSED — Purview delete cooldown on: $OperationName (waiting ${waitMin}m, attempt $attempt of $MaxRetries)" -ForegroundColor DarkYellow
                & $SleepAction $delaySec
                Write-Host "  Resuming operations..." -ForegroundColor Cyan
            } elseif ($isThrottle -and $attempt -le $MaxRetries) {
                $delaySec = $BaseDelaySec * $attempt
                $delayMin = [math]::Round($delaySec / 60, 0)
                Write-Host "  PAUSED — Purview API throttle on: $OperationName (waiting ${delayMin}m / ${delaySec}s, attempt $attempt of $MaxRetries)" -ForegroundColor DarkYellow
                & $SleepAction $delaySec
                Write-Host "  Resuming operations..." -ForegroundColor Cyan
            } elseif ($isTransient -and $attempt -le 2) {
                $delaySec = 30 * $attempt
                Write-Host "  PAUSED — Transient server error on: $OperationName (waiting ${delaySec}s, retry $attempt of 2)" -ForegroundColor DarkYellow
                & $SleepAction $delaySec
                Write-Host "  Resuming operations..." -ForegroundColor Cyan
            } else {
                throw
            }
        }
    }
}
