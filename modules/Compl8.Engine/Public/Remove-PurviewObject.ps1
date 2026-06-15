function Remove-PurviewObject {
    <#
    .SYNOPSIS
        Checks an object's state before deleting it and returns a status string:
        "deleted" | "pending" | "cooldown:Nm" | "not-found" | "failed". (PHASE 4C, Task 7.)

    .DESCRIPTION
        FRESH PORT of DLP-Deploy.psm1's Remove-PurviewObject into Compl8.Engine scope (decision D1 —
        the Engine is the only tenant-mutating layer, D3; the DLP-Deploy original stays live and
        unmodified, this is a deliberate second copy). Behaviour is IDENTICAL to the original; the only
        change is that the inline throttle-retry's sleep is INJECTABLE via -SleepAction (threaded into
        Invoke-WithRetry) so the retry path is testable without real waiting.

        Flow (unchanged from the original):
          1. STATE PRE-CHECK. If no -InputObject, call -GetCommand -Identity. A "not found" style get
             error => "not-found"; any other get error => "failed". A get returning nothing => "not-found".
          2. PENDING-DELETION SKIP. If the object's Mode or State is 'PendingDeletion', return "pending"
             (silently skipped — it is already being removed).
          3. WHATIF. With -WhatIf, return "deleted" WITHOUT calling the remove cmdlet.
          4. REMOVE. Call -RemoveCommand -Identity -Confirm:$false. On success => "deleted". On a
             pending-deletion error => "pending". On a delete-cooldown error => "cooldown:Nm" (N from
             the message + 1, default 60). On a throttle error, retry inline via Invoke-WithRetry =>
             "deleted" on eventual success, "failed" if retries are exhausted. Any other error => "failed".

    .PARAMETER Identity
        The object's identity/name passed to the get/remove cmdlets.

    .PARAMETER GetCommand
        Name of the get cmdlet used for the state pre-check (skipped when -InputObject is supplied).

    .PARAMETER RemoveCommand
        Name of the remove cmdlet (mandatory).

    .PARAMETER InputObject
        A pre-fetched object (from a prior listing); when supplied the get cmdlet is NOT called.

    .PARAMETER OperationName
        Label for messages (e.g. "AL rule").

    .PARAMETER MaxRetries
        Retry budget forwarded to the inline throttle Invoke-WithRetry. Default 3.

    .PARAMETER BaseDelaySec
        Base backoff forwarded to the inline throttle Invoke-WithRetry. Default 300.

    .PARAMETER WhatIf
        Report-only: return "deleted" without calling the remove cmdlet.

    .PARAMETER SleepAction
        Injectable sleep forwarded to the inline throttle Invoke-WithRetry. Tests pass a no-op so the
        retry path runs instantly; defaults to a real Start-Sleep for production callers.
    #>
    param(
        [Parameter(Mandatory)][string]$Identity,
        [string]$GetCommand,
        [Parameter(Mandatory)][string]$RemoveCommand,
        [object]$InputObject,
        [string]$OperationName = "object",
        [int]$MaxRetries = 3,
        [int]$BaseDelaySec = 300,
        [switch]$WhatIf,
        [scriptblock]$SleepAction = { param($s) Start-Sleep -Seconds $s }
    )

    # Step 1: Check if the object exists and inspect its state.
    # If caller already has the object (from a prior listing), skip the Get call.
    $obj = $InputObject
    if (-not $obj) {
        if (-not $GetCommand) {
            Write-Warning "  No -InputObject or -GetCommand provided for $OperationName ${Identity}"
            return "failed"
        }
        try {
            $obj = & $GetCommand -Identity $Identity -ErrorAction Stop
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match "couldn't be found" -or $msg -match "not found" -or $msg -match "does not exist") {
                Write-Host " -> not found, skipped" -ForegroundColor DarkGray
                return "not-found"
            }
            Write-Warning "  Could not query $OperationName ${Identity}: $msg"
            return "failed"
        }
    }

    if (-not $obj) {
        Write-Host "    (not found, skipping): $Identity" -ForegroundColor DarkGray
        return "not-found"
    }

    # Step 2: Check for pending deletion state
    # Purview objects may have Mode = "PendingDeletion" or similar state indicators
    $isPending = $false
    if ($obj.PSObject.Properties['Mode'] -and $obj.Mode -eq 'PendingDeletion') { $isPending = $true }
    if ($obj.PSObject.Properties['State'] -and $obj.State -eq 'PendingDeletion') { $isPending = $true }

    if ($isPending) {
        Write-Host " -> pending deletion, skipped" -ForegroundColor DarkGray
        return "pending"
    }

    # Step 3: Delete
    if ($WhatIf) {
        Write-Host " -> would remove (WhatIf)" -ForegroundColor Yellow
        return "deleted"
    }

    Write-Host " -> deleting..." -ForegroundColor Gray -NoNewline
    try {
        & $RemoveCommand -Identity $Identity -Confirm:$false -ErrorAction Stop
        Write-Host " done" -ForegroundColor Green
        return "deleted"
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "PendingDeletion" -or $msg -match "pending deletion") {
            Write-Host " -> pending deletion, skipped" -ForegroundColor DarkGray
            return "pending"
        }
        if ($msg -match "DeleteRetryInterval" -or $msg -match "retry after (\d+) min") {
            $waitMin = 60
            if ($msg -match "retry after (\d+) min") { $waitMin = [int]$Matches[1] + 1 }
            Write-Host " -> cooldown (${waitMin}m remaining)" -ForegroundColor DarkYellow
            return "cooldown:$waitMin"
        }
        if ($msg -match "server side error" -or $msg -match "try again after some time") {
            Write-Host " -> throttled, retrying..." -ForegroundColor DarkYellow
            # For throttle errors, do retry inline
            try {
                Invoke-WithRetry -OperationName "Remove $OperationName $Identity" -ScriptBlock {
                    & $RemoveCommand -Identity $Identity -Confirm:$false -ErrorAction Stop
                } -MaxRetries $MaxRetries -BaseDelaySec $BaseDelaySec -SleepAction $SleepAction
                Write-Host " -> removed (after retry)" -ForegroundColor Green
                return "deleted"
            } catch {
                Write-Host " -> FAILED after retries: $($_.Exception.Message)" -ForegroundColor Red
                return "failed"
            }
        }
        Write-Host " -> FAILED: $msg" -ForegroundColor Red
        return "failed"
    }
}
