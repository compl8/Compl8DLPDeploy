function Test-Compl8Gate {
    <#
    .SYNOPSIS
        Pluggable gate evaluator: given a plan step's gate object + context, decides whether the
        step may proceed (and, when blocked, why). (PHASE 4C, Task 6; arch design §5, decision D4.)

    .DESCRIPTION
        Gates are DATA on plan steps; enforcement is pluggable and lives HERE. The Engine apply
        loop (Invoke-Compl8Apply) calls Test-Compl8Gate before dispatching each step to its
        executor. A blocked step is NOT applied (apply stops at it and resumes from checkpoint on
        a later run once the gate clears).

        Three v1 gate types (single-sourced enum: Get-Compl8EngineSchemaEnums.GateTypes):

          * propagation — a SIT-upload's dependent rule step must wait for classifier propagation.
            The AUTHORITATIVE signal is tenant VISIBILITY (the same signal the leaf uses: it polls
            Get-DlpSensitiveInformationType until the uploaded SIT IDs appear). When the apply layer has
            probed the tenant, it passes -Context.DependencyVisible: $true => proceed now (propagation
            confirmed, regardless of the clock); $false => block now (genuinely not ready, regardless of
            the clock). ONLY when visibility is unknown (the key is absent — disconnected, or the gate
            carries no SIT ids to probe) does the gate fall back to the time window: the step proceeds
            once NOW has reached the notBefore instant, resolved in priority order:
              1. an explicit gate.notBefore (an ISO-8601 UTC instant), else
              2. (the dependency step's apply time, -Context.DependencyAppliedUtc)
                 + gate.notBeforeOffsetHours (a heuristic FALLBACK, not the primary signal).
            When neither the visibility signal nor a notBefore instant is available the gate is treated
            as BLOCKED (fail-closed) with an explanatory reason.

          * snapshotBeforeDestroy — a destructive step gated this way may proceed only once the
            generated snapshot Step 0.5 has already run (its checkpoint exists). The apply loop
            passes the snapshot's applied state in -Context.SnapshotApplied; the gate passes only
            when that is $true.

          * externalRefs — v1 is operator confirmation (no automated resolver, arch §8). The gate
            HALTS (does not pass) unless -ConfirmExternalRefs is supplied, at which point the
            operator has confirmed the external references resolve and the step may proceed.
            NOTE: this gate is DORMANT in this toolkit — it is attached only when a policy is scoped to
            NAMED external entities (groups/users/sites), and the config model never does that (locations
            are 'All' or rule-level scope filters, not entity references), so New-Compl8Plan never attaches
            it on a real assessment. It remains as the forward hook for if/when named scope members exist.

        DETERMINISM: the clock is INJECTED (-Now). Get-Date is BANNED in this function body so the
        gate decision is a pure function of (gate, now, context, confirmation) — golden-testable.

    .PARAMETER Gate
        The step's gate object ({ type; ... }) or $null. A $null gate always passes.

    .PARAMETER Now
        The injected current instant ([datetime]). Used to evaluate the propagation gate. Get-Date
        is never called — the caller stamps the clock (production passes the live UTC instant; tests
        pin it).

    .PARAMETER Context
        Optional hashtable of evaluation context:
          * DependencyVisible    — [bool] whether the dependency classifier is visible in the tenant
            now (the authoritative propagation signal; set by apply after probing). When present it
            decides the propagation gate outright; when absent the gate falls back to the time window.
          * DependencyAppliedUtc — the apply time of the step this gate's step depends on (the
            propagation offset FALLBACK is measured from here when gate.notBefore is absent).
          * SnapshotApplied       — [bool] whether the snapshot step has checkpointed
            (snapshotBeforeDestroy).

    .PARAMETER ConfirmExternalRefs
        Operator confirmation that the externalRefs are resolved. Required for an externalRefs gate
        to pass (v1 halt-and-confirm).

    .OUTPUTS
        [pscustomobject] { Passed = [bool]; Reason = [string] } — Reason is empty when Passed.
    #>
    [CmdletBinding()]
    param(
        [pscustomobject]$Gate,

        [Parameter(Mandatory)]
        [datetime]$Now,

        [hashtable]$Context = @{},

        [switch]$ConfirmExternalRefs
    )

    # No gate => always proceed.
    if ($null -eq $Gate) {
        return [pscustomobject]@{ Passed = $true; Reason = '' }
    }

    # Coerce a notBefore / dependency-apply value to a UTC [datetime], or $null if unparseable.
    # ConvertFrom-Json auto-converts ISO-8601 strings to [datetime] (Kind=Unspecified/Local), so
    # a gate read from a plan-on-disk carries a [datetime], not the original 'Z' string — handle
    # both. String parsing is invariant-culture + AssumeUniversal so 'YYYY-MM-DDTHH:MM:SSZ' and a
    # round-tripped [datetime] both land on the same instant.
    function ConvertTo-GateInstant {
        param($Value)
        if ($null -eq $Value) { return $null }
        if ($Value -is [datetime]) {
            $dt = [datetime]$Value
            if ($dt.Kind -eq [System.DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($dt, [System.DateTimeKind]::Utc) }
            return $dt.ToUniversalTime()
        }
        if ($Value -is [datetimeoffset]) { return ([datetimeoffset]$Value).UtcDateTime }
        $s = [string]$Value
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        $parsed = [datetimeoffset]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        if ([datetimeoffset]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
            return $parsed.UtcDateTime
        }
        return $null
    }

    $type = [string]$Gate.type

    switch ($type) {
        'propagation' {
            # AUTHORITATIVE signal (matches the leaf, which polls Get-DlpSensitiveInformationType until
            # the uploaded SIT IDs are visible): when the apply layer has probed the tenant and reported
            # whether the dependency classifier is visible, honour it OVER the clock. visible => proceed
            # now; not-yet-visible => block now (propagation genuinely incomplete). Only when visibility
            # is UNKNOWN (no probe — disconnected, or the gate carries no SIT ids) do we fall back to the
            # time-offset window below. This replaces the 4-24h folklore with the real readiness signal.
            if ($Context.ContainsKey('DependencyVisible')) {
                if ([bool]$Context['DependencyVisible']) {
                    return [pscustomobject]@{ Passed = $true; Reason = '' }
                }
                return [pscustomobject]@{
                    Passed = $false
                    Reason = 'propagation gate: the dependency classifier is not yet visible in the tenant (Get-DlpSensitiveInformationType) — propagation incomplete.'
                }
            }

            # Resolve the notBefore instant: explicit gate.notBefore, else dependency-apply-time +
            # offset hours. Parse as UTC for a stable comparison against the injected clock.
            $notBefore = $null
            if ($Gate.PSObject.Properties['notBefore']) {
                $notBefore = ConvertTo-GateInstant -Value $Gate.notBefore
            }
            if ($null -eq $notBefore) {
                $depInstant = if ($Context.ContainsKey('DependencyAppliedUtc')) { ConvertTo-GateInstant -Value $Context['DependencyAppliedUtc'] } else { $null }
                $offsetHours = if ($Gate.PSObject.Properties['notBeforeOffsetHours']) { [double]$Gate.notBeforeOffsetHours } else { $null }
                if ($null -ne $depInstant -and $null -ne $offsetHours) {
                    $notBefore = $depInstant.AddHours($offsetHours)
                }
            }

            if ($null -eq $notBefore) {
                return [pscustomobject]@{
                    Passed = $false
                    Reason = "propagation gate: no notBefore instant could be resolved (need gate.notBefore, or DependencyAppliedUtc + notBeforeOffsetHours) — blocked fail-closed."
                }
            }

            $nowUtc = $Now.ToUniversalTime()
            if ($nowUtc -ge $notBefore) {
                return [pscustomobject]@{ Passed = $true; Reason = '' }
            }
            return [pscustomobject]@{
                Passed = $false
                Reason = "propagation gate: now $($nowUtc.ToString('o')) is before notBefore $($notBefore.ToString('o')) — classifier propagation window not elapsed."
            }
        }

        'snapshotBeforeDestroy' {
            $snapshotApplied = $false
            if ($Context.ContainsKey('SnapshotApplied')) { $snapshotApplied = [bool]$Context['SnapshotApplied'] }
            if ($snapshotApplied) {
                return [pscustomobject]@{ Passed = $true; Reason = '' }
            }
            return [pscustomobject]@{
                Passed = $false
                Reason = 'snapshotBeforeDestroy gate: the snapshot step has not yet run (no checkpoint) — a destructive step cannot proceed before the snapshot lands.'
            }
        }

        'externalRefs' {
            if ($ConfirmExternalRefs) {
                return [pscustomobject]@{ Passed = $true; Reason = '' }
            }
            return [pscustomobject]@{
                Passed = $false
                Reason = 'externalRefs gate: external references (groups/users/sites in policy scopes) require operator confirmation — re-run with -ConfirmExternalRefs once verified (v1 has no automated resolver).'
            }
        }

        default {
            # An unknown gate type fails closed — the enforcement registry does not recognise it.
            return [pscustomobject]@{
                Passed = $false
                Reason = "unknown gate type '$type' — no evaluator registered; blocked fail-closed."
            }
        }
    }
}
