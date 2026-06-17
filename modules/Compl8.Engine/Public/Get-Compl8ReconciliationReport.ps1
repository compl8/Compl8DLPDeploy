function Get-Compl8ReconciliationReport {
    <#
    .SYNOPSIS
        Renders a compl8.reconciliation/v1 object (Invoke-Compl8Reconcile output) as a human-readable
        text summary — the headless baseline the Surface prints during the operator's reconciliation walk
        (Reconciliation R5; spec §5; Stage-5 D6 "the TUI walks, the Engine holds the logic").

    .DESCRIPTION
        Pure transform (no I/O), mirroring Get-Compl8AssessmentReport. It turns the reconciliation result
        into an operator-facing report:

          * a header with the terminal STATUS (converged / blocked), the iteration count, and whether the
            iteration cap was hit;
          * one section per ITERATION — its phase (claim / reconcile), whether it is `projected` (a
            preview that must be re-planned live after the prior mutating iteration applies — see the
            Invoke-Compl8Reconcile APPLY CONTRACT), the actions it takes, the removal BLAST-RADIUS preview
            (referencing rules / blocked state) for any destructive step, and its plan step count;
          * the blocking CALL-OUTS that keep status `blocked` — unresolved name-collisions, pending work
            (actionable entries the loop never planned, e.g. a cap truncation), unreconciled entries (a
            planner gap — drift the executors cannot converge), and unclaimable requests.

        The Surface prints this verbatim and overlays its own interactive prompts; it adds no logic.

    .PARAMETER Reconciliation
        A compl8.reconciliation/v1 object (Invoke-Compl8Reconcile output).

    .OUTPUTS
        A single multi-line string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Reconciliation
    )

    $lines = [System.Collections.Generic.List[string]]::new()

    $lines.Add("Reconciliation ($($Reconciliation.schemaVersion)) — workspace '$($Reconciliation.workspace)'") | Out-Null
    if ($Reconciliation.generatedUtc) { $lines.Add("Generated: $($Reconciliation.generatedUtc)") | Out-Null }
    $capNote = if ($Reconciliation.PSObject.Properties['iterationCapHit'] -and $Reconciliation.iterationCapHit) { '; iteration cap HIT (work remains)' } else { '' }
    $lines.Add("Status: $($Reconciliation.status)   (iterations: $($Reconciliation.iterationCount)$capNote)") | Out-Null
    $lines.Add('') | Out-Null

    foreach ($it in @($Reconciliation.iterations | Sort-Object index)) {
        $proj = if ($it.PSObject.Properties['projected'] -and $it.projected) { 'true' } else { 'false' }
        $lines.Add("Iteration $($it.index) [$($it.phase)] (projected: $proj)") | Out-Null

        $acts = @($it.actions)
        if ($acts.Count -gt 0) {
            $lines.Add('  Actions:') | Out-Null
            foreach ($a in $acts) {
                $lines.Add(("    - {0} {1} '{2}'" -f $a.resolution, $a.objectType, $a.ref)) | Out-Null
            }
        }

        $blast = @($it.blastRadius)
        if ($blast.Count -gt 0) {
            $lines.Add('  Blast radius (removals):') | Out-Null
            foreach ($b in $blast) {
                $refs = @($b.referencingRules)
                $refText = if ($refs.Count -gt 0) { "referencing rules: $($refs -join ', ')" } else { 'no referencing rules' }
                $blockedText = if ($b.blocked) { ' [BLOCKED — dereference required first]' } else { '' }
                $lines.Add(("    - removing {0} '{1}' -> {2}{3}" -f $b.objectType, $b.ref, $refText, $blockedText)) | Out-Null
            }
        }

        $stepCount = @($it.plan.steps).Count
        $lines.Add("  Plan: $stepCount step(s)") | Out-Null

        # Risk strategist verdict per planned change — internal/external impact + hand-back (the deploy's
        # 5c gate withholds the hand-backs pending approval; here it is shown so the operator sees it while
        # walking). Only non-trivial verdicts are listed to keep the report readable.
        $risk = @($it.PSObject.Properties['risk'] ? $it.risk : @())
        $notable = @($risk | Where-Object { $_ -and ($_.handBack -or $_.riskLevel -in 'medium', 'high', 'critical') })
        if ($notable.Count -gt 0) {
            $lines.Add('  Risk:') | Out-Null
            foreach ($r in $notable) {
                $ext = @($r.externalImpact)
                $extText = if ($ext.Count -gt 0) { " — reaches EXTERNAL: $((@($ext | ForEach-Object { $_.ref }) | Sort-Object -Unique) -join ', ')" } else { '' }
                $hb = if ($r.handBack) { ' [HAND BACK — needs approval]' } else { '' }
                $lines.Add(("    - [{0}] {1} {2} '{3}'{4}{5}" -f $r.riskLevel, $r.action, $r.objectType, $r.ref, $extText, $hb)) | Out-Null
            }
        }

        $remaining = @($it.remainingConflicts)
        if ($remaining.Count -gt 0) { $lines.Add("  Conflicts still open after this iteration: $($remaining.Count)") | Out-Null }
        $lines.Add('') | Out-Null
    }

    # --- blocking call-outs (only shown when non-empty) -------------------------------------------
    $unresolved = @($Reconciliation.unresolvedConflicts)
    if ($unresolved.Count -gt 0) {
        $lines.Add("Unresolved conflicts (no/`'leave`' resolution — still blocking): $($unresolved.Count)") | Out-Null
        foreach ($c in @($unresolved | Sort-Object slug, kind)) {
            $lines.Add(("  - {0} [{1}]: {2}" -f $c.slug, $c.kind, $c.detail)) | Out-Null
        }
        $lines.Add('') | Out-Null
    }

    $pending = @($Reconciliation.PSObject.Properties['pendingWork'] ? $Reconciliation.pendingWork : @())
    if ($pending.Count -gt 0) {
        $lines.Add("Pending work (actionable but not planned — e.g. cap truncation, adopted orphans): $($pending.Count)") | Out-Null
        foreach ($p in @($pending | Sort-Object @{ Expression = { $_.objectType } }, @{ Expression = { $_.ref } })) {
            $lines.Add(("  - {0} '{1}' (would be: {2})" -f $p.objectType, $p.ref, $p.wouldBe)) | Out-Null
        }
        $lines.Add('') | Out-Null
    }

    $unreconciled = @($Reconciliation.PSObject.Properties['unreconciled'] ? $Reconciliation.unreconciled : @())
    if ($unreconciled.Count -gt 0) {
        $lines.Add("Unreconciled (the planner cannot turn this drift into a convergent step): $($unreconciled.Count)") | Out-Null
        foreach ($u in @($unreconciled | Sort-Object @{ Expression = { $_.objectType } }, @{ Expression = { $_.ref } })) {
            $lines.Add(("  - {0} '{1}' — {2}" -f $u.objectType, $u.ref, $u.reason)) | Out-Null
        }
        $lines.Add('') | Out-Null
    }

    $unclaimable = @($Reconciliation.PSObject.Properties['unclaimable'] ? $Reconciliation.unclaimable : @())
    if ($unclaimable.Count -gt 0) {
        $lines.Add("Unclaimable (claim request could not be honoured): $($unclaimable.Count)") | Out-Null
        foreach ($u in @($unclaimable | Sort-Object @{ Expression = { $_.objectType } }, @{ Expression = { $_.ref } })) {
            $lines.Add(("  - {0} '{1}' — {2}" -f $u.objectType, $u.ref, $u.reason)) | Out-Null
        }
        $lines.Add('') | Out-Null
    }

    $handBacks = @($Reconciliation.PSObject.Properties['riskHandBacks'] ? $Reconciliation.riskHandBacks : @())
    if ($handBacks.Count -gt 0) {
        $lines.Add("Risk hand-backs (the deploy WILL withhold these for explicit approval): $($handBacks.Count)") | Out-Null
        foreach ($h in $handBacks) {
            $lines.Add(("  - [{0}] {1} {2} '{3}': {4}" -f $h.riskLevel, $h.action, $h.objectType, $h.ref, $h.rationale)) | Out-Null
        }
        $lines.Add('') | Out-Null
    }

    return (($lines -join [Environment]::NewLine).TrimEnd())
}
