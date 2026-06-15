function Get-Compl8AssessmentReport {
    <#
    .SYNOPSIS
        Renders a compl8.assessment/v1 object as a human-readable text summary.
    .DESCRIPTION
        Pure transform (no I/O): turns the seven-bucket assessment produced by
        Invoke-Compl8Assess into an operator-facing summary — a count line per bucket
        (in the deterministic Get-Compl8EngineSchemaEnums walk order), an explicit
        foreign / never-touch call-out (opacity-as-safety, spec §8), and the upgrade
        conflict call-outs carried from the resolve manifest. The render is plain text
        so it drops cleanly into a console, a log, or a TUI panel. The Surface (not the
        Engine) owns the eventual rich rendering; this is the headless baseline.
    .PARAMETER Assessment
        A compl8.assessment/v1 object (from Invoke-Compl8Assess / New-AssessmentObject).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Assessment
    )

    $enums = Get-Compl8EngineSchemaEnums
    $lines = [System.Collections.Generic.List[string]]::new()

    $lines.Add("Assessment ($($Assessment.schemaVersion)) — workspace '$($Assessment.workspace)'") | Out-Null
    if ($Assessment.generatedUtc) { $lines.Add("Generated: $($Assessment.generatedUtc)") | Out-Null }
    $lines.Add("Inputs: resolveManifest=$($Assessment.inputs.resolveManifest) inventory=$($Assessment.inputs.inventory)") | Out-Null
    $lines.Add('') | Out-Null

    # --- bucket counts (deterministic order) ---
    $lines.Add('Buckets:') | Out-Null
    foreach ($bucket in $enums.Buckets) {
        $entries = @($Assessment.buckets.$bucket)
        $lines.Add(("  {0,-16} {1}" -f $bucket, $entries.Count)) | Out-Null
        foreach ($entry in @($entries | Sort-Object @{ Expression = { $_.objectType } }, @{ Expression = { $_.ref } })) {
            $detail = if ($entry.from -and $entry.to) { " ($($entry.from) -> $($entry.to))" } else { '' }
            $lines.Add(("      - {0}: {1}{2}" -f $entry.objectType, $entry.ref, $detail)) | Out-Null
        }
    }
    $lines.Add('') | Out-Null

    # --- foreign / never-touch call-out (opacity-as-safety) ---
    $foreign = @($Assessment.buckets.foreign)
    $lines.Add("Foreign (NOT ours — never touched): $($foreign.Count)") | Out-Null
    foreach ($entry in @($foreign | Sort-Object @{ Expression = { $_.objectType } }, @{ Expression = { $_.ref } })) {
        $lines.Add(("  - {0}: {1}" -f $entry.objectType, $entry.ref)) | Out-Null
    }
    $lines.Add('') | Out-Null

    # --- upgrade conflicts ---
    $conflicts = @($Assessment.upgradeConflicts)
    $lines.Add("Upgrade conflicts: $($conflicts.Count)") | Out-Null
    foreach ($c in @($conflicts | Sort-Object slug, kind)) {
        $lines.Add(("  - {0} [{1}]: {2}" -f $c.slug, $c.kind, $c.detail)) | Out-Null
    }

    # --- impact ---
    $impact = @($Assessment.impact)
    if ($impact.Count -gt 0) {
        $lines.Add('') | Out-Null
        $lines.Add("Impact (changed classifiers referenced by live DLP rules): $($impact.Count)") | Out-Null
        foreach ($i in @($impact | Sort-Object objectRef)) {
            $lines.Add(("  - {0} affects: {1}" -f $i.objectRef, (@($i.affects) -join ', '))) | Out-Null
        }
    }

    return ($lines -join [Environment]::NewLine)
}
