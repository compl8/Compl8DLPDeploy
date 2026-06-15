function Test-PlanSchema {
    <#
    .SYNOPSIS
        Validates a compl8.plan/v1 object against the Engine lifecycle schema.
    .DESCRIPTION
        Pure transform (no I/O): returns { Valid; Errors } rather than throwing, so
        callers can surface every problem at once. Enforces the schemaVersion, unique
        step ids, the known action / objectType / gate.type enums (single-sourced
        from Get-Compl8EngineSchemaEnums), and dependsOn referential integrity (every
        named dependency must be a step id present in the plan). Format per
        docs/superpowers/specs/2026-06-13-engine-lifecycle.md.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan
    )

    $enums = Get-Compl8EngineSchemaEnums
    $errors = [System.Collections.Generic.List[string]]::new()

    if ($Plan.schemaVersion -ne 'compl8.plan/v1') {
        $errors.Add("Unsupported schemaVersion '$($Plan.schemaVersion)' (expected compl8.plan/v1).")
    }
    if (-not $Plan.id) {
        $errors.Add('Plan is missing the id field.')
    }
    if (-not $Plan.workspace) {
        $errors.Add('Plan is missing the workspace field.')
    }

    $steps = @($Plan.steps)
    $stepIds = @($steps | ForEach-Object id)

    $seenIds = @{}
    foreach ($step in $steps) {
        if ($seenIds.ContainsKey($step.id)) {
            $errors.Add("Duplicate step id '$($step.id)'.")
        } else {
            $seenIds[$step.id] = $true
        }

        if ($enums.Actions -notcontains $step.action) {
            $errors.Add("Step '$($step.id)': unknown action '$($step.action)'.")
        }
        if ($enums.ObjectTypes -notcontains $step.objectType) {
            $errors.Add("Step '$($step.id)': unknown objectType '$($step.objectType)'.")
        }

        # Cross-field: a `claim` step may only target a claimable objectType. Without this an
        # unsupported claim (e.g. claim a dictionary) passes schema and fails later in apply dispatch.
        if ($step.action -eq 'claim' -and $enums.ClaimableObjectTypes -notcontains $step.objectType) {
            $errors.Add("Step '$($step.id)': action 'claim' is not valid for objectType '$($step.objectType)' (claimable: $($enums.ClaimableObjectTypes -join ', ')).")
        }

        foreach ($dep in @($step.dependsOn)) {
            if ($stepIds -notcontains $dep) {
                $errors.Add("Step '$($step.id)': dependsOn names a missing step id '$dep'.")
            }
        }

        if ($null -ne $step.gate -and $enums.GateTypes -notcontains $step.gate.type) {
            $errors.Add("Step '$($step.id)': unknown gate.type '$($step.gate.type)'.")
        }
    }

    [pscustomobject]@{
        Valid  = ($errors.Count -eq 0)
        Errors = @($errors)
    }
}
