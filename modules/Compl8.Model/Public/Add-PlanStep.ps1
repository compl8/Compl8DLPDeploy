function Add-PlanStep {
    <#
    .SYNOPSIS
        Appends a step to a compl8.plan/v1 object and returns the updated plan.
    .DESCRIPTION
        Pure transform (no I/O): builds one step in the authoritative shape
        ({ id; action; objectType; objectRef; dependsOn; impact; gate }) and returns
        a new plan with the step appended. Throws on a duplicate step id so the plan
        can never carry two steps with the same id (Test-PlanSchema is the backstop).
        Action / objectType are NOT validated here — Test-PlanSchema is the single
        validator — so a planner can stage a step and validate the whole plan once.
        Format per docs/superpowers/specs/2026-06-13-engine-lifecycle.md.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan,

        [Parameter(Mandatory)]
        [string]$Id,

        [Parameter(Mandatory)]
        [string]$Action,

        [Parameter(Mandatory)]
        [string]$ObjectType,

        [Parameter(Mandatory)]
        [string]$ObjectRef,

        [string[]]$DependsOn = @(),

        [string[]]$Impact = @(),

        [pscustomobject]$Gate = $null
    )

    if (@($Plan.steps | ForEach-Object id) -contains $Id) {
        throw "Plan '$($Plan.id)' already has a step with id '$Id'."
    }

    $step = [pscustomobject]@{
        id         = $Id
        action     = $Action
        objectType = $ObjectType
        objectRef  = $ObjectRef
        dependsOn  = @($DependsOn)
        impact     = @($Impact)
        gate       = $Gate
    }

    $Plan.steps = @($Plan.steps) + $step
    $Plan
}
