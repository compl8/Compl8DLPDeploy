function Get-Compl8EngineSchemaEnums {
    <#
    .SYNOPSIS
        Single source of truth for the Engine lifecycle schema enums.
    .DESCRIPTION
        The assessment bucket names, plan-step actions, object types, and gate
        types are defined ONCE here so the Model validators (Test-AssessmentSchema /
        Test-PlanSchema), the constructors (New-AssessmentObject / New-PlanObject /
        Add-PlanStep), the Engine, and the tests reference them rather than
        re-declaring string literals. Bucket order is significant — it is the
        deterministic walk order the assessment renderer relies on. Pure; no I/O.
        Formats per docs/superpowers/specs/2026-06-13-engine-lifecycle.md
        (compl8.assessment/v1, compl8.plan/v1).
    #>
    [CmdletBinding()]
    param()

    [pscustomobject]@{
        # Assessment buckets — each tenant object lands in exactly one.
        Buckets     = @('create', 'update-in-place', 'repack-move', 'remove', 'orphan', 'foreign', 'drift')
        # Plan-step actions.
        Actions     = @('create', 'update', 'remove', 'repack-move', 'dereference', 'snapshot')
        # Object types referenced by assessment entries and plan steps.
        ObjectTypes = @('dictionary', 'rulePackage', 'sit', 'label', 'labelPolicy', 'dlpRule', 'dlpPolicy', 'autoLabelPolicy', 'tenant')
        # Gate types carried as data on plan steps (enforcement is pluggable in Engine).
        GateTypes   = @('propagation', 'externalRefs', 'snapshotBeforeDestroy')
    }
}
