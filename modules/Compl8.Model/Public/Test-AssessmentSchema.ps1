function Test-AssessmentSchema {
    <#
    .SYNOPSIS
        Validates a compl8.assessment/v1 object against the Engine lifecycle schema.
    .DESCRIPTION
        Pure transform (no I/O): returns { Valid; Errors } rather than throwing, so
        callers can surface every problem at once. Enforces the schemaVersion, the
        known bucket names and object types (single-sourced from
        Get-Compl8EngineSchemaEnums), and the standing invariant that each object ref
        appears in EXACTLY ONE bucket. Format per
        docs/superpowers/specs/2026-06-13-engine-lifecycle.md.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Assessment
    )

    $enums = Get-Compl8EngineSchemaEnums
    $errors = [System.Collections.Generic.List[string]]::new()

    if ($Assessment.schemaVersion -ne 'compl8.assessment/v1') {
        $errors.Add("Unsupported schemaVersion '$($Assessment.schemaVersion)' (expected compl8.assessment/v1).")
    }
    if (-not $Assessment.workspace) {
        $errors.Add('Assessment is missing the workspace field.')
    }
    if ($null -eq $Assessment.buckets) {
        $errors.Add('Assessment is missing the buckets section.')
        return [pscustomobject]@{ Valid = $false; Errors = @($errors) }
    }

    # Every one of the seven buckets MUST be present (even if empty) — the contract is
    # that an assessment is a total partition, so a missing bucket is a malformed object,
    # not an empty one. Without this an assessment that simply omits 'foreign' or 'drift'
    # would validate, silently weakening the exactly-one-of-seven guarantee.
    $presentBuckets = @($Assessment.buckets.PSObject.Properties.Name)
    foreach ($required in $enums.Buckets) {
        if ($presentBuckets -notcontains $required) {
            $errors.Add("Assessment is missing the required '$required' bucket.")
        }
    }

    # Walk every bucket once; flag unknown buckets, unknown object types, and any
    # ref that shows up in more than one bucket (the exactly-one invariant).
    $seen = @{}
    foreach ($prop in $Assessment.buckets.PSObject.Properties) {
        $bucket = $prop.Name
        if ($enums.Buckets -notcontains $bucket) {
            $errors.Add("Unknown assessment bucket '$bucket'.")
            continue
        }
        foreach ($entry in @($prop.Value)) {
            if ($enums.ObjectTypes -notcontains $entry.objectType) {
                $errors.Add("Bucket '$bucket': unknown objectType '$($entry.objectType)' for ref '$($entry.ref)'.")
            }
            $key = "$($entry.objectType)|$($entry.ref)"
            if ($seen.ContainsKey($key)) {
                $errors.Add("Object '$($entry.ref)' ($($entry.objectType)) appears in two buckets ('$($seen[$key])' and '$bucket'); each object must land in exactly one.")
            } else {
                $seen[$key] = $bucket
            }
        }
    }

    [pscustomobject]@{
        Valid  = ($errors.Count -eq 0)
        Errors = @($errors)
    }
}
