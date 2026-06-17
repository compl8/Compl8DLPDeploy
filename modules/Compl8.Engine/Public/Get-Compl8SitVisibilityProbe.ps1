function Get-Compl8SitVisibilityProbe {
    <#
    .SYNOPSIS
        Returns the production propagation probe — a scriptblock that resolves classifier propagation by
        TENANT VISIBILITY (the authoritative signal the leaf uses), for Invoke-Compl8Apply -PropagationProbe.

    .DESCRIPTION
        The leaf (scripts/Deploy-Classifiers.ps1) detects propagation by polling
        Get-DlpSensitiveInformationType until the uploaded SIT IDs are visible in the tenant. This returns
        a scriptblock with that contract so the Engine apply path uses the same real signal instead of the
        4-hour time-window folklore.

        The returned scriptblock takes the SIT entity GUIDs a propagation-gated step needs visible
        (gate.requiresSitIds, stamped by Get-Compl8PlanOrder) and returns:
          * $true  — every required SIT is visible in the tenant now (the gate may proceed),
          * $false — at least one is still missing (propagation incomplete; the gate blocks),
          * $null  — the tenant could not be queried (cmdlet unavailable / call failed) — UNDETERMINED,
                     so the gate falls back to its time-offset window rather than guessing.

        Connected callers (Invoke-Compl8Deploy) default Invoke-Compl8Apply -PropagationProbe to this;
        disconnected/test callers omit it (visibility unknown => time fallback). The probe matches a SIT
        by any of its identity-bearing fields (Identity / Id / Guid) and Name, case-insensitively, so it
        is robust to which field the cmdlet surfaces the entity GUID on.

    .OUTPUTS
        A [scriptblock] of the form { param([string[]]$SitIds) -> $true | $false | $null }.
    #>
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param()

    {
        param([string[]]$SitIds)
        $required = @(@($SitIds) | Where-Object { $_ })
        if ($required.Count -eq 0) { return $null }   # nothing to confirm => undetermined
        try {
            $tenantSits = @(Get-DlpSensitiveInformationType -ErrorAction Stop)
        } catch {
            return $null   # cmdlet absent or the tenant read failed => undetermined => time fallback
        }
        $present = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($sit in $tenantSits) {
            if (-not $sit) { continue }
            foreach ($field in 'Identity', 'Id', 'Guid', 'Name') {
                if ($sit.PSObject.Properties[$field] -and $sit.$field) { $present.Add([string]$sit.$field) | Out-Null }
            }
        }
        foreach ($id in $required) { if (-not $present.Contains([string]$id)) { return $false } }
        return $true
    }
}
