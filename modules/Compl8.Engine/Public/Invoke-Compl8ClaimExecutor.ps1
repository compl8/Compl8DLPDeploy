function Invoke-Compl8ClaimExecutor {
    <#
    .SYNOPSIS
        Adopts an existing NOT-OURS tenant object into management by re-stamping its provenance
        (Reconciliation R2; plan §D2). The apply executor for the `claim` action.

    .DESCRIPTION
        The opacity-as-safety invariant (spec §8) keeps assess from touching `foreign` objects. `claim`
        is the OPERATOR-GATED exception: when an existing object is confirmed to be ours-but-unstamped
        (e.g. an older deployment whose rules carry no current provenance, squatting the names the
        current config wants — the name-collision conflict assess now raises), the operator may ADOPT it.

        Claiming is MINIMAL and NON-DESTRUCTIVE: it reads the live object, appends the current provenance
        marker to its Comment via Add-DeploymentProvenanceStamp (Set-Dlp* with ONLY -Comment — the rule
        condition / policy content is NOT touched), and returns. The object is now ours, so the NEXT
        assess buckets it as `drift` (content differs from desired) or in-sync, and the ordinary update
        path reconciles it IN PLACE — no name collision, no delete-and-recreate, GUIDs retained.

        SCOPE. v1 claims the provenance-stamp-owned types whose ownership the marker confers: dlpRule and
        dlpPolicy (the migration case that motivated this). Other types throw 'unsupported' (dictionaries
        cannot be claimed — their names differ from the desired set, so there is nothing to adopt; labels /
        auto-label policies are future work). The component matches Invoke-Compl8DlpRuleExecutor so a
        claimed object's marker is identical to a freshly-deployed one and ownership resolves the same way.

    .PARAMETER Step
        The plan step (action='claim'; objectType in dlpRule/dlpPolicy; objectRef = the live object name).

    .PARAMETER Prefix
        Deployment naming prefix written into the provenance marker (UNSCOPED when absent).

    .PARAMETER TargetEnvironment
        Optional environment key threaded to the provenance marker.

    .PARAMETER ProvenanceRegistryPath
        Optional provenance registry path (the workspace's history/applies/provenance.json) threaded to
        Add-DeploymentProvenanceStamp -> the registry entry, so the claim is recorded in the workspace.

    .PARAMETER SleepAction
        Injectable sleep for the retry path (defaults to Start-Sleep; tests pass a no-op).

    .PARAMETER WhatIf
        Plan-only: report the claim that WOULD run without mutating.

    .OUTPUTS
        { stepId; action='claim'; objectType; objectRef; status ('claimed'|'planned'|'not-found');
          stampedComment; reason }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Step,
        [string]$Prefix,
        [string]$TargetEnvironment,
        [string]$ProvenanceRegistryPath,
        [scriptblock]$SleepAction = { param($s) Start-Sleep -Seconds $s },
        [switch]$WhatIf
    )

    $type = [string]$Step.objectType
    $name = [string]$Step.objectRef

    # Per-type plumbing: the read/write cmdlets + the provenance Component (must match the normal
    # executor so a claimed object's marker is indistinguishable from a freshly-deployed one).
    switch ($type) {
        'dlpRule'   { $getCmd = 'Get-DlpComplianceRule';     $setCmd = 'Set-DlpComplianceRule';     $component = 'DlpRule';   $metaKey = 'RuleName' }
        'dlpPolicy' { $getCmd = 'Get-DlpCompliancePolicy';   $setCmd = 'Set-DlpCompliancePolicy';   $component = 'DlpPolicy'; $metaKey = 'PolicyName' }
        default     { throw "Invoke-Compl8ClaimExecutor: cannot claim objectType '$type' (only dlpRule / dlpPolicy are claimable in v1)." }
    }

    function New-ClaimResult {
        param([string]$Status, [string]$StampedComment = $null, [string]$Reason = '')
        [pscustomobject]@{
            stepId = [string]$Step.id; action = 'claim'; objectType = $type; objectRef = $name
            status = $Status; stampedComment = $StampedComment; reason = $Reason
        }
    }

    if ($WhatIf) {
        return New-ClaimResult -Status 'planned' -Reason "would re-stamp provenance to adopt $type '$name'."
    }

    # Read the live object so its current Comment is PRESERVED (the stamp is appended, not replaced).
    $live = & $getCmd -Identity $name -ErrorAction SilentlyContinue
    if (-not $live) {
        return New-ClaimResult -Status 'not-found' -Reason "$type '$name' not found in the tenant; nothing to claim."
    }
    $currentComment = if ($live.PSObject.Properties['Comment']) { [string]$live.Comment } else { '' }

    $stamped = Add-DeploymentProvenanceStamp `
        -Text $currentComment `
        -Prefix $(if ($Prefix) { $Prefix } else { 'UNSCOPED' }) -Component $component `
        -TargetEnvironment $TargetEnvironment -Metadata @{ $metaKey = $name } `
        -RegistryPath $ProvenanceRegistryPath

    # Set ONLY the Comment — the object's content (rule condition / policy mode+locations) is untouched.
    Invoke-WithRetry -OperationName "Claim $type $name" -ScriptBlock {
        & $setCmd -Identity $name -Comment $stamped -Confirm:$false -ErrorAction Stop
    } -MaxRetries 2 -BaseDelaySec 30 -SleepAction $SleepAction | Out-Null

    New-ClaimResult -Status 'claimed' -StampedComment $stamped -Reason "adopted $type '$name' under management (prefix $(if ($Prefix) { $Prefix } else { 'UNSCOPED' })) — provenance re-stamped, content unchanged."
}
