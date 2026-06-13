function Get-Compl8ShadowDiff {
    <#
    .SYNOPSIS
        Diffs an Engine executor's PLANNED operations against the old leaf script's -WhatIf
        operations and returns a structured diff. An EMPTY diff (Match=$true) means byte/semantic
        parity — the gate Tasks 8-12 use to prove each executor reproduces the old path.
        (PHASE 4C, Task 7; arch design §5/§6, decision D1.)

    .DESCRIPTION
        The shadow-validation gate. For each apply executor (Tasks 8-12) we run the Engine executor in
        plan/-WhatIf mode and capture the operations it WOULD perform, and separately run the existing
        leaf script (Deploy-*.ps1 / Sync-DlpKeywordDictionaries) under -WhatIf and capture the same.
        This function compares the two lists; an empty diff proves the fresh Engine port reproduces the
        old path exactly, which is the precondition for cutting that object type over.

        NORMALISED OP SHAPE (the contract both sides emit):
            [pscustomobject]@{
                action     = '<create|update|remove|repack-move|dereference|snapshot|...>'
                objectType = '<dictionary|rulePackage|sit|label|labelPolicy|dlpRule|...>'
                objectRef  = '<the object name / ref, e.g. "QGISCF-medium-03" or "{{DICT_X}}">'
                # ...zero or more EXTRA descriptive fields (payloadHash, target, fromPackage, etc.)
            }
        Only `action`, `objectType`, `objectRef` are REQUIRED. This is deliberately compatible with
        Invoke-Compl8Apply -WhatIf's `wouldRun` records ({ stepId; action; objectType; objectRef }) so
        an apply -WhatIf list can be diffed against an old-path -WhatIf list with no reshaping; the
        extra `stepId` field (and any other non-key field present on only one side) is simply ignored
        when absent on the other side and field-compared when present on both.

        COMPARISON STRATEGY (stable + order-insensitive):
          * KEY = "action|objectType|objectRef". This identifies an operation independent of list order.
            (Duplicate keys within one list collapse to the last occurrence — executors emit at most one
            op per object/action, matching the old path.)
          * Both lists are indexed by key.
          * key only in Engine -> OnlyInEngine (the full Engine op object).
          * key only in Old    -> OnlyInOld    (the full Old op object).
          * key in BOTH        -> FIELD-COMPARE the INTERSECTION of non-key properties (fields present
            on BOTH sides). A field present on both with differing string values is a difference. A
            field present on only ONE side is IGNORED (it is descriptive metadata one emitter carries
            and the other does not, e.g. an apply -WhatIf record's `stepId`) — only fields the two
            sides AGREE to describe are part of the parity contract. If any compared field differs the
            op lands in Differing as { key; fields=@(<differing field names, sorted>); engine=<obj>; old=<obj> }.
          * Match = $true  <=>  OnlyInEngine, OnlyInOld, and Differing are all empty.

        Field comparison is by string value (each side's value rendered via [string]) so it is stable
        across JSON round-trips and PSObject vs hashtable inputs. Comparisons are ORDINAL/case-sensitive
        on values (a casing change IS a difference — the old path's exact output is the contract).

    .PARAMETER EngineOps
        The Engine executor's planned operation list (normalised op records). May be empty.

    .PARAMETER OldOps
        The old leaf script's -WhatIf operation list (normalised op records). May be empty.

    .OUTPUTS
        [pscustomobject]@{
            Match        = [bool]    # $true iff all three arrays below are empty
            OnlyInEngine = @(<op>)   # ops the Engine would do that the old path would not
            OnlyInOld    = @(<op>)   # ops the old path would do that the Engine would not
            Differing    = @( { key; fields; engine; old } )  # same key, differing field(s)
        }
    #>
    param(
        [object[]]$EngineOps = @(),
        [object[]]$OldOps    = @()
    )

    # --- internal: the order-insensitive identity key of an op ---------------------------------------
    function Get-OpKey {
        param([object]$Op)
        $a = if ($Op.PSObject.Properties['action'])     { [string]$Op.action }     else { '' }
        $t = if ($Op.PSObject.Properties['objectType']) { [string]$Op.objectType } else { '' }
        $r = if ($Op.PSObject.Properties['objectRef'])  { [string]$Op.objectRef }  else { '' }
        "$a|$t|$r"
    }

    # The key fields are NOT field-compared (they ARE the key); everything else is.
    $keyFields = @('action', 'objectType', 'objectRef')

    # --- internal: render an op's non-key fields as an ordinal map for field comparison --------------
    function Get-OpFieldMap {
        param([object]$Op)
        $map = @{}
        foreach ($p in $Op.PSObject.Properties) {
            if ($keyFields -contains $p.Name) { continue }
            $map[$p.Name] = if ($null -eq $p.Value) { '' } else { [string]$p.Value }
        }
        $map
    }

    # --- index both sides by key --------------------------------------------------------------------
    $engineByKey = [ordered]@{}
    foreach ($op in @($EngineOps)) { if ($null -ne $op) { $engineByKey[(Get-OpKey -Op $op)] = $op } }
    $oldByKey = [ordered]@{}
    foreach ($op in @($OldOps)) { if ($null -ne $op) { $oldByKey[(Get-OpKey -Op $op)] = $op } }

    $onlyInEngine = [System.Collections.Generic.List[object]]::new()
    $onlyInOld    = [System.Collections.Generic.List[object]]::new()
    $differing    = [System.Collections.Generic.List[object]]::new()

    # ops only in Engine, and shared-key field comparison
    foreach ($key in @($engineByKey.Keys)) {
        if (-not $oldByKey.Contains($key)) {
            $onlyInEngine.Add($engineByKey[$key]) | Out-Null
            continue
        }
        $eMap = Get-OpFieldMap -Op $engineByKey[$key]
        $oMap = Get-OpFieldMap -Op $oldByKey[$key]
        # Compare ONLY the intersection: fields present on both sides. A field unique to one side is
        # descriptive metadata (e.g. an apply -WhatIf record's stepId) and is not part of parity.
        $sharedFields = @($eMap.Keys | Where-Object { $oMap.ContainsKey($_) })
        $diffFields = [System.Collections.Generic.List[string]]::new()
        foreach ($f in $sharedFields) {
            if (-not [string]::Equals([string]$eMap[$f], [string]$oMap[$f], [System.StringComparison]::Ordinal)) {
                $diffFields.Add($f) | Out-Null
            }
        }
        if ($diffFields.Count -gt 0) {
            $differing.Add([pscustomobject]@{
                key    = $key
                fields = @($diffFields | Sort-Object)
                engine = $engineByKey[$key]
                old    = $oldByKey[$key]
            }) | Out-Null
        }
    }

    # ops only in Old
    foreach ($key in @($oldByKey.Keys)) {
        if (-not $engineByKey.Contains($key)) {
            $onlyInOld.Add($oldByKey[$key]) | Out-Null
        }
    }

    $match = ($onlyInEngine.Count -eq 0) -and ($onlyInOld.Count -eq 0) -and ($differing.Count -eq 0)

    [pscustomobject]@{
        Match        = [bool]$match
        OnlyInEngine = @($onlyInEngine)
        OnlyInOld    = @($onlyInOld)
        Differing    = @($differing)
    }
}
