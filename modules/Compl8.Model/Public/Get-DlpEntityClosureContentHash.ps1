function Get-DlpEntityClosureContentHash {
    <#
    .SYNOPSIS
        Canonical content hash of a SIT entity PLUS the transitive idRef closure of the sibling
        rule elements its detection logic actually lives in (codex 4A P2-A).

    .DESCRIPTION
        A SIT's detection logic is NOT all inside its <Entity> node. The entity's
        <Pattern> carries <IdMatch idRef="..."> / <Match idRef="..."> attributes that point
        at SIBLING <Regex> / <Keyword> / <Filter> / <Validator> elements (by their `id`
        attribute) declared elsewhere in the same <Rules> node. Editing the body of one of
        those siblings (e.g. changing a deployed <Regex>) changes the SIT's behaviour while
        leaving the <Entity> node byte-identical.

        Get-DlpEntityContentHash hashes ONLY the <Entity> node, so such an edit produces an
        IDENTICAL hash — assess would MISS the drift and the package update-in-place. This
        helper closes that gap: it resolves the entity's transitive idRef closure within its
        own package and hashes the SAME canonical projection of (entity + every referenced
        support element, keyed by id, sorted by id) on BOTH the desired and actual sides.

        Comparability (the whole point): because each side resolves the closure within its OWN
        package and projects it identically — each element canonicalised through the shared
        Get-DlpEntityContentHash (encoding/whitespace/empty-element-form agnostic), then sorted
        by id — two semantically identical packages that differ only in serialisation hash
        EQUAL, while a genuine edit to the entity OR any element in its closure changes the hash.

        Scoping: only elements reachable from the entity via idRef are folded in. An unreferenced
        sibling (another SIT's regex) is OUTSIDE the closure and does not perturb the hash.

        Pure: no tenant calls, no file IO, no Get-Date. Deterministic across processes.

    .PARAMETER Entity
        The entity as an [System.Xml.XmlElement] (node-based overload — the ACTUAL/reader side
        already has parsed nodes). Supply with -RulesNode (or -SupportElements) as the pool.

    .PARAMETER RulesNode
        The containing <Rules> [System.Xml.XmlElement] (or any element whose child elements are
        the sibling support-element pool). The support pool is its non-Entity child elements.

    .PARAMETER EntityXml
        The entity as XML text (string overload — a caller that holds OuterXml). Supply with
        -SupportElementXml.

    .PARAMETER SupportElements
        An explicit list of candidate sibling support [System.Xml.XmlElement]s (alternative to
        -RulesNode for the node overload).

    .PARAMETER SupportElementXml
        An explicit list of candidate sibling support-element XML strings (string overload).

    .OUTPUTS
        [string] 'sha256:' + 64 lowercase hex chars.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Node')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Node')]
        [System.Xml.XmlElement]$Entity,

        [Parameter(ParameterSetName = 'Node')]
        [System.Xml.XmlElement]$RulesNode,

        [Parameter(ParameterSetName = 'Node')]
        [System.Xml.XmlElement[]]$SupportElements,

        [Parameter(Mandatory, ParameterSetName = 'Xml')]
        [string]$EntityXml,

        [Parameter(ParameterSetName = 'Xml')]
        [AllowNull()]
        [string[]]$SupportElementXml
    )

    # Normalise both overloads down to: an entity element + a map of support elements by id.
    $entityElement = $null
    $supportByIdRaw = [System.Collections.Generic.Dictionary[string, System.Xml.XmlElement]]::new([System.StringComparer]::OrdinalIgnoreCase)

    function Add-SupportElement {
        param([System.Xml.XmlElement]$Element, $Map)
        if (-not $Element) { return }
        $id = $Element.GetAttribute('id')
        if (-not [string]::IsNullOrWhiteSpace($id) -and -not $Map.ContainsKey($id)) {
            $Map[$id] = $Element
        }
    }

    if ($PSCmdlet.ParameterSetName -eq 'Node') {
        $entityElement = $Entity
        $pool = @()
        if ($RulesNode) {
            $pool = @($RulesNode.ChildNodes | Where-Object {
                $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -ne 'Entity'
            })
        }
        if ($SupportElements) { $pool = @($pool) + @($SupportElements) }
        foreach ($el in @($pool)) { Add-SupportElement -Element $el -Map $supportByIdRaw }
    } else {
        # Parse the entity text into an element we can walk for idRefs.
        if (-not [string]::IsNullOrWhiteSpace($EntityXml)) {
            try {
                $edoc = New-Object System.Xml.XmlDocument
                $edoc.PreserveWhitespace = $false
                $edoc.LoadXml($EntityXml)
                $entityElement = $edoc.DocumentElement
            } catch { $entityElement = $null }
        }
        foreach ($sx in @($SupportElementXml)) {
            if ([string]::IsNullOrWhiteSpace($sx)) { continue }
            try {
                $sdoc = New-Object System.Xml.XmlDocument
                $sdoc.PreserveWhitespace = $false
                $sdoc.LoadXml($sx)
                if ($sdoc.DocumentElement) { Add-SupportElement -Element $sdoc.DocumentElement -Map $supportByIdRaw }
            } catch { }
        }
    }

    # If the entity is unusable, fall back to the single-node hash so the function never throws
    # and a malformed-on-both-sides entity still compares equal to itself.
    if (-not $entityElement) {
        $rawEntity = if ($PSCmdlet.ParameterSetName -eq 'Xml') { $EntityXml } else { '' }
        return Get-DlpEntityContentHash -EntityXml $rawEntity
    }

    # Resolve the transitive idRef closure. Collect every idRef attribute value reachable from
    # the entity, then from each referenced support element, until no new ids appear. Dictionary
    # placeholder refs ({{...}}) and idRefs with no matching local element are simply not folded
    # in (they have no body here — dictionaries are diffed separately by their own records).
    function Get-IdRefValues {
        param([System.Xml.XmlElement]$Element)
        $ids = New-Object System.Collections.Generic.List[string]
        # The element itself may carry an idRef, plus any descendant.
        $nodes = New-Object System.Collections.Generic.List[System.Xml.XmlElement]
        $nodes.Add($Element) | Out-Null
        foreach ($d in @($Element.SelectNodes('.//*'))) {
            if ($d -is [System.Xml.XmlElement]) { $nodes.Add($d) | Out-Null }
        }
        foreach ($n in $nodes) {
            $v = $n.GetAttribute('idRef')
            if (-not [string]::IsNullOrWhiteSpace($v)) { $ids.Add($v) | Out-Null }
        }
        return $ids
    }

    $closureIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $queue = New-Object System.Collections.Generic.Queue[string]
    foreach ($v in (Get-IdRefValues -Element $entityElement)) {
        if ($supportByIdRaw.ContainsKey($v) -and $closureIds.Add($v)) { $queue.Enqueue($v) }
    }
    while ($queue.Count -gt 0) {
        $cur = $queue.Dequeue()
        $supportEl = $supportByIdRaw[$cur]
        foreach ($v in (Get-IdRefValues -Element $supportEl)) {
            if ($supportByIdRaw.ContainsKey($v) -and $closureIds.Add($v)) { $queue.Enqueue($v) }
        }
    }

    # Canonical projection: the entity's canonical hash, then each referenced support element's
    # canonical hash keyed by id, sorted by id (deterministic regardless of declaration order).
    $entityHash = Get-DlpEntityContentHash -EntityXml $entityElement.OuterXml
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("entity=$entityHash") | Out-Null
    foreach ($id in (@($closureIds) | Sort-Object)) {
        $supportEl = $supportByIdRaw[$id]
        $lines.Add("$id=$(Get-DlpEntityContentHash -EntityXml $supportEl.OuterXml)") | Out-Null
    }
    $projection = ($lines -join "`n")

    return Get-DlpEntityContentHash -EntityXml "<closure>$([System.Security.SecurityElement]::Escape($projection))</closure>"
}
