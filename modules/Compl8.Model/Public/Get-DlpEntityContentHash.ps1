function Get-DlpEntityContentHash {
    <#
    .SYNOPSIS
        Stable, encoding/whitespace-agnostic content hash of a SIT rule-package entity's XML.

    .DESCRIPTION
        THE SHARED CANONICAL CONTENT-HASH CONVENTION used on BOTH sides of an assess diff
        (Stage 4 PHASE 4A; closes codex 4A P1). The problem this solves:

          * The DESIRED side reads an entity straight out of a resolved .xml file (a
            specific encoding/indentation produced by the resolve writer).
          * The ACTUAL side reads the SAME entity back from a deployed package via
            Get-DlpSensitiveInformationTypeRulePackage, whose
            SerializedClassificationRuleCollection is re-serialized by the service
            (possibly UTF-16, a different XML declaration, different whitespace).

        Hashing the raw bytes of each would NEVER match even when the entities are
        semantically identical — every deployed SIT would look "changed" (a false-drift
        storm). To make the two sides genuinely COMPARABLE, both must hash the SAME
        canonical projection of the entity, robust to:

          * XML declaration / encoding differences (UTF-8 vs UTF-16, BOM, no decl).
          * Insignificant (formatting) whitespace between elements / indentation.
          * Default xmlns declarations re-emitted at a different scope.

        Canonicalization: parse the input to an XML element (PreserveWhitespace=$false so
        formatting whitespace between element nodes is dropped — text inside leaf elements
        is preserved), then re-serialize that single element through an XmlWriter with
        OmitXmlDeclaration, no indentation, and NewLineHandling=Replace into a stable
        UTF-8 string. The lowercase-hex SHA-256 of that string is returned, prefixed
        'sha256:'. Two inputs that differ ONLY in declaration/encoding/formatting whitespace
        canonicalize to the same string and therefore hash equal; a genuine content edit
        (a changed regex, a changed attribute, an added/removed pattern) changes the
        canonical string and therefore the hash.

        Pure: no tenant calls, no file IO, no Get-Date. Deterministic across processes.

    .PARAMETER EntityXml
        The entity XML as text. Accepts a full <Entity ...>...</Entity> fragment (the usual
        case — an entity's OuterXml from either side) or any well-formed XML element. If the
        text cannot be parsed as XML, the hash falls back to a whitespace-collapsed form of
        the raw text so the function never throws (a malformed-on-both-sides entity still
        compares equal to itself).

    .OUTPUTS
        [string] 'sha256:' + 64 lowercase hex chars.

    .EXAMPLE
        # Two serially-different encodings of the same entity hash identically:
        $a = Get-DlpEntityContentHash -EntityXml '<Entity id="x"><Pattern/></Entity>'
        $b = Get-DlpEntityContentHash -EntityXml "<?xml version='1.0' encoding='utf-16'?>`n<Entity id=`"x`">`n  <Pattern/>`n</Entity>"
        $a -eq $b   # True
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$EntityXml
    )

    $canonical = $null
    if (-not [string]::IsNullOrWhiteSpace($EntityXml)) {
        try {
            $doc = New-Object System.Xml.XmlDocument
            # Drop formatting whitespace between element nodes; significant text in leaf
            # elements (e.g. a <Term> or <Regex> body) is retained by the parser.
            $doc.PreserveWhitespace = $false
            $doc.LoadXml($EntityXml)

            $element = $doc.DocumentElement
            if ($element) {
                # Normalise empty-element form: a childless element authored as <x></x> on one
                # side and <x/> on the other must serialise identically. Forcing IsEmpty on every
                # childless element collapses both to the self-closing form.
                $stack = New-Object System.Collections.Stack
                $stack.Push($element)
                while ($stack.Count -gt 0) {
                    $node = $stack.Pop()
                    if ($node -is [System.Xml.XmlElement]) {
                        if (-not $node.HasChildNodes) {
                            $node.IsEmpty = $true
                        } else {
                            foreach ($child in $node.ChildNodes) { $stack.Push($child) }
                        }
                    }
                }

                $sb = New-Object System.Text.StringBuilder
                $settings = New-Object System.Xml.XmlWriterSettings
                $settings.OmitXmlDeclaration = $true
                $settings.Indent = $false
                $settings.NewLineHandling = [System.Xml.NewLineHandling]::Replace
                $settings.NewLineChars = "`n"
                $settings.Encoding = [System.Text.Encoding]::UTF8
                $writer = [System.Xml.XmlWriter]::Create($sb, $settings)
                try {
                    $element.WriteTo($writer)
                    $writer.Flush()
                } finally {
                    $writer.Dispose()
                }
                $canonical = $sb.ToString()
            }
        } catch {
            $canonical = $null
        }
    }

    if ($null -eq $canonical) {
        # Unparseable input — collapse all whitespace runs so trivial formatting noise in a
        # malformed fragment still compares stably against itself.
        $raw = if ($null -ne $EntityXml) { [string]$EntityXml } else { '' }
        $canonical = ([regex]::Replace($raw, '\s+', ' ')).Trim()
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canonical))
        $hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    } finally {
        $sha.Dispose()
    }

    return 'sha256:' + $hex
}
