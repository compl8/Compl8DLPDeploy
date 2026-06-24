function ConvertTo-RulePackageXml {
    <#
    .SYNOPSIS
        Composes a Purview rule package from release fragments under the byte-parity contract.
    .DESCRIPTION
        Reproduces, byte for byte, what the Python pipeline (testpattern purview-bundle API +
        optimise()) writes for the same content: UTF-8 without BOM, CRLF newlines, no
        comments, inter-element whitespace collapsed, section order Entities → Regexes →
        Keywords → Filters → Validators → LocalizedStrings, shared definitions deduplicated
        by element id (first occurrence wins), {{DICT_*}} placeholders verbatim.

        Ledger rebinding: every item's fragment GUID is rewritten to its ledger GUID (an
        adopted tenant pins different GUIDs than the release defaults). Attr patches (merge
        overrides) rewrite Entity start-tag attributes; confidenceLevel patches apply to the
        item's Pattern tags. Publisher and Name/Description are inserted raw, matching the
        Python pipeline's plain-text patching.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [object[]]$Items,

        [Parameter(Mandatory)]
        [pscustomobject]$Ledger,

        [Parameter(Mandatory)]
        [string]$Publisher,

        [Parameter(Mandatory)]
        [string]$RulePackId,

        [string]$VersionAttributes = 'major="1" minor="0" build="0" revision="0"'
    )

    $bindings = @{}
    foreach ($entry in $Ledger.Entries) { $bindings[$entry.slug] = $entry.entityId }

    $entities = [System.Collections.Generic.List[string]]::new()
    $ruleDefs = [ordered]@{}   # section name → List[string]
    foreach ($section in 'regexes', 'keywords', 'filters', 'validators') {
        $ruleDefs[$section] = [System.Collections.Generic.List[string]]::new()
    }
    $resources = [System.Collections.Generic.List[string]]::new()
    $seenIds = @{}

    foreach ($item in $Items) {
        if (-not $bindings.ContainsKey($item.Slug)) {
            throw "Item '$($item.Slug)' has no ledger binding; seed the entity ledger before composing."
        }
        $boundId = $bindings[$item.Slug]

        $entityXml = $item.Sections.Entity
        $resourceXmls = @($item.Sections.Resources)

        # Ledger rebind: the fragment's default GUID becomes the ledger-pinned GUID.
        if ($item.EntityId -and $boundId -ne $item.EntityId) {
            $entityXml = $entityXml.Replace($item.EntityId, $boundId)
            $resourceXmls = @($resourceXmls | ForEach-Object { $_.Replace($item.EntityId, $boundId) })
        }

        # Attr patches from merge overrides (whitelisted keys only, validated at import).
        foreach ($key in @($item.AttrPatches.Keys)) {
            $value = $item.AttrPatches[$key]
            switch ($key) {
                'confidenceLevel' {
                    $entityXml = [regex]::Replace($entityXml, 'confidenceLevel="\d+"', "confidenceLevel=`"$value`"")
                }
                default {
                    # Entity start-tag attribute (patternsProximity, recommendedConfidence).
                    $entityXml = [regex]::Replace($entityXml, "$key=`"\d+`"", "$key=`"$value`"", 'None', [timespan]::FromSeconds(5))
                }
            }
        }

        $entities.Add($entityXml)
        foreach ($section in 'regexes', 'keywords', 'filters', 'validators') {
            foreach ($element in @($item.Sections.($section.Substring(0, 1).ToUpper() + $section.Substring(1)))) {
                if (-not $element) { continue }
                $id = if ($element -match 'id="([^"]+)"') { $Matches[1] } else { $element }
                if ($seenIds.ContainsKey($id)) { continue }
                $seenIds[$id] = $true
                $ruleDefs[$section].Add($element)
            }
        }
        foreach ($resource in $resourceXmls) { $resources.Add($resource) }
    }

    $sectionBlocks = foreach ($section in 'regexes', 'keywords', 'filters', 'validators') {
        foreach ($element in $ruleDefs[$section]) { $element }
    }

    $body = @(
        '<?xml version="1.0" encoding="utf-8"?>'
        '<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">'
        "<RulePack id=`"$RulePackId`">"
        "<Version $VersionAttributes />"
        "<Publisher id=`"$RulePackId`" />"
        '<Details defaultLangCode="en-us">'
        '<LocalizedDetails langcode="en-us">'
        "<PublisherName>$Publisher</PublisherName>"
        "<Name>$Name</Name>"
        "<Description>TestPattern bundle with $($entities.Count) patterns</Description>"
        '</LocalizedDetails>'
        '</Details>'
        '</RulePack>'
        '<Rules>'
        $entities
        $sectionBlocks
        '<LocalizedStrings>'
        $resources
        '</LocalizedStrings>'
        '</Rules>'
        '</RulePackage>'
    ) -join "`n"

    # Byte-contract normalisation (defence in depth — fragments arrive pre-optimised):
    # strip comments, collapse inter-element whitespace, then normalise every newline to CRLF.
    $body = [regex]::Replace($body, '<!--.*?-->', '', 'Singleline')
    $body = [regex]::Replace($body, '>\s+<', ">`n<")
    $body = $body.Replace("`r`n", "`n").Replace("`n", "`r`n")

    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($body)

    [pscustomobject]@{
        Name          = $Name
        Text          = $body
        Bytes         = $bytes
        EntityCount   = $entities.Count
        SizeBytes     = $bytes.Length
        Utf16SizeBytes = [System.Text.Encoding]::Unicode.GetByteCount($body)
    }
}
