function ConvertTo-CustomSitFragment {
    <#
    .SYNOPSIS
        Renders an operator-added custom SIT definition into a release-shaped fragment.
    .DESCRIPTION
        Covers the SIMPLE pattern shape only (one regex, optional keyword evidence and
        exclusions): complex SITs (multiple regexes, tiers, validators, filters) must be
        curated in testpattern and shipped via a release. Element ids derive from the slug
        (collision-proof: overlay slugs are namespaced custom-*); the entity GUID is the
        LEDGER-minted binding passed in by the caller, so no hash-to-GUID port is needed.
        Output is deterministic and matches the post-optimise fragment shape (\n newlines;
        composition normalises to CRLF).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Definition,

        [Parameter(Mandatory)]
        [string]$EntityId
    )

    foreach ($unsupported in 'regexes', 'validators', 'filters', 'tiers', 'patterns') {
        if ($Definition.PSObject.Properties[$unsupported]) {
            throw "Custom SIT '$($Definition.slug)': '$unsupported' is not supported in overlay adds — curate complex SITs in testpattern and ship them via a release."
        }
    }
    if (-not $Definition.slug -or -not $Definition.name -or -not $Definition.regex) {
        throw "Custom SIT definition requires slug, name and regex (got slug='$($Definition.slug)')."
    }

    function ConvertTo-EscapedXmlText {
        param([string]$Text)
        $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
    }

    $confidence = switch ("$($Definition.confidence)".ToLowerInvariant()) {
        'high' { 85 }
        'low' { 65 }
        default { 75 }
    }
    $proximity = if ($Definition.proximity) { [int]$Definition.proximity } else { 300 }
    $slug = $Definition.slug

    $regexId = "Pattern_custom_terms_$slug"
    $evidenceId = "Evidence_custom_keywords_$slug"
    $filterId = "Filter_custom_exclusion_$slug"
    $keywords = @($Definition.keywords | Where-Object { $_ })
    $exclusions = @($Definition.exclusions | Where-Object { $_ })

    function New-KeywordElement {
        param([string]$Id, [string[]]$Terms)
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add("<Keyword id=`"$Id`">")
        $lines.Add('<Group matchStyle="word">')
        foreach ($term in $Terms) {
            $lines.Add("<Term caseSensitive=`"false`">$(ConvertTo-EscapedXmlText $term)</Term>")
        }
        $lines.Add('</Group>')
        $lines.Add('</Keyword>')
        $lines -join "`n"
    }

    $patternLines = [System.Collections.Generic.List[string]]::new()
    $patternLines.Add("<Pattern confidenceLevel=`"$confidence`">")
    $patternLines.Add("<IdMatch idRef=`"$regexId`" />")
    if ($keywords.Count -gt 0) {
        $patternLines.Add("<Match idRef=`"$evidenceId`" />")
    }
    if ($exclusions.Count -gt 0) {
        $patternLines.Add('<Any minMatches="0" maxMatches="0">')
        $patternLines.Add("<Match idRef=`"$filterId`" />")
        $patternLines.Add('</Any>')
    }
    $patternLines.Add('</Pattern>')

    $entity = @(
        "<Entity id=`"$EntityId`" patternsProximity=`"$proximity`" recommendedConfidence=`"$confidence`" relaxProximity=`"false`">"
        ($patternLines -join "`n")
        '</Entity>'
    ) -join "`n"

    $keywordElements = @()
    if ($keywords.Count -gt 0) { $keywordElements += New-KeywordElement -Id $evidenceId -Terms $keywords }
    if ($exclusions.Count -gt 0) { $keywordElements += New-KeywordElement -Id $filterId -Terms $exclusions }

    $resource = @(
        "<Resource idRef=`"$EntityId`">"
        "<Name default=`"true`" langcode=`"en-us`">$(ConvertTo-EscapedXmlText $Definition.name)</Name>"
        "<Description default=`"true`" langcode=`"en-us`">$(ConvertTo-EscapedXmlText "$($Definition.description)")</Description>"
        '</Resource>'
    ) -join "`n"

    [pscustomobject]@{
        Slug     = $slug
        EntityId = $EntityId
        Sections = [pscustomobject]@{
            Entity     = $entity
            Regexes    = @("<Regex id=`"$regexId`">$(ConvertTo-EscapedXmlText $Definition.regex)</Regex>")
            Keywords   = $keywordElements
            Filters    = @()
            Validators = @()
            Resources  = @($resource)
        }
    }
}
