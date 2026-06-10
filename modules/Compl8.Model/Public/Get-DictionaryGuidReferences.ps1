function Get-DictionaryGuidReferences {
    <#
    .SYNOPSIS
        Returns the distinct GUID-valued idRef attribute values that are real dictionary
        references in a resolved rule-package XML string. In SIT packages, a dictionary is
        referenced as <Match idRef="GUID"/> (or <ExcludedMatch.../>) inside a <Pattern>.
        Other GUID-valued idRefs are NOT dictionary references:
          - <Resource idRef="GUID"> inside <LocalizedStrings> links a <Resource> to an
            <Entity id="GUID"> (display-name plumbing)
          - <Entity id="GUID"> itself is the entity declaration
        Named idRefs (Pattern_*/Evidence_*/Keyword_*) are also not dictionary refs but they
        do not match the GUID pattern.
    #>
    param([Parameter(Mandatory)][string]$PackageXmlText)
    $guid = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    # Only Match / ExcludedMatch / IdMatch elements carry dictionary refs. Anchoring to the
    # element name keeps Resource/LocalizedStrings entity-display links out of the result.
    $pattern = "<(?:Match|ExcludedMatch|IdMatch)\b[^>]*\bidRef\s*=\s*`"($guid)`""
    $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($m in [regex]::Matches($PackageXmlText, $pattern)) {
        [void]$found.Add($m.Groups[1].Value.ToLowerInvariant())
    }
    return @($found | Sort-Object)
}
