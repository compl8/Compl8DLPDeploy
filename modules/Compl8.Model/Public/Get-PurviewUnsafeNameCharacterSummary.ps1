function Get-PurviewUnsafeNameCharacterSummary {
    param([AllowNull()][string]$Name)

    if ($null -eq $Name) { return @() }

    $seen = [ordered]@{}
    foreach ($char in $Name.ToCharArray()) {
        $value = [int][char]$char
        $charText = [string]$char
        $isAllowed = ($charText -cmatch '^[A-Za-z0-9_.-]$')
        if ($value -lt 32 -or $value -gt 126 -or -not $isAllowed) {
            $label = switch ($value) {
                9  { "tab"; break }
                10 { "line feed"; break }
                13 { "carriage return"; break }
                32 { "space"; break }
                default {
                    if ($value -lt 32 -or $value -gt 126) { "U+{0:X4}" -f $value }
                    else { "'$charText'" }
                }
            }
            if (-not $seen.Contains($label)) {
                $seen[$label] = $true
            }
        }
    }

    return @($seen.Keys)
}
