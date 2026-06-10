# Compl8.Model — pure model layer (schemas, limits, naming, reference graph).
# No tenant calls, no SCC cmdlets, no file-layout knowledge. See
# docs/superpowers/specs/2026-06-10-config-mgmt-architecture-design.md §2.
$publicDir = Join-Path $PSScriptRoot 'Public'
$public = @(Get-ChildItem -Path $publicDir -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)
foreach ($file in $public) { . $file.FullName }
# Convention: each Public/*.ps1 must define exactly one function whose name matches the file basename.
Export-ModuleMember -Function ($public | ForEach-Object BaseName)
