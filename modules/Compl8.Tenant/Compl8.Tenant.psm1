# Compl8.Tenant — tenant boundary layer: sessions, safety gates, tenant readers.
# May call SCC/ExchangeOnline cmdlets. Depends downward on Compl8.Model only.
# See docs/superpowers/specs/2026-06-10-config-mgmt-architecture-design.md §2.
Import-Module (Join-Path $PSScriptRoot '..' 'Compl8.Model') -Force -Global

$publicDir = Join-Path $PSScriptRoot 'Public'
$public = @(Get-ChildItem -Path $publicDir -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)
foreach ($file in $public) { . $file.FullName }
# Convention: each Public/*.ps1 must define exactly one function whose name matches the file basename.
Export-ModuleMember -Function ($public | ForEach-Object BaseName)
