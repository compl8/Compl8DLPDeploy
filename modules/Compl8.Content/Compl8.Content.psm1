# Compl8.Content — desired-state content layer: release, overlay, merge, repack engine,
# entity-ID ledger. Filled in Stage 3. Depends downward on Compl8.Model only.
Import-Module (Join-Path $PSScriptRoot '..' 'Compl8.Model') -Force -Global
$publicDir = Join-Path $PSScriptRoot 'Public'
$public = @(Get-ChildItem -Path $publicDir -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)
foreach ($file in $public) { . $file.FullName }
# Convention: each Public/*.ps1 must define exactly one function whose name matches the file basename.
Export-ModuleMember -Function ($public | ForEach-Object BaseName)
