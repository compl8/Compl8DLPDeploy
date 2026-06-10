# Compl8.Engine — assess / plan / apply. The ONLY layer that may mutate a tenant.
# Filled in Stage 4. Depends downward on Compl8.Content, Compl8.Tenant, Compl8.Model.
Import-Module (Join-Path $PSScriptRoot '..' 'Compl8.Model') -Force -Global
Import-Module (Join-Path $PSScriptRoot '..' 'Compl8.Tenant') -Force -Global
Import-Module (Join-Path $PSScriptRoot '..' 'Compl8.Content') -Force -Global
$publicDir = Join-Path $PSScriptRoot 'Public'
$public = @(Get-ChildItem -Path $publicDir -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)
foreach ($file in $public) { . $file.FullName }
# Convention: each Public/*.ps1 must define exactly one function whose name matches the file basename.
Export-ModuleMember -Function ($public | ForEach-Object BaseName)
