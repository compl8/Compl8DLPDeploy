#Requires -Modules Pester

# Guards the per-tenant config feature end to end at the orchestrator layer:
# Invoke-FullDeployment.ps1 and Invoke-GreenfieldDeployment.ps1 must forward -TargetEnvironment to
# EVERY child deploy phase (Labels, Classifiers, DLPRules). If any phase is
# skipped, that phase silently resolves global config while the others resolve
# the per-tenant dir -- a split deployment. (Regression: Labels phase was missing
# the forward in both orchestrators.)

BeforeAll {
    $script:ProjectRoot = Split-Path $PSScriptRoot -Parent

    $script:DeployScripts = @('Deploy-Labels.ps1', 'Deploy-Classifiers.ps1', 'Deploy-DLPRules.ps1')

    function Get-DeploySplatVars {
        param([Parameter(Mandatory)][string]$ScriptPath)

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $ScriptPath, [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) {
            throw "Could not parse ${ScriptPath}: $($errors[0].Message)"
        }

        $calls = $ast.FindAll({
            param($n) $n -is [System.Management.Automation.Language.CommandAst]
        }, $true)

        $map = @{}
        foreach ($call in $calls) {
            $text = $call.Extent.Text
            foreach ($deploy in $script:DeployScripts) {
                if ($text -notlike "*$deploy*") { continue }
                $splat = $call.CommandElements |
                    Where-Object {
                        $_ -is [System.Management.Automation.Language.VariableExpressionAst] -and $_.Splatted
                    } | Select-Object -First 1
                if ($splat) { $map[$deploy] = $splat.VariablePath.UserPath }
            }
        }
        return $map
    }
}

Describe 'Orchestrator forwards -TargetEnvironment to every deploy phase' {
    $orchestrators = @(
        @{ Name = 'Invoke-FullDeployment.ps1' }
        @{ Name = 'Invoke-GreenfieldDeployment.ps1' }
    )

    It '<Name> splat-invokes all three deploy scripts and forwards TargetEnvironment to each' -ForEach $orchestrators {
        $path = Join-Path $script:ProjectRoot 'scripts' $Name
        $content = Get-Content -LiteralPath $path -Raw
        $splatVars = Get-DeploySplatVars -ScriptPath $path

        foreach ($deploy in $script:DeployScripts) {
            $splatVars.ContainsKey($deploy) |
                Should -BeTrue -Because "$Name should splat-invoke $deploy"

            $var = $splatVars[$deploy]
            # The splatted hashtable for this phase must receive a TargetEnvironment forward.
            $pattern = '\$' + [regex]::Escape($var) +
                '\[["'']TargetEnvironment["'']\]\s*=\s*\$TargetEnvironment'
            ($content -match $pattern) |
                Should -BeTrue -Because "$Name must forward TargetEnvironment into `$$var (the $deploy splat)"
        }
    }
}
