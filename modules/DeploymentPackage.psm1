# Functions are added in subsequent tasks. Stubs throw so tests fail loudly if anyone calls them prematurely.

function New-DeploymentTargetSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfigDir
    )

    # Lazy-import DLP-Deploy.psm1 for the templating engine + config resolvers.
    $dlpModule = Join-Path $PSScriptRoot 'DLP-Deploy.psm1'
    if (-not (Get-Module DLP-Deploy)) { Import-Module $dlpModule -Force }

    function Read-JsonFile { param($p) Get-Content -Raw -LiteralPath $p | ConvertFrom-Json -AsHashtable }

    $settings    = Read-JsonFile (Join-Path $ConfigDir 'settings.json')
    $labelsJson  = Read-JsonFile (Join-Path $ConfigDir 'labels.json')
    $policies    = Read-JsonFile (Join-Path $ConfigDir 'policies.json')
    $classifiers = Read-JsonFile (Join-Path $ConfigDir 'classifiers.json')

    $cfg = Merge-GlobalConfig -Defaults (Get-ModuleDefaults) -GlobalJson ([pscustomobject]$settings)

    # Labels
    $labels = foreach ($l in $labelsJson) {
        [ordered]@{
            name        = Get-DeploymentObjectName -Config $cfg -ObjectType 'label' -Name $l.name -Tokens @{ labelCode = $l.code; displayName = $l.displayName }
            code        = $l.code
            parentGroup = $l.parentGroup
            encryption  = [bool]$l.encrypt
            priority    = [int]$l.priority
            isGroup     = [bool]$l.isGroup
        }
    }

    # Label policy
    $labelPolicy = [ordered]@{
        name      = Get-DeploymentObjectName -Config $cfg -ObjectType 'labelPolicy' -Name $cfg.labelPolicyName
        publishTo = @()
        labels    = @($labels | Where-Object { -not $_.isGroup } | ForEach-Object { $_.name })
        settings  = @{}
    }

    # DLP policies + rules
    $dlpPolicies = @()
    $dlpRules    = @()
    foreach ($p in $policies) {
        if (-not $p.Enabled) { continue }
        $policyName = Get-PolicyName -PolicyNumber $p.Number -PolicyCode $p.Code -Config $cfg
        $dlpPolicies += [ordered]@{
            name       = $policyName
            mode       = (Resolve-PolicyMode -AuditMode:$cfg.auditMode -NotifyUser:$cfg.notifyUser)
            scopeParam = $p.ScopeParam
            scopeValue = $p.ScopeValue
        }
        $ruleNum = 0
        foreach ($key in $classifiers.Keys) {
            $ruleNum++
            $chunks = @(Split-ClassifierChunks -ClassifierList $classifiers[$key] -MaxPerRule 125)
            $idx = 0
            foreach ($chunk in $chunks) {
                $idx++
                $chunkLetter = if ($chunks.Count -gt 1) { Get-ChunkLetter -ChunkIndex $idx } else { '' }
                $ruleName = Get-RuleName -PolicyNumber $p.Number -RuleNumber $ruleNum -PolicyCode $p.Code -LabelCode $key -ChunkLetter $chunkLetter -Config $cfg
                $dlpRules += [ordered]@{
                    name        = $ruleName
                    policy      = $policyName
                    classifiers = @($chunk | ForEach-Object { $_.Id })
                    scopeParam  = $p.ScopeParam
                    scopeValue  = $p.ScopeValue
                }
            }
        }
    }

    # Classifier packages + dictionaries — sourced from xml/deploy/deploy-registry.json if present, else empty.
    $classifierPackages = @()
    $dictionaries       = @()
    $registryFile = Join-Path (Split-Path $ConfigDir -Parent) 'xml/deploy/deploy-registry.json'
    if (Test-Path -LiteralPath $registryFile) {
        $registry = Get-Content -Raw -LiteralPath $registryFile | ConvertFrom-Json -AsHashtable
        foreach ($pkg in $registry.packages) {
            $classifierPackages += [ordered]@{
                name           = Get-DeploymentObjectName -Config $cfg -ObjectType 'classifierPackage' -Name $pkg.key
                rulePackId     = $null
                entities       = @()
                dictionaryRefs = @()
            }
        }
    }

    return [ordered]@{
        schemaVersion       = 1
        labels              = @($labels)
        labelPolicy         = $labelPolicy
        classifierPackages  = @($classifierPackages)
        dictionaries        = @($dictionaries)
        dlpPolicies         = @($dlpPolicies)
        dlpRules            = @($dlpRules)
    }
}
function Get-TenantActualState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$NamingPrefix,
        [Parameter(Mandatory)][string]$TargetEnvironment
    )

    if (-not (Get-Command Test-DeploymentProvenanceOwnership -ErrorAction SilentlyContinue)) {
        $dlp = Join-Path $PSScriptRoot 'DLP-Deploy.psm1'
        if (-not (Get-Module DLP-Deploy)) { Import-Module $dlp -Force }
    }

    function Test-OurObject {
        param([object]$Obj, [string]$Component)
        $r = Test-DeploymentProvenanceOwnership -InputObject $Obj -Prefix $NamingPrefix -Component $Component
        return [bool]$r.IsOwned
    }

    $labels = @(Get-Label | Where-Object { Test-OurObject $_ 'SensitivityLabel' } | ForEach-Object {
        [ordered]@{
            name        = $_.Name
            code        = if ($_.PSObject.Properties['DisplayName']) { $_.DisplayName } else { $null }
            parentGroup = if ($_.PSObject.Properties['ParentId'])    { $_.ParentId }    else { $null }
            encryption  = [bool]($_.PSObject.Properties['EncryptionEnabled'] -and $_.EncryptionEnabled)
            priority    = if ($_.PSObject.Properties['Priority'])    { [int]$_.Priority } else { 0 }
            isGroup     = [bool]($_.PSObject.Properties['IsGroup']    -and $_.IsGroup)
        }
    })

    $labelPolicyObj = Get-LabelPolicy | Where-Object { Test-OurObject $_ 'LabelPolicy' } | Select-Object -First 1
    $labelPolicy = if ($labelPolicyObj) {
        [ordered]@{ name = $labelPolicyObj.Name; publishTo = @(); labels = @(); settings = @{} }
    } else {
        [ordered]@{ name = ''; publishTo = @(); labels = @(); settings = @{} }
    }

    # Classifier packages aren't provenance-stamped today; match on configured prefix.
    $classifierPackages = @(Get-DlpSensitiveInformationTypeRulePackage |
        Where-Object { $_.Name -and $_.Name.StartsWith("$NamingPrefix-", [System.StringComparison]::OrdinalIgnoreCase) } |
        ForEach-Object {
            [ordered]@{
                name           = $_.Name
                rulePackId     = if ($_.PSObject.Properties['RulePackId']) { [string]$_.RulePackId } else { $null }
                entities       = @()
                dictionaryRefs = @()
            }
        })

    $dictionaries = @(Get-DlpKeywordDictionary | Where-Object { Test-OurObject $_ 'KeywordDictionary' } | ForEach-Object {
        [ordered]@{ name = $_.Name; termCountHint = $null; termSetSha256 = $null }
    })

    $dlpPolicies = @(Get-DlpCompliancePolicy | Where-Object { Test-OurObject $_ 'DlpPolicy' } | ForEach-Object {
        [ordered]@{
            name       = $_.Name
            mode       = if ($_.PSObject.Properties['Mode']) { [string]$_.Mode } else { '' }
            scopeParam = ''
            scopeValue = ''
        }
    })

    $dlpRules = @(Get-DlpComplianceRule | Where-Object { Test-OurObject $_ 'DlpRule' } | ForEach-Object {
        [ordered]@{
            name        = $_.Name
            policy      = if ($_.PSObject.Properties['Policy']) { [string]$_.Policy } else { '' }
            classifiers = @()
            scopeParam  = ''
            scopeValue  = ''
        }
    })

    return [ordered]@{
        schemaVersion      = 1
        labels             = $labels
        labelPolicy        = $labelPolicy
        classifierPackages = $classifierPackages
        dictionaries       = $dictionaries
        dlpPolicies        = $dlpPolicies
        dlpRules           = $dlpRules
    }
}
function Compare-DeploymentState { throw 'Not implemented in module skeleton' }
function Update-PendingPackage {
    param(
        [Parameter(Mandatory)][string]$SessionPath,
        [Parameter(Mandatory)][scriptblock]$Mutator,
        [int]$LockTimeoutSec = 30
    )

    if (-not (Test-Path -LiteralPath $SessionPath)) { throw "Session path not found: $SessionPath" }

    $lockPath  = Join-Path $SessionPath '.lock'
    $zipPath   = Join-Path $SessionPath 'pending.zip'
    $shaPath   = "$zipPath.sha256"
    $statusFp  = Join-Path $SessionPath 'status.json'

    # Acquire a non-blocking lock file with retry/backoff.
    $deadline = [datetime]::UtcNow.AddSeconds($LockTimeoutSec)
    $lockHandle = $null
    while ($null -eq $lockHandle) {
        try {
            $lockHandle = [System.IO.File]::Open($lockPath, 'CreateNew', 'Write', 'None')
        } catch {
            if ([datetime]::UtcNow -ge $deadline) {
                throw "Could not acquire session lock at $lockPath after ${LockTimeoutSec}s"
            }
            Start-Sleep -Milliseconds 200
        }
    }

    $stagingZip = "$zipPath.new"
    $tempWork   = Join-Path ([System.IO.Path]::GetTempPath()) ("dp-upd-$([guid]::NewGuid().Guid)")
    try {
        New-Item -ItemType Directory -Path $tempWork -Force | Out-Null

        if (Test-Path -LiteralPath $zipPath) {
            Expand-Archive -LiteralPath $zipPath -DestinationPath $tempWork -Force
        }

        # Run caller's mutation against the temp working dir.
        & $Mutator $tempWork

        # Re-seal to staging path, validate, then atomic rename.
        if (Test-Path -LiteralPath $stagingZip) { Remove-Item -LiteralPath $stagingZip -Force }
        Compress-Archive -Path (Join-Path $tempWork '*') -DestinationPath $stagingZip -CompressionLevel Optimal -Force
        $newSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $stagingZip).Hash

        Move-Item -LiteralPath $stagingZip -Destination $zipPath -Force
        Set-Content -LiteralPath $shaPath -Value $newSha -Encoding ASCII

        # Update status.json with new SHA + timestamp.
        $status = if (Test-Path -LiteralPath $statusFp) {
            Get-Content -Raw -LiteralPath $statusFp | ConvertFrom-Json -AsHashtable
        } else {
            @{ schemaVersion = 1; state = 'pending'; phasesCompleted = @(); phasesPending = @(); pendingZipSha256 = ''; lastUpdated = '' }
        }
        $status.pendingZipSha256 = $newSha
        $status.lastUpdated      = (Get-Date).ToString('o')
        $status | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $statusFp -Encoding UTF8
    }
    finally {
        if ($lockHandle) { $lockHandle.Dispose() }
        Remove-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $tempWork -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $stagingZip) { Remove-Item -LiteralPath $stagingZip -Force -ErrorAction SilentlyContinue }
    }
}
function Get-PendingDeploymentPackage {
    [CmdletBinding(DefaultParameterSetName='Auto')]
    param(
        [Parameter(ParameterSetName='Path', Mandatory)][string]$SessionPath,
        [Parameter(ParameterSetName='Auto', Mandatory)][string]$DeploymentsRoot,
        [Parameter(ParameterSetName='Auto', Mandatory)][string]$Tenant,
        [Parameter(ParameterSetName='Auto', Mandatory)][string]$TargetEnvironment
    )

    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        return Read-DeploymentPackageManifest -SessionPath $SessionPath
    }

    if (-not (Test-Path -LiteralPath $DeploymentsRoot)) { throw "Deployments root not found: $DeploymentsRoot" }
    $hits = @()
    foreach ($dir in Get-ChildItem -Path $DeploymentsRoot -Directory) {
        try {
            $r = Read-DeploymentPackageManifest -SessionPath $dir.FullName
            $terminal = $r.Status.state -in @('succeeded','partial','failed','rolledback')
            if (-not $terminal -and $r.TenantPin.tenant -eq $Tenant -and $r.TenantPin.targetEnvironment -eq $TargetEnvironment) {
                $hits += $r
            }
        } catch { continue }
    }
    if ($hits.Count -eq 0) { throw "No pending session for tenant=$Tenant targetEnvironment=$TargetEnvironment under $DeploymentsRoot" }
    if ($hits.Count -gt 1) {
        $candidates = ($hits | ForEach-Object { $_.SessionPath }) -join "`n"
        throw "Found multiple pending sessions for tenant=$Tenant targetEnvironment=$TargetEnvironment; pass -SessionPath explicitly. Candidates:`n$candidates"
    }
    return $hits[0]
}
function Read-DeploymentPackageManifest {
    param(
        [Parameter(Mandatory)][string]$SessionPath,
        [int]$ExpectedSchemaVersion = 1
    )

    if (-not (Test-Path -LiteralPath $SessionPath)) {
        throw "Session path not found: $SessionPath"
    }

    $zip       = Join-Path $SessionPath 'pending.zip'
    $shaFile   = Join-Path $SessionPath 'pending.zip.sha256'
    $statusFp  = Join-Path $SessionPath 'status.json'

    if ((Test-Path -LiteralPath $zip) -and (Test-Path -LiteralPath $shaFile)) {
        $expected = (Get-Content -Raw -LiteralPath $shaFile).Trim()
        $actual   = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash
        if ($expected -ne $actual) {
            throw "pending.zip SHA-256 mismatch (sidecar says $expected, file is $actual)"
        }
    }

    # Extract pending.zip to a temp working copy so we never mutate the on-disk working/ behind a phase script's back.
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("dp-read-$([guid]::NewGuid().Guid)")
    New-Item -ItemType Directory -Path $temp -Force | Out-Null
    try {
        if (Test-Path -LiteralPath $zip) {
            Expand-Archive -LiteralPath $zip -DestinationPath $temp -Force
        } else {
            # Fall back to the live working dir if no zip is sealed yet (during Initialize-DeploymentSession).
            $working = Join-Path $SessionPath 'working'
            if (Test-Path -LiteralPath $working) { Copy-Item -Path (Join-Path $working '*') -Destination $temp -Recurse -Force }
        }

        $pin = Get-Content -Raw -LiteralPath (Join-Path $temp 'tenant-pin.json')         | ConvertFrom-Json -AsHashtable
        $tgt = Get-Content -Raw -LiteralPath (Join-Path $temp 'deployment-target.json')  | ConvertFrom-Json -AsHashtable
        $adj = Get-Content -Raw -LiteralPath (Join-Path $temp 'plan-adjustments.json')   | ConvertFrom-Json -AsHashtable

        foreach ($pair in @(@('tenant-pin', $pin), @('deployment-target', $tgt), @('plan-adjustments', $adj))) {
            if ($pair[1].schemaVersion -ne $ExpectedSchemaVersion) {
                throw "$($pair[0]) schemaVersion is $($pair[1].schemaVersion); expected $ExpectedSchemaVersion"
            }
        }

        $status = if (Test-Path -LiteralPath $statusFp) {
            Get-Content -Raw -LiteralPath $statusFp | ConvertFrom-Json -AsHashtable
        } else {
            @{ schemaVersion = 1; state = 'pending'; phasesCompleted = @(); phasesPending = @(); pendingZipSha256 = ''; lastUpdated = '' }
        }
        if ($status.schemaVersion -ne $ExpectedSchemaVersion) {
            throw "status schemaVersion is $($status.schemaVersion); expected $ExpectedSchemaVersion"
        }

        # Load phase-*.json files if any are present.
        $phases = @{}
        foreach ($file in Get-ChildItem -Path $temp -Filter 'phase-*.json' -ErrorAction SilentlyContinue) {
            $phaseRecord = Get-Content -Raw -LiteralPath $file.FullName | ConvertFrom-Json -AsHashtable
            $phases[$phaseRecord.phase] = $phaseRecord
        }

        return @{
            SessionPath = $SessionPath
            TenantPin   = $pin
            Target      = $tgt
            Adjustments = $adj
            Status      = $status
            Phases      = $phases
        }
    }
    finally {
        Remove-Item -Path $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
function Add-DeploymentPlanAdjustment {
    param(
        [Parameter(Mandatory)][string]$SessionPath,
        [Parameter(Mandatory)][ValidateSet('refit','operator-review')][string]$Source,
        [Parameter(Mandatory)][ValidateSet('label','labelPolicy','classifierPackage','dictionary','dlpPolicy','dlpRule')][string]$ArtifactType,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Action,
        [hashtable]$Before,
        [hashtable]$After,
        [Parameter(Mandatory)][string]$Reason
    )

    Update-PendingPackage -SessionPath $SessionPath -Mutator {
        param($workingDir)
        $adjFile = Join-Path $workingDir 'plan-adjustments.json'
        $tgtFile = Join-Path $workingDir 'deployment-target.json'
        $adj = Get-Content -Raw -LiteralPath $adjFile | ConvertFrom-Json -AsHashtable
        $tgt = Get-Content -Raw -LiteralPath $tgtFile | ConvertFrom-Json -AsHashtable

        $idKey = "$Source`:$ArtifactType`:$Key`:$Action"
        $existing = $null
        foreach ($entry in $adj.entries) {
            if ("$($entry.source)`:$($entry.artifactType)`:$($entry.key)`:$($entry.action)" -eq $idKey) { $existing = $entry; break }
        }

        # Stale-Before guard (only when Before is provided)
        if ($Before -and $ArtifactType -eq 'classifierPackage' -and $Action -eq 'reuse-rulepackid') {
            $pkg = $tgt.classifierPackages | Where-Object name -eq $Key | Select-Object -First 1
            if ($pkg) {
                $current = $pkg.rulePackId
                $expected = $Before.rulePackId
                if (($null -ne $current) -and ($current -ne $expected)) {
                    throw "stale Before: target classifierPackage '$Key' rulePackId is '$current', adjustment expected '$expected'"
                }
            }
        }

        $entry = [ordered]@{
            ts           = (Get-Date).ToString('o')
            source       = $Source
            artifactType = $ArtifactType
            key          = $Key
            action       = $Action
            before       = $Before
            after        = $After
            reason       = $Reason
        }
        if ($existing) {
            $existing.ts     = $entry.ts
            $existing.before = $entry.before
            $existing.after  = $entry.after
            $existing.reason = $entry.reason
        } else {
            $adj.entries += $entry
        }

        switch ("$ArtifactType`:$Action") {
            'classifierPackage:reuse-rulepackid' {
                $pkg = $tgt.classifierPackages | Where-Object name -eq $Key | Select-Object -First 1
                if ($pkg) { $pkg.rulePackId = $After.rulePackId }
            }
            { $_.EndsWith(':skip') } {
                $collectionName = switch ($ArtifactType) {
                    'label' { 'labels' } 'labelPolicy' { 'labelPolicy' } 'classifierPackage' { 'classifierPackages' }
                    'dictionary' { 'dictionaries' } 'dlpPolicy' { 'dlpPolicies' } 'dlpRule' { 'dlpRules' }
                }
                if ($collectionName -eq 'labelPolicy') { $tgt.labelPolicy = @{ name=''; publishTo=@(); labels=@(); settings=@{} } }
                else { $tgt[$collectionName] = @($tgt[$collectionName] | Where-Object { $_.name -ne $Key }) }
            }
        }

        $adj | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $adjFile -Encoding UTF8
        $tgt | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $tgtFile -Encoding UTF8
    }
}
function Add-DeploymentPhaseResult {
    param(
        [Parameter(Mandatory)][string]$SessionPath,
        [Parameter(Mandatory)][ValidateSet('classifiers','labels','dlprules','refit')][string]$Phase,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][ValidateSet('success','partial','failed')][string]$Status,
        [Parameter(Mandatory)][string]$StartedAt,
        [Parameter(Mandatory)][string]$CompletedAt,
        [object[]]$Artifacts = @(),
        [object[]]$Errors    = @(),
        [string]$ReportPath
    )

    # Write phase-{name}.json into the sealed zip via Update-PendingPackage.
    Update-PendingPackage -SessionPath $SessionPath -Mutator {
        param($workingDir)
        $phaseFile = Join-Path $workingDir "phase-$Phase.json"
        $record = [ordered]@{
            schemaVersion = 1
            phase         = $Phase
            action        = $Action
            status        = $Status
            startedAt     = $StartedAt
            completedAt   = $CompletedAt
            artifacts     = @($Artifacts)
            errors        = @($Errors)
        }
        if ($ReportPath) { $record.reportPath = $ReportPath }
        $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $phaseFile -Encoding UTF8
    }

    # Status.json lives OUTSIDE the zip in the session dir. Update-PendingPackage already
    # refreshed pendingZipSha256 + lastUpdated; we read the post-seal version, layer the
    # phase-transition fields on top, write back.
    $statusFp = Join-Path $SessionPath 'status.json'
    $s = Get-Content -Raw -LiteralPath $statusFp | ConvertFrom-Json -AsHashtable
    if ($Status -eq 'success') {
        if ($s.phasesCompleted -notcontains $Phase) { $s.phasesCompleted += $Phase }
        $s.phasesPending = @($s.phasesPending | Where-Object { $_ -ne $Phase })
    }
    if ($s.state -eq 'pending') { $s.state = 'in-progress' }
    $s.lastUpdated = (Get-Date).ToString('o')
    $s | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $statusFp -Encoding UTF8
}
function Move-DeploymentPackageToArchive { throw 'Not implemented in module skeleton' }

Export-ModuleMember -Function @(
    'New-DeploymentTargetSnapshot',
    'Get-TenantActualState',
    'Compare-DeploymentState',
    'Update-PendingPackage',
    'Get-PendingDeploymentPackage',
    'Read-DeploymentPackageManifest',
    'Add-DeploymentPlanAdjustment',
    'Add-DeploymentPhaseResult',
    'Move-DeploymentPackageToArchive'
)
