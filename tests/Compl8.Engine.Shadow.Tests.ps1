#Requires -Modules Pester

# Compl8.Engine — SCC-mutation helpers (Remove-PurviewObject, Invoke-WithRetry) + the shadow-diff
# harness (Get-Compl8ShadowDiff). (Stage 4 PHASE 4C, Task 7; arch design §5, decisions D1/D3.)
#
# D1 — these two mutation helpers are FRESH PORTS into Compl8.Engine scope. The originals stay live
# and UNMODIFIED in DLP-Deploy.psm1; this is a deliberate second copy in Engine scope (the only
# tenant-mutating layer, D3). Behaviour is identical to the originals EXCEPT one determinism change:
# the real Start-Sleep is INJECTABLE (-SleepAction) so tests assert retry COUNTS instantly with no
# wall-clock wait, and Get-Date / real Start-Sleep never run in tests.
#
# Get-Compl8ShadowDiff is NEW: it diffs the Engine executor's PLANNED operations against the old
# leaf script's -WhatIf operations. An EMPTY diff (Match=$true) = byte/semantic parity, the gate
# Tasks 8-12 use to prove each executor reproduces the old path.

BeforeAll {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction SilentlyContinue
    $script:RepoRoot  = Split-Path $PSScriptRoot -Parent
    $script:EngineDir = Join-Path $script:RepoRoot 'modules' 'Compl8.Engine'
    Remove-Module DLP-Deploy -Force -ErrorAction SilentlyContinue
    Import-Module $script:EngineDir -Force

    # SCC cmdlets are not installed in CI and Remove-PurviewObject invokes them DYNAMICALLY (& $cmd),
    # so there is no static reference for Pester to bootstrap a mock from. Define global stubs (the
    # established repo pattern, e.g. DLP-Deploy.Tests.ps1's global Get-DlpComplianceRule) so the
    # commands EXIST and `Mock -ModuleName Compl8.Engine` can shadow them inside the module scope.
    function global:Get-AutoSensitivityLabelRule { [CmdletBinding()] param([string]$Identity, [string]$ErrorAction) }
    function global:Remove-AutoSensitivityLabelRule { [CmdletBinding()] param([string]$Identity, [switch]$Confirm, [string]$ErrorAction) }

    # A no-op sleep recorder: tests inject this so Invoke-WithRetry never really sleeps. The list of
    # requested delays lets a test assert HOW MANY times (and for how long) a retry would have waited.
    function New-SleepRecorder {
        $rec = [pscustomobject]@{ Delays = [System.Collections.Generic.List[int]]::new() }
        $action = { param($s) $rec.Delays.Add([int]$s) | Out-Null }.GetNewClosure()
        [pscustomobject]@{ Action = $action; Recorder = $rec }
    }

    # Normalised op-record helper mirroring the documented Get-Compl8ShadowDiff op shape.
    function New-Op {
        param([string]$Action, [string]$ObjectType, [string]$ObjectRef, [hashtable]$Extra = @{})
        $o = [ordered]@{ action = $Action; objectType = $ObjectType; objectRef = $ObjectRef }
        foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] }
        [pscustomobject]$o
    }
}

AfterAll {
    Remove-Item function:global:Get-AutoSensitivityLabelRule -ErrorAction SilentlyContinue
    Remove-Item function:global:Remove-AutoSensitivityLabelRule -ErrorAction SilentlyContinue
}

Describe 'module surface' {
    It 'exports the three Task 7 functions from Compl8.Engine' {
        foreach ($fn in 'Remove-PurviewObject', 'Invoke-WithRetry', 'Get-Compl8ShadowDiff') {
            (Get-Command -Name $fn -Module Compl8.Engine -ErrorAction SilentlyContinue) |
                Should -Not -BeNullOrEmpty -Because "$fn must be exported"
        }
    }
}

# ============================================================================ Invoke-WithRetry
Describe 'Invoke-WithRetry — retry semantics with injected (instant) sleep' {

    It 'retries a throttle error twice then succeeds (inner scriptblock runs 3 times, no real sleep)' {
        $sleep = New-SleepRecorder
        $script:calls = 0
        $sb = {
            $script:calls++
            if ($script:calls -lt 3) { throw "We are experiencing a server side error. Please try again after some time." }
            return 'ok'
        }
        $result = Invoke-WithRetry -ScriptBlock $sb -OperationName 'test' -MaxRetries 3 -BaseDelaySec 300 -SleepAction $sleep.Action
        $result | Should -Be 'ok'
        $script:calls | Should -Be 3 -Because 'two throttle failures + one success'
        $sleep.Recorder.Delays.Count | Should -Be 2 -Because 'one injected sleep per retry, no real waiting'
    }

    It 'throws immediately on a NON-retryable error (inner scriptblock runs once)' {
        $sleep = New-SleepRecorder
        $script:calls2 = 0
        $sb = { $script:calls2++; throw "Some permanent validation failure" }
        { Invoke-WithRetry -ScriptBlock $sb -OperationName 'test' -MaxRetries 3 -SleepAction $sleep.Action } |
            Should -Throw
        $script:calls2 | Should -Be 1 -Because 'non-retryable errors are not retried'
        $sleep.Recorder.Delays.Count | Should -Be 0
    }

    It 'respects MaxRetries — gives up (throws) after N retries on a persistent throttle' {
        $sleep = New-SleepRecorder
        $script:calls3 = 0
        $sb = { $script:calls3++; throw "server side error" }
        { Invoke-WithRetry -ScriptBlock $sb -OperationName 'test' -MaxRetries 2 -BaseDelaySec 1 -SleepAction $sleep.Action } |
            Should -Throw
        # MaxRetries=2 => attempts 1,2,3 (initial + 2 retries) then the loop ends and rethrows.
        $script:calls3 | Should -Be 3 -Because 'initial attempt + MaxRetries retries'
        $sleep.Recorder.Delays.Count | Should -Be 2 -Because 'one sleep before each of the 2 retries'
    }

    It 'treats a pending-deletion message as success (no throw, returns without retry)' {
        $sleep = New-SleepRecorder
        $script:calls4 = 0
        $sb = { $script:calls4++; throw "The object is in PendingDeletion state" }
        { Invoke-WithRetry -ScriptBlock $sb -OperationName 'test' -SleepAction $sleep.Action } | Should -Not -Throw
        $script:calls4 | Should -Be 1
        $sleep.Recorder.Delays.Count | Should -Be 0
    }

    It 'recognises a delete-cooldown message and retries (injected sleep, no real wait)' {
        $sleep = New-SleepRecorder
        $script:calls5 = 0
        $sb = {
            $script:calls5++
            if ($script:calls5 -lt 2) { throw "DeleteRetryInterval: please retry after 5 min" }
            return 'done'
        }
        $result = Invoke-WithRetry -ScriptBlock $sb -OperationName 'test' -MaxRetries 3 -SleepAction $sleep.Action
        $result | Should -Be 'done'
        $script:calls5 | Should -Be 2
        $sleep.Recorder.Delays.Count | Should -Be 1
    }
}

# ============================================================================ Remove-PurviewObject
Describe 'Remove-PurviewObject — status contract (mocked get/remove cmdlets -ModuleName Compl8.Engine)' {

    It 'returns "deleted" on a successful remove' {
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { [pscustomobject]@{ Name = 'R01' } }
        Mock -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule { }
        $status = Remove-PurviewObject -Identity 'R01' `
            -GetCommand 'Get-AutoSensitivityLabelRule' -RemoveCommand 'Remove-AutoSensitivityLabelRule' `
            -OperationName 'AL rule'
        $status | Should -Be 'deleted'
        Should -Invoke -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule -Times 1
    }

    It 'returns "not-found" when the get-command reports the object is absent' {
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { throw "The object couldn't be found." }
        Mock -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule { }
        $status = Remove-PurviewObject -Identity 'GONE' `
            -GetCommand 'Get-AutoSensitivityLabelRule' -RemoveCommand 'Remove-AutoSensitivityLabelRule' `
            -OperationName 'AL rule'
        $status | Should -Be 'not-found'
        Should -Invoke -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule -Times 0
    }

    It 'returns "pending" for an object already in PendingDeletion (Mode property)' {
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { [pscustomobject]@{ Name = 'R01'; Mode = 'PendingDeletion' } }
        Mock -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule { }
        $status = Remove-PurviewObject -Identity 'R01' `
            -GetCommand 'Get-AutoSensitivityLabelRule' -RemoveCommand 'Remove-AutoSensitivityLabelRule' `
            -OperationName 'AL rule'
        $status | Should -Be 'pending'
        Should -Invoke -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule -Times 0
    }

    It 'returns "pending" for an object in PendingDeletion (State property)' {
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { [pscustomobject]@{ Name = 'R01'; State = 'PendingDeletion' } }
        Mock -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule { }
        $status = Remove-PurviewObject -Identity 'R01' `
            -GetCommand 'Get-AutoSensitivityLabelRule' -RemoveCommand 'Remove-AutoSensitivityLabelRule' `
            -OperationName 'AL rule'
        $status | Should -Be 'pending'
    }

    It 'returns "pending" when the REMOVE throws a pending-deletion error' {
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { [pscustomobject]@{ Name = 'R01' } }
        Mock -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule { throw "The object is in pending deletion." }
        $status = Remove-PurviewObject -Identity 'R01' `
            -GetCommand 'Get-AutoSensitivityLabelRule' -RemoveCommand 'Remove-AutoSensitivityLabelRule' `
            -OperationName 'AL rule'
        $status | Should -Be 'pending'
    }

    It 'returns "cooldown:Nm" when the remove hits a delete cooldown (waitMin = N+1)' {
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { [pscustomobject]@{ Name = 'R01' } }
        Mock -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule { throw "Please retry after 5 min (DeleteRetryInterval)." }
        $status = Remove-PurviewObject -Identity 'R01' `
            -GetCommand 'Get-AutoSensitivityLabelRule' -RemoveCommand 'Remove-AutoSensitivityLabelRule' `
            -OperationName 'AL rule'
        $status | Should -Be 'cooldown:6' -Because 'message says 5 min, helper adds 1'
    }

    It 'returns "deleted" when a throttled remove succeeds on retry (injected sleep, instant)' {
        $script:rmCalls = 0
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { [pscustomobject]@{ Name = 'R01' } }
        Mock -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule {
            $script:rmCalls++
            if ($script:rmCalls -eq 1) { throw "We are experiencing a server side error. Please try again after some time." }
        }
        $sleepAction = { param($s) }   # no-op
        $status = Remove-PurviewObject -Identity 'R01' `
            -GetCommand 'Get-AutoSensitivityLabelRule' -RemoveCommand 'Remove-AutoSensitivityLabelRule' `
            -OperationName 'AL rule' -MaxRetries 2 -BaseDelaySec 1 -SleepAction $sleepAction
        $status | Should -Be 'deleted'
        $script:rmCalls | Should -BeGreaterThan 1 -Because 'first attempt threw a throttle, retry succeeded'
    }

    It 'returns "failed" on a non-recoverable remove error' {
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { [pscustomobject]@{ Name = 'R01' } }
        Mock -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule { throw "Insufficient permissions to delete." }
        $status = Remove-PurviewObject -Identity 'R01' `
            -GetCommand 'Get-AutoSensitivityLabelRule' -RemoveCommand 'Remove-AutoSensitivityLabelRule' `
            -OperationName 'AL rule'
        $status | Should -Be 'failed'
    }

    It 'uses -InputObject when provided and SKIPS the get-command entirely' {
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { throw 'get should not be called' }
        Mock -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule { }
        $status = Remove-PurviewObject -Identity 'R01' `
            -InputObject ([pscustomobject]@{ Name = 'R01' }) `
            -GetCommand 'Get-AutoSensitivityLabelRule' -RemoveCommand 'Remove-AutoSensitivityLabelRule' `
            -OperationName 'AL rule'
        $status | Should -Be 'deleted'
        Should -Invoke -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule -Times 0
    }

    It 'returns "deleted" without calling remove under -WhatIf' {
        Mock -ModuleName Compl8.Engine Get-AutoSensitivityLabelRule { [pscustomobject]@{ Name = 'R01' } }
        Mock -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule { }
        $status = Remove-PurviewObject -Identity 'R01' `
            -GetCommand 'Get-AutoSensitivityLabelRule' -RemoveCommand 'Remove-AutoSensitivityLabelRule' `
            -OperationName 'AL rule' -WhatIf
        $status | Should -Be 'deleted'
        Should -Invoke -ModuleName Compl8.Engine Remove-AutoSensitivityLabelRule -Times 0
    }
}

# ============================================================================ Get-Compl8ShadowDiff
Describe 'Get-Compl8ShadowDiff — executor planned ops vs old-script -WhatIf ops' {

    It 'identical op lists => Match=$true and all diff arrays empty (parity)' {
        $ops = @(
            New-Op -Action 'create' -ObjectType 'dictionary'  -ObjectRef '{{DICT_X}}'
            New-Op -Action 'update' -ObjectType 'rulePackage' -ObjectRef 'QGISCF-test-01'
        )
        $diff = Get-Compl8ShadowDiff -EngineOps $ops -OldOps $ops
        $diff.Match | Should -BeTrue
        @($diff.OnlyInEngine).Count | Should -Be 0
        @($diff.OnlyInOld).Count    | Should -Be 0
        @($diff.Differing).Count    | Should -Be 0
    }

    It 'an op only in Engine => OnlyInEngine has it and Match=$false' {
        $engine = @(
            New-Op -Action 'create' -ObjectType 'dictionary'  -ObjectRef '{{DICT_X}}'
            New-Op -Action 'update' -ObjectType 'rulePackage' -ObjectRef 'QGISCF-test-01'
        )
        $old = @( New-Op -Action 'create' -ObjectType 'dictionary' -ObjectRef '{{DICT_X}}' )
        $diff = Get-Compl8ShadowDiff -EngineOps $engine -OldOps $old
        $diff.Match | Should -BeFalse
        @($diff.OnlyInEngine).Count | Should -Be 1
        @($diff.OnlyInEngine)[0].objectRef | Should -Be 'QGISCF-test-01'
        @($diff.OnlyInOld).Count    | Should -Be 0
    }

    It 'an op only in the old path => OnlyInOld has it and Match=$false' {
        $engine = @( New-Op -Action 'create' -ObjectType 'dictionary' -ObjectRef '{{DICT_X}}' )
        $old = @(
            New-Op -Action 'create' -ObjectType 'dictionary'  -ObjectRef '{{DICT_X}}'
            New-Op -Action 'remove' -ObjectType 'dlpRule'     -ObjectRef 'QGISCF-Rule-99'
        )
        $diff = Get-Compl8ShadowDiff -EngineOps $engine -OldOps $old
        $diff.Match | Should -BeFalse
        @($diff.OnlyInOld).Count | Should -Be 1
        @($diff.OnlyInOld)[0].objectRef | Should -Be 'QGISCF-Rule-99'
        @($diff.OnlyInEngine).Count | Should -Be 0
    }

    It 'an op present in BOTH but with a differing field => Differing has it, Match=$false' {
        $engine = @( New-Op -Action 'update' -ObjectType 'dictionary' -ObjectRef '{{DICT_X}}' -Extra @{ payloadHash = 'AAA' } )
        $old    = @( New-Op -Action 'update' -ObjectType 'dictionary' -ObjectRef '{{DICT_X}}' -Extra @{ payloadHash = 'BBB' } )
        $diff = Get-Compl8ShadowDiff -EngineOps $engine -OldOps $old
        $diff.Match | Should -BeFalse
        @($diff.Differing).Count | Should -Be 1
        @($diff.Differing)[0].key        | Should -Be 'update|dictionary|{{DICT_X}}'
        @($diff.Differing)[0].fields      | Should -Contain 'payloadHash'
        @($diff.OnlyInEngine).Count | Should -Be 0
        @($diff.OnlyInOld).Count    | Should -Be 0
    }

    It 'is ORDER-INSENSITIVE: same ops in a different order => Match=$true' {
        $a = @(
            New-Op -Action 'create' -ObjectType 'dictionary'  -ObjectRef '{{DICT_X}}'
            New-Op -Action 'update' -ObjectType 'rulePackage' -ObjectRef 'QGISCF-test-01'
            New-Op -Action 'remove' -ObjectType 'dlpRule'     -ObjectRef 'QGISCF-Rule-07'
        )
        $b = @(
            New-Op -Action 'remove' -ObjectType 'dlpRule'     -ObjectRef 'QGISCF-Rule-07'
            New-Op -Action 'create' -ObjectType 'dictionary'  -ObjectRef '{{DICT_X}}'
            New-Op -Action 'update' -ObjectType 'rulePackage' -ObjectRef 'QGISCF-test-01'
        )
        $diff = Get-Compl8ShadowDiff -EngineOps $a -OldOps $b
        $diff.Match | Should -BeTrue
        @($diff.OnlyInEngine).Count | Should -Be 0
        @($diff.OnlyInOld).Count    | Should -Be 0
        @($diff.Differing).Count    | Should -Be 0
    }

    It 'handles two EMPTY lists as a clean match' {
        $diff = Get-Compl8ShadowDiff -EngineOps @() -OldOps @()
        $diff.Match | Should -BeTrue
    }

    It 'is compatible with Invoke-Compl8Apply -WhatIf wouldRun shape ({ action; objectType; objectRef })' {
        # The wouldRun records use stepId/action/objectType/objectRef; the harness keys on
        # action|objectType|objectRef so an apply -WhatIf list can be diffed directly.
        $engine = @( [pscustomobject]@{ stepId = 's01'; action = 'create'; objectType = 'dictionary'; objectRef = '{{DICT_X}}' } )
        $old    = @( [pscustomobject]@{ action = 'create'; objectType = 'dictionary'; objectRef = '{{DICT_X}}' } )
        $diff = Get-Compl8ShadowDiff -EngineOps $engine -OldOps $old
        $diff.Match | Should -BeTrue
    }
}
