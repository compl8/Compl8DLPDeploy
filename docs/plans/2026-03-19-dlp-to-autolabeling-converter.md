# DLP-to-Auto-Labeling Converter Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a PowerShell script that scans a tenant's DLP rules, builds an auditable conversion plan, and executes it to create auto-labeling policies.

**Architecture:** Two-phase script (Scan & Plan / Execute) operating on a plan JSON file. Convertibility logic lives in a helper module. The main script orchestrates scanning, label assignment, approval, and execution. Reuses DLP-Deploy.psm1 for connection, retry, and SIT condition building.

**Tech Stack:** PowerShell 7+, ExchangeOnlineManagement module, Microsoft Purview Security & Compliance cmdlets

**Spec:** `docs/specs/2026-03-18-dlp-to-autolabeling-converter-design.md`

---

## File Structure

| File | Responsibility |
|------|----------------|
| `modules/AutoLabel-Converter.psm1` | All conversion logic: condition extraction, convertibility classification, condition merging, label assignment resolution, plan JSON read/write |
| `scripts/Convert-DLPToAutoLabeling.ps1` | Entry point script: params, connection, orchestrates scan/execute/cleanup phases, interactive prompts, terminal summary |
| `tests/AutoLabel-Converter.Tests.ps1` | Pester unit tests for the converter module (all pure functions, no tenant calls) |

The converter module is separate from DLP-Deploy.psm1 because it has a different concern (reading/analysing existing rules vs deploying new ones). It imports DLP-Deploy.psm1 for shared functions.

---

### Task 1: Convertibility classifier — the DLP-only conditions lookup

**Files:**
- Create: `modules/AutoLabel-Converter.psm1`
- Create: `tests/AutoLabel-Converter.Tests.ps1`

This task builds the core lookup that decides whether a DLP rule condition is convertible, droppable, or blocks conversion entirely.

- [ ] **Step 1: Write failing tests for `Get-ConditionConvertibility`**

```powershell
# tests/AutoLabel-Converter.Tests.ps1
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot ".." "modules" "AutoLabel-Converter.psm1") -Force
}

Describe "Get-ConditionConvertibility" {
    It "classifies ContentContainsSensitiveInformation as convertible" {
        $result = Get-ConditionConvertibility -ConditionName "ContentContainsSensitiveInformation"
        $result.Status | Should -Be "convertible"
    }
    It "classifies AccessScope as convertible" {
        $result = Get-ConditionConvertibility -ConditionName "AccessScope"
        $result.Status | Should -Be "convertible"
    }
    It "classifies ExceptIfContentContainsSensitiveInformation as convertible" {
        $result = Get-ConditionConvertibility -ConditionName "ExceptIfContentContainsSensitiveInformation"
        $result.Status | Should -Be "convertible"
    }
    It "classifies SubjectContainsWords as droppable with what/why" {
        $result = Get-ConditionConvertibility -ConditionName "SubjectContainsWords"
        $result.Status | Should -Be "droppable"
        $result.What | Should -Not -BeNullOrEmpty
        $result.Why | Should -Not -BeNullOrEmpty
    }
    It "classifies FromScope as droppable" {
        $result = Get-ConditionConvertibility -ConditionName "FromScope"
        $result.Status | Should -Be "droppable"
    }
    It "classifies MessageTypeMatches as droppable" {
        $result = Get-ConditionConvertibility -ConditionName "MessageTypeMatches"
        $result.Status | Should -Be "droppable"
    }
    It "returns unknown for unrecognised conditions" {
        $result = Get-ConditionConvertibility -ConditionName "SomeFutureCondition"
        $result.Status | Should -Be "unknown"
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pwsh -Command "Invoke-Pester tests/AutoLabel-Converter.Tests.ps1 -Output Detailed"`
Expected: FAIL — module not found

- [ ] **Step 3: Implement `Get-ConditionConvertibility`**

```powershell
# modules/AutoLabel-Converter.psm1
# Auto-Label Converter Module
# Provides DLP-to-auto-labeling conversion logic.

#region Condition Classification

$script:ConvertibleConditions = @(
    "ContentContainsSensitiveInformation"
    "ExceptIfContentContainsSensitiveInformation"
    "AccessScope"
    "ExceptIfAccessScope"
    "ContentExtensionMatchesWords"
    "ExceptIfContentExtensionMatchesWords"
    "ContentPropertyContainsWords"
    "DocumentIsPasswordProtected"
    "DocumentIsUnsupported"
    "DocumentCreatedBy"
    "DocumentNameMatchesWords"
    "DocumentSizeOver"
    "SubjectMatchesPatterns"
    "HeaderMatchesPatterns"
    "SenderDomainIs"
    "RecipientDomainIs"
    "SentTo"
    "SentToMemberOf"
    "AnyOfRecipientAddressContainsWords"
    "AnyOfRecipientAddressMatchesPatterns"
    "FromAddressContainsWords"
    "FromAddressMatchesPatterns"
    "SenderIPRanges"
    "ProcessingLimitExceeded"
)

$script:DroppableConditions = @{
    "FromScope" = @{
        What = "Sender location filtering will be dropped"
        Why  = "Auto-labeling has no equivalent to FromScope. Partial workaround: SenderDomainIs or SenderIPRanges."
    }
    "From" = @{
        What = "Specific sender filter will be dropped"
        Why  = "The From parameter is reserved for internal Microsoft use on auto-labeling cmdlets."
    }
    "FromMemberOf" = @{
        What = "Sender group membership filter will be dropped"
        Why  = "The FromMemberOf parameter is reserved for internal Microsoft use on auto-labeling cmdlets."
    }
    "SenderADAttributeContainsWords" = @{
        What = "Sender AD attribute word matching will be dropped"
        Why  = "Auto-labeling has no AD attribute conditions."
    }
    "SenderADAttributeMatchesPatterns" = @{
        What = "Sender AD attribute pattern matching will be dropped"
        Why  = "Auto-labeling has no AD attribute conditions."
    }
    "RecipientADAttributeContainsWords" = @{
        What = "Recipient AD attribute word matching will be dropped"
        Why  = "Auto-labeling has no AD attribute conditions."
    }
    "RecipientADAttributeMatchesPatterns" = @{
        What = "Recipient AD attribute pattern matching will be dropped"
        Why  = "Auto-labeling has no AD attribute conditions."
    }
    "MessageTypeMatches" = @{
        What = "Message type filtering will be dropped"
        Why  = "Auto-labeling cannot filter by message type (AutoForward, Encrypted, etc.)."
    }
    "SubjectContainsWords" = @{
        What = "Word matching on email subjects will be dropped"
        Why  = "Auto-labeling only supports regex patterns (SubjectMatchesPatterns), not word lists. The rule will match more broadly."
    }
    "SubjectOrBodyContainsWords" = @{
        What = "Body/subject word matching will be dropped"
        Why  = "Auto-labeling has no equivalent to SubjectOrBodyContainsWords. The rule will trigger on SIT matches alone."
    }
    "SubjectOrBodyMatchesPatterns" = @{
        What = "Body/subject pattern matching will be dropped"
        Why  = "Auto-labeling has no body content pattern matching."
    }
    "DocumentContainsWords" = @{
        What = "Document body word search will be dropped"
        Why  = "Auto-labeling has no document body word search."
    }
    "DocumentMatchesPatterns" = @{
        What = "Document body pattern matching will be dropped"
        Why  = "Auto-labeling has no document body pattern matching."
    }
    "DocumentNameMatchesPatterns" = @{
        What = "Document name pattern matching will be dropped"
        Why  = "Auto-labeling only supports word matching on document names (DocumentNameMatchesWords), not regex patterns."
    }
    "HeaderContainsWords" = @{
        What = "Header word matching will be dropped"
        Why  = "Auto-labeling only supports regex patterns (HeaderMatchesPatterns), not word lists."
    }
    "ContentIsNotLabeled" = @{
        What = "Unlabeled content condition will be dropped"
        Why  = "Auto-labeling cannot condition on whether content already has a label."
    }
    "AttachmentIsNotLabeled" = @{
        What = "Unlabeled attachment condition will be dropped"
        Why  = "Auto-labeling cannot condition on attachment label state."
    }
    "MessageIsNotLabeled" = @{
        What = "Unlabeled message condition will be dropped"
        Why  = "Auto-labeling cannot condition on message label state."
    }
    "ContentIsShared" = @{
        What = "Content sharing condition will be dropped"
        Why  = "Auto-labeling has no ContentIsShared condition."
    }
    "HasSenderOverride" = @{
        What = "Sender override condition will be dropped"
        Why  = "Auto-labeling has no sender override detection."
    }
    "MessageSizeOver" = @{
        What = "Message size condition will be dropped"
        Why  = "Auto-labeling has DocumentSizeOver (Exchange) but not MessageSizeOver."
    }
    "WithImportance" = @{
        What = "Message importance condition will be dropped"
        Why  = "Auto-labeling cannot filter by message importance."
    }
    "StopPolicyProcessing" = @{
        What = "Stop processing flag will be dropped"
        Why  = "Auto-labeling has no StopPolicyProcessing — highest priority label wins."
    }
    "EvaluateRulePerComponent" = @{
        What = "Per-component evaluation will be dropped"
        Why  = "Auto-labeling has no per-component condition matching."
    }
    "SharedByIRMUserRisk" = @{
        What = "IRM user risk condition will be dropped"
        Why  = "Auto-labeling has no IRM user risk detection."
    }
}

function Get-ConditionConvertibility {
    param([Parameter(Mandatory)][string]$ConditionName)

    if ($ConditionName -in $script:ConvertibleConditions) {
        return @{ Status = "convertible" }
    }
    if ($script:DroppableConditions.ContainsKey($ConditionName)) {
        $info = $script:DroppableConditions[$ConditionName]
        return @{ Status = "droppable"; What = $info.What; Why = $info.Why }
    }
    return @{ Status = "unknown" }
}

#endregion
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pwsh -Command "Invoke-Pester tests/AutoLabel-Converter.Tests.ps1 -Output Detailed"`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add modules/AutoLabel-Converter.psm1 tests/AutoLabel-Converter.Tests.ps1
git commit -m "feat: add condition convertibility classifier for DLP-to-auto-labeling"
```

---

### Task 2: SIT condition extraction from DLP rule objects

**Files:**
- Modify: `modules/AutoLabel-Converter.psm1`
- Modify: `tests/AutoLabel-Converter.Tests.ps1`

Extracts SIT conditions from DLP rule PSObjects (as returned by `Get-DlpComplianceRule`). Handles both Simple and AdvancedRule formats.

- [ ] **Step 1: Write failing tests for `ConvertFrom-DlpRuleConditions`**

```powershell
Describe "ConvertFrom-DlpRuleConditions" {
    It "extracts Simple format CCSI and AccessScope" {
        $mockRule = [PSCustomObject]@{
            ContentContainsSensitiveInformation = @{
                operator = "And"
                groups = @(@{
                    operator = "Or"; name = "Default"
                    sensitivetypes = @(
                        @{ name = "Credit Card Number"; id = "50842eb7-edc8-4019-85dd-5a5c1f2bb085"; mincount = 1; maxcount = -1; confidencelevel = "High" }
                    )
                })
            }
            AccessScope = "NotInOrganization"
            AdvancedRule = $null
        }
        $result = ConvertFrom-DlpRuleConditions -DlpRule $mockRule
        $result.HasSIT | Should -BeTrue
        $result.HasTrainableClassifier | Should -BeFalse
        $result.Converted.ContentContainsSensitiveInformation | Should -Not -BeNullOrEmpty
        $result.Converted.AccessScope | Should -Be "NotInOrganization"
        $result.Dropped.Count | Should -Be 0
    }

    It "detects trainable classifiers in AdvancedRule JSON" {
        $advJson = @{
            Condition = @{
                SubConditions = @(
                    @{
                        ConditionName = "ContentContainsSensitiveInformation"
                        Value = @(@{
                            Groups = @(@{
                                Sensitivetypes = @(
                                    @{ Name = "TC-Model"; Id = "abc-123"; Classifiertype = "MLModel" }
                                )
                            })
                        })
                    }
                )
            }
        } | ConvertTo-Json -Depth 10
        $mockRule = [PSCustomObject]@{
            ContentContainsSensitiveInformation = $null
            AdvancedRule = $advJson
            AccessScope = $null
        }
        $result = ConvertFrom-DlpRuleConditions -DlpRule $mockRule
        $result.HasSIT | Should -BeTrue
        $result.HasTrainableClassifier | Should -BeTrue
    }

    It "records droppable conditions with what/why" {
        $mockRule = [PSCustomObject]@{
            ContentContainsSensitiveInformation = @{
                operator = "And"
                groups = @(@{ operator = "Or"; name = "Default"; sensitivetypes = @(@{ name = "SSN"; id = "a44669fe"; mincount = 1; maxcount = -1; confidencelevel = "High" }) })
            }
            AccessScope = $null
            AdvancedRule = $null
            SubjectContainsWords = @("CONFIDENTIAL")
            FromScope = "InOrganization"
        }
        $result = ConvertFrom-DlpRuleConditions -DlpRule $mockRule
        $result.Dropped.Count | Should -Be 2
        $result.Dropped[0].condition | Should -BeIn @("SubjectContainsWords", "FromScope")
        $result.Dropped[0].what | Should -Not -BeNullOrEmpty
        $result.Dropped[0].why | Should -Not -BeNullOrEmpty
    }

    It "returns HasSIT false for rules without SIT conditions" {
        $mockRule = [PSCustomObject]@{
            ContentContainsSensitiveInformation = $null
            AdvancedRule = $null
            AccessScope = $null
            HeaderContainsWords = @("X-Custom: true")
        }
        $result = ConvertFrom-DlpRuleConditions -DlpRule $mockRule
        $result.HasSIT | Should -BeFalse
    }

    It "extracts ExceptIf conditions" {
        $mockRule = [PSCustomObject]@{
            ContentContainsSensitiveInformation = @{
                operator = "And"
                groups = @(@{ operator = "Or"; name = "Default"; sensitivetypes = @(@{ name = "SSN"; id = "a44669fe"; mincount = 1; maxcount = -1; confidencelevel = "High" }) })
            }
            ExceptIfContentContainsSensitiveInformation = @{
                operator = "And"
                groups = @(@{ operator = "Or"; name = "Default"; sensitivetypes = @(@{ name = "Test Pattern"; id = "bbb-222"; mincount = 5; maxcount = -1; confidencelevel = "Low" }) })
            }
            ExceptIfAccessScope = "InOrganization"
            AdvancedRule = $null
            AccessScope = "NotInOrganization"
        }
        $result = ConvertFrom-DlpRuleConditions -DlpRule $mockRule
        $result.ExceptIf.ExceptIfContentContainsSensitiveInformation | Should -Not -BeNullOrEmpty
        $result.ExceptIf.ExceptIfAccessScope | Should -Be "InOrganization"
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pwsh -Command "Invoke-Pester tests/AutoLabel-Converter.Tests.ps1 -Output Detailed -Tag 'ConvertFrom-DlpRuleConditions'"`
Expected: FAIL — function not found

- [ ] **Step 3: Implement `ConvertFrom-DlpRuleConditions`**

Add to `modules/AutoLabel-Converter.psm1`:

```powershell
#region Condition Extraction

function ConvertFrom-DlpRuleConditions {
    <#
    .SYNOPSIS
        Extracts and classifies conditions from a DLP compliance rule object.
        Returns: HasSIT, HasTrainableClassifier, Converted (hashtable), ExceptIf (hashtable), Dropped (array)
    #>
    param([Parameter(Mandatory)][PSObject]$DlpRule)

    $converted = @{}
    $exceptIf = @{}
    $dropped = @()
    $hasSIT = $false
    $hasTC = $false

    # Extract SIT conditions — Simple format
    if ($DlpRule.ContentContainsSensitiveInformation) {
        $hasSIT = $true
        $converted["ContentContainsSensitiveInformation"] = Convert-PSOToHashtable $DlpRule.ContentContainsSensitiveInformation
    }

    # Extract SIT conditions — AdvancedRule format
    if (-not $hasSIT -and $DlpRule.AdvancedRule) {
        $parsed = $DlpRule.AdvancedRule | ConvertFrom-Json -Depth 20
        $ccsi = Find-CCSIInAdvancedRule -ParsedRule $parsed
        if ($ccsi) {
            $hasSIT = $true
            $converted["ContentContainsSensitiveInformation"] = Convert-PSOToHashtable $ccsi
        }
        # Check for trainable classifiers
        $hasTC = Test-HasTrainableClassifier -ParsedRule $parsed
        # Extract embedded AccessScope
        $scope = Find-AccessScopeInAdvancedRule -ParsedRule $parsed
        if ($scope) { $converted["AccessScope"] = $scope }
    }

    # Scan all properties for convertible/droppable conditions
    $knownConditionProps = @(
        "ContentContainsSensitiveInformation", "AdvancedRule",  # already handled
        "ExceptIfContentContainsSensitiveInformation", "ExceptIfAccessScope"  # handled below
    )

    foreach ($prop in $DlpRule.PSObject.Properties) {
        $name = $prop.Name
        $val = $prop.Value
        if (-not $val -or $name -in $knownConditionProps) { continue }

        $conv = Get-ConditionConvertibility -ConditionName $name
        switch ($conv.Status) {
            "convertible" { $converted[$name] = $val }
            "droppable"   { $dropped += @{ condition = $name; value = $val; what = $conv.What; why = $conv.Why } }
            # "unknown" conditions are ignored (non-condition properties like Name, Policy, etc.)
        }
    }

    # ExceptIf conditions
    if ($DlpRule.ExceptIfContentContainsSensitiveInformation) {
        $exceptIf["ExceptIfContentContainsSensitiveInformation"] = Convert-PSOToHashtable $DlpRule.ExceptIfContentContainsSensitiveInformation
    }
    if ($DlpRule.ExceptIfAccessScope) {
        $exceptIf["ExceptIfAccessScope"] = $DlpRule.ExceptIfAccessScope
    }

    return @{
        HasSIT                  = $hasSIT
        HasTrainableClassifier  = $hasTC
        Converted               = $converted
        ExceptIf                = $exceptIf
        Dropped                 = $dropped
    }
}

function Convert-PSOToHashtable {
    <# Recursively converts a PSObject tree to ordered hashtables for JSON serialization. #>
    param($InputObject)
    if ($InputObject -is [System.Collections.IDictionary]) {
        $ht = [ordered]@{}
        foreach ($key in $InputObject.Keys) { $ht[$key] = Convert-PSOToHashtable $InputObject[$key] }
        return $ht
    }
    if ($InputObject -is [System.Management.Automation.PSObject] -and $InputObject -isnot [string]) {
        $ht = [ordered]@{}
        foreach ($prop in $InputObject.PSObject.Properties) { $ht[$prop.Name] = Convert-PSOToHashtable $prop.Value }
        return $ht
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        return @($InputObject | ForEach-Object { Convert-PSOToHashtable $_ })
    }
    return $InputObject
}

function Find-CCSIInAdvancedRule {
    <# Walks AdvancedRule JSON tree to find ContentContainsSensitiveInformation subcondition. #>
    param($ParsedRule)
    if (-not $ParsedRule) { return $null }
    if ($ParsedRule.Condition.SubConditions) {
        foreach ($sub in $ParsedRule.Condition.SubConditions) {
            if ($sub.ConditionName -eq "ContentContainsSensitiveInformation") {
                return $sub.Value
            }
        }
    }
    if ($ParsedRule.ConditionName -eq "ContentContainsSensitiveInformation") {
        return $ParsedRule.Value
    }
    return $null
}

function Find-AccessScopeInAdvancedRule {
    <# Extracts AccessScope from AdvancedRule JSON if embedded. #>
    param($ParsedRule)
    if (-not $ParsedRule) { return $null }
    if ($ParsedRule.Condition.SubConditions) {
        foreach ($sub in $ParsedRule.Condition.SubConditions) {
            if ($sub.ConditionName -eq "AccessScope") { return $sub.Value }
        }
    }
    return $null
}

function Test-HasTrainableClassifier {
    <# Checks if AdvancedRule JSON contains any MLModel/trainable classifier references. #>
    param($ParsedRule)
    $json = $ParsedRule | ConvertTo-Json -Depth 20
    return $json -match '"Classifiertype"\s*:\s*"MLModel"' -or $json -match '"classifiertype"\s*:\s*"MLModel"'
}

#endregion
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pwsh -Command "Invoke-Pester tests/AutoLabel-Converter.Tests.ps1 -Output Detailed"`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add modules/AutoLabel-Converter.psm1 tests/AutoLabel-Converter.Tests.ps1
git commit -m "feat: add SIT condition extraction from DLP rule objects"
```

---

### Task 3: Label assignment resolution (naming convention + mapping JSON + wildcard)

**Files:**
- Modify: `modules/AutoLabel-Converter.psm1`
- Modify: `tests/AutoLabel-Converter.Tests.ps1`

- [ ] **Step 1: Write failing tests for `Resolve-LabelAssignment`**

```powershell
Describe "Resolve-LabelAssignment" {
    BeforeAll {
        $tenantLabels = @("OFFICIALv2", "SENSITIVE-Personal-Privacyv2", "SENSITIVE-Financialv2")
    }

    It "resolves toolkit naming convention (P01-R04-ECH-SENS_Fin-EXT-ADT)" {
        $mappings = @()
        $result = Resolve-LabelAssignment -RuleName "P01-R04-ECH-SENS_Fin-EXT-ADT" -Mappings $mappings -TenantLabels $tenantLabels -LabelsJson @(@{code="SENS_Fin"; name="SENSITIVE-Financialv2"})
        $result.Label | Should -Be "SENSITIVE-Financialv2"
        $result.LabelCode | Should -Be "SENS_Fin"
        $result.AssignedBy | Should -Be "naming-convention"
    }

    It "resolves exact mapping JSON match" {
        $mappings = @(@{ dlpRule = "Custom-Rule-1"; label = "SENSITIVE-Financialv2" })
        $result = Resolve-LabelAssignment -RuleName "Custom-Rule-1" -Mappings $mappings -TenantLabels $tenantLabels -LabelsJson @()
        $result.Label | Should -Be "SENSITIVE-Financialv2"
        $result.AssignedBy | Should -Be "mapping-json"
    }

    It "resolves wildcard mapping JSON match" {
        $mappings = @(@{ dlpRule = "Finance-*"; label = "SENSITIVE-Financialv2" })
        $result = Resolve-LabelAssignment -RuleName "Finance-PII-Rule" -Mappings $mappings -TenantLabels $tenantLabels -LabelsJson @()
        $result.Label | Should -Be "SENSITIVE-Financialv2"
        $result.AssignedBy | Should -Be "mapping-json"
    }

    It "returns null label when no match found (interactive needed)" {
        $mappings = @()
        $result = Resolve-LabelAssignment -RuleName "Unknown-Rule" -Mappings $mappings -TenantLabels $tenantLabels -LabelsJson @()
        $result.Label | Should -BeNullOrEmpty
        $result.AssignedBy | Should -Be "unresolved"
    }

    It "first mapping match wins for overlapping wildcards" {
        $mappings = @(
            @{ dlpRule = "Finance-PII-*"; label = "SENSITIVE-Personal-Privacyv2" }
            @{ dlpRule = "Finance-*"; label = "SENSITIVE-Financialv2" }
        )
        $result = Resolve-LabelAssignment -RuleName "Finance-PII-Rule" -Mappings $mappings -TenantLabels $tenantLabels -LabelsJson @()
        $result.Label | Should -Be "SENSITIVE-Personal-Privacyv2"
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pwsh -Command "Invoke-Pester tests/AutoLabel-Converter.Tests.ps1 -Output Detailed"`
Expected: FAIL — function not found

- [ ] **Step 3: Implement `Resolve-LabelAssignment`**

Add to `modules/AutoLabel-Converter.psm1`:

```powershell
#region Label Assignment

function Resolve-LabelAssignment {
    <#
    .SYNOPSIS
        Resolves which sensitivity label a DLP rule should map to.
        Tries: 1) toolkit naming convention, 2) mapping JSON, 3) returns unresolved.
    #>
    param(
        [Parameter(Mandatory)][string]$RuleName,
        [array]$Mappings,
        [array]$TenantLabels,
        [array]$LabelsJson
    )

    # 1. Toolkit naming convention: P{nn}-R{nn}-{Workload}-{LabelCode}-{Suffix}
    if ($RuleName -match '^P\d{2}-R\d{2}[a-z]?-[A-Z]{3}-(.+)-[A-Z]+-[A-Z]+$') {
        $labelCode = $Matches[1]
        $labelEntry = $LabelsJson | Where-Object { $_.code -eq $labelCode } | Select-Object -First 1
        if ($labelEntry -and $labelEntry.name -in $TenantLabels) {
            return @{ Label = $labelEntry.name; LabelCode = $labelCode; AssignedBy = "naming-convention" }
        }
    }

    # 2. Mapping JSON (exact + wildcard)
    foreach ($mapping in $Mappings) {
        if ($RuleName -like $mapping.dlpRule) {
            if ($mapping.label -in $TenantLabels) {
                return @{ Label = $mapping.label; LabelCode = $null; AssignedBy = "mapping-json" }
            }
        }
    }

    # 3. Unresolved — needs interactive assignment
    return @{ Label = $null; LabelCode = $null; AssignedBy = "unresolved" }
}

#endregion
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pwsh -Command "Invoke-Pester tests/AutoLabel-Converter.Tests.ps1 -Output Detailed"`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add modules/AutoLabel-Converter.psm1 tests/AutoLabel-Converter.Tests.ps1
git commit -m "feat: add label assignment resolution with naming convention and mapping JSON"
```

---

### Task 4: DLP rule classification (full/partial/unconvertible) and workload detection

**Files:**
- Modify: `modules/AutoLabel-Converter.psm1`
- Modify: `tests/AutoLabel-Converter.Tests.ps1`

- [ ] **Step 1: Write failing tests for `Get-DlpRuleClassification` and `Get-WorkloadFromPolicy`**

```powershell
Describe "Get-DlpRuleClassification" {
    It "returns 'full' for SIT-only rule" {
        $conditions = @{ HasSIT = $true; HasTrainableClassifier = $false; Dropped = @() }
        $result = Get-DlpRuleClassification -ExtractedConditions $conditions
        $result | Should -Be "full"
    }
    It "returns 'partial' for SIT rule with droppable conditions" {
        $conditions = @{ HasSIT = $true; HasTrainableClassifier = $false; Dropped = @(@{condition="SubjectContainsWords"}) }
        $result = Get-DlpRuleClassification -ExtractedConditions $conditions
        $result | Should -Be "partial"
    }
    It "returns 'unconvertible' for rule without SIT" {
        $conditions = @{ HasSIT = $false; HasTrainableClassifier = $false; Dropped = @() }
        $result = Get-DlpRuleClassification -ExtractedConditions $conditions
        $result | Should -Be "unconvertible"
    }
    It "returns 'unconvertible' for rule with trainable classifiers" {
        $conditions = @{ HasSIT = $true; HasTrainableClassifier = $true; Dropped = @() }
        $result = Get-DlpRuleClassification -ExtractedConditions $conditions
        $result | Should -Be "unconvertible"
    }
}

Describe "Get-WorkloadFromPolicy" {
    It "detects Exchange" {
        $policy = [PSCustomObject]@{ ExchangeLocation = @("All"); SharePointLocation = $null; OneDriveLocation = $null }
        Get-WorkloadFromPolicy -Policy $policy | Should -Be "Exchange"
    }
    It "detects SharePoint" {
        $policy = [PSCustomObject]@{ ExchangeLocation = $null; SharePointLocation = @("All"); OneDriveLocation = $null }
        Get-WorkloadFromPolicy -Policy $policy | Should -Be "SharePoint"
    }
    It "detects OneDriveForBusiness" {
        $policy = [PSCustomObject]@{ ExchangeLocation = $null; SharePointLocation = $null; OneDriveLocation = @("All") }
        Get-WorkloadFromPolicy -Policy $policy | Should -Be "OneDriveForBusiness"
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement both functions**

```powershell
#region Classification

function Get-DlpRuleClassification {
    param([Parameter(Mandatory)][hashtable]$ExtractedConditions)

    if (-not $ExtractedConditions.HasSIT) { return "unconvertible" }
    if ($ExtractedConditions.HasTrainableClassifier) { return "unconvertible" }
    if ($ExtractedConditions.Dropped.Count -gt 0) { return "partial" }
    return "full"
}

function Get-WorkloadFromPolicy {
    <# Derives the auto-labeling workload string from DLP policy location properties. #>
    param([Parameter(Mandatory)][PSObject]$Policy)

    if ($Policy.ExchangeLocation) { return "Exchange" }
    if ($Policy.SharePointLocation) { return "SharePoint" }
    if ($Policy.OneDriveLocation) { return "OneDriveForBusiness" }
    if ($Policy.TeamsLocation) { return "Teams" }
    if ($Policy.EndpointDlpLocation) { return "Endpoint" }
    return "Unknown"
}

#endregion
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add modules/AutoLabel-Converter.psm1 tests/AutoLabel-Converter.Tests.ps1
git commit -m "feat: add DLP rule classification and workload detection"
```

---

### Task 5: SIT condition merging

**Files:**
- Modify: `modules/AutoLabel-Converter.psm1`
- Modify: `tests/AutoLabel-Converter.Tests.ps1`

- [ ] **Step 1: Write failing tests for `Merge-SITConditions`**

```powershell
Describe "Merge-SITConditions" {
    It "unions SITs from two sources into one OR group" {
        $source1 = @{ operator = "And"; groups = @(@{ operator = "Or"; name = "Default"; sensitivetypes = @(@{ name = "SSN"; id = "aaa"; mincount = 1; maxcount = -1; confidencelevel = "High" }) }) }
        $source2 = @{ operator = "And"; groups = @(@{ operator = "Or"; name = "Default"; sensitivetypes = @(@{ name = "CCN"; id = "bbb"; mincount = 2; maxcount = -1; confidencelevel = "Medium" }) }) }
        $result = Merge-SITConditions -Sources @($source1, $source2)
        $allSITs = $result.Merged.groups | ForEach-Object { $_.sensitivetypes } | ForEach-Object { $_ }
        $allSITs.Count | Should -Be 2
    }

    It "resolves duplicate SIT IDs with most permissive values" {
        $source1 = @{ operator = "And"; groups = @(@{ operator = "Or"; name = "Default"; sensitivetypes = @(@{ name = "SSN"; id = "aaa"; mincount = 3; maxcount = -1; confidencelevel = "High" }) }) }
        $source2 = @{ operator = "And"; groups = @(@{ operator = "Or"; name = "Default"; sensitivetypes = @(@{ name = "SSN"; id = "aaa"; mincount = 1; maxcount = -1; confidencelevel = "Medium" }) }) }
        $result = Merge-SITConditions -Sources @($source1, $source2)
        $sit = $result.Merged.groups[0].sensitivetypes | Where-Object { $_.id -eq "aaa" }
        $sit.mincount | Should -Be 1
        $sit.confidencelevel | Should -Be "Medium"
        $result.Notes | Should -Not -BeNullOrEmpty
    }

    It "returns single source unchanged" {
        $source = @{ operator = "And"; groups = @(@{ operator = "Or"; name = "Default"; sensitivetypes = @(@{ name = "SSN"; id = "aaa"; mincount = 1; maxcount = -1; confidencelevel = "High" }) }) }
        $result = Merge-SITConditions -Sources @($source)
        $result.Notes.Count | Should -Be 0
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement `Merge-SITConditions`**

```powershell
#region Condition Merging

function Merge-SITConditions {
    <#
    .SYNOPSIS
        Merges multiple ContentContainsSensitiveInformation hashtables into one.
        Returns: @{ Merged = <hashtable>; Notes = @(<strings>) }
    #>
    param([Parameter(Mandatory)][array]$Sources)

    $notes = @()

    if ($Sources.Count -eq 1) {
        return @{ Merged = $Sources[0]; Notes = @() }
    }

    # Collect all SITs across all sources
    $allSITs = @{}  # keyed by lowercase ID
    foreach ($source in $Sources) {
        foreach ($group in $source.groups) {
            foreach ($sit in $group.sensitivetypes) {
                $key = "$($sit.id)".ToLower()
                if ($allSITs.ContainsKey($key)) {
                    # Duplicate — use most permissive
                    $existing = $allSITs[$key]
                    $changed = $false
                    if ([int]$sit.mincount -lt [int]$existing.mincount) {
                        $existing.mincount = $sit.mincount; $changed = $true
                    }
                    $confOrder = @{ "Low" = 1; "Medium" = 2; "High" = 3 }
                    $newConf = if ($confOrder.ContainsKey("$($sit.confidencelevel)")) { $confOrder["$($sit.confidencelevel)"] } else { 2 }
                    $existConf = if ($confOrder.ContainsKey("$($existing.confidencelevel)")) { $confOrder["$($existing.confidencelevel)"] } else { 2 }
                    if ($newConf -lt $existConf) {
                        $existing.confidencelevel = $sit.confidencelevel; $changed = $true
                    }
                    if ($changed) {
                        $notes += "Duplicate SIT '$($sit.name)' ($key): merged with most permissive thresholds (minCount=$($existing.mincount), confidence=$($existing.confidencelevel))"
                    }
                    $allSITs[$key] = $existing
                } else {
                    $allSITs[$key] = @{
                        name            = $sit.name
                        id              = $sit.id
                        mincount        = $sit.mincount
                        maxcount        = $sit.maxcount
                        confidencelevel = $sit.confidencelevel
                    }
                }
            }
        }
    }

    $merged = @{
        operator = "And"
        groups = @(@{
            operator       = "Or"
            name           = "Default"
            sensitivetypes = @($allSITs.Values)
        })
    }

    return @{ Merged = $merged; Notes = $notes }
}

#endregion
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add modules/AutoLabel-Converter.psm1 tests/AutoLabel-Converter.Tests.ps1
git commit -m "feat: add SIT condition merging with duplicate resolution"
```

---

### Task 6: Plan JSON builder

**Files:**
- Modify: `modules/AutoLabel-Converter.psm1`
- Modify: `tests/AutoLabel-Converter.Tests.ps1`

- [ ] **Step 1: Write failing tests for `New-ConversionPlan` and `Export-ConversionPlan`**

```powershell
Describe "New-ConversionPlan" {
    It "creates a plan with correct version and structure" {
        $plan = New-ConversionPlan -Tenant "test.dev" -ScannedBy "admin@test.dev"
        $plan.version | Should -Be "1"
        $plan.tenant | Should -Be "test.dev"
        $plan.labels | Should -Not -BeNullOrEmpty
        $plan.unconvertible | Should -BeOfType [System.Collections.IList]
    }
}

Describe "Export-ConversionPlan" {
    It "writes valid JSON to disk and reads back" {
        $plan = New-ConversionPlan -Tenant "test.dev" -ScannedBy "admin@test.dev"
        $tempFile = Join-Path $TestDrive "test-plan.json"
        Export-ConversionPlan -Plan $plan -Path $tempFile
        $loaded = Get-Content $tempFile -Raw | ConvertFrom-Json
        $loaded.version | Should -Be "1"
        $loaded.tenant | Should -Be "test.dev"
    }
}

Describe "Import-ConversionPlan" {
    It "reads a plan JSON and returns structured object" {
        $plan = New-ConversionPlan -Tenant "test.dev" -ScannedBy "admin@test.dev"
        $tempFile = Join-Path $TestDrive "test-plan.json"
        Export-ConversionPlan -Plan $plan -Path $tempFile
        $loaded = Import-ConversionPlan -Path $tempFile
        $loaded.tenant | Should -Be "test.dev"
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement plan JSON functions**

```powershell
#region Plan JSON

function New-ConversionPlan {
    param(
        [Parameter(Mandatory)][string]$Tenant,
        [Parameter(Mandatory)][string]$ScannedBy,
        [int]$ExistingPolicies = 0,
        [string]$ScalingStatus = "ok"
    )
    return @{
        version                   = "1"
        scanDate                  = (Get-Date).ToUniversalTime().ToString("o")
        tenant                    = $Tenant
        scannedBy                 = $ScannedBy
        existingAutoLabelPolicies = $ExistingPolicies
        scalingStatus             = $ScalingStatus
        labels                    = [ordered]@{}
        unconvertible             = [System.Collections.Generic.List[object]]::new()
        execution                 = @{ executedAt = $null; policiesCreated = 0; rulesCreated = 0; failures = @() }
    }
}

function Export-ConversionPlan {
    param(
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)][string]$Path
    )
    $dir = Split-Path $Path -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $Plan | ConvertTo-Json -Depth 20 | Set-Content -Path $Path -Encoding UTF8
}

function Import-ConversionPlan {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { Write-Error "Plan file not found: $Path"; return $null }
    return Get-Content $Path -Raw | ConvertFrom-Json -Depth 20
}

#endregion
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add modules/AutoLabel-Converter.psm1 tests/AutoLabel-Converter.Tests.ps1
git commit -m "feat: add plan JSON builder, exporter, and importer"
```

---

### Task 7: Scaling guardrails

**Files:**
- Modify: `modules/AutoLabel-Converter.psm1`
- Modify: `tests/AutoLabel-Converter.Tests.ps1`

- [ ] **Step 1: Write failing tests for `Test-ScalingLimits`**

```powershell
Describe "Test-ScalingLimits" {
    It "returns 'ok' when under warning threshold" {
        $result = Test-ScalingLimits -ExistingPolicies 10 -PlannedPolicies 5 -WarnAt 80 -MaxPolicies 100
        $result.Status | Should -Be "ok"
    }
    It "returns 'warning' at threshold" {
        $result = Test-ScalingLimits -ExistingPolicies 75 -PlannedPolicies 5 -WarnAt 80 -MaxPolicies 100
        $result.Status | Should -Be "warning"
        $result.Message | Should -Match "80"
    }
    It "returns 'blocked' over max" {
        $result = Test-ScalingLimits -ExistingPolicies 95 -PlannedPolicies 10 -WarnAt 80 -MaxPolicies 100
        $result.Status | Should -Be "blocked"
    }
    It "returns 'ok' at exactly max" {
        $result = Test-ScalingLimits -ExistingPolicies 90 -PlannedPolicies 10 -WarnAt 80 -MaxPolicies 100
        $result.Status | Should -Be "warning"
    }
}
```

- [ ] **Step 2: Run tests, verify fail**

- [ ] **Step 3: Implement `Test-ScalingLimits`**

```powershell
#region Scaling

function Test-ScalingLimits {
    param(
        [int]$ExistingPolicies,
        [int]$PlannedPolicies,
        [int]$WarnAt = 80,
        [int]$MaxPolicies = 100
    )
    $total = $ExistingPolicies + $PlannedPolicies
    if ($total -gt $MaxPolicies) {
        return @{ Status = "blocked"; Total = $total; Message = "Would exceed tenant limit of $MaxPolicies auto-labeling policies ($ExistingPolicies existing + $PlannedPolicies planned = $total)." }
    }
    if ($total -ge $WarnAt) {
        return @{ Status = "warning"; Total = $total; Message = "Approaching tenant limit: $total of $MaxPolicies auto-labeling policies ($ExistingPolicies existing + $PlannedPolicies planned). Warning threshold: $WarnAt." }
    }
    return @{ Status = "ok"; Total = $total; Message = "" }
}

#endregion
```

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add modules/AutoLabel-Converter.psm1 tests/AutoLabel-Converter.Tests.ps1
git commit -m "feat: add scaling limit guardrails"
```

---

### Task 8: Main script — Scan phase

**Files:**
- Create: `scripts/Convert-DLPToAutoLabeling.ps1`

This is the orchestration script. The Scan phase connects to the tenant, reads DLP rules, builds the plan, handles interactive prompts, and writes the plan JSON.

- [ ] **Step 1: Write the Scan phase script**

```powershell
# scripts/Convert-DLPToAutoLabeling.ps1
# (full implementation — see spec for interface)
# Params, connection, scan logic, interactive prompts, plan output
```

The script is large but mostly orchestration — the heavy logic is in `AutoLabel-Converter.psm1`. Key sections:

1. Parameter block with `-Scan`, `-Execute`, `-Cleanup`, `-MappingFile`, `-PlanFile`, `-DlpPolicyFilter`, `-IncludeDisabled`, `-AutoApprove`, `-Connect`, `-UPN`, `-WhatIf`
2. Config loading (optional settings.json with ALC/SIM fallback)
3. Scan phase: iterate DLP policies/rules, extract conditions, classify, resolve labels
4. Interactive label assignment for unresolved rules
5. Scaling check
6. Terminal summary (grouped by label)
7. Per-label approval prompts
8. Write plan JSON

This step produces the full script. Due to its size (~400 lines), it should be implemented in one go following the spec exactly, then tested against the real tenant.

- [ ] **Step 2: Dry-run test (no connection)**

Run: `pwsh -File scripts/Convert-DLPToAutoLabeling.ps1 -Scan -WhatIf`
Expected: Config loads, fails at connection assertion (expected without `-Connect`)

- [ ] **Step 3: Commit**

```bash
git add scripts/Convert-DLPToAutoLabeling.ps1
git commit -m "feat: add Convert-DLPToAutoLabeling.ps1 scan phase"
```

---

### Task 9: Main script — Execute phase

**Files:**
- Modify: `scripts/Convert-DLPToAutoLabeling.ps1`

- [ ] **Step 1: Add Execute phase to the script**

Reads approved plan JSON, creates auto-labeling policies and rules, stamps execution results back to the plan. Reuses `Invoke-WithRetry` from DLP-Deploy.psm1. Key logic:

1. Load plan, validate version and approval status
2. For each approved label: create policy with `New-AutoSensitivityLabelPolicy`
3. For each workload under that label: create rule with `New-AutoSensitivityLabelRule`
4. Stamp each source rule's `executed` field
5. Update plan JSON execution summary
6. Print results

- [ ] **Step 2: Commit**

```bash
git add scripts/Convert-DLPToAutoLabeling.ps1
git commit -m "feat: add Convert-DLPToAutoLabeling.ps1 execute phase"
```

---

### Task 10: Main script — Cleanup phase

**Files:**
- Modify: `scripts/Convert-DLPToAutoLabeling.ps1`

- [ ] **Step 1: Add Cleanup phase**

Reads plan JSON, removes only resources with `executed.status = "success"`, clears execution stamps.

- [ ] **Step 2: Commit**

```bash
git add scripts/Convert-DLPToAutoLabeling.ps1
git commit -m "feat: add Convert-DLPToAutoLabeling.ps1 cleanup phase"
```

---

### Task 11: Integration test against testp4ttern.dev

**Files:**
- No new files — manual test against live tenant

- [ ] **Step 1: Run scan against testp4ttern.dev**

```powershell
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Scan -DlpPolicyFilter "P0*"
```

Verify: plan JSON created, toolkit rules auto-detected, summary printed, approval prompts work.

- [ ] **Step 2: Review the plan JSON**

Check: correct label assignments, workload detection, SIT counts, no false unconvertible classifications.

- [ ] **Step 3: Execute the plan (WhatIf first)**

```powershell
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Execute -PlanFile .\plans\<plan-file>.json -WhatIf
```

Verify: dry run shows correct policy/rule names.

- [ ] **Step 4: Execute for real**

```powershell
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Execute -PlanFile .\plans\<plan-file>.json
```

Verify: policies/rules created, plan JSON stamped with execution results.

- [ ] **Step 5: Cleanup**

```powershell
.\scripts\Convert-DLPToAutoLabeling.ps1 -Connect -Cleanup -PlanFile .\plans\<plan-file>.json
```

Verify: resources removed, plan JSON updated.

- [ ] **Step 6: Final commit**

```bash
git add -A
git commit -m "feat: DLP-to-auto-labeling converter — complete implementation"
git push
```
