function Test-DlpRulePackageRemovalReferenceGuard {
    param(
        [Parameter(Mandatory)][object[]]$Packages,
        [object[]]$DlpRules,
        [string]$OperationName = "classifier package removal"
    )

    $packageEntityIndex = @(Get-DlpRulePackageEntityIds -Packages $Packages)
    $candidateIds = @($packageEntityIndex | ForEach-Object { $_.EntityIds } | Sort-Object -Unique)
    $referenceIndex = [pscustomobject]@{
        CandidateIdCount = $candidateIds.Count
        RulesScanned     = 0
        MatchingRuleCount = 0
        References       = @()
    }

    # When no entity IDs could be extracted (e.g. every package failed to parse), there is
    # nothing to scan for. The unparsed-package check below still fails the guard closed.
    if ($candidateIds.Count -gt 0) {
        $rules = @()
        if ($PSBoundParameters.ContainsKey("DlpRules")) {
            $rules = @($DlpRules)
        } else {
            try {
                $rules = @(Get-DlpComplianceRule -ErrorAction Stop)
            } catch {
                Write-Warning "Could not retrieve DLP rules for classifier reference check: $($_.Exception.Message)"
            }
        }

        $referenceIndex.RulesScanned = @($rules).Count
        if ($referenceIndex.RulesScanned -gt 0) {
            $candidateLookup = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($id in @($candidateIds)) {
                if (-not [string]::IsNullOrWhiteSpace($id)) {
                    $candidateLookup.Add($id.ToString()) | Out-Null
                }
            }

            $graph = Get-DeploymentReferenceGraph -SitPackages $Packages -DlpRules $rules
            $nodesById = @{}
            foreach ($node in @($graph.Nodes)) {
                $nodesById[$node.Id] = $node
            }

            $referencesByRule = @{}
            foreach ($edge in @($graph.Edges | Where-Object { $_.Type -eq "sitReferencedByRule" })) {
                if (-not $edge.From.StartsWith("sit:", [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                $matchedId = $edge.From.Substring(4)
                if (-not $candidateLookup.Contains($matchedId)) { continue }

                if (-not $referencesByRule.ContainsKey($edge.To)) {
                    $ruleNode = $nodesById[$edge.To]
                    $ruleName = if ($ruleNode -and $ruleNode.Name) { $ruleNode.Name } elseif ($edge.To -like "dlpRule:*") { $edge.To.Substring(8) } else { "(unknown)" }
                    $policyNames = @($graph.Edges |
                        Where-Object { $_.Type -eq "ruleBelongsToPolicy" -and $_.From -eq $edge.To } |
                        ForEach-Object {
                            if ($nodesById.ContainsKey($_.To) -and $nodesById[$_.To].Name) {
                                $nodesById[$_.To].Name
                            } elseif ($_.To -like "dlpPolicy:*") {
                                $_.To.Substring(10)
                            }
                        } |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                        Sort-Object -Unique)
                    $referencesByRule[$edge.To] = [pscustomobject]@{
                        RuleName = $ruleName
                        PolicyNames = @($policyNames)
                        MatchedClassifierIds = New-Object System.Collections.Generic.List[string]
                    }
                }
                $referencesByRule[$edge.To].MatchedClassifierIds.Add($matchedId.ToLowerInvariant()) | Out-Null
            }

            $references = @()
            foreach ($entry in @($referencesByRule.GetEnumerator() | Sort-Object { $_.Value.RuleName })) {
                $ids = @($entry.Value.MatchedClassifierIds | Sort-Object -Unique)
                $references += [pscustomobject]@{
                    RuleName = $entry.Value.RuleName
                    PolicyNames = @($entry.Value.PolicyNames)
                    MatchedClassifierIds = $ids
                }
            }
            $referenceIndex.MatchingRuleCount = @($references).Count
            $referenceIndex.References = @($references)
        }
    }
    $referencedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ref in @($referenceIndex.References)) {
        foreach ($id in @($ref.MatchedClassifierIds)) {
            $referencedIds.Add($id) | Out-Null
        }
    }

    $referencedPackages = @($packageEntityIndex | Where-Object {
        $hit = $false
        foreach ($id in @($_.EntityIds)) {
            if ($referencedIds.Contains($id)) {
                $hit = $true
                break
            }
        }
        $hit
    })
    $unparsedPackages = @($packageEntityIndex | Where-Object { -not $_.Parsed })

    $safe = ($referenceIndex.MatchingRuleCount -eq 0 -and $unparsedPackages.Count -eq 0)
    Write-Host "`n=== Classifier Reference Guard ===" -ForegroundColor Cyan
    Write-Host "  Operation:          $OperationName" -ForegroundColor Gray
    Write-Host "  Packages checked:   $(@($Packages).Count)" -ForegroundColor Gray
    Write-Host "  Entity IDs checked: $($referenceIndex.CandidateIdCount)" -ForegroundColor Gray
    Write-Host "  DLP rules scanned:  $($referenceIndex.RulesScanned)" -ForegroundColor Gray
    if ($unparsedPackages.Count -gt 0) {
        Write-Host "  Unparsed packages:  $($unparsedPackages.Count)" -ForegroundColor Red
        foreach ($pkg in @($unparsedPackages | Select-Object -First 8)) {
            Write-Host "    - $($pkg.Identity): $($pkg.ParseError)" -ForegroundColor Red
        }
    }
    $color = if ($safe) { "Green" } else { "Red" }
    Write-Host "  Referencing rules:  $($referenceIndex.MatchingRuleCount)" -ForegroundColor $color

    if (-not $safe) {
        foreach ($ref in @($referenceIndex.References | Select-Object -First 12)) {
            Write-Host "    - $($ref.RuleName) [$(@($ref.PolicyNames) -join ', ')]" -ForegroundColor Red
        }
        if ($referenceIndex.MatchingRuleCount -gt 12) {
            Write-Host "    ... $($referenceIndex.MatchingRuleCount - 12) more referencing rule(s)" -ForegroundColor Red
        }
    }

    return [pscustomobject]@{
        Safe = [bool]$safe
        PackagesChecked = @($Packages).Count
        EntityIdsChecked = $referenceIndex.CandidateIdCount
        RulesScanned = $referenceIndex.RulesScanned
        ReferencingRuleCount = $referenceIndex.MatchingRuleCount
        References = @($referenceIndex.References)
        ReferencedPackages = @($referencedPackages)
        UnparsedPackages = @($unparsedPackages)
    }
}
