#Requires -Version 5.1
<#
.SYNOPSIS
    Checks the root CA in LocalMachine\Root, which physical store delivered it, and the trust GPO + domain link.

.DESCRIPTION
    2026 REPRODUCIBILITY EXTENSION - read-only. Subset of verify-pki.ps1.
    Exit code: 0 = no FAIL, 1 = at least one FAIL, 2 = not Windows.
#>
[CmdletBinding()]
param(
    [string] $CaName = 'IRB-ADCS-RootCA',
    [string] $DomainName = 'irb.local',
    [string] $GpoName = 'IRB Root CA Trust'
)

Import-Module (Join-Path $PSScriptRoot 'lib/PkiLab.psm1') -Force
if (-not (Test-LabIsWindows)) { Write-Error 'Run this on the Windows Server lab host.'; exit 2 }

$results = @(Invoke-LabTrustCheck -CaName $CaName -DomainName $DomainName -GpoName $GpoName)
$results | Format-LabCheckResult
Write-LabSummary -Results $results
if (@($results | Where-Object Status -EQ 'FAIL').Count -gt 0) { exit 1 }
exit 0
