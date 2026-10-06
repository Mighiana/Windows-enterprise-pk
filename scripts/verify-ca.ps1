#Requires -Version 5.1
<#
.SYNOPSIS
    Checks that the AD CS Enterprise Root CA service is installed, running and named as expected.

.DESCRIPTION
    2026 REPRODUCIBILITY EXTENSION - read-only. Subset of verify-pki.ps1.
    Exit code: 0 = no FAIL, 1 = at least one FAIL, 2 = not Windows.
#>
[CmdletBinding()]
param(
    [string] $CaName = 'IRB-ADCS-RootCA'
)

Import-Module (Join-Path $PSScriptRoot 'lib/PkiLab.psm1') -Force
if (-not (Test-LabIsWindows)) { Write-Error 'Run this on the Windows Server lab host.'; exit 2 }

$results = @(Invoke-LabCaCheck -CaName $CaName)
$results | Format-LabCheckResult
Write-LabSummary -Results $results
if (@($results | Where-Object Status -EQ 'FAIL').Count -gt 0) { exit 1 }
exit 0
