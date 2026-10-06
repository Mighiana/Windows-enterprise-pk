#Requires -Version 5.1
<#
.SYNOPSIS
    Checks OS, AD DS / AD CS / DNS / IIS roles, domain membership and DNS resolution.

.DESCRIPTION
    2026 REPRODUCIBILITY EXTENSION - read-only. Subset of verify-pki.ps1.
    Exit code: 0 = no FAIL, 1 = at least one FAIL, 2 = not Windows.
#>
[CmdletBinding()]
param(
    [string] $DomainName = 'irb.local',
    [string] $ServerFqdn = 'server.irb.local',
    [string] $ExpectedIPv4
)

Import-Module (Join-Path $PSScriptRoot 'lib/PkiLab.psm1') -Force
if (-not (Test-LabIsWindows)) { Write-Error 'Run this on the Windows Server lab host.'; exit 2 }

$results = @(Invoke-LabDomainCheck -DomainName $DomainName -ServerFqdn $ServerFqdn -ExpectedIPv4 $ExpectedIPv4)
$results | Format-LabCheckResult
Write-LabSummary -Results $results
if (@($results | Where-Object Status -EQ 'FAIL').Count -gt 0) { exit 1 }
exit 0
