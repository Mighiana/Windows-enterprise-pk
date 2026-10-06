#Requires -Version 5.1
<#
.SYNOPSIS
    Checks the IIS HTTPS :443 binding and performs a TLS handshake validated by the Windows trust store.

.DESCRIPTION
    2026 REPRODUCIBILITY EXTENSION - read-only. Subset of verify-pki.ps1.
    Exit code: 0 = no FAIL, 1 = at least one FAIL, 2 = not Windows.
#>
[CmdletBinding()]
param(
    [string] $ServerFqdn = 'server.irb.local',
    [string] $SiteName = 'Default Web Site',
    [int] $Port = 443,
    [switch] $CheckRevocation
)

Import-Module (Join-Path $PSScriptRoot 'lib/PkiLab.psm1') -Force
if (-not (Test-LabIsWindows)) { Write-Error 'Run this on the Windows Server lab host.'; exit 2 }

$results = @(Invoke-LabIisTlsCheck -ServerFqdn $ServerFqdn -SiteName $SiteName -Port $Port -CheckRevocation:$CheckRevocation)
$results | Format-LabCheckResult
Write-LabSummary -Results $results
if (@($results | Where-Object Status -EQ 'FAIL').Count -gt 0) { exit 1 }
exit 0
