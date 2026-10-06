#Requires -Version 5.1
<#
.SYNOPSIS
    Checks the server.irb.local machine certificate: issuer, Subject, SAN, validity, private key, EKU, signature.

.DESCRIPTION
    2026 REPRODUCIBILITY EXTENSION - read-only. Subset of verify-pki.ps1.
    Exit code: 0 = no FAIL, 1 = at least one FAIL, 2 = not Windows.
#>
[CmdletBinding()]
param(
    [string] $ServerFqdn = 'server.irb.local',
    [string] $CaName = 'IRB-ADCS-RootCA',
    [string] $Thumbprint,
    [int] $ExpiryWarningDays = 30
)

Import-Module (Join-Path $PSScriptRoot 'lib/PkiLab.psm1') -Force
if (-not (Test-LabIsWindows)) { Write-Error 'Run this on the Windows Server lab host.'; exit 2 }

$results = @(Invoke-LabCertificateCheck -ServerFqdn $ServerFqdn -CaName $CaName -Thumbprint $Thumbprint -ExpiryWarningDays $ExpiryWarningDays)
$results | Format-LabCheckResult
Write-LabSummary -Results $results
if (@($results | Where-Object Status -EQ 'FAIL').Count -gt 0) { exit 1 }
exit 0
