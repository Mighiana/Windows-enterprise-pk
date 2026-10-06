#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only end-to-end verification of the Windows Enterprise PKI lab.

.DESCRIPTION
    2026 REPRODUCIBILITY EXTENSION - not part of the original May 2026 lab.

    Re-checks the evidence chain documented in the original lab:
      DNS -> AD DS / roles -> Enterprise Root CA -> GPO root trust -> machine certificate
      -> IIS :443 binding -> TLS handshake trusted by the Windows trust store.

    The script makes NO changes. It reads WMI/CIM, the registry, the LocalMachine
    certificate stores, IIS configuration and Group Policy objects, then opens one
    TLS connection and sends one HTTP GET. Private keys are never read or exported.

    Run it on the lab server (server.irb.local) from an elevated Windows PowerShell 5.1
    or PowerShell 7 session. Exit code: 0 = no FAIL, 1 = at least one FAIL, 2 = not Windows.

.EXAMPLE
    .\verify-pki.ps1

.EXAMPLE
    .\verify-pki.ps1 -OutputFormat Html -OutFile .\pki-report.html

.EXAMPLE
    .\verify-pki.ps1 -ExpectedIPv4 192.168.233.131 -OutputFormat Json > pki-report.json
#>
[CmdletBinding()]
param(
    [string] $DomainName = 'irb.local',
    [string] $ServerFqdn = 'server.irb.local',
    [string] $CaName = 'IRB-ADCS-RootCA',
    [string] $GpoName = 'IRB Root CA Trust',
    [string] $SiteName = 'Default Web Site',
    [ValidateRange(1, 65535)] [int] $Port = 443,
    [string] $ExpectedIPv4,
    [ValidateRange(0, 3650)] [int] $ExpiryWarningDays = 30,
    [switch] $CheckRevocation,
    [ValidateSet('Console', 'Json', 'Html')] [string] $OutputFormat = 'Console',
    [string] $OutFile = 'pki-report.html',
    [switch] $PassThru
)

Import-Module (Join-Path $PSScriptRoot 'lib/PkiLab.psm1') -Force

if (-not (Test-LabIsWindows)) {
    Write-Error 'verify-pki.ps1 must run on the Windows Server lab host.'
    exit 2
}

$bound = Get-LabBoundThumbprint -SiteName $SiteName -Port $Port -ServerFqdn $ServerFqdn

$results = @(
    Invoke-LabDomainCheck -DomainName $DomainName -ServerFqdn $ServerFqdn -ExpectedIPv4 $ExpectedIPv4
    Invoke-LabCaCheck -CaName $CaName
    Invoke-LabTrustCheck -CaName $CaName -DomainName $DomainName -GpoName $GpoName
    Invoke-LabCertificateCheck -ServerFqdn $ServerFqdn -CaName $CaName -Thumbprint $bound -ExpiryWarningDays $ExpiryWarningDays
    Invoke-LabIisTlsCheck -ServerFqdn $ServerFqdn -SiteName $SiteName -Port $Port -CheckRevocation:$CheckRevocation
)

if ($PassThru) {
    $results
} elseif ($OutputFormat -eq 'Html') {
    $html = ConvertTo-LabHtmlReport -Results $results -Title 'Windows Enterprise PKI lab verification' -Subtitle ('{0} - {1:u}' -f $ServerFqdn, (Get-Date).ToUniversalTime())
    Set-Content -LiteralPath $OutFile -Value $html -Encoding UTF8
    Write-Output "Wrote $OutFile"
} elseif ($OutputFormat -eq 'Json') {
    $results | Select-Object Area, Check, Status, Detail | ConvertTo-Json -Depth 3
} else {
    Write-Host ("Windows Enterprise PKI lab verification - {0} ({1:u})" -f $ServerFqdn, (Get-Date).ToUniversalTime())
    Write-Host ''
    $results | Format-LabCheckResult
    Write-LabSummary -Results $results
}

if (@($results | Where-Object Status -EQ 'FAIL').Count -gt 0) { exit 1 }
exit 0
