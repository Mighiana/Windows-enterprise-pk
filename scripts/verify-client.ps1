#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only relying-party checks from a separate domain-joined Windows client.
.DESCRIPTION
    2026 extension. Checks domain membership, physical GPO root trust, GPO application (RSoP),
    an optional auto-enrolled certificate from a named template, and remote TLS.
    It does not install roles, import roots, request certificates, or modify CRL caches.
.EXAMPLE
    .\verify-client.ps1 -TemplateName PKILabServerTLS -CheckRevocation
#>
[CmdletBinding()]
param(
    [string] $DomainName = 'irb.local',
    [string] $ServerFqdn = 'server.irb.local',
    [string] $CaName = 'IRB-ADCS-RootCA',
    [string] $GpoName = 'IRB Root CA Trust',
    [ValidateRange(1, 65535)] [int] $Port = 443,
    [string] $ExpectedThumbprint,
    [string] $TemplateName,
    [switch] $CheckRevocation,
    [ValidateSet('Console', 'Json', 'Html')] [string] $OutputFormat = 'Console',
    [string] $OutFile = 'pki-report-client.html'
)

Import-Module (Join-Path $PSScriptRoot 'lib/PkiLab.psm1') -Force
if (-not (Test-LabIsWindows)) { Write-Error 'Run on a domain-joined Windows client.'; exit 2 }

$results = @(
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($computer.PartOfDomain -and $computer.Domain -eq $DomainName) {
        New-LabCheckResult 'CLIENT' 'Domain membership' 'PASS' ("{0} joined to {1}" -f $computer.Name, $computer.Domain)
    } else {
        New-LabCheckResult 'CLIENT' 'Domain membership' 'FAIL' ("Expected $DomainName; observed $($computer.Domain)")
    }
    Invoke-LabTrustCheck -CaName $CaName -DomainName $DomainName -GpoName $GpoName
    if ($TemplateName) {
        $fqdn = ('{0}.{1}' -f $env:COMPUTERNAME, $DomainName).ToLowerInvariant()
        Test-LabEnrolledCertificate -Certificates @(Get-LabStoreCertificate -StoreName My) -TemplateName $TemplateName -Fqdn $fqdn -CaName $CaName
    }
    $hs = Invoke-LabTlsHandshake -HostName $ServerFqdn -Port $Port -CheckRevocation:$CheckRevocation
    Test-LabTlsResult -Handshake $hs -Url "https://${ServerFqdn}:$Port" -ExpectedThumbprint $ExpectedThumbprint
)
if ($OutputFormat -eq 'Html') {
    $html = ConvertTo-LabHtmlReport -Results $results -Title 'Separate Windows client verification' -Subtitle ('{0} -> {1} ({2:u})' -f $env:COMPUTERNAME, $ServerFqdn, (Get-Date).ToUniversalTime())
    Set-Content -LiteralPath $OutFile -Value $html -Encoding UTF8
    Write-Output "Wrote $OutFile"
} elseif ($OutputFormat -eq 'Json') {
    $results | ConvertTo-Json -Depth 4
} else {
    $results | Format-LabCheckResult
    Write-LabSummary -Results $results
}
if (@($results | Where-Object Status -eq 'FAIL').Count) { exit 1 }
exit 0
