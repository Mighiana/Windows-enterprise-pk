#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Binds the server certificate to an IIS HTTPS binding (default: Default Web Site, :443).

.DESCRIPTION
    2026 REPRODUCIBILITY EXTENSION - the original lab configured the binding in IIS Manager.

    Selects the newest valid certificate in LocalMachine\My whose SAN contains -ServerFqdn
    and which has a private key, unless -Thumbprint is given. Creates the https binding if it
    does not exist and attaches the certificate. Supports -WhatIf; asks for confirmation.
    Does not remove the existing HTTP :80 binding.

.EXAMPLE
    .\Set-IisHttpsBinding.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $ServerFqdn = 'server.irb.local',
    [string] $SiteName = 'Default Web Site',
    [int] $Port = 443,
    [string] $Thumbprint,
    [string] $CaName = 'IRB-ADCS-RootCA'
)

Import-Module (Join-Path $PSScriptRoot '../lib/PkiLab.psm1') -Force
Import-Module WebAdministration -ErrorAction Stop

$now = Get-Date
$isUsable = {
    param($c)
    $c.HasPrivateKey -and $c.NotBefore -le $now -and $c.NotAfter -gt $now -and
    (Get-LabCommonName $c.Issuer) -eq $CaName -and
    @(Get-LabSanDnsName $c) -contains $ServerFqdn -and (Test-LabHasServerAuthEku $c)
}
$certs = @(Get-LabStoreCertificate -StoreName My)
if ($Thumbprint) {
    $cert = $certs | Where-Object { $_.Thumbprint -eq $Thumbprint } | Select-Object -First 1
    if ($cert -and -not (& $isUsable $cert)) {
        throw "Certificate $Thumbprint is not usable for https://${ServerFqdn}: needs a private key, current validity, issuer $CaName, SAN $ServerFqdn and Server Authentication EKU."
    }
} else {
    $cert = $certs | Where-Object { & $isUsable $_ } | Sort-Object NotAfter -Descending | Select-Object -First 1
}
if ($null -eq $cert) { throw "No usable certificate for $ServerFqdn issued by $CaName in LocalMachine\My." }
Write-Verbose ('Using certificate {0} ({1})' -f $cert.Thumbprint, $cert.Subject)

$binding = Get-WebBinding -Name $SiteName -Protocol https -Port $Port -HostHeader $ServerFqdn -ErrorAction SilentlyContinue
if ($null -eq $binding -and $PSCmdlet.ShouldProcess("$SiteName", "New-WebBinding https *:${Port}:$ServerFqdn")) {
    New-WebBinding -Name $SiteName -Protocol https -Port $Port -HostHeader $ServerFqdn -SslFlags 1
    $binding = Get-WebBinding -Name $SiteName -Protocol https -Port $Port -HostHeader $ServerFqdn
}
if ($binding -and $PSCmdlet.ShouldProcess("$SiteName https :$Port", "Bind certificate $($cert.Thumbprint)")) {
    $binding.AddSslCertificate($cert.Thumbprint, 'My')
    Write-Output ('Bound {0} to https://{1}:{2}' -f $cert.Thumbprint, $ServerFqdn, $Port)
}
