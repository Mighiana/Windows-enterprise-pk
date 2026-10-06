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
    [string] $Thumbprint
)

Import-Module (Join-Path $PSScriptRoot '../lib/PkiLab.psm1') -Force
Import-Module WebAdministration -ErrorAction Stop

$certs = @(Get-LabStoreCertificate -StoreName My)
if ($Thumbprint) {
    $cert = $certs | Where-Object { $_.Thumbprint -eq $Thumbprint } | Select-Object -First 1
} else {
    $now = Get-Date
    $cert = $certs |
        Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt $now -and (Get-LabSanDnsName $_) -contains $ServerFqdn } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
}
if ($null -eq $cert) { throw "No usable certificate for $ServerFqdn in LocalMachine\My." }
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
