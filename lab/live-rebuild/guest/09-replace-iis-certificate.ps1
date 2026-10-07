#Requires -Version 5.1
<# Run on SERVER. Enrolls a replacement from PKILabServerTLS, binds it to the IIS https binding and
   removes the revoked certificate from LocalMachine\My. #>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)] [string] $RevokedThumbprint,
    [string] $TemplateName = 'PKILabServerTLS'
)
$ErrorActionPreference = 'Stop'
if (-not $PSCmdlet.ShouldProcess('Default Web Site :443', "Replace $RevokedThumbprint")) { return }
"== Enroll replacement from $TemplateName"
certreq -enroll -machine -q $TemplateName | Select-String 'Installed|Request|Status|Thumbprint'
$new = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.Thumbprint -ne $RevokedThumbprint -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and
    ($_.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' } | ForEach-Object { $_.Format($false) }) -match [regex]::Escape($TemplateName)
} | Sort-Object NotBefore | Select-Object -Last 1
if (-not $new) { throw 'No replacement certificate' }
"New: $($new.Thumbprint) serial $($new.SerialNumber)"
Import-Module WebAdministration
$binding = Get-WebBinding -Name 'Default Web Site' -Protocol https -Port 443
$binding.AddSslCertificate($new.Thumbprint, 'My')
'== netsh binding'
netsh http show sslcert ipport=0.0.0.0:443 | Select-String 'Certificate Hash'
Remove-Item ('Cert:\LocalMachine\My\' + $RevokedThumbprint)
"Removed revoked certificate $RevokedThumbprint from LocalMachine\My"
