#Requires -Version 5.1
<# Run on SERVER. Enrolls a replacement from PKILabServerTLS, binds it to the IIS https binding and
   removes the revoked certificate from LocalMachine\My. Changes nothing unless exactly one new,
   valid certificate from the template was issued by this enrollment. #>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)] [string] $RevokedThumbprint,
    [string] $TemplateName = 'PKILabServerTLS',
    [string] $Fqdn = 'server.irb.local',
    [string] $CaName = 'IRB-ADCS-RootCA',
    # Where install-tooling.ps1 unpacks scripts/ on the VM.
    [string] $ModulePath = 'C:\pki\tooling\scripts\lib\PkiLab.psm1'
)
$ErrorActionPreference = 'Stop'
if (-not $PSCmdlet.ShouldProcess('Default Web Site :443', "Replace $RevokedThumbprint")) { return }
Import-Module $ModulePath -Force

$before = @(Get-ChildItem Cert:\LocalMachine\My | ForEach-Object Thumbprint)
"== Enroll replacement from $TemplateName"
$output = certreq -enroll -machine -q $TemplateName
$exit = $LASTEXITCODE
$output | Select-String 'Installed|Request|Status|Thumbprint'
if ($exit -ne 0) { throw "certreq -enroll failed with exit code $exit; binding left unchanged." }

$pattern = '(^|[=\s])' + [regex]::Escape($TemplateName) + '(\(|$|,|\s)'
$now = Get-Date
$new = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $before -notcontains $_.Thumbprint -and $_.HasPrivateKey -and
    $_.NotBefore -le $now -and $_.NotAfter -gt $now -and
    (Get-LabCertificateTemplateInfo -Certificate $_) -match $pattern -and
    (Get-LabCommonName $_.Issuer) -eq $CaName -and
    @(Get-LabSanDnsName $_) -contains $Fqdn -and
    (Test-LabHasServerAuthEku $_)
})
if ($new.Count -ne 1) { throw "Expected exactly one newly issued $TemplateName certificate for $Fqdn, found $($new.Count); binding left unchanged." }
$new = $new[0]
"New: $($new.Thumbprint) serial $($new.SerialNumber)"
Import-Module WebAdministration
$binding = Get-WebBinding -Name 'Default Web Site' -Protocol https -Port 443
$binding.AddSslCertificate($new.Thumbprint, 'My')
'== netsh binding'
netsh http show sslcert ipport=0.0.0.0:443 | Select-String 'Certificate Hash'
Remove-Item ('Cert:\LocalMachine\My\' + $RevokedThumbprint)
"Removed revoked certificate $RevokedThumbprint from LocalMachine\My"
