#Requires -Version 5.1
<# Run on SERVER (the CA). Revokes one certificate and publishes a new CRL, printing the CA database
   row before/after and the published CRL entry. Lab test only. #>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)] [string] $SerialNumber,
    [ValidateRange(0, 6)] [int] $Reason = 1,
    [string] $Config = 'server.irb.local\IRB-ADCS-RootCA'
)
$ErrorActionPreference = 'Stop'
$columns = 'RequestID,RequesterName,CertificateTemplate,Disposition,RevokedReason,RevokedEffectiveWhen'
'== Before: CA database row'
certutil -config $Config -view -restrict "SerialNumber=$SerialNumber" -out $columns csv
if (-not $PSCmdlet.ShouldProcess($SerialNumber, "Revoke (reason $Reason) and publish CRL")) { return }
"== Revoke (reason $Reason)"
certutil -config $Config -revoke $SerialNumber $Reason | Select-String 'Revok|completed|Serial'
'== Publish CRL'
certutil -crl | Select-String 'completed|CRL'
Start-Sleep -Seconds 3
'== After: CA database row'
certutil -config $Config -view -restrict "SerialNumber=$SerialNumber" -out $columns csv
'== Published CRL (local copy)'
$crl = Get-ChildItem C:\Windows\System32\CertSrv\CertEnroll\*.crl | Where-Object Name -NotMatch '\+' | Sort-Object LastWriteTime | Select-Object -Last 1
certutil -dump $crl.FullName | Select-String 'CRL Number|ThisUpdate|NextUpdate|Serial Number: |CRL Reason|Key Compromise|CRL Entries' | ForEach-Object { $_.Line.Trim() }
'== CDP URLs in the revoked certificate'
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object SerialNumber -EQ $SerialNumber
if ($cert) { ($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.31' }).Format($true) }
