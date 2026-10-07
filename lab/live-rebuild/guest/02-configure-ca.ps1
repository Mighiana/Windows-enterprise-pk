#Requires -Version 5.1
<# Run on SERVER as IRB\Administrator after the forest reboot.
   Enterprise Root CA, HTTP CDP/AIA under /pki, root-trust GPO, auto-enrollment GPO, and no default
   templates published (only PKILabServerTLS is published later by 04-configure-template.ps1).

   The CDP list includes C:\pki\publication (the folder IIS serves). The live run first omitted it,
   so a revocation was not visible over HTTP until it was added - see evidence 09-10. #>
$ErrorActionPreference = 'Stop'
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools | Select-Object Success, RestartNeeded, ExitCode
Import-Module ADCSDeployment
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName IRB-ADCS-RootCA -ValidityPeriod Years -ValidityPeriodUnits 10 -HashAlgorithmName SHA256 -KeyLength 3072 -Force
Import-Module WebAdministration
New-Item -ItemType Directory C:\pki\publication -Force | Out-Null
New-WebVirtualDirectory -Site 'Default Web Site' -Name pki -PhysicalPath C:\pki\publication
$cdp = '1:C:\Windows\System32\CertSrv\CertEnroll\%3%8%9.crl\n1:C:\pki\publication\%3%8%9.crl\n2:http://server.irb.local/pki/%3%8%9.crl'
$aia = '1:C:\Windows\System32\CertSrv\CertEnroll\%1_%3%4.crt\n2:http://server.irb.local/pki/%1_%3%4.crt'
certutil -setreg CA\CRLPublicationURLs $cdp
if ($LASTEXITCODE) { throw 'CDP configuration failed' }
certutil -setreg CA\CACertPublicationURLs $aia
certutil -setreg CA\CRLDeltaPeriodUnits 0
certutil -setreg CA\CRLPeriodUnits 1
certutil -setreg CA\CRLPeriod Days
Restart-Service CertSvc
do { Start-Sleep -Seconds 2; certutil -config 'server.irb.local\IRB-ADCS-RootCA' -ping | Out-Null } until ($LASTEXITCODE -eq 0)
certutil -crl
if ($LASTEXITCODE) { throw 'CRL publication failed' }
Copy-Item C:\Windows\System32\CertSrv\CertEnroll\*.cr* C:\pki\publication -Force
certutil '-ca.cert' C:\pki\root.cer
if ($LASTEXITCODE) { throw 'Root export failed' }
certutil -f -grouppolicy -addstore Root C:\pki\root.cer
$root = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new('C:\pki\root.cer')
$key = 'HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates\' + $root.Thumbprint
$blob = (Get-ItemProperty ('Registry::' + $key) -Name Blob).Blob
Import-Module GroupPolicy
New-GPO -Name 'IRB Root CA Trust' | New-GPLink -Target 'DC=irb,DC=local' -LinkEnabled Yes | Out-Null
Set-GPRegistryValue -Name 'IRB Root CA Trust' -Key $key -ValueName Blob -Type Binary -Value $blob | Out-Null
New-GPO -Name 'IRB Machine Autoenrollment' | New-GPLink -Target 'DC=irb,DC=local' -LinkEnabled Yes | Out-Null
Set-GPRegistryValue -Name 'IRB Machine Autoenrollment' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName AEPolicy -Type DWord -Value 7 | Out-Null
New-NetFirewallRule -DisplayName 'PKI lab HTTP CRL and HTTPS relying parties' -Direction Inbound -Protocol TCP -LocalPort 80, 443 -RemoteAddress 192.168.77.0/24 -Action Allow -Profile Any | Out-Null
$config = (Get-ADRootDSE).configurationNamingContext
$ca = Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$config" -LDAPFilter '(objectClass=pKIEnrollmentService)'
Set-ADObject $ca -Clear certificateTemplates
Write-Output ('Root thumbprint: ' + $root.Thumbprint)
