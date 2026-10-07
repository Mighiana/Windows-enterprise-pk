#Requires -Version 5.1
<# Run on SERVER (local Administrator). Installs AD DS, IIS and GPMC, then creates the irb.local forest.
   Lab only: the DSRM password is the generated lab password read from the private bootstrap media. #>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Isolated lab: generated password read from private unattend media, never stored in the repo')]
param()
$ErrorActionPreference = 'Stop'
Install-WindowsFeature AD-Domain-Services, Web-Server, GPMC -IncludeManagementTools | Select-Object Success, RestartNeeded, ExitCode
if (-not (Get-WindowsFeature AD-Domain-Services).Installed) { throw 'Role installation failed' }
$media = Get-Volume | Where-Object FileSystemLabel -eq PKIBOOT
$value = (Select-Xml -Path ($media.DriveLetter + ':\Autounattend.xml') -XPath '//*[local-name()="AdministratorPassword"]/*[local-name()="Value"]').Node.InnerText
$secret = $value | ConvertTo-SecureString -AsPlainText -Force
Install-ADDSForest -DomainName irb.local -DomainNetbiosName IRB -InstallDns -SafeModeAdministratorPassword $secret -Force
