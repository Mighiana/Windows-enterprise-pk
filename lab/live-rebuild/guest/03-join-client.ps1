#Requires -Version 5.1
<# Run on CLIENT (local Administrator). Joins irb.local and restarts. Lab only: uses the generated
   lab password from the private bootstrap media. #>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Isolated lab: generated password read from private unattend media, never stored in the repo')]
param()
$ErrorActionPreference = 'Stop'
$media = Get-Volume | Where-Object FileSystemLabel -eq PKIBOOT
$value = (Select-Xml -Path ($media.DriveLetter + ':\Autounattend.xml') -XPath '//*[local-name()="AdministratorPassword"]/*[local-name()="Value"]').Node.InnerText
$credential = [pscredential]::new('IRB\Administrator', ($value | ConvertTo-SecureString -AsPlainText -Force))
Add-Computer -DomainName irb.local -Credential $credential -Force -Restart
