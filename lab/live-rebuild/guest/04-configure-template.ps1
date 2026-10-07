#Requires -Version 5.1
<# Run on SERVER as IRB\Administrator. Creates the dedicated, hardened PKILabServerTLS template
   (DNS subject/SAN built from AD, Server Authentication EKU only, non-exportable 2048-bit key, 90-day
   validity) and restricts Enroll + AutoEnroll to the PKITLSAutoenroll group (SERVER, CLIENT). #>
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$config = (Get-ADRootDSE).configurationNamingContext
$pks = "CN=Public Key Services,CN=Services,$config"
$path = "CN=Certificate Templates,$pks"
$name = 'PKILabServerTLS'
$source = Get-ADObject "CN=Machine,$path" -Properties *
$properties = @{}
foreach ($property in @('pKIDefaultCSPs','pKIDefaultKeySpec','pKIKeyUsage','pKIMaxIssuingDepth','pKICriticalExtensions')) {
    if ($null -ne $source.$property -and $source.$property.Count) {
        if ($source.$property -is [byte[]]) { $properties[$property] = $source.$property }
        elseif ($source.$property.Count -eq 1) { $properties[$property] = $source.$property[0] }
        else { $properties[$property] = [string[]]$source.$property }
    }
}
$oidContainer = Get-ADObject "CN=OID,$pks" -Properties msPKI-Cert-Template-OID
$oid = $oidContainer.'msPKI-Cert-Template-OID' + '.' + (Get-Random -Minimum 100000 -Maximum 2000000000) + '.' + (Get-Random -Minimum 100000 -Maximum 2000000000)
New-ADObject -Name ([guid]::NewGuid().ToString()) -Type msPKI-Enterprise-Oid -Path "CN=OID,$pks" -OtherAttributes @{'msPKI-Cert-Template-OID'=$oid; displayName=$name; flags=1}
$properties['displayName'] = 'PKI Lab - scoped machine TLS'
$properties['flags'] = 0x60
$properties['revision'] = 100
$properties['msPKI-Template-Schema-Version'] = 2
$properties['msPKI-Template-Minor-Revision'] = 1
$properties['msPKI-Cert-Template-OID'] = $oid
$properties['msPKI-Certificate-Name-Flag'] = 0x18000000
$properties['msPKI-Enrollment-Flag'] = 0x20
$properties['msPKI-Private-Key-Flag'] = 0x100
$properties['msPKI-Minimal-Key-Size'] = 2048
$properties['msPKI-RA-Signature'] = 0
$properties['pKIExtendedKeyUsage'] = '1.3.6.1.5.5.7.3.1'
$properties['msPKI-Certificate-Application-Policy'] = '1.3.6.1.5.5.7.3.1'
$properties['pKIExpirationPeriod'] = [BitConverter]::GetBytes(-[timespan]::FromDays(90).Ticks)
$properties['pKIOverlapPeriod'] = [BitConverter]::GetBytes(-[timespan]::FromDays(7).Ticks)
New-ADObject -Name $name -Type pKICertificateTemplate -Path $path -OtherAttributes $properties
New-ADGroup -Name 'PKI TLS Autoenroll' -SamAccountName PKITLSAutoenroll -GroupScope Global -GroupCategory Security
Add-ADGroupMember -Identity PKITLSAutoenroll -Members (Get-ADComputer server),(Get-ADComputer client)
$group = (Get-ADGroup PKITLSAutoenroll).SID
$domainSid = (Get-ADDomain).DomainSID.Value
$security = New-Object System.DirectoryServices.ActiveDirectorySecurity
$security.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18', "$domainSid-512", "$domainSid-519")) {
    $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new($sid), [System.DirectoryServices.ActiveDirectoryRights]::GenericAll, [System.Security.AccessControl.AccessControlType]::Allow)
    $security.AddAccessRule($rule)
}
$security.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-11'), [System.DirectoryServices.ActiveDirectoryRights]::GenericRead, [System.Security.AccessControl.AccessControlType]::Allow))
$security.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new($group, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead, [System.Security.AccessControl.AccessControlType]::Allow))
foreach ($guid in @('0e10c968-78fb-11d2-90d4-00c04f79dc55','a05b8cc2-17bc-4802-a710-e7c15ab866a2')) {
    $security.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new($group, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, [System.Security.AccessControl.AccessControlType]::Allow, [guid]$guid))
}
$entry = [adsi]"LDAP://CN=$name,$path"
$entry.ObjectSecurity = $security
$entry.CommitChanges()
$ca = Get-ADObject -SearchBase "CN=Enrollment Services,$pks" -LDAPFilter '(objectClass=pKIEnrollmentService)'
Set-ADObject $ca -Replace @{certificateTemplates=$name}
Restart-Service CertSvc
Write-Output "Created dedicated template $name ($oid); enrollment scoped to PKITLSAutoenroll, with privileged administrative control retained."
Get-ADObject "CN=$name,$path" -Properties msPKI-Certificate-Name-Flag,msPKI-Private-Key-Flag,msPKI-Minimal-Key-Size,pKIExtendedKeyUsage | Format-List
