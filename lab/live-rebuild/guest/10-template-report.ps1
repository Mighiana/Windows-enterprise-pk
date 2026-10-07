#Requires -Version 5.1
<# Run on SERVER. Prints the PKILabServerTLS flags, ACL, enrollment-group members and CA publication. #>
$ErrorActionPreference='Stop'
Import-Module ActiveDirectory
$pks = "CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"
$t = Get-ADObject "CN=PKILabServerTLS,CN=Certificate Templates,$pks" -Properties *
'msPKI-Certificate-Name-Flag : 0x{0:X8} (SUBJECT_REQUIRE_DNS_AS_CN + SUBJECT_ALT_REQUIRE_DNS: built from AD; ENROLLEE_SUPPLIES_SUBJECT not set)' -f $t.'msPKI-Certificate-Name-Flag'
'msPKI-Enrollment-Flag       : 0x{0:X} (CT_FLAG_AUTO_ENROLLMENT)' -f $t.'msPKI-Enrollment-Flag'
'msPKI-Private-Key-Flag      : 0x{0:X} (CT_FLAG_EXPORTABLE_KEY 0x10 not set = private key not exportable; 0x100 = legacy CSP)' -f $t.'msPKI-Private-Key-Flag'
'msPKI-Minimal-Key-Size      : {0}' -f $t.'msPKI-Minimal-Key-Size'
'msPKI-RA-Signature          : {0}' -f $t.'msPKI-RA-Signature'
'pKIExtendedKeyUsage         : {0}' -f ($t.pKIExtendedKeyUsage -join ', ')
'Validity / renewal overlap  : {0} days / {1} days' -f ([timespan]::FromTicks(-[BitConverter]::ToInt64($t.pKIExpirationPeriod,0)).TotalDays), ([timespan]::FromTicks(-[BitConverter]::ToInt64($t.pKIOverlapPeriod,0)).TotalDays)
''
'ACL (inheritance disabled: {0})' -f $t.nTSecurityDescriptor.AreAccessRulesProtected
$map = @{ '0e10c968-78fb-11d2-90d4-00c04f79dc55'='Certificate-Enrollment'; 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'='Certificate-AutoEnrollment'; '00000000-0000-0000-0000-000000000000'='' }
$t.nTSecurityDescriptor.Access | ForEach-Object {
  [pscustomobject]@{ Identity=$_.IdentityReference; Rights=$_.ActiveDirectoryRights; ExtendedRight=$map["$($_.ObjectType)"] }
} | Format-Table -AutoSize | Out-String -Width 160
'PKITLSAutoenroll members: ' + ((Get-ADGroupMember PKITLSAutoenroll | ForEach-Object Name | Sort-Object) -join ', ')
'Published on CA: ' + ((Get-ADObject -SearchBase "CN=Enrollment Services,$pks" -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties certificateTemplates).certificateTemplates -join ', ')
