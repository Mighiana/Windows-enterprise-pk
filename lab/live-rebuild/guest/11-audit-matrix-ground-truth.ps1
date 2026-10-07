#Requires -Version 5.1
<# Run on SERVER. Independent ground truth for the audit matrix: raw LabTest-* template flags and
   low-privileged ACEs, the CA EditFlags and whether Web Enrollment is installed. #>
$ErrorActionPreference='Stop'
Import-Module ActiveDirectory
$pks = "CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"
Get-ADObject -SearchBase "CN=Certificate Templates,$pks" -LDAPFilter '(cn=LabTest-*)' -Properties msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,pKIExtendedKeyUsage,nTSecurityDescriptor | ForEach-Object {
  [pscustomobject]@{
    Template=$_.Name
    NameFlag=('0x{0:X8}' -f $_.'msPKI-Certificate-Name-Flag')
    EnrollmentFlag=('0x{0:X}' -f $_.'msPKI-Enrollment-Flag')
    EKU=($_.pKIExtendedKeyUsage -join ',')
    LowPrivAces=(($_.nTSecurityDescriptor.Access | Where-Object { $_.IdentityReference -match 'Domain Users|Authenticated Users' -and $_.ActiveDirectoryRights -ne 'GenericRead' } | ForEach-Object { "$($_.IdentityReference):$($_.ActiveDirectoryRights)" }) -join '; ')
  }
} | Sort-Object Template | Format-Table -AutoSize | Out-String -Width 220
certutil -getreg policy\EditFlags | Select-String 'EDITF_ATTRIBUTESUBJECTALTNAME2|EditFlags REG'
"ADCS-Web-Enrollment installed: $((Get-WindowsFeature ADCS-Web-Enrollment).Installed)"
