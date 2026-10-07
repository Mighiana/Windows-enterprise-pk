#Requires -Version 5.1
<#
.SYNOPSIS
    Puts an ISOLATED lab CA into a known-insecure, remediated or clean state so that
    audit-adcs.ps1 can be validated against real AD CS configuration.

.DESCRIPTION
    2026 LIVE-LAB EXTENSION - not part of the original May 2026 lab.

    This is a detection test fixture, not an attack tool: it never requests, issues or uses a
    certificate. It only changes configuration on the CA it runs on, and refuses to run unless
    the domain matches -LabDomain and -IsolatedLab is passed.

      -State Insecure    create LabTest-ESC1..ESC4 templates (one weakness each), publish them,
                         set EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6) and install AD CS Web
                         Enrollment on the existing HTTP site (ESC8)
      -State Remediated  fix each weakness in place (the templates stay, so the audit shows
                         that the specific setting, not the template's existence, was the issue)
      -State Removed     unpublish and delete the LabTest-* templates and their OIDs

    Run on the Enterprise CA as a member of Enterprise Admins.

.EXAMPLE
    .\Set-AdcsAuditTestMatrix.ps1 -State Insecure -IsolatedLab -Confirm:$false
    ..\audit-adcs.ps1 -OutputFormat Json
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)] [ValidateSet('Insecure', 'Remediated', 'Removed')] [string] $State,
    [Parameter(Mandatory)] [switch] $IsolatedLab,
    [string] $LabDomain = 'irb.local',
    [string] $CaName = 'IRB-ADCS-RootCA'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$domain = Get-ADDomain
if (-not $IsolatedLab -or $domain.DNSRoot -ne $LabDomain) {
    throw "Refusing to change AD CS configuration outside the isolated lab domain '$LabDomain'."
}

$domainSid = $domain.DomainSID.Value
$pks = "CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"
$templatePath = "CN=Certificate Templates,$pks"
$caObject = Get-ADObject -SearchBase "CN=Enrollment Services,$pks" -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties certificateTemplates
$policyKey = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"

$enrollGuid = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$clientAuth = '1.3.6.1.5.5.7.3.2'
$serverAuth = '1.3.6.1.5.5.7.3.1'
$anyPurpose = '2.5.29.37.0'
$requestAgent = '1.3.6.1.4.1.311.20.2.1'
$domainUsers = [Security.Principal.SecurityIdentifier]"$domainSid-513"
$authenticatedUsers = [Security.Principal.SecurityIdentifier]'S-1-5-11'

# Each template carries exactly one weakness so every audit finding maps to one setting.
$matrix = [ordered]@{
    'LabTest-ESC1' = @{ Eku = $clientAuth;   NameFlag = 0x1; EnrollmentFlag = 0; DomainUsersEnroll = $true;  AuthUsersWrite = $false }
    'LabTest-ESC2' = @{ Eku = $anyPurpose;   NameFlag = 0x82000000; EnrollmentFlag = 0; DomainUsersEnroll = $true;  AuthUsersWrite = $false }
    'LabTest-ESC3' = @{ Eku = $requestAgent; NameFlag = 0x82000000; EnrollmentFlag = 0; DomainUsersEnroll = $true;  AuthUsersWrite = $false }
    'LabTest-ESC4' = @{ Eku = $serverAuth;   NameFlag = 0x18000000; EnrollmentFlag = 0; DomainUsersEnroll = $false; AuthUsersWrite = $true }
}

function New-Rule([Security.Principal.SecurityIdentifier] $Sid, [DirectoryServices.ActiveDirectoryRights] $Rights, [guid] $ObjectType = [guid]::Empty) {
    [DirectoryServices.ActiveDirectoryAccessRule]::new($Sid, $Rights, [Security.AccessControl.AccessControlType]::Allow, $ObjectType)
}

function Set-TemplateAcl([string] $Name, [hashtable] $Spec) {
    $security = [DirectoryServices.ActiveDirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', "$domainSid-512", "$domainSid-519")) {
        $security.AddAccessRule((New-Rule ([Security.Principal.SecurityIdentifier]$sid) GenericAll))
    }
    $security.AddAccessRule((New-Rule $authenticatedUsers GenericRead))
    $security.AddAccessRule((New-Rule ([Security.Principal.SecurityIdentifier]"$domainSid-512") ExtendedRight $enrollGuid))
    if ($Spec.DomainUsersEnroll) { $security.AddAccessRule((New-Rule $domainUsers ExtendedRight $enrollGuid)) }
    if ($Spec.AuthUsersWrite) { $security.AddAccessRule((New-Rule $authenticatedUsers WriteDacl)) }
    $entry = [adsi]"LDAP://CN=$Name,$templatePath"
    $entry.ObjectSecurity = $security
    $entry.CommitChanges()
}

function Restart-Ca {
    Restart-Service CertSvc
    $deadline = (Get-Date).AddMinutes(2)
    do {
        Start-Sleep -Seconds 2
        & certutil.exe -config "$env:COMPUTERNAME.$LabDomain\$CaName" -ping | Out-Null
    } until ($LASTEXITCODE -eq 0 -or (Get-Date) -gt $deadline)
}

function Set-Publication([string[]] $Add, [string[]] $Remove) {
    $current = @((Get-ADObject $caObject -Properties certificateTemplates).certificateTemplates)
    $wanted = @($current | Where-Object { $Remove -notcontains $_ }) + @($Add | Where-Object { $current -notcontains $_ })
    Set-ADObject $caObject -Replace @{ certificateTemplates = [string[]]$wanted }
}

switch ($State) {
    'Insecure' {
        if (-not $PSCmdlet.ShouldProcess($CaName, 'Introduce controlled ESC1/2/3/4/6/8 lab misconfigurations')) { return }
        $base = Get-ADObject "CN=User,$templatePath" -Properties pKIDefaultKeySpec, pKIKeyUsage, pKIMaxIssuingDepth, pKICriticalExtensions, pKIExpirationPeriod, pKIOverlapPeriod
        $oidRoot = (Get-ADObject "CN=OID,$pks" -Properties msPKI-Cert-Template-OID).'msPKI-Cert-Template-OID'
        foreach ($name in $matrix.Keys) {
            $spec = $matrix[$name]
            if (-not (Get-ADObject -LDAPFilter "(cn=$name)" -SearchBase $templatePath)) {
                $oid = '{0}.{1}.{2}' -f $oidRoot, (Get-Random -Minimum 100000 -Maximum 2000000000), (Get-Random -Minimum 100000 -Maximum 2000000000)
                New-ADObject -Name ([guid]::NewGuid().ToString()) -Type msPKI-Enterprise-Oid -Path "CN=OID,$pks" -OtherAttributes @{ 'msPKI-Cert-Template-OID' = $oid; displayName = $name; flags = 1 }
                $attributes = @{
                    displayName                         = "$name (controlled audit test - lab only)"
                    flags                               = 0x20
                    revision                            = 100
                    pKIDefaultKeySpec                   = $base.pKIDefaultKeySpec
                    pKIKeyUsage                         = $base.pKIKeyUsage
                    pKIMaxIssuingDepth                  = $base.pKIMaxIssuingDepth
                    pKICriticalExtensions               = [string[]]$base.pKICriticalExtensions
                    pKIExpirationPeriod                 = $base.pKIExpirationPeriod
                    pKIOverlapPeriod                    = $base.pKIOverlapPeriod
                    pKIExtendedKeyUsage                 = $spec.Eku
                    'msPKI-Certificate-Application-Policy' = $spec.Eku
                    'msPKI-Template-Schema-Version'     = 2
                    'msPKI-Template-Minor-Revision'     = 1
                    'msPKI-Cert-Template-OID'           = $oid
                    'msPKI-Certificate-Name-Flag'       = [int]$spec.NameFlag
                    'msPKI-Enrollment-Flag'             = [int]$spec.EnrollmentFlag
                    'msPKI-Private-Key-Flag'            = 0
                    'msPKI-Minimal-Key-Size'            = 2048
                    'msPKI-RA-Signature'                = 0
                }
                New-ADObject -Name $name -Type pKICertificateTemplate -Path $templatePath -OtherAttributes $attributes
            }
            Set-TemplateAcl -Name $name -Spec $spec
        }
        Set-Publication -Add @($matrix.Keys) -Remove @()
        & certutil.exe -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2 | Out-Null
        Install-WindowsFeature ADCS-Web-Enrollment | Out-Null
        Install-AdcsWebEnrollment -Force | Out-Null
        Restart-Ca
    }
    'Remediated' {
        if (-not $PSCmdlet.ShouldProcess($CaName, 'Remediate controlled lab misconfigurations in place')) { return }
        # ESC1: build the subject from AD instead of the request.
        Set-ADObject "CN=LabTest-ESC1,$templatePath" -Replace @{ 'msPKI-Certificate-Name-Flag' = [int]0x82000000 }
        # ESC2: require CA certificate manager approval before issuance.
        Set-ADObject "CN=LabTest-ESC2,$templatePath" -Replace @{ 'msPKI-Enrollment-Flag' = 0x2 }
        # ESC3: enrollment agent rights for Domain Admins only.
        Set-TemplateAcl -Name 'LabTest-ESC3' -Spec @{ DomainUsersEnroll = $false; AuthUsersWrite = $false }
        # ESC4: remove the low-privileged WriteDacl ACE.
        Set-TemplateAcl -Name 'LabTest-ESC4' -Spec @{ DomainUsersEnroll = $false; AuthUsersWrite = $false }
        & certutil.exe -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 | Out-Null
        Uninstall-AdcsWebEnrollment -Force | Out-Null
        Uninstall-WindowsFeature ADCS-Web-Enrollment | Out-Null
        Restart-Ca
    }
    'Removed' {
        if (-not $PSCmdlet.ShouldProcess($CaName, 'Delete LabTest-* templates')) { return }
        Set-Publication -Add @() -Remove @($matrix.Keys)
        foreach ($name in $matrix.Keys) {
            $template = Get-ADObject -LDAPFilter "(cn=$name)" -SearchBase $templatePath -Properties msPKI-Cert-Template-OID
            if ($template) {
                Get-ADObject -SearchBase "CN=OID,$pks" -LDAPFilter "(msPKI-Cert-Template-OID=$($template.'msPKI-Cert-Template-OID'))" | Remove-ADObject -Confirm:$false
                Remove-ADObject $template -Confirm:$false
            }
        }
        Restart-Ca
    }
}

$editFlags = (Get-ItemProperty $policyKey).EditFlags
[pscustomobject]@{
    State          = $State
    Published      = @((Get-ADObject $caObject -Properties certificateTemplates).certificateTemplates)
    EditFlags      = '0x{0:X}' -f $editFlags
    Esc6FlagSet    = ($editFlags -band 0x40000) -ne 0
    WebEnrollment  = (Get-WindowsFeature ADCS-Web-Enrollment).Installed
}
