#Requires -Version 5.1
<#
.SYNOPSIS
    Renders docs/sample-report.html from fixture data using the real evaluators.

.DESCRIPTION
    2026 REPRODUCIBILITY EXTENSION. Produces an illustrative report for the README without a lab VM:
    an in-memory root/leaf pair, a fixture TLS handshake and fixture certificate templates
    (including one deliberately vulnerable template, 'ESC1-Demo') are passed through the same
    Test-Lab* functions that verify-pki.ps1 and audit-adcs.ps1 use. It is NOT a recorded run
    against the original lab.
#>
[CmdletBinding()]
param([string] $OutFile = (Join-Path $PSScriptRoot '../docs/sample-report.html'))

Import-Module (Join-Path $PSScriptRoot '../scripts/lib/PkiLab.psm1') -Force
$X = 'System.Security.Cryptography.X509Certificates'
$sha = [System.Security.Cryptography.HashAlgorithmName]::SHA256
$pad = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1

$rootKey = [System.Security.Cryptography.RSA]::Create(2048)
$rootReq = New-Object "$X.CertificateRequest" ('CN=IRB-ADCS-RootCA', $rootKey, $sha, $pad)
$rootReq.CertificateExtensions.Add((New-Object "$X.X509BasicConstraintsExtension" ($true, $false, 0, $true)))
$root = $rootReq.CreateSelfSigned([datetimeoffset]::Now.AddDays(-30), [datetimeoffset]::Now.AddYears(10))

$leafKey = [System.Security.Cryptography.RSA]::Create(2048)
$leafReq = New-Object "$X.CertificateRequest" ('CN=server.irb.local', $leafKey, $sha, $pad)
$san = New-Object "$X.SubjectAlternativeNameBuilder"; $san.AddDnsName('server.irb.local')
$leafReq.CertificateExtensions.Add($san.Build())
$oids = New-Object System.Security.Cryptography.OidCollection
[void]$oids.Add((New-Object System.Security.Cryptography.Oid '1.3.6.1.5.5.7.3.1'))
$leafReq.CertificateExtensions.Add((New-Object "$X.X509EnhancedKeyUsageExtension" ($oids, $false)))
$leaf = $leafReq.Create($root, [datetimeoffset]::Now.AddDays(-1), [datetimeoffset]::Now.AddDays(729), [byte[]](1..8))
$leaf = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($leaf, $leafKey)

$handshake = [pscustomobject]@{ Connected = $true; PolicyErrors = 'None'; ChainStatus = @(); Thumbprint = $leaf.Thumbprint
                                Protocol = 'Tls12'; HttpStatus = 200; Error = $null; RevocationChecked = $false }

$domainAdmins = 'S-1-5-21-1111111111-2222222222-3333333333-512'
$domainComputers = 'S-1-5-21-1111111111-2222222222-3333333333-515'
$enroll = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
function New-FixtureAce([string] $Sid, [string] $Principal) {
    [pscustomobject]@{ Sid = $Sid; Principal = $Principal; Rights = 'ReadProperty, ExtendedRight'; ObjectType = $enroll; Type = 'Allow' }
}
$templates = @(
    [pscustomobject]@{ Name = 'WebServer'; Published = $true; EnrolleeSuppliesSubject = $true; ManagerApproval = $false; AuthorizedSignatures = 0
                       Ekus = @('1.3.6.1.5.5.7.3.1'); Acl = @(New-FixtureAce $domainAdmins 'IRB\Domain Admins') }
    [pscustomobject]@{ Name = 'Machine'; Published = $true; EnrolleeSuppliesSubject = $false; ManagerApproval = $false; AuthorizedSignatures = 0
                       Ekus = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.1'); Acl = @(New-FixtureAce $domainComputers 'IRB\Domain Computers') }
    [pscustomobject]@{ Name = 'ESC1-Demo'; Published = $true; EnrolleeSuppliesSubject = $true; ManagerApproval = $false; AuthorizedSignatures = 0
                       Ekus = @('1.3.6.1.5.5.7.3.2'); Acl = @(New-FixtureAce 'S-1-5-11' 'NT AUTHORITY\Authenticated Users') }
)

$results = @(
    Test-LabServerCertificate -Certificate $leaf -Fqdn 'server.irb.local' -CaName 'IRB-ADCS-RootCA' -RootCertificate $root -ExpiryWarningDays 30
    Test-LabTlsResult -Handshake $handshake -Url 'https://server.irb.local:443' -ExpectedThumbprint $leaf.Thumbprint
    Test-LabTemplateRisk -Templates $templates
    Test-LabCaConfigRisk -EditFlags 0x0011014E -WebEnrollment ([pscustomobject]@{ Installed = $false; Http = $false })
)

$html = ConvertTo-LabHtmlReport -Results $results -Title 'Windows Enterprise PKI lab - sample report' `
    -Subtitle 'server.irb.local / IRB-ADCS-RootCA - fixture data' `
    -Banner "SAMPLE OUTPUT: fixture data run through the real evaluators (tools/New-SampleReport.ps1). Not a recorded run against the original lab. 'ESC1-Demo' is a deliberately vulnerable fixture template."
Set-Content -LiteralPath $OutFile -Value $html -Encoding UTF8
Write-Output "Wrote $OutFile"
