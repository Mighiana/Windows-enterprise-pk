#Requires -Version 5.1
<# Run on SERVER or CLIENT. Prints the PKILabServerTLS certificates in LocalMachine\My as JSON. #>
$ErrorActionPreference = 'Stop'
$certificates = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $template = $_.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' } | Select-Object -First 1
    $null -ne $template -and $template.Format($false) -match 'PKILabServerTLS'
})
[ordered]@{
    Utc = (Get-Date).ToUniversalTime().ToString('o')
    Computer = (Get-CimInstance Win32_ComputerSystem | Select-Object Name,Domain,PartOfDomain)
    AutoenrollmentPolicy = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment').AEPolicy
    Certificates = @($certificates | ForEach-Object {
        $cert = $_
        $eku = $cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] }
        [ordered]@{
            Subject = $cert.Subject
            Issuer = $cert.Issuer
            Thumbprint = $cert.Thumbprint
            SerialNumber = $cert.SerialNumber
            NotBefore = $cert.NotBefore.ToUniversalTime().ToString('o')
            NotAfter = $cert.NotAfter.ToUniversalTime().ToString('o')
            HasPrivateKey = $cert.HasPrivateKey
            PrivateKeyExportable = $cert.PrivateKey.CspKeyContainerInfo.Exportable
            PublicKeyBits = $cert.PublicKey.Key.KeySize
            SAN = @($cert.DnsNameList | ForEach-Object Unicode)
            EKU = @($eku.EnhancedKeyUsages | ForEach-Object Value)
            Template = ($cert.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' }).Format($false)
        }
    })
} | ConvertTo-Json -Depth 6
