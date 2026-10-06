#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Unit tests for scripts/lib/PkiLab.psm1 (2026 reproducibility extension).
    Runs on Windows PowerShell 5.1 and PowerShell 7 (Windows/Linux). No lab VM required:
    certificates are generated in memory and Windows-only cmdlets are mocked.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../scripts/lib/PkiLab.psm1') -Force

    # Stubs so Pester can mock commands that do not exist on every platform.
    foreach ($name in 'Get-GPO', 'Get-GPInheritance', 'Get-WindowsFeature', 'Get-WebBinding', 'Resolve-DnsName', 'Get-NetIPAddress', 'Get-Service') {
        if (-not (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
            New-Item -Path "function:global:$name" -Value { param() } | Out-Null
        }
    }

    $X = 'System.Security.Cryptography.X509Certificates'
    function New-TestRoot([string] $Cn = 'IRB-ADCS-RootCA') {
        $key = [System.Security.Cryptography.RSA]::Create(2048)
        $req = New-Object "$X.CertificateRequest" ("CN=$Cn", $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $req.CertificateExtensions.Add((New-Object "$X.X509BasicConstraintsExtension" ($true, $false, 0, $true)))
        $req.CertificateExtensions.Add((New-Object "$X.X509KeyUsageExtension" ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'KeyCertSign, CrlSign', $true)))
        $req.CreateSelfSigned([datetimeoffset]::Now.AddDays(-365), [datetimeoffset]::Now.AddYears(10))
    }
    function New-TestLeaf {
        param($Root, [string] $Cn = 'server.irb.local', [string[]] $San = @('server.irb.local'),
              [int] $DaysBefore = -1, [int] $DaysAfter = 730, [switch] $NoKey, [string] $EkuOid = '1.3.6.1.5.5.7.3.1')
        $key = [System.Security.Cryptography.RSA]::Create(2048)
        $req = New-Object "$X.CertificateRequest" ("CN=$Cn", $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        if ($San.Count) {
            $b = New-Object "$X.SubjectAlternativeNameBuilder"
            foreach ($n in $San) { $b.AddDnsName($n) }
            $req.CertificateExtensions.Add($b.Build())
        }
        $oids = New-Object System.Security.Cryptography.OidCollection
        [void]$oids.Add((New-Object System.Security.Cryptography.Oid $EkuOid))
        $req.CertificateExtensions.Add((New-Object "$X.X509EnhancedKeyUsageExtension" ($oids, $false)))
        $serial = [byte[]](1..8 | ForEach-Object { Get-Random -Minimum 1 -Maximum 255 })
        $cert = $req.Create($Root, [datetimeoffset]::Now.AddDays($DaysBefore), [datetimeoffset]::Now.AddDays($DaysAfter), $serial)
        if ($NoKey) { return $cert }
        [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($cert, $key)
    }
    function Get-Status($Results, [string] $Check) { ($Results | Where-Object Check -EQ $Check | Select-Object -First 1).Status }

    $script:Root = New-TestRoot
    $script:Leaf = New-TestLeaf -Root $script:Root
}

Describe 'Get-LabCommonName' {
    It 'extracts the CN from a distinguished name' {
        Get-LabCommonName 'CN=server.irb.local, OU=Lab, DC=irb, DC=local' | Should -Be 'server.irb.local'
        Get-LabCommonName 'DC=irb, CN=IRB-ADCS-RootCA' | Should -Be 'IRB-ADCS-RootCA'
    }
    It 'returns null when no CN is present' {
        Get-LabCommonName 'O=Example' | Should -BeNullOrEmpty
    }
}

Describe 'Get-LabSanDnsName' {
    It 'reads every DNS name from the SAN extension' {
        $c = New-TestLeaf -Root $Root -San 'server.irb.local', 'www.irb.local'
        Get-LabSanDnsName $c | Should -Be @('server.irb.local', 'www.irb.local')
    }
    It 'returns an empty list without SAN' {
        @(Get-LabSanDnsName (New-TestLeaf -Root $Root -San @())).Count | Should -Be 0
    }
}

Describe 'Test-LabServerCertificate' {
    It 'passes every check for a correct lab certificate' {
        $r = Test-LabServerCertificate -Certificate $Leaf -Fqdn 'server.irb.local' -CaName 'IRB-ADCS-RootCA' -RootCertificate $Root
        $r | Where-Object Status -NE 'PASS' | Should -BeNullOrEmpty
        @($r).Count | Should -Be 8
    }
    It 'fails when the certificate is missing' {
        $r = Test-LabServerCertificate -Certificate $null -Fqdn 'server.irb.local' -CaName 'IRB-ADCS-RootCA' -RootCertificate $Root
        $r.Status | Should -Be 'FAIL'
    }
    It 'fails when the SAN does not contain the FQDN' {
        $c = New-TestLeaf -Root $Root -San 'other.irb.local'
        $r = Test-LabServerCertificate -Certificate $c -Fqdn 'server.irb.local' -CaName 'IRB-ADCS-RootCA' -RootCertificate $Root
        Get-Status $r 'SAN contains DNS name' | Should -Be 'FAIL'
    }
    It 'fails a CN-only certificate (no SAN)' {
        $c = New-TestLeaf -Root $Root -San @()
        $r = Test-LabServerCertificate -Certificate $c -Fqdn 'server.irb.local' -CaName 'IRB-ADCS-RootCA' -RootCertificate $Root
        Get-Status $r 'SAN contains DNS name' | Should -Be 'FAIL'
    }
    It 'fails an expired certificate and warns on one close to expiry' {
        $expired = New-TestLeaf -Root $Root -DaysBefore -30 -DaysAfter -1
        Get-Status (Test-LabServerCertificate -Certificate $expired -Fqdn 'server.irb.local' -CaName 'IRB-ADCS-RootCA' -RootCertificate $Root) 'Validity period' | Should -Be 'FAIL'
        $soon = New-TestLeaf -Root $Root -DaysAfter 10
        Get-Status (Test-LabServerCertificate -Certificate $soon -Fqdn 'server.irb.local' -CaName 'IRB-ADCS-RootCA' -RootCertificate $Root) 'Validity period' | Should -Be 'WARN'
    }
    It 'fails when the private key is not associated' {
        $c = New-TestLeaf -Root $Root -NoKey
        Get-Status (Test-LabServerCertificate -Certificate $c -Fqdn 'server.irb.local' -CaName 'IRB-ADCS-RootCA' -RootCertificate $Root) 'Associated private key present' | Should -Be 'FAIL'
    }
    It 'fails without the Server Authentication EKU' {
        $c = New-TestLeaf -Root $Root -EkuOid '1.3.6.1.5.5.7.3.2'
        Get-Status (Test-LabServerCertificate -Certificate $c -Fqdn 'server.irb.local' -CaName 'IRB-ADCS-RootCA' -RootCertificate $Root) 'Server Authentication EKU' | Should -Be 'FAIL'
    }
    It 'fails when signed by a different CA that reuses the same name' {
        $impostor = New-TestRoot
        $c = New-TestLeaf -Root $impostor
        $r = Test-LabServerCertificate -Certificate $c -Fqdn 'server.irb.local' -CaName 'IRB-ADCS-RootCA' -RootCertificate $Root
        Get-Status $r 'Issued by enterprise CA' | Should -Be 'PASS'
        Get-Status $r 'Signed by trusted root' | Should -Be 'FAIL'
    }
    It 'fails when issued by another CA name' {
        $other = New-TestRoot -Cn 'Some-Other-CA'
        $r = Test-LabServerCertificate -Certificate (New-TestLeaf -Root $other) -Fqdn 'server.irb.local' -CaName 'IRB-ADCS-RootCA' -RootCertificate $Root
        Get-Status $r 'Issued by enterprise CA' | Should -Be 'FAIL'
    }
}

Describe 'Find-LabServerCertificate / Find-LabRootCertificate' {
    It 'returns the newest matching certificate first and ignores unrelated ones' {
        $older = New-TestLeaf -Root $Root -DaysAfter 100
        $newer = New-TestLeaf -Root $Root -DaysAfter 700
        $unrelated = New-TestLeaf -Root (New-TestRoot -Cn 'Other') -Cn 'x.example' -San 'x.example'
        $found = @(Find-LabServerCertificate -Certificates @($older, $unrelated, $newer, $Root) -Fqdn 'server.irb.local' -CaName 'IRB-ADCS-RootCA')
        $found.Count | Should -Be 2
        $found[0].Thumbprint | Should -Be $newer.Thumbprint
    }
    It 'only treats self-signed certificates as the root' {
        @(Find-LabRootCertificate -Certificates @($Leaf, $Root) -CaName 'IRB-ADCS-RootCA')[0].Thumbprint | Should -Be $Root.Thumbprint
        @(Find-LabRootCertificate -Certificates @($Leaf) -CaName 'IRB-ADCS-RootCA').Count | Should -Be 0
    }
}

Describe 'Invoke-LabTrustCheck' {
    BeforeEach {
        Mock -ModuleName PkiLab Get-LabStoreCertificate { $Root }
        Mock -ModuleName PkiLab Get-GPO { [pscustomobject]@{ DisplayName = 'IRB Root CA Trust'; GpoStatus = 'AllSettingsEnabled' } }
        Mock -ModuleName PkiLab Get-GPInheritance {
            [pscustomobject]@{ GpoLinks = @([pscustomobject]@{ DisplayName = 'IRB Root CA Trust'; Enabled = $true; Enforced = $false }) }
        }
    }
    It 'passes when the root is delivered by Group Policy and the GPO is linked' {
        Mock -ModuleName PkiLab Test-LabRegistryKey { $Path -like '*Policies*' -or $Path -like '*EnterpriseCertificates*' }
        $r = Invoke-LabTrustCheck -CaName 'IRB-ADCS-RootCA' -DomainName 'irb.local' -GpoName 'IRB Root CA Trust'
        $r | Where-Object Status -NE 'PASS' | Should -BeNullOrEmpty
        ($r | Where-Object Check -EQ 'Root delivered by Group Policy').Detail | Should -Match 'Group Policy, Enterprise'
    }
    It 'warns when the root is trusted only via the local registry store' {
        Mock -ModuleName PkiLab Test-LabRegistryKey { $Path -like '*SystemCertificates\ROOT*' -and $Path -notlike '*Policies*' }
        $r = Invoke-LabTrustCheck -CaName 'IRB-ADCS-RootCA' -DomainName 'irb.local' -GpoName 'IRB Root CA Trust'
        Get-Status $r 'Root delivered by Group Policy' | Should -Be 'WARN'
    }
    It 'fails when the GPO link is disabled' {
        Mock -ModuleName PkiLab Test-LabRegistryKey { $true }
        Mock -ModuleName PkiLab Get-GPInheritance {
            [pscustomobject]@{ GpoLinks = @([pscustomobject]@{ DisplayName = 'IRB Root CA Trust'; Enabled = $false; Enforced = $false }) }
        }
        Get-Status (Invoke-LabTrustCheck -CaName 'IRB-ADCS-RootCA' -DomainName 'irb.local' -GpoName 'IRB Root CA Trust') 'Linked to irb.local' | Should -Be 'FAIL'
    }
    It 'fails when the root CA is not trusted' {
        Mock -ModuleName PkiLab Get-LabStoreCertificate { }
        Get-Status (Invoke-LabTrustCheck -CaName 'IRB-ADCS-RootCA' -DomainName 'irb.local' -GpoName 'IRB Root CA Trust') "Root CA 'IRB-ADCS-RootCA' in LocalMachine\Root" | Should -Be 'FAIL'
    }
}

Describe 'Invoke-LabCaCheck' {
    It 'passes for a running Enterprise Root CA with the expected name' {
        Mock -ModuleName PkiLab Get-Service { [pscustomobject]@{ Name = 'CertSvc'; Status = 'Running' } }
        Mock -ModuleName PkiLab Get-LabRegistryValue { if ($Name -eq 'Active') { 'IRB-ADCS-RootCA' } else { 0 } }
        Invoke-LabCaCheck -CaName 'IRB-ADCS-RootCA' | Where-Object Status -NE 'PASS' | Should -BeNullOrEmpty
    }
    It 'warns for a standalone CA and fails for a stopped service' {
        Mock -ModuleName PkiLab Get-Service { [pscustomobject]@{ Name = 'CertSvc'; Status = 'Stopped' } }
        Mock -ModuleName PkiLab Get-LabRegistryValue { if ($Name -eq 'Active') { 'IRB-ADCS-RootCA' } else { 3 } }
        $r = Invoke-LabCaCheck -CaName 'IRB-ADCS-RootCA'
        Get-Status $r 'Certificate Services (CertSvc)' | Should -Be 'FAIL'
        Get-Status $r 'CA type' | Should -Be 'WARN'
    }
    It 'fails when AD CS is not installed' {
        Mock -ModuleName PkiLab Get-Service { $null }
        (Invoke-LabCaCheck -CaName 'IRB-ADCS-RootCA').Status | Should -Be 'FAIL'
    }
}

Describe 'Test-LabTlsResult' {
    It 'passes a trusted handshake whose certificate matches the IIS binding' {
        $hs = [pscustomobject]@{ Connected = $true; PolicyErrors = 'None'; ChainStatus = @(); Thumbprint = 'AB'; Protocol = 'Tls12'; HttpStatus = 200; Error = $null }
        Test-LabTlsResult -Handshake $hs -Url 'https://server.irb.local:443' -ExpectedThumbprint 'AB' | Where-Object Status -NE 'PASS' | Should -BeNullOrEmpty
    }
    It 'fails an untrusted chain or name mismatch and reports why' {
        $hs = [pscustomobject]@{ Connected = $true; PolicyErrors = 'RemoteCertificateChainErrors'; ChainStatus = @('UntrustedRoot'); Thumbprint = 'AB'; Protocol = 'Tls12'; HttpStatus = 200; Error = $null }
        $r = Test-LabTlsResult -Handshake $hs -Url 'https://server.irb.local:443'
        ($r | Where-Object Check -EQ 'Client trusts certificate (no warning)').Detail | Should -Match 'UntrustedRoot'
        Get-Status $r 'Client trusts certificate (no warning)' | Should -Be 'FAIL'
    }
    It 'fails when the served certificate differs from the bound one' {
        $hs = [pscustomobject]@{ Connected = $true; PolicyErrors = 'None'; ChainStatus = @(); Thumbprint = 'AB'; Protocol = 'Tls13'; HttpStatus = 200; Error = $null }
        Get-Status (Test-LabTlsResult -Handshake $hs -Url 'u' -ExpectedThumbprint 'CD') 'Served certificate = IIS-bound certificate' | Should -Be 'FAIL'
    }
    It 'warns on legacy protocols and fails when the port is closed' {
        $legacy = [pscustomobject]@{ Connected = $true; PolicyErrors = 'None'; ChainStatus = @(); Thumbprint = 'AB'; Protocol = 'Tls11'; HttpStatus = 200; Error = $null }
        Get-Status (Test-LabTlsResult -Handshake $legacy -Url 'u') 'Protocol version' | Should -Be 'WARN'
        $closed = [pscustomobject]@{ Connected = $false; PolicyErrors = $null; ChainStatus = @(); Thumbprint = $null; Protocol = $null; HttpStatus = $null; Error = 'refused' }
        (Test-LabTlsResult -Handshake $closed -Url 'u').Status | Should -Be 'FAIL'
    }
}

Describe 'Invoke-LabTlsHandshake (live local TLS server)' -Skip:(-not (Get-Command openssl -ErrorAction SilentlyContinue) -or -not (Get-Command python3 -ErrorAction SilentlyContinue) -or ($PSVersionTable.PSEdition -eq 'Desktop')) {
    BeforeAll {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("pkilab-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $dir | Out-Null
        $pem = {
            param($Bytes, $Label)
            "-----BEGIN $Label-----`n" + [Convert]::ToBase64String($Bytes, 'InsertLineBreaks') + "`n-----END $Label-----`n"
        }
        $script:TlsLeaf = New-TestLeaf -Root $Root -San 'localhost'
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($TlsLeaf)
        Set-Content (Join-Path $dir 'cert.pem') (& $pem $TlsLeaf.RawData 'CERTIFICATE')
        Set-Content (Join-Path $dir 'key.pem') (& $pem $rsa.ExportPkcs8PrivateKey() 'PRIVATE KEY')
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $listener.Start()
        $script:TlsPort = $listener.LocalEndpoint.Port; $listener.Stop()
        $pyDir = $dir -replace '\\', '/'
        $py = @"
import http.server, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain('$pyDir/cert.pem', '$pyDir/key.pem')
srv = http.server.HTTPServer(('127.0.0.1', $TlsPort), http.server.SimpleHTTPRequestHandler)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True); srv.serve_forever()
"@
        Set-Content (Join-Path $dir 'srv.py') $py
        $script:Server = Start-Process python3 -ArgumentList (Join-Path $dir 'srv.py') -WorkingDirectory $dir -PassThru
        $deadline = (Get-Date).AddSeconds(10)
        do { Start-Sleep -Milliseconds 200; $c = New-Object System.Net.Sockets.TcpClient; try { $c.Connect('127.0.0.1', $TlsPort); $ok = $true } catch { $ok = $false } finally { $c.Close() } } until ($ok -or (Get-Date) -gt $deadline)
        $script:TmpDir = $dir
    }
    AfterAll {
        if ($Server) { Stop-Process -Id $Server.Id -Force -ErrorAction SilentlyContinue }
        if ($TmpDir) { Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue }
    }
    It 'completes the handshake, captures the served thumbprint and reports the untrusted test root' {
        $hs = Invoke-LabTlsHandshake -HostName 'localhost' -Port $TlsPort
        $hs.Error | Should -BeNullOrEmpty
        $hs.Connected | Should -BeTrue
        $hs.Protocol | Should -Match 'Tls1[23]'
        $hs.Thumbprint | Should -Be $TlsLeaf.Thumbprint
        $hs.PolicyErrors | Should -Match 'RemoteCertificateChainErrors'
        $hs.HttpStatus | Should -Be 200
        $r = Test-LabTlsResult -Handshake $hs -Url "https://localhost:$TlsPort" -ExpectedThumbprint $TlsLeaf.Thumbprint
        Get-Status $r 'Client trusts certificate (no warning)' | Should -Be 'FAIL'
        Get-Status $r 'Served certificate = IIS-bound certificate' | Should -Be 'PASS'
    }
    It 'reports a closed port without throwing' {
        $hs = Invoke-LabTlsHandshake -HostName '127.0.0.1' -Port 1 -TimeoutMs 1000
        $hs.Connected | Should -BeFalse
        $hs.Error | Should -Not -BeNullOrEmpty
    }
}
