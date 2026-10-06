#Requires -Version 5.1
<#
    PkiLab.psm1 - read-only verification helpers for the Windows Enterprise PKI lab.

    2026 REPRODUCIBILITY EXTENSION. Not part of the original May 2026 lab.

    Design:
      * Collectors (Get-Lab*) read system state. They never change it.
      * Evaluators (Test-Lab*) turn collected state into PASS / WARN / FAIL / SKIP results.
      * Only public certificate metadata (subject, issuer, thumbprint, dates) is ever printed.
        Private keys are never read or exported; only the HasPrivateKey flag is inspected.
#>

Set-StrictMode -Version 2.0

$script:OidServerAuth = '1.3.6.1.5.5.7.3.1'
$script:OidSan        = '2.5.29.17'

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

function New-LabCheckResult {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Area,
        [Parameter(Mandatory)] [string] $Check,
        [Parameter(Mandatory)] [ValidateSet('PASS', 'WARN', 'FAIL', 'SKIP')] [string] $Status,
        [string] $Detail = ''
    )
    [pscustomobject]@{
        PSTypeName = 'PkiLab.CheckResult'
        Area       = $Area
        Check      = $Check
        Status     = $Status
        Detail     = $Detail
    }
}

function Format-LabCheckResult {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)] [pscustomobject] $Result)
    process {
        $colour = switch ($Result.Status) {
            'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'DarkGray' }
        }
        $line = '[{0}] {1,-8} {2}' -f $Result.Status, $Result.Area, $Result.Check
        if ($Result.Detail) { $line = '{0} - {1}' -f $line, $Result.Detail }
        # Write-Host is intentional: this is the human-readable console report.
        Write-Host $line -ForegroundColor $colour
    }
}

function Write-LabSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results)
    $count = @{}
    foreach ($s in 'PASS', 'WARN', 'FAIL', 'SKIP') { $count[$s] = @($Results | Where-Object Status -EQ $s).Count }
    Write-Host ''
    Write-Host ('Summary: {0} PASS, {1} WARN, {2} FAIL, {3} SKIP' -f $count.PASS, $count.WARN, $count.FAIL, $count.SKIP)
}

# ---------------------------------------------------------------------------
# Thin, mockable wrappers around platform APIs
# ---------------------------------------------------------------------------

function Test-LabIsWindows {
    if (Test-Path variable:IsWindows) { return [bool]$IsWindows }
    return $true   # Windows PowerShell 5.1 only runs on Windows
}

function Get-LabStoreCertificate {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param([Parameter(Mandatory)] [ValidateSet('My', 'Root')] [string] $StoreName)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, 'LocalMachine')
    try {
        $store.Open('ReadOnly, OpenExistingOnly')
        foreach ($c in $store.Certificates) { $c }
    } finally {
        $store.Close()
    }
}

function Test-LabRegistryKey {
    param([Parameter(Mandatory)] [string] $Path)
    Test-Path -LiteralPath $Path
}

function Get-LabRegistryValue {
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [string] $Name)
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    $item.$Name
}

# ---------------------------------------------------------------------------
# Certificate helpers (pure; unit-tested)
# ---------------------------------------------------------------------------

function Get-LabCommonName {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $DistinguishedName)
    if ($DistinguishedName -match '(?:^|,\s*)CN=([^,]+)') { return $Matches[1].Trim() }
    return $null
}

function Get-LabSanDnsName {
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
    $ext = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq $script:OidSan } | Select-Object -First 1
    if ($null -eq $ext) { return }
    # Format() renders "DNS Name=host" on Windows and "DNS:host" on Linux/macOS.
    $text = $ext.Format($false)
    foreach ($m in [regex]::Matches($text, '(?:DNS Name=|DNS:)\s*([^,\r\n]+)')) { $m.Groups[1].Value.Trim() }
}

function Test-LabHasServerAuthEku {
    param([Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
    $eku = $Certificate.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } | Select-Object -First 1
    if ($null -eq $eku) { return $true }   # no EKU extension = not restricted
    foreach ($oid in $eku.EnhancedKeyUsages) { if ($oid.Value -eq $script:OidServerAuth) { return $true } }
    return $false
}

function Find-LabRootCertificate {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Certificates,
        [Parameter(Mandatory)] [string] $CaName
    )
    $Certificates |
        Where-Object { (Get-LabCommonName $_.Subject) -eq $CaName -and $_.Subject -eq $_.Issuer } |
        Sort-Object NotAfter -Descending
}

function Find-LabServerCertificate {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Certificates,
        [Parameter(Mandatory)] [string] $Fqdn,
        [Parameter(Mandatory)] [string] $CaName
    )
    $Certificates |
        Where-Object {
            (Get-LabCommonName $_.Issuer) -eq $CaName -and
            ((Get-LabCommonName $_.Subject) -eq $Fqdn -or (Get-LabSanDnsName $_) -contains $Fqdn)
        } |
        Sort-Object NotAfter -Descending
}

function Test-LabServerCertificate {
    <#
        Evaluates one server certificate against the lab's expectations.
        Pure function: everything it needs is passed in.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter(Mandatory)] [string] $Fqdn,
        [Parameter(Mandatory)] [string] $CaName,
        [AllowNull()] [System.Security.Cryptography.X509Certificates.X509Certificate2] $RootCertificate,
        [int] $ExpiryWarningDays = 30,
        [datetime] $Now = (Get-Date)
    )
    $a = 'CERT'
    if ($null -eq $Certificate) {
        New-LabCheckResult $a "Server certificate for $Fqdn in LocalMachine\My" 'FAIL' "No certificate issued by $CaName for $Fqdn"
        return
    }
    New-LabCheckResult $a "Server certificate for $Fqdn in LocalMachine\My" 'PASS' ('Thumbprint {0}' -f $Certificate.Thumbprint)

    $issuerCn = Get-LabCommonName $Certificate.Issuer
    if ($issuerCn -eq $CaName) { New-LabCheckResult $a 'Issued by enterprise CA' 'PASS' $Certificate.Issuer }
    else { New-LabCheckResult $a 'Issued by enterprise CA' 'FAIL' ('Issuer is {0}' -f $Certificate.Issuer) }

    $subjectCn = Get-LabCommonName $Certificate.Subject
    if ($subjectCn -eq $Fqdn) { New-LabCheckResult $a 'Subject CN matches FQDN' 'PASS' $Certificate.Subject }
    else { New-LabCheckResult $a 'Subject CN matches FQDN' 'WARN' ('Subject is {0}; clients rely on the SAN' -f $Certificate.Subject) }

    $san = @(Get-LabSanDnsName $Certificate)
    if ($san -contains $Fqdn) { New-LabCheckResult $a 'SAN contains DNS name' 'PASS' ('DNS=' + ($san -join ', DNS=')) }
    elseif ($san.Count -gt 0) { New-LabCheckResult $a 'SAN contains DNS name' 'FAIL' ('SAN has ' + ($san -join ', ') + " but not $Fqdn") }
    else { New-LabCheckResult $a 'SAN contains DNS name' 'FAIL' 'No SAN extension; modern browsers reject CN-only certificates' }

    if ($Now -lt $Certificate.NotBefore) {
        New-LabCheckResult $a 'Validity period' 'FAIL' ('Not valid before {0:u}' -f $Certificate.NotBefore)
    } elseif ($Now -gt $Certificate.NotAfter) {
        New-LabCheckResult $a 'Validity period' 'FAIL' ('Expired {0:u}' -f $Certificate.NotAfter)
    } elseif ($Certificate.NotAfter -lt $Now.AddDays($ExpiryWarningDays)) {
        New-LabCheckResult $a 'Validity period' 'WARN' ('Expires soon: {0:u}' -f $Certificate.NotAfter)
    } else {
        New-LabCheckResult $a 'Validity period' 'PASS' ('{0:yyyy-MM-dd} to {1:yyyy-MM-dd}' -f $Certificate.NotBefore, $Certificate.NotAfter)
    }

    if ($Certificate.HasPrivateKey) { New-LabCheckResult $a 'Associated private key present' 'PASS' 'Key is not read or exported' }
    else { New-LabCheckResult $a 'Associated private key present' 'FAIL' 'certreq -accept may not have completed on this machine' }

    if (Test-LabHasServerAuthEku $Certificate) { New-LabCheckResult $a 'Server Authentication EKU' 'PASS' $script:OidServerAuth }
    else { New-LabCheckResult $a 'Server Authentication EKU' 'FAIL' 'Certificate is not valid for TLS server authentication' }

    if ($null -eq $RootCertificate) {
        New-LabCheckResult $a 'Signed by trusted root' 'SKIP' 'Root CA certificate not found'
    } elseif ($Certificate.Issuer -eq $RootCertificate.Subject -and (Test-LabSignedBy -Certificate $Certificate -Issuer $RootCertificate)) {
        New-LabCheckResult $a 'Signed by trusted root' 'PASS' ('Root thumbprint {0}' -f $RootCertificate.Thumbprint)
    } else {
        New-LabCheckResult $a 'Signed by trusted root' 'FAIL' 'Signature does not verify against the root CA public key'
    }
}

function Select-LabSigningRoot {
    <# Picks the trusted root that actually signed the leaf (handles renewed roots that reuse the CA name). #>
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [AllowEmptyCollection()] [object[]] $Roots = @()
    )
    if (-not $Roots -or $Roots.Count -eq 0) { return $null }
    if ($Certificate) {
        foreach ($root in $Roots) {
            if ($Certificate.Issuer -eq $root.Subject -and (Test-LabSignedBy -Certificate $Certificate -Issuer $root)) { return $root }
        }
    }
    $Roots[0]
}

function Test-LabSignedBy {
    <# Builds a chain using only the supplied issuer as an extra store; no network, no revocation. #>
    param(
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Issuer
    )
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    try {
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        $chain.ChainPolicy.VerificationFlags = 'AllowUnknownCertificateAuthority'
        [void]$chain.ChainPolicy.ExtraStore.Add($Issuer)
        [void]$chain.Build($Certificate)
        if ($chain.ChainElements.Count -lt 2) { return $false }
        $top = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
        if ($top.Thumbprint -ne $Issuer.Thumbprint) { return $false }
        foreach ($s in $chain.ChainStatus) {
            if ($s.Status -notin 'NoError', 'UntrustedRoot', 'RevocationStatusUnknown', 'OfflineRevocation') { return $false }
        }
        return $true
    } finally {
        if ($chain.PSObject.Methods.Name -contains 'Dispose') { $chain.Dispose() }
    }
}

function Test-LabRootCertificate {
    param(
        [AllowNull()] [System.Security.Cryptography.X509Certificates.X509Certificate2] $RootCertificate,
        [Parameter(Mandatory)] [string] $CaName,
        [datetime] $Now = (Get-Date)
    )
    if ($null -eq $RootCertificate) {
        New-LabCheckResult 'TRUST' "Root CA '$CaName' in LocalMachine\Root" 'FAIL' 'Not found in the trusted root store'
        return
    }
    New-LabCheckResult 'TRUST' "Root CA '$CaName' in LocalMachine\Root" 'PASS' ('Thumbprint {0}' -f $RootCertificate.Thumbprint)
    if ($Now -gt $RootCertificate.NotAfter) {
        New-LabCheckResult 'TRUST' 'Root CA validity' 'FAIL' ('Expired {0:u}' -f $RootCertificate.NotAfter)
    } else {
        New-LabCheckResult 'TRUST' 'Root CA validity' 'PASS' ('Valid until {0:yyyy-MM-dd}' -f $RootCertificate.NotAfter)
    }
}

# ---------------------------------------------------------------------------
# Collectors + checks per area (read-only system access)
# ---------------------------------------------------------------------------

function Invoke-LabDomainCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $DomainName,
        [Parameter(Mandatory)] [string] $ServerFqdn,
        [string] $ExpectedIPv4
    )
    $a = 'DOMAIN'

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os.Caption -match 'Server 2022') { New-LabCheckResult $a 'Operating system' 'PASS' $os.Caption }
        else { New-LabCheckResult $a 'Operating system' 'WARN' ('{0} (original lab used Windows Server 2022)' -f $os.Caption) }
    } catch { New-LabCheckResult $a 'Operating system' 'SKIP' $_.Exception.Message }

    $roles = [ordered]@{ 'AD-Domain-Services' = 'AD DS'; 'ADCS-Cert-Authority' = 'AD CS'; 'DNS' = 'DNS'; 'Web-Server' = 'IIS' }
    if (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue) {
        foreach ($name in $roles.Keys) {
            try {
                $f = Get-WindowsFeature -Name $name -ErrorAction Stop
                if ($f -and $f.Installed) { New-LabCheckResult $a "Role installed: $($roles[$name])" 'PASS' $name }
                else { New-LabCheckResult $a "Role installed: $($roles[$name])" 'FAIL' "$name is not installed" }
            } catch { New-LabCheckResult $a "Role installed: $($roles[$name])" 'SKIP' $_.Exception.Message }
        }
    } else {
        New-LabCheckResult $a 'Server roles' 'SKIP' 'Get-WindowsFeature unavailable (not Windows Server / ServerManager module missing)'
    }

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs.PartOfDomain -and $cs.Domain -eq $DomainName) { New-LabCheckResult $a 'Domain membership' 'PASS' $cs.Domain }
        elseif ($cs.PartOfDomain) { New-LabCheckResult $a 'Domain membership' 'FAIL' ('Joined to {0}, expected {1}' -f $cs.Domain, $DomainName) }
        else { New-LabCheckResult $a 'Domain membership' 'FAIL' 'Machine is not domain-joined' }
        # DomainRole 4/5 = backup/primary domain controller
        if ($cs.DomainRole -ge 4) { New-LabCheckResult $a 'Domain controller role' 'PASS' "DomainRole=$($cs.DomainRole)" }
        else { New-LabCheckResult $a 'Domain controller role' 'WARN' "DomainRole=$($cs.DomainRole); original lab ran the checks on the DC itself" }
    } catch { New-LabCheckResult $a 'Domain membership' 'SKIP' $_.Exception.Message }

    $resolved = @()
    try {
        $resolved = @(Resolve-DnsName -Name $ServerFqdn -Type A -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress })
        if ($resolved.Count -gt 0) { New-LabCheckResult 'DNS' "A record for $ServerFqdn" 'PASS' ($resolved -join ', ') }
        else { New-LabCheckResult 'DNS' "A record for $ServerFqdn" 'FAIL' 'No A record returned' }
    } catch { New-LabCheckResult 'DNS' "A record for $ServerFqdn" 'FAIL' $_.Exception.Message }

    if ($ExpectedIPv4) {
        if ($resolved -contains $ExpectedIPv4) { New-LabCheckResult 'DNS' 'A record matches expected address' 'PASS' $ExpectedIPv4 }
        else { New-LabCheckResult 'DNS' 'A record matches expected address' 'FAIL' ('Resolved {0}, expected {1}' -f ($resolved -join ', '), $ExpectedIPv4) }
    }

    if ($resolved.Count -gt 0 -and (Get-Command -Name Get-NetIPAddress -ErrorAction SilentlyContinue)) {
        try {
            $local = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $resolved -contains $_.IPAddress })
            if ($local.Count -eq 0) {
                New-LabCheckResult 'DNS' 'A record points to this host' 'WARN' 'Resolved address is not bound locally (run on the IIS server)'
            } elseif (@($local | Where-Object { $_.PrefixOrigin -eq 'Dhcp' }).Count -gt 0) {
                New-LabCheckResult 'DNS' 'Static IPv4 address' 'WARN' ('{0} is DHCP-assigned; AD DS/CA hosts should be static' -f $local[0].IPAddress)
            } else {
                New-LabCheckResult 'DNS' 'Static IPv4 address' 'PASS' ('{0} ({1})' -f $local[0].IPAddress, $local[0].PrefixOrigin)
            }
        } catch { New-LabCheckResult 'DNS' 'Static IPv4 address' 'SKIP' $_.Exception.Message }
    }
}

function Invoke-LabCaCheck {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $CaName)
    $a = 'CA'
    $svc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        New-LabCheckResult $a 'Certificate Services (CertSvc)' 'FAIL' 'Service not present - AD CS CA not installed on this host'
        return
    }
    if ($svc.Status -eq 'Running') { New-LabCheckResult $a 'Certificate Services (CertSvc)' 'PASS' 'Running' }
    else { New-LabCheckResult $a 'Certificate Services (CertSvc)' 'FAIL' ('Status {0}' -f $svc.Status) }

    $cfg = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    $active = Get-LabRegistryValue -Path $cfg -Name 'Active'
    if ($active -eq $CaName) { New-LabCheckResult $a 'Active CA name' 'PASS' $active }
    elseif ($active) { New-LabCheckResult $a 'Active CA name' 'FAIL' ('Active CA is {0}, expected {1}' -f $active, $CaName) }
    else { New-LabCheckResult $a 'Active CA name' 'SKIP' 'CA configuration not readable' }

    if ($active) {
        # ENUM_CATYPES: 0 Enterprise Root, 1 Enterprise Subordinate, 3 Standalone Root, 4 Standalone Subordinate
        $types = @{ 0 = 'Enterprise Root'; 1 = 'Enterprise Subordinate'; 3 = 'Standalone Root'; 4 = 'Standalone Subordinate' }
        $type = Get-LabRegistryValue -Path ('{0}\{1}' -f $cfg, $active) -Name 'CAType'
        if ($null -eq $type) { New-LabCheckResult $a 'CA type' 'SKIP' 'CAType not readable' }
        elseif ($type -eq 0) { New-LabCheckResult $a 'CA type' 'PASS' 'Enterprise Root' }
        else { New-LabCheckResult $a 'CA type' 'WARN' ('{0} (original lab used Enterprise Root)' -f $types[[int]$type]) }
    }
}

function Invoke-LabTrustCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $CaName,
        [Parameter(Mandatory)] [string] $DomainName,
        [Parameter(Mandatory)] [string] $GpoName
    )
    $root = $null
    try {
        $root = Find-LabRootCertificate -Certificates (Get-LabStoreCertificate -StoreName Root) -CaName $CaName | Select-Object -First 1
    } catch {
        New-LabCheckResult 'TRUST' 'Read LocalMachine\Root' 'FAIL' $_.Exception.Message
    }
    Test-LabRootCertificate -RootCertificate $root -CaName $CaName

    if ($null -ne $root) {
        # The logical Root store merges several physical stores; report which ones hold the CA.
        $sources = [ordered]@{
            'Group Policy'       = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates'
            'Enterprise (AD DS)' = 'HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates'
            'Local machine'      = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates'
        }
        $found = @(foreach ($k in $sources.Keys) { if (Test-LabRegistryKey ('{0}\{1}' -f $sources[$k], $root.Thumbprint)) { $k } })
        if ($found -contains 'Group Policy') {
            New-LabCheckResult 'TRUST' 'Root delivered by Group Policy' 'PASS' ('Physical stores: ' + ($found -join ', '))
        } else {
            New-LabCheckResult 'TRUST' 'Root delivered by Group Policy' 'WARN' ('Not in the policy store (run gpupdate /force). Present in: ' + ($(if ($found) { $found -join ', ' } else { 'none' })))
        }
    }

    if (-not (Get-Command -Name Get-GPO -ErrorAction SilentlyContinue)) {
        New-LabCheckResult 'GPO' "GPO '$GpoName'" 'SKIP' 'GroupPolicy module unavailable (install GPMC / RSAT)'
        return
    }
    try {
        $gpo = Get-GPO -Name $GpoName -Domain $DomainName -ErrorAction Stop
        New-LabCheckResult 'GPO' "GPO '$GpoName' exists" 'PASS' ('Status {0}' -f $gpo.GpoStatus)
        if ("$($gpo.GpoStatus)" -match 'ComputerSettingsDisabled|AllSettingsDisabled') {
            New-LabCheckResult 'GPO' 'Computer settings enabled' 'FAIL' "$($gpo.GpoStatus)"
        }
    } catch {
        New-LabCheckResult 'GPO' "GPO '$GpoName' exists" 'FAIL' $_.Exception.Message
        return
    }
    try {
        $domainDn = ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','
        $link = Get-GPInheritance -Target $domainDn -Domain $DomainName -ErrorAction Stop |
            Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq $GpoName } | Select-Object -First 1
        if ($null -eq $link) { New-LabCheckResult 'GPO' "Linked to $DomainName" 'FAIL' 'No link at the domain root' }
        elseif ($link.Enabled) { New-LabCheckResult 'GPO' "Linked to $DomainName" 'PASS' ('Link enabled, enforced={0}' -f $link.Enforced) }
        else { New-LabCheckResult 'GPO' "Linked to $DomainName" 'FAIL' 'Link exists but is disabled' }
    } catch { New-LabCheckResult 'GPO' "Linked to $DomainName" 'SKIP' $_.Exception.Message }
}

function Get-LabIisHttpsBinding {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $SiteName, [int] $Port = 443)
    Import-Module WebAdministration -ErrorAction Stop
    @(Get-WebBinding -Name $SiteName -Protocol https -ErrorAction Stop |
        Where-Object { $_.bindingInformation -match (":{0}:" -f $Port) })
}

function Invoke-LabCertificateCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ServerFqdn,
        [Parameter(Mandatory)] [string] $CaName,
        [string] $Thumbprint,
        [int] $ExpiryWarningDays = 30
    )
    $roots = @(); $mine = @()
    try { $roots = @(Find-LabRootCertificate -Certificates (Get-LabStoreCertificate -StoreName Root) -CaName $CaName) } catch { $roots = @() }
    try { $mine = @(Get-LabStoreCertificate -StoreName My) } catch {
        New-LabCheckResult 'CERT' 'Read LocalMachine\My' 'FAIL' $_.Exception.Message
        return
    }
    $candidates = @(Find-LabServerCertificate -Certificates $mine -Fqdn $ServerFqdn -CaName $CaName)
    $cert = $null
    if ($Thumbprint) {
        $cert = $mine | Where-Object { $_.Thumbprint -eq $Thumbprint } | Select-Object -First 1
    } else {
        $cert = $candidates | Select-Object -First 1
    }
    if ($candidates.Count -gt 1) {
        New-LabCheckResult 'CERT' 'Duplicate server certificates' 'WARN' ('{0} certificates for {1}; evaluating {2}' -f $candidates.Count, $ServerFqdn, $(if ($cert) { $cert.Thumbprint } else { 'none' }))
    }
    $root = Select-LabSigningRoot -Certificate $cert -Roots $roots
    Test-LabServerCertificate -Certificate $cert -Fqdn $ServerFqdn -CaName $CaName -RootCertificate $root -ExpiryWarningDays $ExpiryWarningDays
}

function Invoke-LabTlsHandshake {
    <#
        Opens a TLS connection, records how the OS validated the server certificate, then
        sends a single HTTP GET. Returns a plain object; never throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $HostName,
        [int] $Port = 443,
        [int] $TimeoutMs = 5000,
        [switch] $CheckRevocation
    )
    $r = [ordered]@{ Connected = $false; PolicyErrors = $null; ChainStatus = @(); Thumbprint = $null; Protocol = $null; HttpStatus = $null; Error = $null; RevocationChecked = [bool]$CheckRevocation }
    $state = @{ Errors = $null; Chain = @(); Cert = $null }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw "TCP connect to ${HostName}:$Port timed out" }
        $client.EndConnect($ar)
        $r.Connected = $true

        # Observe the platform's verdict but let the handshake finish so we can report details.
        $callback = {
            param($source, $certificate, $chain, $errors)
            $state.Errors = $errors
            if ($null -ne $chain) { $state.Chain = @($chain.ChainStatus | ForEach-Object { "$($_.Status)" }) }
            if ($null -ne $certificate) { $state.Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificate) }
            return $true
        }.GetNewClosure()

        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false, [System.Net.Security.RemoteCertificateValidationCallback]$callback)
        $ssl.ReadTimeout = $TimeoutMs; $ssl.WriteTimeout = $TimeoutMs
        $ssl.AuthenticateAsClient($HostName, $null, [System.Security.Authentication.SslProtocols]::None, [bool]$CheckRevocation)

        $r.PolicyErrors = "$($state.Errors)"
        $r.ChainStatus = $state.Chain
        if ($state.Cert) { $r.Thumbprint = $state.Cert.Thumbprint }
        $r.Protocol = "$($ssl.SslProtocol)"

        $req = [System.Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: $HostName`r`nConnection: close`r`n`r`n")
        $ssl.Write($req, 0, $req.Length); $ssl.Flush()
        $reader = New-Object System.IO.StreamReader($ssl, [System.Text.Encoding]::ASCII)
        $status = $reader.ReadLine()
        if ($status -match '^HTTP/\d(?:\.\d)?\s+(\d{3})') { $r.HttpStatus = [int]$Matches[1] }
    } catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        $r.Error = $e.Message
        if ($null -ne $state.Errors) { $r.PolicyErrors = "$($state.Errors)" }
    } finally {
        $client.Close()
    }
    [pscustomobject]$r
}

function Test-LabTlsResult {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Handshake,
        [Parameter(Mandatory)] [string] $Url,
        [string] $ExpectedThumbprint
    )
    $a = 'TLS'
    if (-not $Handshake.Connected) {
        New-LabCheckResult $a "TCP connect $Url" 'FAIL' $Handshake.Error
        return
    }
    if ($null -eq $Handshake.Protocol) {
        New-LabCheckResult $a "TLS handshake $Url" 'FAIL' $Handshake.Error
        return
    }
    New-LabCheckResult $a "TLS handshake $Url" 'PASS' $Handshake.Protocol
    if ($Handshake.Protocol -match 'Ssl|Tls$|Tls11') {
        New-LabCheckResult $a 'Protocol version' 'WARN' ('{0} negotiated; disable legacy protocols' -f $Handshake.Protocol)
    }

    if ($Handshake.PolicyErrors -eq 'None') {
        New-LabCheckResult $a 'Client trusts certificate (no warning)' 'PASS' 'Name and chain validated by the Windows trust store'
        if ($Handshake.PSObject.Properties['RevocationChecked'] -and $Handshake.RevocationChecked) { New-LabCheckResult $a 'Revocation status' 'PASS' 'CRL/OCSP checked during chain validation' }
        else { New-LabCheckResult $a 'Revocation status' 'SKIP' 'Not checked; a revoked certificate would still pass. Rerun with -CheckRevocation' }
    } else {
        $chain = @($Handshake.ChainStatus | Where-Object { $_ -ne 'NoError' })
        $detail = $Handshake.PolicyErrors
        if ($chain.Count) { $detail = '{0}; chain: {1}' -f $detail, ($chain -join ', ') }
        New-LabCheckResult $a 'Client trusts certificate (no warning)' 'FAIL' $detail
    }

    if ($ExpectedThumbprint) {
        if ($Handshake.Thumbprint -eq $ExpectedThumbprint) { New-LabCheckResult $a 'Served certificate = IIS-bound certificate' 'PASS' $Handshake.Thumbprint }
        else { New-LabCheckResult $a 'Served certificate = IIS-bound certificate' 'FAIL' ('Served {0}, bound {1}' -f $Handshake.Thumbprint, $ExpectedThumbprint) }
    }

    if ($null -eq $Handshake.HttpStatus) { New-LabCheckResult $a 'HTTPS response' 'WARN' "No HTTP status line ($($Handshake.Error))" }
    elseif ($Handshake.HttpStatus -lt 400) { New-LabCheckResult $a 'HTTPS response' 'PASS' "HTTP $($Handshake.HttpStatus)" }
    else { New-LabCheckResult $a 'HTTPS response' 'WARN' "HTTP $($Handshake.HttpStatus)" }
}

function Invoke-LabIisTlsCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ServerFqdn,
        [string] $SiteName = 'Default Web Site',
        [int] $Port = 443,
        [switch] $CheckRevocation
    )
    $boundThumbprint = $null
    try {
        $bindings = @(Get-LabIisHttpsBinding -SiteName $SiteName -Port $Port)
        if ($bindings.Count -eq 0) {
            New-LabCheckResult 'IIS' "HTTPS binding on :$Port ($SiteName)" 'FAIL' 'No https binding'
        } else {
            $b = $bindings | Where-Object { $_.bindingInformation -like "*:$ServerFqdn" } | Select-Object -First 1
            if ($null -eq $b) { $b = $bindings[0] }
            New-LabCheckResult 'IIS' "HTTPS binding on :$Port ($SiteName)" 'PASS' $b.bindingInformation
            if ("$($b.certificateHash)") {
                $boundThumbprint = "$($b.certificateHash)".ToUpperInvariant()
                New-LabCheckResult 'IIS' 'Certificate bound to HTTPS binding' 'PASS' ('Thumbprint {0} (store {1})' -f $boundThumbprint, $b.certificateStoreName)
            } else {
                New-LabCheckResult 'IIS' 'Certificate bound to HTTPS binding' 'FAIL' 'Binding has no certificate'
            }
        }
        $http = @(Get-WebBinding -Name $SiteName -Protocol http -ErrorAction SilentlyContinue)
        if ($http.Count -gt 0) {
            New-LabCheckResult 'IIS' 'Plain HTTP binding' 'WARN' ('{0} still served over HTTP (no redirect/HSTS configured by this lab)' -f ($http.bindingInformation -join ', '))
        }
    } catch {
        New-LabCheckResult 'IIS' "HTTPS binding on :$Port ($SiteName)" 'SKIP' ('WebAdministration unavailable: {0}' -f $_.Exception.Message)
    }

    if ($boundThumbprint) {
        $cert = $null
        try { $cert = Get-LabStoreCertificate -StoreName My | Where-Object { $_.Thumbprint -eq $boundThumbprint } | Select-Object -First 1 } catch { $cert = $null }
        if ($null -eq $cert) { New-LabCheckResult 'IIS' 'Bound certificate exists in LocalMachine\My' 'FAIL' $boundThumbprint }
        else {
            $names = @(Get-LabSanDnsName $cert)
            if ($names -contains $ServerFqdn) { New-LabCheckResult 'IIS' 'Bound certificate matches host name' 'PASS' $ServerFqdn }
            else { New-LabCheckResult 'IIS' 'Bound certificate matches host name' 'FAIL' ('SAN: {0}' -f ($names -join ', ')) }
        }
    }

    $hs = Invoke-LabTlsHandshake -HostName $ServerFqdn -Port $Port -CheckRevocation:$CheckRevocation
    Test-LabTlsResult -Handshake $hs -Url ('https://{0}:{1}' -f $ServerFqdn, $Port) -ExpectedThumbprint $boundThumbprint
    return
}

function Get-LabBoundThumbprint {
    param([string] $SiteName = 'Default Web Site', [int] $Port = 443, [string] $ServerFqdn)
    try {
        $b = @(Get-LabIisHttpsBinding -SiteName $SiteName -Port $Port)
        $pick = $b | Where-Object { $_.bindingInformation -like "*:$ServerFqdn" } | Select-Object -First 1
        if ($null -eq $pick -and $b.Count) { $pick = $b[0] }
        if ($pick -and "$($pick.certificateHash)") { return "$($pick.certificateHash)".ToUpperInvariant() }
    } catch { Write-Verbose $_.Exception.Message }
    return $null
}

Export-ModuleMember -Function @(
    'New-LabCheckResult', 'Select-LabSigningRoot', 'Format-LabCheckResult', 'Write-LabSummary', 'Test-LabIsWindows',
    'Get-LabStoreCertificate', 'Test-LabRegistryKey', 'Get-LabRegistryValue',
    'Get-LabCommonName', 'Get-LabSanDnsName', 'Test-LabHasServerAuthEku', 'Test-LabSignedBy',
    'Find-LabRootCertificate', 'Find-LabServerCertificate', 'Test-LabServerCertificate', 'Test-LabRootCertificate',
    'Invoke-LabDomainCheck', 'Invoke-LabCaCheck', 'Invoke-LabTrustCheck', 'Invoke-LabCertificateCheck',
    'Get-LabIisHttpsBinding', 'Get-LabBoundThumbprint', 'Invoke-LabTlsHandshake', 'Test-LabTlsResult', 'Invoke-LabIisTlsCheck'
)
