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
$script:OidTemplateV2 = '1.3.6.1.4.1.311.21.7'
$script:OidTemplateV1 = '1.3.6.1.4.1.311.20.2'

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
        # Member clients usually lack GPMC; fall back to this computer's Resultant Set of Policy.
        $applied = Get-LabAppliedGpoName
        if ($null -eq $applied) {
            New-LabCheckResult 'GPO' "GPO '$GpoName'" 'SKIP' 'GroupPolicy module unavailable and RSoP not readable (run elevated, or install GPMC / RSAT)'
        } elseif (@($applied) -contains $GpoName) {
            New-LabCheckResult 'GPO' "GPO '$GpoName' applied to this computer" 'PASS' ('Resultant Set of Policy: ' + (@($applied) -join ', '))
        } else {
            New-LabCheckResult 'GPO' "GPO '$GpoName' applied to this computer" 'WARN' ('Not in Resultant Set of Policy (run gpupdate /force). Applied: ' + $(if (@($applied).Count) { @($applied) -join ', ' } else { 'none' }))
        }
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

function Get-LabAppliedGpoName {
    <# Names of the GPOs in this computer's RSoP (logging mode). $null when RSoP cannot be read. #>
    [OutputType([string[]])]
    param()
    try {
        $gpos = @(Get-CimInstance -Namespace 'root/rsop/computer' -ClassName RSOP_GPO -ErrorAction Stop)
        , [string[]]@($gpos | Where-Object { $_.Name } | ForEach-Object { $_.Name } | Sort-Object -Unique)
    } catch {
        return $null
    }
}

function Get-LabCertificateTemplateInfo {
    <# Text of the certificate-template extension (v2 template information, else v1 template name). #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
    foreach ($oid in $script:OidTemplateV2, $script:OidTemplateV1) {
        $ext = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq $oid } | Select-Object -First 1
        if ($null -ne $ext) { return $ext.Format($false) }
    }
    return $null
}

function Test-LabEnrolledCertificate {
    <#
        Verifies that this machine holds a usable certificate issued from a specific template,
        e.g. one obtained through GPO auto-enrollment. Pure evaluator apart from the template lookup.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Certificates,
        [Parameter(Mandatory)] [string] $TemplateName,
        [Parameter(Mandatory)] [string] $Fqdn,
        [Parameter(Mandatory)] [string] $CaName,
        [datetime] $Now = (Get-Date)
    )
    $check = "Enrolled certificate from template '$TemplateName'"
    $pattern = '(^|[=\s])' + [regex]::Escape($TemplateName) + '(\(|$|,|\s)'
    $candidates = @($Certificates | Where-Object {
        $info = Get-LabCertificateTemplateInfo -Certificate $_
        $null -ne $info -and $info -match $pattern
    } | Sort-Object NotAfter -Descending)
    if ($candidates.Count -eq 0) {
        New-LabCheckResult 'ENROLL' $check 'FAIL' 'None in LocalMachine\My (auto-enrollment not run yet, or this computer is not permitted to enroll)'
        return
    }
    $cert = @($candidates | Where-Object { $_.NotBefore -le $Now -and $_.NotAfter -gt $Now } | Select-Object -First 1)
    if ($cert.Count -eq 0) {
        New-LabCheckResult 'ENROLL' $check 'FAIL' ('{0} certificate(s), none currently valid' -f $candidates.Count)
        return
    }
    $cert = $cert[0]
    $problems = @(
        if ((Get-LabCommonName $cert.Issuer) -ne $CaName) { "issuer is $($cert.Issuer)" }
        if (@(Get-LabSanDnsName $cert) -notcontains $Fqdn) { "SAN does not contain $Fqdn" }
        if (-not (Test-LabHasServerAuthEku $cert)) { 'no Server Authentication EKU' }
        if (-not $cert.HasPrivateKey) { 'no associated private key' }
    )
    if ($problems.Count) {
        New-LabCheckResult 'ENROLL' $check 'FAIL' ('{0}: {1}' -f $cert.Thumbprint, ($problems -join '; '))
    } else {
        New-LabCheckResult 'ENROLL' $check 'PASS' ('{0}; DNS={1}; expires {2:yyyy-MM-dd}' -f $cert.Thumbprint, $Fqdn, $cert.NotAfter)
    }
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
    $ssl = $null
    try {
        $ar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw "TCP connect to ${HostName}:$Port timed out" }
        $client.EndConnect($ar)
        $r.Connected = $true

        $callback = {
            param($source, $certificate, $chain, $errors)
            $state.Errors = $errors
            if ($null -ne $chain) { $state.Chain = @($chain.ChainStatus | ForEach-Object { "$($_.Status)" }) }
            if ($null -ne $certificate) { $state.Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificate) }
            return ($errors -eq [System.Net.Security.SslPolicyErrors]::None)
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
        if ($null -ne $state.Errors) { $r.PolicyErrors = "$($state.Errors)" }
        $r.ChainStatus = $state.Chain
        if ($state.Cert) { $r.Thumbprint = $state.Cert.Thumbprint; $state.Cert.Dispose() }
        if ($ssl) { $ssl.Dispose() }
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
    $checked = $Handshake.PSObject.Properties['RevocationChecked'] -and $Handshake.RevocationChecked
    $chain = @($Handshake.ChainStatus | Where-Object { $_ -ne 'NoError' })
    if (-not $checked) {
        New-LabCheckResult $a 'Revocation status' 'SKIP' 'Not checked; a revoked certificate could still pass. Rerun with -CheckRevocation'
    } elseif ($chain -match 'Revoked') {
        New-LabCheckResult $a 'Revocation status' 'FAIL' ('Certificate revoked; chain: ' + ($chain -join ', '))
    } elseif ($chain -match 'RevocationStatusUnknown|OfflineRevocation') {
        New-LabCheckResult $a 'Revocation status' 'FAIL' ('Revocation could not be established; chain: ' + ($chain -join ', '))
    } elseif ($Handshake.PolicyErrors -eq 'None' -and $Handshake.Protocol) {
        New-LabCheckResult $a 'Revocation status' 'PASS' 'CRL/OCSP checked during chain validation'
    } else {
        New-LabCheckResult $a 'Revocation status' 'SKIP' 'Certificate validation did not complete; no revocation assurance'
    }
    if ($ExpectedThumbprint) {
        if (-not $Handshake.Thumbprint) { New-LabCheckResult $a 'Served certificate = IIS-bound certificate' 'SKIP' 'Peer certificate unavailable' }
        elseif ($Handshake.Thumbprint -eq $ExpectedThumbprint) { New-LabCheckResult $a 'Served certificate = IIS-bound certificate' 'PASS' $Handshake.Thumbprint }
        else { New-LabCheckResult $a 'Served certificate = IIS-bound certificate' 'FAIL' ('Served {0}, bound {1}' -f $Handshake.Thumbprint, $ExpectedThumbprint) }
    }
    if ($null -eq $Handshake.Protocol) {
        New-LabCheckResult $a "TLS handshake $Url" 'FAIL' $Handshake.Error
        if ($Handshake.PolicyErrors) {
            New-LabCheckResult $a 'Client trusts certificate (no warning)' 'FAIL' ('{0}; chain: {1}' -f $Handshake.PolicyErrors, ($chain -join ', '))
        }
        return
    }
    New-LabCheckResult $a "TLS handshake $Url" 'PASS' $Handshake.Protocol
    if ($Handshake.Protocol -match 'Ssl|Tls$|Tls11') {
        New-LabCheckResult $a 'Protocol version' 'WARN' ('{0} negotiated; disable legacy protocols' -f $Handshake.Protocol)
    }

    if ($Handshake.PolicyErrors -eq 'None') {
        New-LabCheckResult $a 'Client trusts certificate (no warning)' 'PASS' 'Name and chain validated by the Windows trust store'
    } else {
        $detail = $Handshake.PolicyErrors
        if ($chain.Count) { $detail = '{0}; chain: {1}' -f $detail, ($chain -join ', ') }
        New-LabCheckResult $a 'Client trusts certificate (no warning)' 'FAIL' $detail
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

# ---------------------------------------------------------------------------
# AD CS security audit (ESC1-4, ESC6, ESC8) - read-only, 2026 extension
# ---------------------------------------------------------------------------

$script:OidClientAuth     = '1.3.6.1.5.5.7.3.2'
$script:OidPkinit         = '1.3.6.1.5.2.3.4'
$script:OidSmartcardLogon = '1.3.6.1.4.1.311.20.2.2'
$script:OidAnyPurpose     = '2.5.29.37.0'
$script:OidRequestAgent   = '1.3.6.1.4.1.311.20.2.1'
$script:AuthEkus          = @($script:OidClientAuth, $script:OidPkinit, $script:OidSmartcardLogon, $script:OidAnyPurpose)
$script:RightEnroll       = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
$script:RightAutoEnroll   = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
$script:EmptyGuid         = '00000000-0000-0000-0000-000000000000'
$script:EditfSan2         = 0x00040000

function Test-LabLowPrivilegedSid {
    <# Everyone, Anonymous, Authenticated Users, BUILTIN\Users, Domain Users, Domain Computers. #>
    param([string] $Sid)
    if (@('S-1-1-0', 'S-1-5-7', 'S-1-5-11', 'S-1-5-32-545') -contains $Sid) { return $true }
    return ($Sid -match '^S-1-5-21-[\d-]+-(513|515)$')
}

function Get-LabTemplateExposure {
    <#
        Reduces a template ACL to the low-privileged principals that can enroll or modify it.
        Deny ACEs are deliberately not subtracted: findings err on the side of review.
    #>
    param([AllowEmptyCollection()] [object[]] $Acl = @())
    $enroll = @(); $write = @()
    foreach ($ace in @($Acl)) {
        if ($null -eq $ace -or $ace.Type -ne 'Allow' -or -not (Test-LabLowPrivilegedSid $ace.Sid)) { continue }
        $who = if ($ace.Principal) { [string]$ace.Principal } else { [string]$ace.Sid }
        $rights = [string]$ace.Rights
        $obj = ([string]$ace.ObjectType).ToLowerInvariant()
        $anyObject = ($obj -eq '' -or $obj -eq $script:EmptyGuid)
        if ($rights -match 'GenericAll' -or ($rights -match 'ExtendedRight' -and ($anyObject -or $obj -eq $script:RightEnroll -or $obj -eq $script:RightAutoEnroll))) { $enroll += $who }
        if ($rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner' -or ($rights -match 'WriteProperty' -and $anyObject)) { $write += $who }
    }
    [pscustomobject]@{ Enroll = @($enroll | Select-Object -Unique); Write = @($write | Select-Object -Unique) }
}

function Test-LabTemplateRisk {
    <#
        Pure evaluator for certificate templates. Input objects:
        Name, Published, EnrolleeSuppliesSubject, ManagerApproval, AuthorizedSignatures, Ekus[], Acl[]
        (Acl entries: Sid, Principal, Rights, ObjectType, Type).
    #>
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Templates)
    $a = 'ADCS'; $out = @()
    foreach ($t in @($Templates)) {
        if ($null -eq $t) { continue }
        $exp = Get-LabTemplateExposure -Acl $t.Acl
        $ekus = @($t.Ekus | Where-Object { $_ })
        $status = if ($t.Published) { 'FAIL' } else { 'WARN' }
        $where = if ($t.Published) { 'published on a CA' } else { 'not published (latent)' }
        $ungated = (-not $t.ManagerApproval) -and ([int]$t.AuthorizedSignatures -eq 0)
        $enrollers = $exp.Enroll -join ', '
        if ($ungated -and $exp.Enroll.Count -gt 0) {
            $authCapable = ($ekus.Count -eq 0) -or (@($ekus | Where-Object { $script:AuthEkus -contains $_ }).Count -gt 0)
            if ($t.EnrolleeSuppliesSubject -and $authCapable) {
                $out += New-LabCheckResult $a "ESC1 template '$($t.Name)'" $status "Requester supplies subject/SAN + authentication EKU; enrollable by $enrollers; no approval; $where. Impersonation of any user (ATT&CK T1649)"
            }
            if ($ekus.Count -eq 0 -or $ekus -contains $script:OidAnyPurpose) {
                $out += New-LabCheckResult $a "ESC2 template '$($t.Name)'" $status "Any Purpose / no EKU; enrollable by $enrollers; no approval; $where (ATT&CK T1649)"
            }
            if ($ekus -contains $script:OidRequestAgent) {
                $out += New-LabCheckResult $a "ESC3 template '$($t.Name)'" $status "Certificate Request Agent EKU; enrollable by $enrollers; enroll on behalf of others; $where (ATT&CK T1649)"
            }
        }
        if ($exp.Write.Count -gt 0) {
            $out += New-LabCheckResult $a "ESC4 template '$($t.Name)'" $status ("{0} can modify the template ACL/settings; $where (ATT&CK T1649)" -f ($exp.Write -join ', '))
        }
    }
    if ($out.Count -eq 0) {
        $out += New-LabCheckResult $a 'Template exposure (ESC1-ESC4)' 'PASS' ('{0} templates reviewed; none enrollable or writable by low-privileged principals in a dangerous configuration' -f @($Templates).Count)
    }
    $out
}

function Test-LabCaConfigRisk {
    param([object] $EditFlags, [object] $WebEnrollment)
    $a = 'ADCS'
    if ($null -eq $EditFlags) {
        New-LabCheckResult $a 'ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2' 'SKIP' 'CA policy EditFlags not readable (run on the CA host)'
    } elseif (([int64]$EditFlags -band $script:EditfSan2) -ne 0) {
        New-LabCheckResult $a 'ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2' 'FAIL' 'CA honours requester-supplied SANs on every template. Fix: certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 (ATT&CK T1649)'
    } else {
        New-LabCheckResult $a 'ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2' 'PASS' ('Not set (EditFlags 0x{0:X})' -f [int64]$EditFlags)
    }
    if ($null -eq $WebEnrollment) {
        New-LabCheckResult $a 'ESC8 Web enrollment (/certsrv)' 'SKIP' 'IIS configuration not readable'
    } elseif (-not $WebEnrollment.Installed) {
        New-LabCheckResult $a 'ESC8 Web enrollment (/certsrv)' 'PASS' 'AD CS Web Enrollment is not installed'
    } elseif ($WebEnrollment.Http) {
        New-LabCheckResult $a 'ESC8 Web enrollment (/certsrv)' 'FAIL' '/certsrv is reachable over HTTP: NTLM relay to the CA can mint certificates. Require HTTPS + Extended Protection (ATT&CK T1557, T1649)'
    } else {
        New-LabCheckResult $a 'ESC8 Web enrollment (/certsrv)' 'WARN' 'HTTPS only; confirm Extended Protection for Authentication is required and NTLM is disabled where possible'
    }
}

function Get-LabFirstValue {
    param($Values, $Default = $null)
    if ($null -ne $Values -and @($Values).Count -gt 0) { return @($Values)[0] }
    $Default
}

function Get-LabAdcsTemplate {
    <# Collector: reads templates and their ACLs from the AD configuration partition over LDAP. #>
    [CmdletBinding()]
    param()
    $cfg = [string](Get-LabFirstValue ([adsi]'LDAP://RootDSE').Properties['configurationNamingContext'])
    $pks = "CN=Public Key Services,CN=Services,$cfg"
    $published = @{}
    $es = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://CN=Enrollment Services,$pks", '(objectClass=pKIEnrollmentService)')
    foreach ($r in $es.FindAll()) { foreach ($n in $r.Properties['certificatetemplates']) { $published[[string]$n] = $true } }
    $ts = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://CN=Certificate Templates,$pks", '(objectClass=pKICertificateTemplate)')
    foreach ($r in $ts.FindAll()) {
        $p = $r.Properties
        $name = [string](Get-LabFirstValue $p['name'])
        $acl = @()
        foreach ($ace in $r.GetDirectoryEntry().ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $sid = $ace.IdentityReference.Value
            $principal = $sid
            try { $principal = $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { Write-Verbose "Unresolved SID $sid" }
            $acl += [pscustomobject]@{ Sid = $sid; Principal = $principal; Rights = [string]$ace.ActiveDirectoryRights; ObjectType = [string]$ace.ObjectType; Type = [string]$ace.AccessControlType }
        }
        $ekus = @($p['pkiextendedkeyusage']) + @($p['mspki-certificate-application-policy']) | Where-Object { $_ } | ForEach-Object { [string]$_ } | Select-Object -Unique
        [pscustomobject]@{
            Name                    = $name
            Published               = $published.ContainsKey($name)
            EnrolleeSuppliesSubject = (([int](Get-LabFirstValue $p['mspki-certificate-name-flag'] 0)) -band 1) -ne 0
            ManagerApproval         = (([int](Get-LabFirstValue $p['mspki-enrollment-flag'] 0)) -band 2) -ne 0
            AuthorizedSignatures    = [int](Get-LabFirstValue $p['mspki-ra-signature'] 0)
            Ekus                    = @($ekus)
            Acl                     = $acl
        }
    }
}

function Get-LabCaEditFlag {
    param([Parameter(Mandatory)] [string] $CaName)
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\' + $CaName + '\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy'
    Get-LabRegistryValue -Path $path -Name 'EditFlags'
}

function Get-LabWebEnrollmentState {
    try { Import-Module WebAdministration -ErrorAction Stop } catch { return $null }
    $app = Get-WebApplication -Name 'CertSrv' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $app) { return [pscustomobject]@{ Installed = $false; Http = $false } }
    $site = 'Default Web Site'
    if ("$($app.ItemXPath)" -match "@name='([^']+)'") { $site = $Matches[1] }
    $http = @(Get-WebBinding -Name $site -Protocol http -ErrorAction SilentlyContinue).Count -gt 0
    [pscustomobject]@{ Installed = $true; Http = $http }
}

function Invoke-LabAdcsAudit {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $CaName)
    try {
        $templates = @(Get-LabAdcsTemplate)
        New-LabCheckResult 'ADCS' 'Read certificate templates (LDAP)' 'PASS' ('{0} templates, {1} published' -f $templates.Count, @($templates | Where-Object Published).Count)
        Test-LabTemplateRisk -Templates $templates
    } catch {
        New-LabCheckResult 'ADCS' 'Read certificate templates (LDAP)' 'SKIP' $_.Exception.Message
    }
    $flags = $null; try { $flags = Get-LabCaEditFlag -CaName $CaName } catch { $flags = $null }
    $web = $null; try { $web = Get-LabWebEnrollmentState } catch { $web = $null }
    Test-LabCaConfigRisk -EditFlags $flags -WebEnrollment $web
}

# ---------------------------------------------------------------------------
# HTML report (self-contained, no external assets)
# ---------------------------------------------------------------------------

function ConvertTo-LabHtmlReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results,
        [string] $Title = 'Windows Enterprise PKI lab verification',
        [string] $Subtitle = '',
        [string] $Banner = ''
    )
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $count = @{}
    foreach ($s in 'PASS', 'WARN', 'FAIL', 'SKIP') { $count[$s] = @($Results | Where-Object Status -EQ $s).Count }
    $verdict = if ($count.FAIL -gt 0) { 'FAIL' } elseif ($count.WARN -gt 0) { 'WARN' } else { 'PASS' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(& $enc $Title)</title><style>
:root{--ink:#111;--mut:#666;--line:#d8d8d8;--bg:#fafafa;--PASS:#0a7d3e;--WARN:#a86400;--FAIL:#b3261e;--SKIP:#777}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 "DejaVu Sans Mono",Consolas,"JetBrains Mono",monospace}
main{max-width:1100px;margin:0 auto;padding:32px 28px 48px}h1{font-size:20px;letter-spacing:.5px;margin:0 0 4px;text-transform:uppercase}
.sub{color:var(--mut);margin:0 0 18px}.banner{border:1.5px dashed var(--ink);padding:8px 12px;margin:0 0 18px;font-weight:700}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:0 0 26px}.tile{background:#fff;border:1.6px solid var(--ink);padding:10px 12px}
.tile b{display:block;font-size:26px}.tile span{color:var(--mut);font-size:11px;letter-spacing:1.5px}
.v{border-width:2.6px}.v b{font-size:22px}h2{font-size:12px;letter-spacing:2px;color:var(--mut);margin:24px 0 8px}
table{width:100%;border-collapse:collapse;background:#fff;border:1.6px solid var(--ink)}td{padding:7px 10px;border-top:1px solid var(--line);vertical-align:top}
td.s{width:70px}td.c{width:36%;font-weight:700}td.d{color:#333;word-break:break-word}
.pill{display:inline-block;min-width:48px;text-align:center;color:#fff;font-weight:700;font-size:11px;padding:2px 6px}
.PASS{background:var(--PASS)}.WARN{background:var(--WARN)}.FAIL{background:var(--FAIL)}.SKIP{background:var(--SKIP)}
footer{margin-top:22px;color:var(--mut);font-size:12px}@media(max-width:720px){.tiles{grid-template-columns:repeat(2,1fr)}td.c{width:auto}}
</style></head><body><main>
<h1>$(& $enc $Title)</h1><p class="sub">$(& $enc $Subtitle)</p>
"@)
    if ($Banner) { [void]$sb.Append("<div class=`"banner`">$(& $enc $Banner)</div>") }
    [void]$sb.Append("<div class=`"tiles`"><div class=`"tile v`" style=`"border-color:var(--$verdict)`"><span>VERDICT</span><b style=`"color:var(--$verdict)`">$verdict</b></div>")
    foreach ($s in 'PASS', 'WARN', 'FAIL', 'SKIP') { [void]$sb.Append("<div class=`"tile`"><span>$s</span><b style=`"color:var(--$s)`">$($count[$s])</b></div>") }
    [void]$sb.Append('</div>')
    foreach ($group in ($Results | Group-Object Area)) {
        [void]$sb.Append("<h2>$(& $enc $group.Name)</h2><table>")
        foreach ($r in $group.Group) {
            [void]$sb.Append("<tr><td class=`"s`"><span class=`"pill $($r.Status)`">$($r.Status)</span></td><td class=`"c`">$(& $enc $r.Check)</td><td class=`"d`">$(& $enc $r.Detail)</td></tr>")
        }
        [void]$sb.Append('</table>')
    }
    [void]$sb.Append('<footer>Generated by the read-only 2026 reproducibility tooling of windows-enterprise-pki-lab. No private keys are read or exported.</footer></main></body></html>')
    $sb.ToString()
}

Export-ModuleMember -Function @(
    'New-LabCheckResult', 'Select-LabSigningRoot', 'Format-LabCheckResult', 'Write-LabSummary', 'Test-LabIsWindows',
    'Get-LabStoreCertificate', 'Test-LabRegistryKey', 'Get-LabRegistryValue',
    'Get-LabCommonName', 'Get-LabSanDnsName', 'Test-LabHasServerAuthEku', 'Test-LabSignedBy',
    'Find-LabRootCertificate', 'Find-LabServerCertificate', 'Test-LabServerCertificate', 'Test-LabRootCertificate',
    'Invoke-LabDomainCheck', 'Invoke-LabCaCheck', 'Invoke-LabTrustCheck', 'Invoke-LabCertificateCheck',
    'Get-LabAppliedGpoName', 'Get-LabCertificateTemplateInfo', 'Test-LabEnrolledCertificate',
    'Get-LabIisHttpsBinding', 'Get-LabBoundThumbprint', 'Invoke-LabTlsHandshake', 'Test-LabTlsResult', 'Invoke-LabIisTlsCheck',
    'Test-LabLowPrivilegedSid', 'Get-LabTemplateExposure', 'Test-LabTemplateRisk', 'Test-LabCaConfigRisk',
    'Get-LabAdcsTemplate', 'Get-LabCaEditFlag', 'Get-LabWebEnrollmentState', 'Invoke-LabAdcsAudit', 'ConvertTo-LabHtmlReport'
)
