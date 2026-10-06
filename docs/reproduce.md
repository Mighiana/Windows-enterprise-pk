# Rebuild runbook

> **2026 REPRODUCIBILITY EXTENSION.** This runbook was written after the original lab. It
> reconstructs the documented end state. It is not a transcript of the original session.
> **Use only in an isolated lab VM. Take a snapshot first.**

Legend: **SCRIPT** = provided script (supports `-WhatIf`), **MANUAL** = documented command or GUI
step you run yourself, **CHECK** = read-only verification.

| # | Step | Kind |
|---|---|---|
| 0 | Fresh Windows Server 2022 VM, isolated network, snapshot | MANUAL |
| 1 | Static IP | MANUAL |
| 2 | Install roles | SCRIPT `reproduce/Install-LabRoles.ps1` |
| 3 | Promote to DC (`irb.local`) | MANUAL |
| 4 | Configure Enterprise Root CA | MANUAL |
| 5 | Trust GPO | MANUAL (GPMC) |
| 6 | Request the server certificate | SCRIPT `reproduce/New-ServerCertificateRequest.ps1` + `certreq` |
| 7 | IIS https binding | SCRIPT `reproduce/Set-IisHttpsBinding.ps1` |
| 8 | Verify | CHECK `verify-pki.ps1` |

### 1. Static IP (MANUAL)

Use addresses from your own isolated lab network:

```powershell
$if = (Get-NetAdapter | Where-Object Status -EQ 'Up' | Select-Object -First 1).Name
New-NetIPAddress -InterfaceAlias $if -IPAddress <lab-ip> -PrefixLength 24 -DefaultGateway <lab-gw>
Set-DnsClientServerAddress -InterfaceAlias $if -ServerAddresses 127.0.0.1
Rename-Computer -NewName server -Restart
```

### 2. Roles (SCRIPT)

```powershell
.\scripts\reproduce\Install-LabRoles.ps1 -WhatIf
.\scripts\reproduce\Install-LabRoles.ps1
```

### 3. Domain controller (MANUAL, not scripted on purpose)

Creates a new forest. Irreversible without demotion. The DSRM password is prompted and never stored:

```powershell
Install-ADDSForest -DomainName irb.local -DomainNetbiosName IRB -InstallDns `
    -SafeModeAdministratorPassword (Read-Host -AsSecureString 'DSRM password')
```

### 4. Enterprise Root CA (MANUAL)

```powershell
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName 'IRB-ADCS-RootCA' `
    -ValidityPeriod Years -ValidityPeriodUnits 10 -HashAlgorithmName SHA256 -KeyLength 2048
```

The 10-year validity matches the observed root expiry (2036-05-25). The original key length
and hash algorithm were not recorded; SHA256/2048 is a 2026 choice.

### 5. Trust GPO (MANUAL)

```powershell
New-GPO -Name 'IRB Root CA Trust' | New-GPLink -Target 'DC=irb,DC=local' -LinkEnabled Yes
certutil -ca.cert C:\pki\IRB-ADCS-RootCA.cer     # public certificate only
```

Then in **Group Policy Management Editor** on `IRB Root CA Trust`:
*Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies →
Trusted Root Certification Authorities → Import…* → `C:\pki\IRB-ADCS-RootCA.cer`.
Apply with `gpupdate /force`.

To demonstrate delivery beyond the original lab, join a second VM to `irb.local` and run
`.\scripts\verify-trust.ps1` there. It should report `Root delivered by Group Policy: PASS`.

### 6. Server certificate (SCRIPT + certreq)

```powershell
.\scripts\reproduce\New-ServerCertificateRequest.ps1 -OutFile C:\pki\server.inf
certreq -new    C:\pki\server.inf C:\pki\server.req
certreq -submit -config "$env:COMPUTERNAME\IRB-ADCS-RootCA" C:\pki\server.req C:\pki\server.cer
certreq -accept C:\pki\server.cer
```

The INF requests template `WebServer` (a 2026 choice; override with `-Template`).

### 7. IIS binding (SCRIPT)

```powershell
.\scripts\reproduce\Set-IisHttpsBinding.ps1 -WhatIf
.\scripts\reproduce\Set-IisHttpsBinding.ps1
```

### 8. Verify (CHECK)

```powershell
.\scripts\verify-pki.ps1
```

Exit code `0` = no FAIL, `1` = at least one FAIL, `2` = not running on Windows.
