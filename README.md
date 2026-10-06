# Windows Enterprise PKI & Certificate Trust Lab

![Windows Server 2022](https://img.shields.io/badge/Windows%20Server-2022-111?style=flat-square)
![AD CS](https://img.shields.io/badge/AD%20CS-Enterprise%20Root%20CA-111?style=flat-square)
![Group Policy](https://img.shields.io/badge/Group%20Policy-trust%20distribution-111?style=flat-square)
![IIS](https://img.shields.io/badge/IIS-HTTPS%20%3A443-111?style=flat-square)
![Status](https://img.shields.io/badge/status-completed%20lab%20%2B%202026%20extension-0a7d3e?style=flat-square)

An Active Directory-integrated public key infrastructure built on Windows Server 2022.
An AD CS **Enterprise Root CA** issues a machine certificate. **Group Policy** distributes
trust in that root. **IIS** serves HTTPS with the issued certificate, and Microsoft Edge connects
to `https://server.irb.local` with **no certificate warning**.

> **Provenance.** This repository documents and reproduces a Windows Enterprise PKI lab
> originally completed in **May 2026** as part of university coursework. The original
> implementation was performed manually in Windows Server 2022 and is preserved through the
> accompanying lab evidence. The repository itself was created later (October 2026) to
> organize the documentation and provide a reproducible portfolio version of the environment.
> Everything under [`scripts/`](scripts/) and [`tests/`](tests/) is a
> **2026 reproducibility extension** and was **not** part of the original lab.
> See [Repository provenance](#repository-provenance).

---

## Overview

| | |
|---|---|
| **Domain** | `irb.local` (lab-only domain) |
| **Server** | `server.irb.local`: Windows Server 2022 Standard (evaluation), single VM |
| **Roles** | AD DS · DNS · AD CS (Certification Authority) · IIS |
| **CA** | `IRB-ADCS-RootCA`: Enterprise Root CA, self-signed, valid to 2036-05-25 |
| **Trust GPO** | `IRB Root CA Trust`, linked to `irb.local` |
| **Service certificate** | `CN=server.irb.local`, SAN `DNS=server.irb.local`, valid 2026-05-25 → 2028-05-24 |
| **Endpoint** | IIS *Default Web Site*, `https` · `server.irb.local` · `:443` |
| **Result** | Edge: *"Connection is secure: valid certificate, issued by a trusted authority"* |

## Problem / security goal

Enterprise environments need an internal trust model to authenticate services and encrypt
internal traffic. Trusting individual self-signed certificates one by one doesn't scale.

This lab implements an AD-integrated PKI with AD CS. It distributes trust in the root CA through
Group Policy, issues a machine certificate to a domain server, binds that certificate to IIS and
verifies that the client trusts the HTTPS service without certificate warnings.

It is a **lab** PKI that demonstrates the trust chain end to end. It is **not** a production PKI design
(see [Limitations](#limitations)).

## Architecture

![Architecture: AD DS, DNS, GPO, Enterprise Root CA, machine certificate, IIS :443, Edge](docs/architecture.png)

```
ACTIVE DIRECTORY DOMAIN  irb.local          (all roles on server.irb.local, Windows Server 2022)
        │
        ├── DNS ─────────────── A  server.irb.local → static IPv4
        │
        ├── GROUP POLICY ─────  GPO "IRB Root CA Trust" (linked to irb.local)
        │        └── Trusted Root Certification Authorities ← IRB-ADCS-RootCA
        │
        └── AD CS  ENTERPRISE ROOT CA  IRB-ADCS-RootCA
                 │ issues (certreq)
                 ▼
          SERVER CERTIFICATE  CN / SAN = server.irb.local   (LocalMachine\My + private key)
                 │ bound
                 ▼
          IIS  Default Web Site  https :443
                 │ TLS
                 ▼
          DOMAIN MEMBER / EDGE  https://server.irb.local   (same host in this lab)
                 │
                 ▼
          TRUSTED CONNECTION: chain ends at IRB-ADCS-RootCA, no warning
```

Source: [`docs/architecture.svg`](docs/architecture.svg). Details: [`docs/lab-overview.md`](docs/lab-overview.md).

## Lab environment

| Component | Value (from the original lab evidence) |
|---|---|
| Hypervisor | VMware (single VM, NAT network) |
| OS | Windows Server 2022 Standard Evaluation, build 20348 |
| Host name / FQDN | `server` / `server.irb.local` |
| Addressing | Static private IPv4, DHCP disabled, DNS server = `127.0.0.1` |
| Installed roles | AD CS, AD DS, DNS, File and Storage Services, IIS |
| Client used for verification | Microsoft Edge **on the same server** |

## Active Directory foundation

The server was given a static address, then promoted to the first domain controller of a new
forest, `irb.local`. AD-integrated DNS hosts the `irb.local` zone with the `server` A record.
That record matters later because the name clients resolve must match the certificate's SAN.

<img src="docs/screenshots/01-server-manager-roles.png" width="640" alt="Server Manager: AD CS, AD DS, DNS, IIS roles installed">

## Enterprise Root CA

AD CS was installed and configured as an **Enterprise Root CA** named `IRB-ADCS-RootCA`.
Because it is an *enterprise* CA, its configuration and root certificate are integrated with
Active Directory. That CA signed the IIS server certificate.

<img src="docs/screenshots/03-enterprise-root-ca.png" width="640" alt="Certification Authority console: IRB-ADCS-RootCA running">

## Trust distribution with Group Policy

A dedicated GPO, **`IRB Root CA Trust`**, is linked to the `irb.local` domain (link enabled,
security filtering: *Authenticated Users*). The CA certificate was imported into:

```
Computer Configuration
 → Policies
   → Windows Settings
     → Security Settings
       → Public Key Policies
         → Trusted Root Certification Authorities
```

**Why it matters:** every domain-joined computer that applies the GPO trusts the enterprise CA
automatically. Nobody has to import the root by hand on each machine, and the trust decision is
managed centrally, so it can also be revoked centrally.

| GPO linked to the domain | Root CA inside the GPO |
|---|---|
| <img src="docs/screenshots/04-gpo-linked-to-domain.png" alt="GPMC: IRB Root CA Trust linked to irb.local"> | <img src="docs/screenshots/05-gpo-trusted-root-ca.png" alt="GPO editor: IRB-ADCS-RootCA under Trusted Root Certification Authorities"> |

On the server, `certlm.msc` shows `IRB-ADCS-RootCA` in the local machine
*Trusted Root Certification Authorities* store.

> **Scope of the evidence:** the lab had a single VM, so the GPO effect was observed on the domain
> controller itself. Delivery to a *separate* domain client was not recorded. Certificate
> **auto-enrollment** was not configured; the server certificate was requested manually.

## Certificate request and issuance

The machine certificate was requested with **`certreq`** in the local-machine context:

| Field | Value |
|---|---|
| Subject | `CN=server.irb.local` |
| Subject Alternative Name | `DNS=server.irb.local` |
| Issuer | `IRB-ADCS-RootCA` |
| Validity | 2026-05-25 → 2028-05-24 |
| Store | `Cert:\LocalMachine\My` (Personal), linked to its private key after `certreq -accept` |

The original report does not record the certificate template or the INF file used.
This repository does not invent them.
[`scripts/reproduce/New-ServerCertificateRequest.ps1`](scripts/reproduce/New-ServerCertificateRequest.ps1)
is a 2026 reconstruction that produces the same Subject and SAN.

<img src="docs/screenshots/07-machine-certificate-personal-store.png" width="640" alt="certlm Personal store: server.irb.local issued by IRB-ADCS-RootCA">

## IIS HTTPS configuration

The certificate was bound to the IIS **Default Web Site** as an `https` binding on port **443**
with host name `server.irb.local`. TLS then protects browser-to-server traffic. The original
`http :80` binding was left in place (see Limitations).

<img src="docs/screenshots/08-iis-https-binding-443.png" width="640" alt="IIS Site Bindings: https server.irb.local 443">

## Trust chain verification

Edge opened `https://server.irb.local` and showed
**"Connection is secure"** with no warning. The certificate viewer shows the chain ending at the
enterprise root.

| Connection is secure | Certificate viewer |
|---|---|
| <img src="docs/screenshots/09-edge-connection-secure.png" alt="Edge: Connection is secure for https://server.irb.local"> | <img src="docs/screenshots/10-certificate-viewer-chain.png" alt="Certificate Viewer: Issued To server.irb.local, Issued By IRB-ADCS-RootCA"> |

## Validation evidence

The evidence chain from the original lab, and the 2026 automated check that re-tests each link:

| # | Claim | Original evidence | `verify-pki.ps1` check |
|---|---|---|---|
| 01 | DNS resolves `server.irb.local` | [DNS A record](docs/screenshots/02-dns-a-record.png) | `DNS` · A record for server.irb.local |
| 02 | Enterprise Root CA is trusted | [Trusted Root store](docs/screenshots/06-local-machine-trusted-root-store.png), [GPO](docs/screenshots/05-gpo-trusted-root-ca.png) | `TRUST` · Root CA in LocalMachine\Root · Root delivered by Group Policy |
| 03 | Server certificate issued by `IRB-ADCS-RootCA` | [Personal store](docs/screenshots/07-machine-certificate-personal-store.png) | `CERT` · Issued by enterprise CA · Signed by trusted root |
| 04 | Subject / SAN match `server.irb.local` | [Certificate viewer](docs/screenshots/10-certificate-viewer-chain.png), report | `CERT` · Subject CN matches FQDN · SAN contains DNS name |
| 05 | Certificate installed with its private key | Personal store (key icon), report | `CERT` · Associated private key present |
| 06 | IIS uses the certificate on port 443 | [IIS bindings](docs/screenshots/08-iis-https-binding-443.png) | `IIS` · HTTPS binding · Bound certificate matches host name |
| 07 | Browser connects to `https://server.irb.local` | [Edge](docs/screenshots/09-edge-connection-secure.png) | `TLS` · TLS handshake · HTTPS response |
| 08 | No certificate warning | [Edge](docs/screenshots/09-edge-connection-secure.png) | `TLS` · Client trusts certificate (no warning) |
| 09 | Chain ends at the trusted enterprise root | [Certificate viewer](docs/screenshots/10-certificate-viewer-chain.png) | `TLS` · Served certificate = IIS-bound certificate |

## Security concepts demonstrated

- **PKI trust hierarchy:** a self-signed root anchors trust; the leaf is trusted only through it.
- **Enterprise Root CA:** an AD CS CA integrated with AD DS (vs. a standalone CA).
- **Certificate issuance:** CSR (PKCS#10) → CA signature → acceptance into the machine store.
- **Public/private key relationship:** the private key never leaves the server; the certificate binds the public key to a name.
- **Subject Alternative Name:** browsers validate the host name against the SAN, not the CN.
- **Certificate trust stores:** `LocalMachine\My` (service identity) vs. `LocalMachine\Root` (trust anchors).
- **Group Policy trust distribution:** central, revocable trust configuration for domain computers.
- **TLS / HTTPS:** an IIS binding on :443 with the issued certificate.
- **DNS ↔ certificate name relationship:** the resolved FQDN = the SAN = the IIS host header.
- **Certificate chain validation:** the browser builds and validates the chain to a trusted root.
- **Active Directory integration:** domain, DNS, GPO and CA all live in one AD trust boundary.

| Threat | Control demonstrated |
|---|---|
| Untrusted internal server certificate | Enterprise CA + domain trust |
| Manual trust configuration on every client | GPO-based root CA distribution |
| Certificate host name mismatch | SAN `DNS=server.irb.local` |
| Unencrypted HTTP traffic | IIS HTTPS binding on :443 |
| Unknown or forged certificate chain | Client-side chain validation to `IRB-ADCS-RootCA` |

More detail: [`docs/security-model.md`](docs/security-model.md).

## Screenshots

All public screenshots come from the original May 2026 lab. Before publishing they were
**re-encoded with all metadata removed** (EXIF/XMP/ICC). One frame was cropped to remove the
hypervisor window. No student identifiers appear in any image.

| | |
|---|---|
| [01 Server Manager roles](docs/screenshots/01-server-manager-roles.png) | [06 Local machine Trusted Root store](docs/screenshots/06-local-machine-trusted-root-store.png) |
| [02 DNS A record](docs/screenshots/02-dns-a-record.png) | [07 Machine certificate (Personal)](docs/screenshots/07-machine-certificate-personal-store.png) |
| [03 Enterprise Root CA](docs/screenshots/03-enterprise-root-ca.png) | [08 IIS HTTPS :443 binding](docs/screenshots/08-iis-https-binding-443.png) |
| [04 GPO linked to irb.local](docs/screenshots/04-gpo-linked-to-domain.png) | [09 Edge: connection is secure](docs/screenshots/09-edge-connection-secure.png) |
| [05 GPO: Trusted Root CA](docs/screenshots/05-gpo-trusted-root-ca.png) | [10 Certificate viewer](docs/screenshots/10-certificate-viewer-chain.png) |

## Reproducibility

> **2026 REPRODUCIBILITY EXTENSION.** Created after the lab, not part of the original
> university submission. Nothing here was used to build the original environment.

The extension is **verification first**. Provisioning a domain controller or a CA is hard to
undo, so those steps stay documented manual steps rather than scripts.

| Path | Kind | What it does |
|---|---|---|
| [`scripts/verify-pki.ps1`](scripts/verify-pki.ps1) | **read-only** | Full evidence chain, `PASS` / `WARN` / `FAIL` / `SKIP` per check, exit code 1 on any FAIL, `-OutputFormat Json` |
| [`scripts/verify-domain.ps1`](scripts/verify-domain.ps1) | read-only | OS, roles, domain membership, DC role, DNS A record, static IP |
| [`scripts/verify-ca.ps1`](scripts/verify-ca.ps1) | read-only | `CertSvc` running, active CA name, CA type = Enterprise Root |
| [`scripts/verify-trust.ps1`](scripts/verify-trust.ps1) | read-only | Root in `LocalMachine\Root`, *which* physical store delivered it (Group Policy / Enterprise / local), GPO exists and is linked |
| [`scripts/verify-certificate.ps1`](scripts/verify-certificate.ps1) | read-only | Issuer, Subject, SAN, validity / expiry warning, private key present, Server Auth EKU, signature against the root |
| [`scripts/verify-iis-tls.ps1`](scripts/verify-iis-tls.ps1) | read-only | IIS https binding + bound thumbprint, live TLS handshake validated by the Windows trust store, HTTP status |
| [`scripts/reproduce/Install-LabRoles.ps1`](scripts/reproduce/Install-LabRoles.ps1) | changes system · `-WhatIf` · confirm | Installs role binaries only (no promotion) |
| [`scripts/reproduce/New-ServerCertificateRequest.ps1`](scripts/reproduce/New-ServerCertificateRequest.ps1) | writes a file | `certreq` INF with Subject + SAN, non-exportable machine key |
| [`scripts/reproduce/Set-IisHttpsBinding.ps1`](scripts/reproduce/Set-IisHttpsBinding.ps1) | changes system · `-WhatIf` · confirm | Creates/updates the IIS https binding with the matching certificate |

```powershell
# On server.irb.local, elevated Windows PowerShell 5.1 or PowerShell 7
Set-Location .\scripts
.\verify-pki.ps1
.\verify-pki.ps1 -OutputFormat Json > pki-report.json
```

Example console line format (illustrative, not a captured run):

```
[PASS] CERT     SAN contains DNS name - DNS=server.irb.local
[WARN] IIS      Plain HTTP binding - *:80: still served over HTTP (no redirect/HSTS configured by this lab)
[PASS] TLS      Client trusts certificate (no warning) - Name and chain validated by the Windows trust store
```

The full rebuild runbook (script steps and manual steps) is in [`docs/reproduce.md`](docs/reproduce.md).

**How the tooling is tested.** `tests/PkiLab.Tests.ps1` (Pester 5) generates a root CA and
leaf certificates in memory and mocks Windows-only cmdlets. It also runs a live local TLS server
to exercise the handshake check. CI runs PSScriptAnalyzer and Pester on PowerShell 7 (Linux,
Windows) and Windows PowerShell 5.1. **The scripts have not yet been run against a rebuilt
`irb.local` lab VM.** Treat them as tested tooling, not as recorded evidence from the original lab.

## Lessons / technical decisions

| Decision | Reason |
|---|---|
| **Enterprise Root CA** (not standalone) | Integrates the CA with AD DS so trust and issuance live in the domain's trust boundary. |
| **GPO-based trust distribution** | Domain computers trust the root without manual import on each machine. Central control, central removal. |
| **SAN-based certificate** | Browsers validate the host name against the SAN, so `DNS=server.irb.local` must match the name clients use. |
| **Machine (LocalMachine) certificate store** | The certificate identifies the *server*, not a user. IIS reads it from `LocalMachine\My`. |
| **HTTPS on port 443 with a host name** | Tests the whole chain in a real service: DNS → TLS → chain → browser UI. |
| **Static IP + local DNS** | AD DS and certificate names depend on stable name resolution. |
| *(2026)* **Verification over provisioning** | Read-only checks are safe to run repeatedly. Automating DC promotion and CA setup is fragile and hard to undo. |

## Limitations

- Single lab VM: CA, DC, DNS, IIS and the browser all run on `server.irb.local`.
- Single-tier PKI: no offline root, no subordinate/issuing CA hierarchy.
- No HSM; CA keys are software keys on the CA host.
- No OCSP responder or CRL/AIA design was assessed.
- No certificate auto-enrollment; the certificate was requested manually with `certreq`.
- No advanced certificate lifecycle automation (renewal, monitoring, revocation drills).
- GPO trust delivery to a *separate* client was not demonstrated.
- `http :80` stayed bound: no HTTP→HTTPS redirect, no HSTS, no TLS cipher/protocol hardening review.
- Two `server.irb.local` certificates are present in the Personal store (likely a repeated request). Only the IIS-bound one matters, but cleanup was not documented.
- No production hardening assessment. **Not** intended as a production PKI architecture.

## Repository provenance

| | Original lab | 2026 reproducibility extension |
|---|---|---|
| **When** | May 2026 (report dated 2026-05-25) | October 2026 |
| **What** | Manual configuration in Windows Server 2022 GUI/CLI, documented in a PDF report with screenshots | This repository: docs, diagram, sanitized screenshots, PowerShell verification + helper scripts, tests, CI |
| **Source code / Git history** | None. The lab had no repository, scripts or infrastructure-as-code. | First commit in this repository, October 2026. No backdated history. |

The unsanitized original report is **not** published. See [`original-lab/README.md`](original-lab/README.md)
for what was in it and how the public evidence was selected and sanitized.

## License

[MIT](LICENSE) for the scripts and documentation. Screenshots are original lab captures by the author.
