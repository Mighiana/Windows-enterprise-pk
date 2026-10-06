# Security model

## Trust model

```
IRB-ADCS-RootCA (self-signed, trust anchor)
   │  trust anchor distributed by: GPO "IRB Root CA Trust" → LocalMachine\Root on domain computers
   │
   └── signs ──► CN=server.irb.local  (SAN DNS=server.irb.local, EKU Server Authentication)
                    private key: LocalMachine, on server.irb.local only
                    presented by: IIS https :443
```

A client trusts `https://server.irb.local` only if **all** of the following hold. Each is
checked by the 2026 `verify-pki.ps1`:

1. The name resolves (DNS A record) and the client connects to that host.
2. The presented certificate's SAN contains the requested name.
3. The certificate is within its validity period and permits Server Authentication.
4. The certificate's signature chains to a root in the client's trusted root store.
5. That root is present because policy (the GPO) put it there, not because a user clicked "trust".

## Threats and controls (as demonstrated)

| Threat | Control | Where it was demonstrated |
|---|---|---|
| Untrusted internal server certificate (self-signed, per-server trust) | Enterprise CA issues service certificates; the domain trusts one root | CA console, certificate viewer |
| Manual, inconsistent trust configuration on each client | GPO-based root CA distribution | GPMC link + GPO editor |
| Host name mismatch / impersonation with a certificate for another name | SAN `DNS=server.irb.local` matches the DNS name and IIS host header | Certificate viewer, IIS bindings |
| Unencrypted HTTP traffic | IIS HTTPS binding on :443 | IIS bindings, Edge |
| Unknown or forged certificate chain | Client chain validation to `IRB-ADCS-RootCA` | Edge "Connection is secure" |

## Key handling

- CA and server private keys were generated on the server and never exported in the lab.
- This repository contains **no** certificates, private keys, PFX files or passwords.
  `.gitignore` blocks common key and certificate file types.
- The verification scripts read only `HasPrivateKey`. They never open, read or export a key.
- `New-ServerCertificateRequest.ps1` sets `Exportable = FALSE` and `MachineKeySet = TRUE`.

## Not covered (by design of the lab)

| Area | Status |
|---|---|
| Offline root + issuing subordinate CA | Not implemented (single-tier) |
| HSM-protected CA keys | Not implemented |
| CRL distribution / OCSP / AIA design | Not assessed; the verifier skips revocation unless `-CheckRevocation` is used |
| Auto-enrollment, renewal and expiry monitoring | Not implemented |
| HTTP → HTTPS redirect, HSTS, cipher-suite and protocol hardening | Not implemented (`http :80` remained bound) |
| CA role separation, auditing, template ACL review (e.g. ESC-style misconfigurations) | Not assessed |

## ATT&CK mapping (2026 extension)

| Technique | How it applies to this design | Control / check |
|---|---|---|
| [T1649](https://attack.mitre.org/techniques/T1649/) Steal or Forge Authentication Certificates | Misconfigured templates or CA flags let a low-privileged user request a certificate for another identity (ESC1-ESC4, ESC6) | `scripts/audit-adcs.ps1`; CA audit events 4886/4887 |
| [T1557](https://attack.mitre.org/techniques/T1557/) Adversary-in-the-Middle | NTLM relay to AD CS Web Enrollment over HTTP (ESC8); TLS interception with an untrusted certificate | `audit-adcs.ps1` ESC8; client-side chain validation in `verify-iis-tls.ps1` |
| [T1553.004](https://attack.mitre.org/techniques/T1553/004/) Subvert Trust Controls: Install Root Certificate | The same GPO path that distributes `IRB-ADCS-RootCA` can push a rogue root to every domain computer if its edit rights are too broad | Restrict edit rights on `IRB Root CA Trust`; `verify-trust.ps1` reports which store delivered the root |

The audit evaluates ACLs conservatively: it does not subtract Deny ACEs. A finding means "review
this template", not "exploitation confirmed". Background: SpecterOps, *Certified Pre-Owned* (2021).
