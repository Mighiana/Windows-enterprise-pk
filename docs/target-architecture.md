# Target production design (not implemented)

> **Design only, 2026.** This page describes how the single-VM lab would be rebuilt for a real
> enterprise. None of it was built in the original May 2026 lab or since. It exists to show the
> gap between a working lab trust chain and a defensible production PKI.

![Target production design: offline root, issuing CA, HTTP CDP + OCSP, GPO, hardened templates, monitoring](target-architecture.png)

Source: [`target-architecture.svg`](target-architecture.svg)

## Lab vs. target

| Area | Original lab (May 2026) | Target design | Why |
|---|---|---|---|
| CA hierarchy | One Enterprise Root CA on the domain controller | Offline standalone root + online enterprise issuing CA | A compromised online CA can be revoked by the root without rebuilding trust on every host |
| CA key protection | Software key on the CA host | HSM-backed keys; root ceremonies with two people | Key theft = ability to mint trusted identities for the whole domain |
| Role placement | CA, DC, DNS and IIS on one VM | CA on dedicated Tier 0 servers, never on a DC or web server | Limits blast radius; the DC and IIS are high-exposure hosts |
| Revocation | No CDP/AIA/OCSP design assessed | HTTP CDP + AIA (`pki.irb.local`), Online Responder (OCSP), short CRL + delta CRL | Relying parties must be able to reject a revoked certificate |
| Issuance | Manual `certreq` | GPO autoenrollment from hardened templates | Removes manual key handling and makes renewal automatic |
| Templates | Template not recorded | Server Auth only, subject built from AD, enrollment restricted to a group, no requester-supplied SAN | Closes ESC1-ESC4 paths |
| CA flags / web enrollment | Not reviewed | `EDITF_ATTRIBUTESUBJECTALTNAME2` off; no `/certsrv` over HTTP, Extended Protection on | Closes ESC6 and ESC8 |
| Trust distribution | GPO, observed on the same host | GPO to all hosts; GPO edit rights limited to Tier 0; NTAuth store controlled | Whoever can edit the trust GPO can push a rogue root (T1553.004) |
| Validation | Edge on the server itself | Separate domain clients, revocation checked | Proves the distribution path, not just the local store |
| TLS endpoint | `https :443` with `http :80` still bound | HTTP→HTTPS redirect, HSTS, TLS 1.2+ only | Removes the plaintext path |
| Monitoring | None | CA audit events 4886-4900 to a SIEM; scheduled `verify-pki.ps1` / `audit-adcs.ps1` | Detects certificate abuse and expiry before users do |

## Rollout order

1. Build and secure the offline root; publish its certificate and CRL to the HTTP CDP/AIA.
2. Build the issuing CA, sign it from the root, and enable CA auditing.
3. Stand up the Online Responder and confirm CDP/AIA/OCSP from a client (`certutil -url`, `certutil -verify -urlfetch`).
4. Duplicate and harden templates, publish only those, then run `scripts/audit-adcs.ps1` until it reports no FAIL.
5. Distribute trust and enable autoenrollment by GPO; confirm on a separate client.
6. Re-issue the IIS certificate from the issuing CA, enable redirect + HSTS, and run
   `scripts/verify-pki.ps1 -CheckRevocation` from a client.
7. Schedule both scripts with JSON output and alert on any FAIL.

## How the 2026 tooling maps to the design

| Control | Check |
|---|---|
| Hardened templates, CA flags, web enrollment | `audit-adcs.ps1`: ESC1, ESC2, ESC3, ESC4, ESC6, ESC8 |
| Leaf certificate quality | `verify-certificate.ps1`: SAN, EKU, validity, private key, signature against the signing root |
| Trust delivered by GPO | `verify-trust.ps1`: which physical store delivered the root |
| Revocation reachable | `verify-pki.ps1 -CheckRevocation` (TLS `Revocation status`) |
| Served = bound certificate | `verify-iis-tls.ps1` |

Not covered by the tooling: HSM configuration, root ceremony procedure, ESC5/ESC7 (CA object
and CA officer permissions), NTAuth store content, and SIEM rules.
