# Lab overview

Faithful description of the **original May 2026 lab**. Facts come from the lab report and
screenshots. Anything inferred is marked *(inference)*.

## Build sequence (original, manual)

| # | Step | Tooling used in the original lab |
|---|---|---|
| 1 | Static IPv4, DHCP off, DNS server = `127.0.0.1` | Network adapter settings; verified with `ipconfig /all` |
| 2 | Install AD DS, DNS, AD CS, IIS roles | Server Manager |
| 3 | Promote to DC of new forest `irb.local` | Server Manager AD DS configuration wizard |
| 4 | Confirm DNS zone `irb.local` and `server` A record | DNS Manager |
| 5 | Configure AD CS as **Enterprise Root CA** `IRB-ADCS-RootCA` | AD CS configuration wizard |
| 6 | Create GPO `IRB Root CA Trust`, link to `irb.local` | Group Policy Management |
| 7 | Import the CA certificate into the GPO's *Trusted Root Certification Authorities* | Group Policy Management Editor |
| 8 | Serve a simple test page from IIS *Default Web Site* | IIS |
| 9 | Generate a machine CSR with Subject + SAN, submit, accept | `certreq` |
| 10 | Bind the certificate to *Default Web Site* https :443, host `server.irb.local` | IIS Manager → Site Bindings |
| 11 | Browse `https://server.irb.local`, inspect the certificate | Microsoft Edge |

## Observed configuration

| Item | Observed value | Evidence |
|---|---|---|
| OS | Windows Server 2022 Standard Evaluation, build 20348 | Desktop watermark |
| Roles | AD CS, AD DS, DNS, File and Storage Services, IIS (5 roles) | Server Manager |
| Domain containers | Builtin, Computers, Domain Controllers, ForeignSecurityPrincipals, Managed Service Accounts, Users | ADUC (report step 3) |
| DNS | `irb.local` forward zone; `_msdcs.irb.local`; SOA/NS `server.irb.local`; A `server` | DNS Manager |
| CA | `IRB-ADCS-RootCA`, Enterprise Root, service running | certsrv |
| Root CA validity | issued by itself, expires 2036-05-25 | GPO editor |
| GPO | `IRB Root CA Trust`; link at `irb.local` enabled, not enforced; filtering = Authenticated Users; no WMI filter | GPMC |
| Server certificate | `CN=server.irb.local`; SAN `DNS=server.irb.local`; issuer `IRB-ADCS-RootCA`; 2026-05-25 07:27:29 → 2028-05-24 07:27:29 | Certificate viewer, report conclusion |
| IIS bindings | `http` `*:80` (no host); `https` `*:443` host `server.irb.local` | Site Bindings |
| Browser | Edge: "This site has a valid certificate, issued by a trusted authority" | Edge |

## Observations worth knowing

- **The root appears three times in the merged Trusted Root view.** `certlm.msc` shows a
  *logical* store that merges several physical stores. On an Enterprise CA host the root is
  typically present in the local registry store (CA setup), the Enterprise store (published to
  AD DS) and the Group Policy store (the GPO). *(inference: the physical stores were not
  inspected in the original lab.)* `verify-trust.ps1` reports exactly which physical stores
  hold it.
- **Because of this, the DC alone does not prove GPO delivery.** The CA host would trust its own
  root even without the GPO. The GPO configuration itself is evidenced (link + certificate in the
  policy). A second, separate domain member would demonstrate delivery conclusively. That is a
  natural next step and is listed as a limitation.
- **Two `server.irb.local` certificates** are in the Personal store, both issued by the CA
  *(inference: the request was submitted twice)*. IIS uses one of them. `verify-certificate.ps1`
  warns on duplicates and evaluates the IIS-bound one.
- **The SAN is what made Edge accept the certificate.** Chromium-based browsers ignore the CN
  for host name validation, so the "Connection is secure" result also confirms that the SAN is correct.
- **Certificate template not recorded.** An enterprise CA issues against a template, but the report
  does not name it. The 2-year validity is consistent with common web-server templates, but that
  is not evidence of which template was used.
