# Original lab (May 2026)

The original **Windows PKI Lab** was completed manually on a Windows Server 2022 virtual
machine as university coursework. It was submitted as a 14-page PDF report dated
**2026-05-25** with 12 annotated screenshots.

The report is **not** published in this repository because it contains student identifiers.
Only sanitized screenshots selected from it are public, in [`../docs/screenshots/`](../docs/screenshots/).

There was **no source code, script, Git repository or infrastructure-as-code** in the original
lab. Every configuration step was performed by hand in Server Manager, MMC consoles,
IIS Manager, `cmd`/PowerShell and `certreq`.

## Original evidence index

| Report step | Content | Public? |
|---|---|---|
| 1 | `ipconfig /all`: static IP, DNS suffix `irb.local`, DNS server `127.0.0.1` | **No.** Contains the VM's MAC address and DHCPv6 DUID. The facts are summarized in the docs. |
| 2 | Server Manager: AD CS, AD DS, DNS, IIS roles | Yes: `01-server-manager-roles.png` |
| 3 | Active Directory Users and Computers: `irb.local` default containers | No. Low evidential value (default OUs only). |
| 4 | DNS Manager: `server` A record in the `irb.local` zone | Yes: `02-dns-a-record.png` |
| 5 | Certification Authority: `IRB-ADCS-RootCA` running | Yes: `03-enterprise-root-ca.png` |
| 6 | GPMC: `IRB Root CA Trust` linked to `irb.local` | Yes: `04-gpo-linked-to-domain.png` |
| 7 | GPO editor: root CA under Trusted Root Certification Authorities | Yes: `05-gpo-trusted-root-ca.png` (hypervisor frame cropped) |
| 8 | `certlm.msc` Personal: `server.irb.local` issued by `IRB-ADCS-RootCA` | Yes: `07-machine-certificate-personal-store.png` |
| 9 | `certlm.msc` Trusted Root: `IRB-ADCS-RootCA` present | Yes: `06-local-machine-trusted-root-store.png` |
| 10 | IIS Site Bindings: https `server.irb.local` :443 | Yes: `08-iis-https-binding-443.png` |
| 11 | Edge: "Connection is secure" | Yes: `09-edge-connection-secure.png` |
| 12 | Certificate Viewer: issued to / by, validity, SHA-256 fingerprints | Yes: `10-certificate-viewer-chain.png` |

## Sanitization applied

- Student name and student ID (they appear only in the PDF header/cover) are excluded, because the PDF is not published.
- Every published image was decoded and re-encoded as PNG from raw pixels, so **all EXIF, XMP and
  ICC metadata is removed**. Two source images carried author metadata that is not part of the evidence.
- Step 7 was cropped to the VM display, removing the hypervisor window chrome.
- No passwords, private keys or exported key material existed in the screenshots, and none are added
  here. The SHA-256 fingerprints visible in step 12 are public certificate data.
- The VM's private NAT address appears in the DNS screenshot. It is non-routable lab addressing.
