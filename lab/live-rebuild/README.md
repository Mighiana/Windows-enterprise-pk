# Live rebuild scripts (2026)

> **2026 LIVE-LAB EXTENSION.** The scripts used for the [two-VM rebuild](../../docs/live-lab.md) on
> 2026-10-07. Use only on an isolated host-only network with evaluation media.

## Host (Linux + QEMU/KVM)

| File | What |
|---|---|
| [`network.sh`](network.sh) | Host-only bridge `pkibr0` (192.168.77.1/24) + taps `pki-srv`, `pki-cli`. No NAT. |
| [`provision.py`](provision.py) | Generates a random lab password, unattend files and bootstrap ISOs, creates disks. Writes only to `private/` (git-ignored). Expects the ISOs in `media/` (git-ignored). |
| [`start-vm.py`](start-vm.py) | Boots `server` or `client` (client gets a software TPM for Windows 11) |
| [`qmp.py`](qmp.py) | QEMU monitor helper (screenshots, key presses during setup) |
| [`await-winrm.py`](await-winrm.py), [`await-domain.py`](await-domain.py) | Wait for WinRM / AD to come up |
| [`remote.py`](remote.py) | Runs a PowerShell file on a VM over WinRM (`pywinrm`), using the private credentials |

## Guest (run in order)

| Step | VM | Script |
|---|---|---|
| 1 | SERVER | [`guest/01-prepare-server.ps1`](guest/01-prepare-server.ps1) — roles + new forest `irb.local` (reboots) |
| 2 | SERVER | [`guest/02-configure-ca.ps1`](guest/02-configure-ca.ps1) — Enterprise Root CA, CDP/AIA over HTTP, trust + auto-enrollment GPOs, default templates unpublished |
| 3 | CLIENT | [`guest/03-join-client.ps1`](guest/03-join-client.ps1) — join `irb.local` (reboots) |
| 4 | SERVER | [`guest/04-configure-template.ps1`](guest/04-configure-template.ps1) — hardened `PKILabServerTLS`, `PKITLSAutoenroll` group, publish |
| 5 | both | [`guest/05-trigger-autoenrollment.ps1`](guest/05-trigger-autoenrollment.ps1) — `gpupdate` + `certutil -pulse` |
| 6 | both | [`guest/06-collect-enrollment.ps1`](guest/06-collect-enrollment.ps1) — evidence: enrolled certificates |
| — | SERVER | `scripts/reproduce/Set-IisHttpsBinding.ps1` — bind the auto-enrolled certificate |
| 7 | SERVER | [`guest/07-revoke-certificate.ps1`](guest/07-revoke-certificate.ps1) `-SerialNumber <serial>` |
| 8 | relying party | [`guest/08-flush-crl-cache.ps1`](guest/08-flush-crl-cache.ps1) |
| 9 | SERVER | [`guest/09-replace-iis-certificate.ps1`](guest/09-replace-iis-certificate.ps1) `-RevokedThumbprint <thumbprint>` |
| 10 | SERVER | [`guest/10-template-report.ps1`](guest/10-template-report.ps1) — evidence: template settings and ACL |
| 11 | SERVER | `scripts/lab/Set-AdcsAuditTestMatrix.ps1 -State Insecure|Remediated|Removed -IsolatedLab`, each followed by `scripts/audit-adcs.ps1 -OutputFormat Json` and [`guest/11-audit-matrix-ground-truth.ps1`](guest/11-audit-matrix-ground-truth.ps1) |

The verifiers (`scripts/verify-pki.ps1` on SERVER, `scripts/verify-client.ps1` on CLIENT) were run
between the steps; see the [evidence index](../../evidence/live-2026-10-07/README.md).
[`guest/install-tooling.ps1`](guest/install-tooling.ps1) copies `scripts/` to a VM from a
host-only HTTP server.

### Differences from what was literally typed on 2026-10-07

These are the same commands, tidied for reuse:

- Serial numbers and thumbprints that were hard-coded in the revoke/replace scripts are now parameters.
- CA setup was run as two scripts; they are merged into `02-configure-ca.ps1`. The CDP list in it
  already includes `C:\pki\publication`. In the live run that entry was only added after the
  revocation test exposed the gap (evidence `09`–`10`).
- Comment headers were added.
