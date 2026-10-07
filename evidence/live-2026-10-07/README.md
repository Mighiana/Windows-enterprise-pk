# Live-lab evidence, 2026-10-07

Raw output from the [two-VM rebuild](../../docs/live-lab.md). **Not** from the original May 2026 lab.

- `*.txt` is console output; `*.json` is the structured output of the same run.
- `*.html` was rendered later from the JSON by [`tools/Render-LiveEvidence.ps1`](../../tools/Render-LiveEvidence.ps1). Nothing is re-evaluated.
- Files were renamed into run order, trailing whitespace was trimmed and the host path was removed
  from `00-media-sha256.txt`. Nothing else was edited.
- Privacy: checked for passwords, SIDs, MAC addresses and personal names before commit. The
  `192.168.77.0/24` addresses are the host-only lab network.

| File | What |
|---|---|
| `00` | SHA-256 of the evaluation ISOs |
| `01` | Client verifier in WORKGROUP, before joining |
| `02` | Client: Group Policy root store before/after `gpupdate`, `gpresult` |
| `03` | Server baseline: auto-enrolled certificate bound to IIS, `verify-pki.ps1`, `audit-adcs.ps1` |
| `04` | `PKILabServerTLS` flags, EKU, lifetime, ACL, group members, published templates |
| `05`–`06` | Auto-enrolled certificates on SERVER and CLIENT, CA database rows, enrollment events, `gpresult` |
| `07` | Client verifier, valid certificate |
| `08` | Revoke + publish CRL |
| `09`–`12` | Stale HTTP CRL, CDP publication fix, served CRL (`openssl crl`), cached CRL, cache flush |
| `13`–`15` | Revoked certificate detected (client with and without `-CheckRevocation`; server) |
| `16`–`19` | Replacement certificate, recovery, final client check |
| `audit-matrix/1-*` | Controlled insecure AD CS state: audit, ground truth, `/certsrv` HTTP probe |
| `audit-matrix/2-*` | Same weaknesses remediated in place |
| `audit-matrix/3-*` | Test templates removed |
