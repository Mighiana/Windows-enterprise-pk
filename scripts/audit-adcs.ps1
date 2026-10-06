#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only AD CS security audit for the lab CA (ESC1-ESC4, ESC6, ESC8).

.DESCRIPTION
    2026 REPRODUCIBILITY EXTENSION - not part of the original May 2026 lab.

    Reviews the misconfiguration classes described in "Certified Pre-Owned" (SpecterOps, 2021)
    that let low-privileged users obtain authentication certificates for other identities
    (MITRE ATT&CK T1649):
      ESC1  requester-supplied subject/SAN + authentication EKU + low-privileged enrollment
      ESC2  Any Purpose / no EKU template enrollable by low-privileged principals
      ESC3  Certificate Request Agent template enrollable by low-privileged principals
      ESC4  low-privileged principals can modify a template
      ESC6  CA flag EDITF_ATTRIBUTESUBJECTALTNAME2
      ESC8  AD CS Web Enrollment reachable over HTTP (NTLM relay)

    Reads LDAP (configuration partition), the CA policy registry key and IIS configuration.
    It changes nothing and does not request certificates. Deny ACEs are not subtracted, so a
    finding means "review this", not "exploit confirmed".

.EXAMPLE
    .\audit-adcs.ps1
.EXAMPLE
    .\audit-adcs.ps1 -OutputFormat Html -OutFile .\adcs-audit.html
#>
[CmdletBinding()]
param(
    [string] $CaName = 'IRB-ADCS-RootCA',
    [ValidateSet('Console', 'Json', 'Html')] [string] $OutputFormat = 'Console',
    [string] $OutFile = 'adcs-audit.html'
)

Import-Module (Join-Path $PSScriptRoot 'lib/PkiLab.psm1') -Force
if (-not (Test-LabIsWindows)) { Write-Error 'Run this on a domain-joined Windows host (ideally the CA).'; exit 2 }

$results = @(Invoke-LabAdcsAudit -CaName $CaName)

switch ($OutputFormat) {
    'Json' { $results | Select-Object Area, Check, Status, Detail | ConvertTo-Json -Depth 3 }
    'Html' {
        Set-Content -LiteralPath $OutFile -Encoding UTF8 -Value (ConvertTo-LabHtmlReport -Results $results -Title 'AD CS security audit' -Subtitle ('{0} - {1:u}' -f $CaName, (Get-Date).ToUniversalTime()))
        Write-Output "Wrote $OutFile"
    }
    default {
        Write-Host ("AD CS security audit - {0} ({1:u})" -f $CaName, (Get-Date).ToUniversalTime())
        Write-Host ''
        $results | Format-LabCheckResult
        Write-LabSummary -Results $results
    }
}

if (@($results | Where-Object Status -EQ 'FAIL').Count -gt 0) { exit 1 }
exit 0
