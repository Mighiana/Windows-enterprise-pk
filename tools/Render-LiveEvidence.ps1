#Requires -Version 5.1
<#
.SYNOPSIS
    Renders the recorded JSON results of the October 2026 live rebuild as HTML reports.

.DESCRIPTION
    2026 LIVE-LAB EXTENSION. Input is the JSON that verify-*.ps1 / audit-adcs.ps1 printed on the
    lab VMs (evidence/live-2026-10-07). Nothing is re-evaluated here; the HTML only re-formats it.
#>
[CmdletBinding()]
param([string] $EvidencePath = (Join-Path $PSScriptRoot '../evidence/live-2026-10-07'))

Import-Module (Join-Path $PSScriptRoot '../scripts/lib/PkiLab.psm1') -Force
$banner = 'Live lab, 2026-10-07 (two-VM rebuild). Re-rendered from the JSON recorded on the VM.'
$reports = [ordered]@{
    '19-client-verify-final'                 = @('CLIENT: final verification', 'client.irb.local -> https://server.irb.local (template enrollment + revocation checked)')
    '13-client-verify-revoked'               = @('CLIENT: after revoking the IIS certificate', 'CRL published, client CRL cache flushed, -CheckRevocation')
    '17-client-verify-after-replacement'     = @('CLIENT: after replacing the revoked certificate', 'New PKILabServerTLS certificate bound to IIS')
    '18-server-verify-after-replacement'     = @('SERVER: full verification after replacement', 'verify-pki.ps1 -CheckRevocation on server.irb.local')
    'audit-matrix/1-insecure-audit'          = @('AD CS audit: controlled insecure state', 'LabTest-ESC1..4 templates, EDITF_ATTRIBUTESUBJECTALTNAME2, Web Enrollment over HTTP')
    'audit-matrix/2-remediated-audit'        = @('AD CS audit: remediated in place', 'Same templates, each weakness fixed')
}
foreach ($name in $reports.Keys) {
    $results = Get-Content -Raw -Path (Join-Path $EvidencePath "$name.json") | ConvertFrom-Json
    $html = ConvertTo-LabHtmlReport -Results @($results) -Title $reports[$name][0] -Subtitle $reports[$name][1] -Banner $banner
    Set-Content -Path (Join-Path $EvidencePath "$name.html") -Value $html -Encoding UTF8
    Write-Output "$name.html"
}
