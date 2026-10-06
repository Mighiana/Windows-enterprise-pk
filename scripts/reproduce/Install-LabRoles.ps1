#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the Windows Server roles used by the lab (binaries only).

.DESCRIPTION
    2026 REPRODUCIBILITY EXTENSION - not part of the original May 2026 lab, where the
    roles were added through Server Manager.

    Installs AD DS, AD CS (Certification Authority), DNS and IIS with management tools.
    It does NOT promote a domain controller, configure a CA or touch DNS zones - those
    steps stay manual (see docs/reproduce.md) because they are hard to undo.

    Supports -WhatIf and asks for confirmation. Intended for an isolated lab VM only.

.EXAMPLE
    .\Install-LabRoles.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param()

$features = 'AD-Domain-Services', 'ADCS-Cert-Authority', 'DNS', 'Web-Server'

if (-not (Get-Command -Name Install-WindowsFeature -ErrorAction SilentlyContinue)) {
    throw 'Install-WindowsFeature not found. Run on Windows Server with the ServerManager module.'
}

$missing = @(Get-WindowsFeature -Name $features | Where-Object { -not $_.Installed } | ForEach-Object Name)
if ($missing.Count -eq 0) {
    Write-Output 'All lab roles are already installed.'
    return
}

if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Install-WindowsFeature $($missing -join ', ') -IncludeManagementTools")) {
    $result = Install-WindowsFeature -Name $missing -IncludeManagementTools
    $result | Select-Object Success, RestartNeeded, ExitCode
    if (-not $result.Success) { throw "Install-WindowsFeature failed (ExitCode $($result.ExitCode)). Fix the error before continuing." }
    if ("$($result.RestartNeeded)" -eq 'Yes') { Write-Warning 'A restart is required before continuing.' }
}
