#Requires -Version 5.1
<# Run on SERVER or CLIENT. Downloads this repo's scripts from the host's lab-only HTTP server
   (python3 -m http.server 8088 --bind 192.168.77.1, serving a zip of scripts/). #>
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory C:\pki -Force | Out-Null
Invoke-WebRequest -UseBasicParsing -Uri http://192.168.77.1:8088/tooling.zip -OutFile C:\pki\tooling.zip
Expand-Archive -Path C:\pki\tooling.zip -DestinationPath C:\pki\tooling -Force
Get-ChildItem C:\pki\tooling\scripts | Select-Object Name
