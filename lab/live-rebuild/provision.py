import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
from xml.sax.saxutils import escape

BASE = Path(__file__).parent
PRIVATE = BASE / 'private'
secret_file = PRIVATE / 'credentials.json'
PRIVATE.mkdir(parents=True, exist_ok=True)
if not secret_file.exists():
    secret_file.write_text(json.dumps({'password': secrets.token_urlsafe(28) + '!aA1'}))
    secret_file.chmod(0o600)
password = json.loads(secret_file.read_text())['password']

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)

import sys
selected = sys.argv[1:] or ['server', 'client']
for name, ip, index in [('server', '192.168.77.10', 2), ('client', '192.168.77.20', 1)]:
    if name not in selected:
        continue
    folder = PRIVATE / name
    folder.mkdir(exist_ok=True)
    bootstrap = r'''$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path C:\pki -Force | Out-Null
Start-Transcript -Path C:\pki\bootstrap.log
$nic = Get-NetAdapter | Where-Object Status -eq Up | Select-Object -First 1
Set-NetIPInterface -InterfaceIndex $nic.ifIndex -Dhcp Disabled
New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress '@IP@' -PrefixLength 24
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses 192.168.77.10
Enable-PSRemoting -SkipNetworkProfileCheck -Force
New-NetFirewallRule -DisplayName 'PKI lab encrypted WinRM management' -Direction Inbound -Protocol TCP -LocalPort 5985 -RemoteAddress 192.168.77.1 -Action Allow -Profile Any
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Service WinRM -StartupType Automatic
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null
Stop-Transcript
'''.replace('@IP@', ip)
    (folder / 'bootstrap.ps1').write_text(bootstrap)
    attrs = 'name="{name}" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"'
    def component(name, body):
        return '<component ' + attrs.format(name=name) + '>' + body + '</component>'
    pe = component('Microsoft-Windows-International-Core-WinPE', '<SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage><InputLocale>0409:00000409</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>')
    pe += component('Microsoft-Windows-Setup', f'''<DiskConfiguration><Disk wcm:action="add"><DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk><CreatePartitions><CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>100</Size></CreatePartition><CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition><CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition></CreatePartitions><ModifyPartitions><ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition><ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition></ModifyPartitions></Disk><WillShowUI>OnError</WillShowUI></DiskConfiguration><ImageInstall><OSImage><InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>{index}</Value></MetaData></InstallFrom><InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo><WillShowUI>OnError</WillShowUI></OSImage></ImageInstall><UserData><AcceptEula>true</AcceptEula><FullName>PKI Lab</FullName><Organization>Isolated evaluation lab</Organization></UserData>''')
    special = component('Microsoft-Windows-Shell-Setup', f'<ComputerName>{name}</ComputerName><TimeZone>UTC</TimeZone>')
    special += component('Microsoft-Windows-Deployment', '<RunSynchronous><RunSynchronousCommand wcm:action="add"><Order>1</Order><Description>Lab VM: no automatic device encryption</Description><Path>reg.exe add HKLM\\SYSTEM\\CurrentControlSet\\Control\\BitLocker /v PreventDeviceEncryption /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand></RunSynchronous>')
    oobe = component('Microsoft-Windows-International-Core', '<InputLocale>0409:00000409</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>')
    cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"$v=Get-Volume | Where-Object FileSystemLabel -eq 'PKIBOOT'; &amp; ($v.DriveLetter + ':\\bootstrap.ps1')\""
    oobe += component('Microsoft-Windows-Shell-Setup', f'''<OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE><UserAccounts><AdministratorPassword><Value>{escape(password)}</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts><AutoLogon><Username>Administrator</Username><Enabled>true</Enabled><LogonCount>1</LogonCount><Password><Value>{escape(password)}</Value><PlainText>true</PlainText></Password></AutoLogon><FirstLogonCommands><SynchronousCommand wcm:action="add"><Order>1</Order><Description>Isolated PKI lab management</Description><CommandLine>{cmd}</CommandLine></SynchronousCommand></FirstLogonCommands>''')
    (folder / 'Autounattend.xml').write_text(f'<?xml version="1.0" encoding="utf-8"?><unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"><settings pass="windowsPE">{pe}</settings><settings pass="specialize">{special}</settings><settings pass="oobeSystem">{oobe}</settings></unattend>')
    run('genisoimage', '-quiet', '-J', '-r', '-V', 'PKIBOOT', '-o', str(PRIVATE / f'{name}-bootstrap.iso'), str(folder))
    if not (PRIVATE / f'{name}.qcow2').exists():
        run('qemu-img', 'create', '-f', 'qcow2', str(PRIVATE / f'{name}.qcow2'), '55G')
    if not (PRIVATE / f'{name}-vars.fd').exists():
        shutil.copy('/usr/share/OVMF/OVMF_VARS_4M.ms.fd', PRIVATE / f'{name}-vars.fd')
print('Generated private unattended media and VM disks; no credentials printed.')
