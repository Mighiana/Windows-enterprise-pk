import json
import base64
from pathlib import Path
import sys
import uuid
import xml.etree.ElementTree as ET
import winrm

base = Path(__file__).parent
name = sys.argv[1]
domain = '--domain' in sys.argv
if domain:
    sys.argv.remove('--domain')
password = json.loads((base / 'private/credentials.json').read_text())['password']
ip = {'server':'192.168.77.10', 'client':'192.168.77.20'}[name]
user = 'IRB\\Administrator' if domain else name + '\\Administrator'
s = winrm.Session(f'http://{ip}:5985/wsman', auth=(user,password), transport='ntlm', message_encryption='always', read_timeout_sec=360, operation_timeout_sec=300)
script = Path(sys.argv[2]).read_text() if len(sys.argv) > 2 else sys.stdin.read()
prefix = "$ProgressPreference='SilentlyContinue'; Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force\n"
if len(base64.b64encode((prefix+script).encode('utf-16le'))) > 7000:
    remote = 'C:\\pki\\remote-' + uuid.uuid4().hex
    payload = base64.b64encode(script.encode('utf-8')).decode()
    for offset in range(0,len(payload),1200):
        chunk = payload[offset:offset+1200]
        staging = s.run_ps(f"[IO.File]::AppendAllText('{remote}.b64','{chunk}')")
        if staging.status_code:
            raise RuntimeError('Encrypted remote script staging failed')
    wrapper = f"$ErrorActionPreference='Stop'; $LASTEXITCODE=0; try {{ [IO.File]::WriteAllText('{remote}.ps1',[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([IO.File]::ReadAllText('{remote}.b64')))); & '{remote}.ps1'; exit $LASTEXITCODE }} finally {{ Remove-Item '{remote}.ps1','{remote}.b64' -Force -ErrorAction SilentlyContinue }}"
    result = s.run_ps(prefix + wrapper)
else:
    result = s.run_ps(prefix + script)
sys.stdout.write(result.std_out.decode('utf-8',errors='replace'))
if result.std_err:
    error = result.std_err.decode('utf-8',errors='replace')
    if error.startswith('#< CLIXML'):
        try:
            tree = ET.fromstring(error.split('\n',1)[1])
            error = '\n'.join(e.text or '' for e in tree.iter() if e.attrib.get('S') in ('error','warning'))
            error = error.replace('_x000D__x000A_', '\n')
        except ET.ParseError:
            pass
    sys.stderr.write(error)
sys.exit(result.status_code)
