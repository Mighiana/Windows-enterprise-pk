import json
from pathlib import Path
import time
import winrm

base = Path(__file__).parent
password = json.loads((base / 'private/credentials.json').read_text())['password']
deadline = time.monotonic() + 1200
while time.monotonic() < deadline:
    try:
        session = winrm.Session('http://192.168.77.10:5985/wsman', auth=('IRB\\Administrator',password), transport='ntlm', message_encryption='always', operation_timeout_sec=30, read_timeout_sec=45)
        result = session.run_ps("$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; (Get-ADDomain).DNSRoot")
        if result.status_code == 0 and result.std_out.decode().strip() == 'irb.local':
            print('irb.local domain controller authenticated and AD Web Services ready',flush=True)
            break
    except Exception:
        pass
    time.sleep(30)
else:
    raise SystemExit('Domain controller did not become authenticated/AD-ready within 20 minutes')
