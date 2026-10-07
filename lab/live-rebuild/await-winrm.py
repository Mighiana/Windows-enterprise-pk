import socket
import sys
import time

ip = {'server':'192.168.77.10','client':'192.168.77.20'}[sys.argv[1]]
deadline = time.monotonic() + 1800
if '--reboot' in sys.argv:
    close_deadline = time.monotonic() + 90
    while time.monotonic() < close_deadline:
        try:
            with socket.create_connection((ip,5985),timeout=2):
                time.sleep(1)
        except OSError:
            break
    else:
        sys.exit('WinRM did not stop for the requested reboot')
while time.monotonic() < deadline:
    try:
        with socket.create_connection((ip,5985),timeout=2):
            print(f'{sys.argv[1]} WinRM ready',flush=True)
            break
    except OSError:
        time.sleep(5)
else:
    sys.exit('WinRM did not become ready within 30 minutes')
