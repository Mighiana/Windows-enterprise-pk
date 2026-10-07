from pathlib import Path
import subprocess
import sys

base = Path(__file__).parent
p = base / 'private'
name = sys.argv[1]
# Install media and the bootstrap ISO (which holds the lab password) are attached only for setup.
install = '--install' in sys.argv[2:]
client = name == 'client'
port = 12 if client else 11
args = ['qemu-system-x86_64', '-name', f'PKI-{name}', '-accel', 'kvm', '-machine', 'q35,smm=on', '-cpu', 'host,hv_relaxed,hv_vapic,hv_spinlocks=0x1fff', '-smp', '4', '-m', '6144', '-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.ms.fd', '-drive', f'if=pflash,format=raw,file={p}/{name}-vars.fd', '-drive', f'file={p}/{name}.qcow2,format=qcow2,if=ide', '-netdev', f'tap,id=net0,ifname={"pki-cli" if client else "pki-srv"},script=no,downscript=no', '-device', f'e1000e,netdev=net0,mac=52:54:00:77:00:{20 if client else 10}', '-vnc', f'127.0.0.1:{port}', '-display', 'none', '-qmp', f'unix:{p}/{name}.qmp,server=on,wait=off', '-pidfile', f'{p}/{name}.pid']
if install:
    args += ['-drive', f'file={base}/media/{"windows11" if client else "server2022"}.iso,media=cdrom,if=ide,readonly=on', '-drive', f'file={p}/{name}-bootstrap.iso,media=cdrom,if=ide,readonly=on', '-boot', 'order=c,once=d']
if client:
    tpm = p / 'tpm-client'
    tpm.mkdir(exist_ok=True)
    subprocess.run(['swtpm','socket','--tpm2','--tpmstate',f'dir={tpm}','--ctrl',f'type=unixio,path={p}/client-tpm.sock','--daemon'],check=True)
    args += ['-chardev', f'socket,id=chrtpm,path={p}/client-tpm.sock', '-tpmdev', 'emulator,id=tpm0,chardev=chrtpm','-device','tpm-tis,tpmdev=tpm0']
subprocess.run(['sudo', '-n'] + args + ['-runas', 'ubuntu'],check=True)
