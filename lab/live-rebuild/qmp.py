import json
from pathlib import Path
import socket
import sys

p = Path(__file__).parent / 'private'
s = socket.socket(socket.AF_UNIX)
s.connect(str(p / (sys.argv[1] + '.qmp')))
f = s.makefile('rwb',buffering=0)
print(f.readline().decode().strip())
def command(obj):
    f.write((json.dumps(obj) + '\n').encode())
    while True:
        result = json.loads(f.readline())
        if 'return' in result or 'error' in result:
            print(json.dumps(result))
            return
command({'execute':'qmp_capabilities'})
if sys.argv[2] == 'screen':
    command({'execute':'screendump','arguments':{'filename':str(p / (sys.argv[1] + '.ppm'))}})
    from PIL import Image
    Image.open(p / (sys.argv[1] + '.ppm')).save(p / (sys.argv[1] + '.png'))
elif sys.argv[2] == 'key':
    command({'execute':'human-monitor-command','arguments':{'command-line':'sendkey ' + sys.argv[3]}})
elif sys.argv[2] == 'keys':
    import time
    for key in sys.argv[3:]:
        command({'execute':'human-monitor-command','arguments':{'command-line':'sendkey ' + key}})
        time.sleep(.2)
elif sys.argv[2] == 'type':
    import time
    punctuation={' ': 'spc', '\\':'backslash', ':':'shift-semicolon', '/':'slash', '.':'dot', '-':'minus', '_':'shift-minus', '"':'shift-apostrophe', '|':'shift-backslash', '>':'shift-dot', '=':'equal', '\n':'ret'}
    for char in sys.argv[3]:
        key=punctuation.get(char, 'shift-'+char.lower() if char.isupper() else char)
        command({'execute':'human-monitor-command','arguments':{'command-line':'sendkey ' + key}})
        time.sleep(.11)
elif sys.argv[2] == 'boot-install':
    import time
    command({'execute':'system_reset'})
    for _ in range(40):
        command({'execute':'human-monitor-command','arguments':{'command-line':'sendkey ret'}})
        time.sleep(0.25)
else:
    command({'execute':sys.argv[2]})
