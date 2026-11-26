#!/usr/bin/env python3
"""Drive the installed Windows RDP client through the private fixture console."""

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from windows_web_browser import Console


def probe(fixture, config, check=False):
    console = Console(fixture / 'qmp')
    try:
        cdrom = next(item for item in console.command('query-block') if item['device'] == 'probe')
        original = cdrom.get('inserted', {}).get('file')
        if not cdrom['removable'] or not original:
            raise RuntimeError('the Windows client requires its existing probe drive')

        config['run'] = uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix='ocean-windows-rdp-') as name:
            stage = Path(name)
            files = [stage / filename for filename in ('rdp.ps1', 'rdp.json')]
            if check:
                config['check'] = True
            else:
                for name in ('root', 'leaf'):
                    certificate = stage / (name + '.cer')
                    certificate.write_bytes(bytes.fromhex(config.pop(name)))
                    files.append(certificate)
            (stage / 'rdp.json').write_text(json.dumps(config), encoding='utf-8')
            script = Path(__file__).with_name('verify_windows_desktop_rdp.ps1')
            (stage / 'rdp.ps1').write_bytes(script.read_bytes())
            medium = stage / 'rdp.iso'
            subprocess.run(['genisoimage', '-quiet', '-J', '-V', 'OCEAN_RDP', '-o', medium, *files], check=True)

            with (fixture / 'guest-serial.log').open(encoding='utf-8', errors='replace') as serial:
                serial.seek(0, os.SEEK_END)
                console.command('blockdev-change-medium', device='probe', filename=str(medium), format='raw')
                try:
                    console.run_dialog('powershell.exe -NoP -Sta -Ep Bypass -C '
                                       r'''"& ((Get-Volume -FileSystemLabel OCEAN_RDP).DriveLetter+':\rdp.ps1')"''')
                    deadline = time.monotonic() + (20 if check else 46)
                    while time.monotonic() < deadline:
                        position = serial.tell()
                        line = serial.readline()
                        if not line.endswith('\n'):
                            serial.seek(position)
                            time.sleep(0.1)
                            continue
                        prefix = 'OCEAN-DESKTOP-RDP '
                        if not line.startswith(prefix):
                            continue
                        record = json.loads(line.removeprefix(prefix))
                        if record.pop('run', None) != config['run']:
                            continue
                        print(json.dumps(record), flush=True)
                        if record['event'] == ('ready' if check else 'finished'):
                            return
                        if record['event'] == 'error':
                            raise RuntimeError('the installed Windows client reported an error')
                    raise TimeoutError('the Windows fixture did not respond to its readiness check' if check
                                       else 'the unlocked Windows client did not finish its RDP attempt')
                finally:
                    console.command('blockdev-change-medium', device='probe', filename=original, format='raw')
    finally:
        console.close()


def interrupt(_signum, _frame):
    raise InterruptedError('the Windows desktop attempt was interrupted')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupt)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--check', action='store_true', help='check the unlocked native Windows desktop before provisioning')
    options = parser.parse_args()
    probe(options.state / 'windows-11', json.load(sys.stdin), options.check)
