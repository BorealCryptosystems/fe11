# SPDX-License-Identifier: Apache-2.0
"""Remove DAC bypass in one child; never change the supervisor or host policy."""
import json
import os
from pathlib import Path
import shutil
import stat
from run import digest, save

DAC_BYPASS = (1 << 1) | (1 << 2)


def constrain(command, environment, root):
    fields = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    effective = int(fields['CapEff'].strip(), 16)
    record = dict(supervisor_effective_uid=os.geteuid(), supervisor_dac_bypass=bool(effective & DAC_BYPASS),
                  worker_assertion='Actual worker requires CapEff DAC_OVERRIDE and DAC_READ_SEARCH absent before C_Initialize.')
    if effective & DAC_BYPASS:
        found = shutil.which('setpriv', path=environment['PATH'])
        if not found:
            raise ValueError('child-only privilege limiter unavailable')
        executable = Path(found).resolve(strict=True)
        record.update(launcher=str(executable), launcher_sha256=digest(executable))
        command = [str(executable), '--bounding-set=-dac_override,-dac_read_search',
                   '--inh-caps=-all', '--ambient-caps=-all'] + command
    save(root / 'permission-launcher.json', record)
    return command


def inspect(root):
    tokens = root / 'tokens'
    if tokens.is_symlink() or stat.S_IMODE(tokens.stat().st_mode) != 0:
        raise ValueError('denied store modes changed before observation')
    record = json.loads((root / 'permission-launcher.json').read_text())
    if 'launcher' in record and digest(Path(record['launcher'])) != record['launcher_sha256']:
        raise ValueError('permission launcher identity changed')
    return dict(status='PASS', mode_octal='0o0', launcher=record,
                scope='Only the disposable store. Actual native worker checks DAC bypass is absent; exact C_Initialize GENERAL_ERROR is observed. Owner permissions restored after child exit for cleanup.')
