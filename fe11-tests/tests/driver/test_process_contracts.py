# SPDX-License-Identifier: Apache-2.0
"""Real subprocess exits remain distinct from native cryptographic verdicts."""
from pathlib import Path
import json
import os
import signal
import sys
import tempfile
import unittest
from process import execute, frames, erase
from report_validation import verify_worker


class ProcessOutcomes(unittest.TestCase):
    def setUp(self):
        root = Path(os.environ['TMPDIR']).resolve(strict=True)
        self.directory = tempfile.TemporaryDirectory(prefix='process-contract-', dir=root)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def child(self, script, data=b'', **options):
        self.command = [sys.executable, '-c', script]
        self.result = execute(self.command, dict(os.environ), self.root / 'child', data, **options)
        return self.result

    def rejected_as_worker(self, result):
        # There is no terminal record after these fixture failures. A fabricated
        # success record must not override the supervisor's real exit evidence.
        with self.assertRaisesRegex(ValueError, 'worker did not produce a regular outcome'):
            verify_worker(self.root / 'not-created.jsonl', result, {}, 'terminal')

    def test_normal_exit_control(self):
        result = self.child('import sys; sys.stdin.buffer.read(); print("complete")')
        self.assertEqual((result['state'], result['exit_code'], result['signal']), ('EXITED', 0, None))
        self.assertEqual((self.root / 'child/stdout.raw').read_bytes(), b'complete\n')

    def test_real_abort_preserves_crash_and_signal(self):
        result = self.child('import os; os.write(1,b"started\\n"); os.abort()')
        self.assertEqual((result['state'], result['exit_code'], result['signal']),
                         ('CRASH', -signal.SIGABRT, signal.SIGABRT))
        self.assertEqual((self.root / 'child/stdout.raw').read_bytes(), b'started\n')
        self.rejected_as_worker(result)
        self.assertFalse(any(p.name.startswith('core') for p in self.root.rglob('*')))

    def test_real_termination_signal_preserves_number(self):
        result = self.child('import os,signal; os.write(1,b"started\\n"); os.kill(os.getpid(),signal.SIGTERM)')
        self.assertEqual((result['state'], result['exit_code'], result['signal']),
                         ('SIGNALED', -signal.SIGTERM, signal.SIGTERM))
        self.assertEqual((self.root / 'child/stdout.raw').read_bytes(), b'started\n')
        self.rejected_as_worker(result)

    def test_expired_deadline_kills_and_reaps_real_child(self):
        result = self.child('import sys; sys.stdin.buffer.read()', deadline_seconds=0)
        self.assertEqual((result['state'], result['exit_code'], result['signal']),
                         ('TIMEOUT', -signal.SIGKILL, signal.SIGKILL))
        self.rejected_as_worker(result)
        # No execution-time assertion: the explicit expired deadline selects the
        # timeout branch regardless of scheduler speed or child initialization.

    def test_binary_credentials_stay_out_of_process_diagnostics(self):
        officer, user = bytearray(os.urandom(32)), bytearray(os.urandom(32))
        wire = frames(officer, user)
        try:
            result = self.child('import sys; data=sys.stdin.buffer.read(); print(len(data))', wire)
            self.assertEqual((result['state'], result['exit_code']), ('EXITED', 0))
            self.assertEqual(result['input_bytes_sent'], len(wire))
            self.assertEqual((self.root / 'child/stdout.raw').read_bytes(), str(len(wire)).encode() + b'\n')
            artifacts = [p.read_bytes() for p in self.root.rglob('*') if p.is_file()]
            artifacts += [json.dumps(result).encode(), json.dumps(self.command).encode()]
            for secret in (officer, user):
                for data in artifacts:
                    self.assertNotIn(bytes(secret), data)
                    self.assertNotIn(secret.hex().encode(), data)
        finally:
            erase(wire)
            erase(officer)
            erase(user)


if __name__ == '__main__':
    unittest.main()
