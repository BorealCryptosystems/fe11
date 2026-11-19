# SPDX-License-Identifier: Apache-2.0
"""Exercise report framing and real child exits without loading a native module."""
from pathlib import Path
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

from report_validation import verify_worker


class ReportContract(unittest.TestCase):
    def setUp(self):
        root = Path(os.environ['TMPDIR']).resolve(strict=True)
        self.directory = tempfile.TemporaryDirectory(prefix='report-contract-', dir=root)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.report = self.root / 'report.jsonl'
        self.identity = dict(case='control.a', source_sha256='a' * 64,
                             recipe_sha256='b' * 64, module_sha256='c' * 64)
        common = dict(schema=1, **self.identity)
        self.assertion = dict(common, kind='assertion', sequence=1, phase='body',
                              assertion='protocol_control', producer='test_oracle', value=True)
        self.terminal = dict(common, kind='terminal', assertions=1, setup='PASS', body='PASS',
                             cleanup='PASS', status='PASS', attribution='NONE')

    def write(self, records):
        # Use exact wire bytes: removing LF from a Windows CRLF would leave a
        # valid CR terminator instead of the deliberately incomplete stream.
        self.report.write_bytes(''.join(json.dumps(row) + '\n' for row in records).encode('utf8'))

    def validate(self, code=0, require_success=True):
        return verify_worker(self.report, dict(state='EXITED', exit_code=code),
                             self.identity, 'terminal', require_success=require_success)

    def child(self, script, records):
        # The subprocess is a protocol fixture, never a replacement PKCS#11
        # implementation. All output and scratch paths belong to this test.
        with self.report.open('wb') as output, (self.root / 'stderr.txt').open('wb') as error:
            return subprocess.run([sys.executable, '-c', script], cwd=self.root,
                                  input=json.dumps(records).encode('utf8'), stdout=output,
                                  stderr=error, timeout=3600, check=False).returncode

    def test_valid_report_control(self):
        self.write([self.assertion, self.terminal])
        self.assertEqual(self.validate()[-1]['status'], 'PASS')

    def test_zero_exit_without_terminal_is_rejected(self):
        code = self.child('import sys; sys.stdin.buffer.read()', [])
        self.assertEqual(code, 0)
        with self.assertRaises(ValueError):
            self.validate(code)

    def test_nonzero_exit_after_pass_is_rejected(self):
        script = ('import json,sys\n'
                  'for row in json.load(sys.stdin): print(json.dumps(row))\n'
                  'sys.exit(1)\n')
        code = self.child(script, [self.assertion, self.terminal])
        self.assertEqual(code, 1)
        with self.assertRaises(ValueError):
            self.validate(code)

    def test_body_and_cleanup_failures_remain_distinct(self):
        body = dict(self.assertion, assertion='body_panic', value=False)
        cleanup = dict(self.assertion, sequence=2, phase='cleanup',
                       assertion='cleanup_failure', value=False)
        terminal = dict(self.terminal, assertions=2, body='FAIL', cleanup='FAIL',
                        status='FAIL', attribution='UNKNOWN')
        script = ('import json,sys\nrows=json.load(sys.stdin)\n'
                  'try:\n raise RuntimeError("body")\n'
                  'except RuntimeError:\n print(json.dumps(rows[0]))\n'
                  'try:\n raise RuntimeError("cleanup")\n'
                  'except RuntimeError:\n print(json.dumps(rows[1]))\n'
                  'print(json.dumps(rows[2]))\nsys.exit(1)\n')
        code = self.child(script, [body, cleanup, terminal])
        records = self.validate(code, require_success=False)
        self.assertEqual([(r['phase'], r['value']) for r in records[:-1]],
                         [('body', False), ('cleanup', False)])
        self.assertEqual((records[-1]['body'], records[-1]['cleanup']), ('FAIL', 'FAIL'))
        with self.assertRaises(ValueError):
            self.validate(code)

    def test_mixed_case_or_source_identity_is_rejected(self):
        for field, changed in [('case', 'control.b'), ('source_sha256', 'd' * 64),
                               ('recipe_sha256', 'd' * 64), ('module_sha256', 'd' * 64)]:
            with self.subTest(field=field):
                self.write([dict(self.assertion, **{field: changed}), self.terminal])
                with self.assertRaises(ValueError):
                    self.validate()

    def test_assertion_count_and_order_are_checked(self):
        variants = [([dict(self.assertion, sequence=2), self.terminal]),
                    ([self.assertion, dict(self.terminal, assertions=0)]),
                    ([self.assertion, self.assertion, dict(self.terminal, assertions=2)])]
        for records in variants:
            with self.subTest(records=len(records)):
                self.write(records)
                with self.assertRaises(ValueError):
                    self.validate()

    def test_cleanup_failure_cannot_be_reported_as_pass(self):
        self.write([self.assertion, dict(self.terminal, cleanup='FAIL')])
        with self.assertRaises(ValueError):
            self.validate()

    def test_native_function_and_code_are_preserved(self):
        native = dict(function='C_Verify', code=192, may_have_effect=False)
        row = dict(self.assertion, producer='native', value=native)
        terminal = dict(self.terminal, body='FAIL', status='FAIL', attribution='UNKNOWN')
        self.write([row, terminal])
        records = self.validate(1, require_success=False)
        self.assertEqual(records[0]['producer'], 'native')
        self.assertEqual(records[0]['value'], native)
        self.assertEqual(records[-1]['status'], 'FAIL')

    def test_unknown_fields_and_truncated_stream_are_rejected(self):
        records = [self.assertion, self.terminal]
        for position in (0, 1):
            changed = copy.deepcopy(records)
            changed[position]['unexpected'] = True
            self.write(changed)
            with self.assertRaises(ValueError):
                self.validate()
        self.write(records)
        self.report.write_bytes(self.report.read_bytes()[:-1])
        with self.assertRaises(ValueError):
            self.validate()


if __name__ == '__main__':
    unittest.main()
