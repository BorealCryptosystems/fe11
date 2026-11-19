# SPDX-License-Identifier: Apache-2.0
"""Reject malformed diagnostic records without treating an expected error as PASS."""
from pathlib import Path
import json
import os
import tempfile
import unittest
from report_validation import verify_worker


class DiagnosticProtocol(unittest.TestCase):
    def validate(self, value, producer="fe11_local"):
        identity=dict(case="protocol.diagnostic",source_sha256="a"*64,
                      recipe_sha256="b"*64,module_sha256="c"*64)
        common=dict(schema=1,**identity)
        assertion=dict(common,kind="assertion",sequence=1,phase="body",
                       assertion="local_busy",producer=producer,value=value)
        terminal=dict(common,kind="terminal",assertions=1,setup="PASS",body="FAIL",
                      cleanup="PASS",status="FAIL",attribution="UNKNOWN")
        root=Path(os.environ["TMPDIR"]).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="protocol-",dir=root) as folder:
            report=Path(folder)/"report.jsonl"
            report.write_text(json.dumps(assertion)+"\n"+json.dumps(terminal)+"\n")
            return verify_worker(report,dict(state="EXITED",exit_code=1),identity,
                                 "terminal",require_success=False)

    def test_typed_diagnostic_preserves_failure(self):
        for category,cause in (("busy","ModuleLifecycle(AdvancedTokenActivity)"),
                               ("rejected","NativeLoading(RequiredFunctionMissing)")):
            records=self.validate(dict(category=category,cause=cause))
            self.assertEqual(records[0]["value"]["cause"],cause)
            self.assertEqual(records[-1]["status"],"FAIL")

    def test_rejects_text_outside_typed_vocabulary(self):
        for cause in ("Busy\nInjected",'Busy"Injected',"Busy\\Injected", "a"*257, "", 1):
            with self.subTest(cause=cause),self.assertRaises(ValueError):
                self.validate(dict(category="busy",cause=cause))

    def test_rejects_changed_schema_and_producer(self):
        for value in (dict(category="other",cause="Busy"),
                      dict(category="busy",cause="Busy",extra=True)):
            with self.assertRaises(ValueError):self.validate(value)
        with self.assertRaises(ValueError):
            self.validate(dict(category="busy",cause="Busy"),producer="native")


if __name__ == "__main__":
    unittest.main()
