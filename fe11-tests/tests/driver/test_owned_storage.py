# SPDX-License-Identifier: Apache-2.0
"""Real filesystem ownership checks; no PKCS#11 component is simulated."""
from pathlib import Path
import os
import tempfile
import unittest
from owned_storage import OwnedTokens


class OwnedStorage(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve(strict=True)
        self.case = self.root / 'case'
        self.case.mkdir()
        self.control = self.root / 'control'
        self.control.mkdir()
        (self.control / 'object').write_bytes(b'independent control')

    def assert_control(self):
        self.assertEqual((self.control / 'object').read_bytes(), b'independent control')

    def test_cleanup_preserves_sibling_and_case_evidence(self):
        owner = OwnedTokens(self.case)
        (owner.path / 'token').mkdir()
        (owner.path / 'token/object').write_bytes(b'owned object')
        (self.case / 'receipt').write_text('retained')
        self.assertEqual(owner.cleanup(), {'status': 'REMOVED'})
        self.assertFalse(owner.path.exists())
        self.assertEqual((self.case / 'receipt').read_text(), 'retained')
        self.assert_control()

    def test_existing_directory_cannot_be_adopted(self):
        (self.case / 'tokens').mkdir()
        (self.case / 'tokens/object').write_bytes(b'not ours')
        with self.assertRaises(FileExistsError):
            OwnedTokens(self.case)
        self.assertEqual((self.case / 'tokens/object').read_bytes(), b'not ours')
        self.assert_control()

    def test_replaced_token_directory_is_not_deleted(self):
        owner = OwnedTokens(self.case)
        owner.path.rename(self.case / 'retained-original')
        owner.path.mkdir()
        (owner.path / 'object').write_bytes(b'not ours')
        with self.assertRaisesRegex(ValueError, 'token directory identity changed'):
            owner.cleanup()
        self.assertEqual((owner.path / 'object').read_bytes(), b'not ours')
        self.assertTrue((self.case / 'retained-original').is_dir())
        self.assert_control()

    def test_closed_owner_does_not_delete_a_later_directory(self):
        owner = OwnedTokens(self.case)
        owner.cleanup()
        owner.path.mkdir()
        (owner.path / 'object').write_bytes(b'new owner')
        self.assertEqual(owner.cleanup(), {'status': 'ALREADY_REMOVED'})
        self.assertEqual((owner.path / 'object').read_bytes(), b'new owner')
        self.assert_control()

    def test_replaced_case_directory_is_not_deleted(self):
        owner = OwnedTokens(self.case)
        self.case.rename(self.root / 'retained-case')
        self.case.mkdir()
        (self.case / 'tokens').mkdir()
        (self.case / 'tokens/object').write_bytes(b'not ours')
        with self.assertRaisesRegex(ValueError, 'case directory identity changed'):
            owner.cleanup()
        self.assertEqual((self.case / 'tokens/object').read_bytes(), b'not ours')
        self.assert_control()


class PosixLinks(unittest.TestCase):
    # These methods are selected only on Linux; no inherited test is repeated.
    setUp = OwnedStorage.setUp
    assert_control = OwnedStorage.assert_control
    def test_descendant_link_does_not_escape_owned_storage(self):
        self.assertEqual(os.name, 'posix')
        owner = OwnedTokens(self.case)
        (owner.path / 'link').symlink_to(self.control, target_is_directory=True)
        owner.cleanup()
        self.assert_control()

    def test_root_link_cannot_replace_owned_storage(self):
        self.assertEqual(os.name, 'posix')
        owner = OwnedTokens(self.case)
        owner.path.rename(self.case / 'retained-original')
        owner.path.symlink_to(self.control, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'must remain a directory'):
            owner.cleanup()
        self.assertTrue(owner.path.is_symlink())
        self.assert_control()
