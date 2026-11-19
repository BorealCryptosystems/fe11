# SPDX-License-Identifier: Apache-2.0
"""Campaign-level omissions cannot be disguised by valid individual reports."""
import unittest
from campaign_validation import verify_case_set, verify_inventory_mapping


class CampaignCompleteness(unittest.TestCase):
    def setUp(self):
        self.expected = ['control.a', 'control.b']
        self.results = [{'case': name, 'status': 'PASS'} for name in self.expected]

    def test_complete_result_control(self):
        self.assertEqual(verify_case_set(self.expected, reversed(self.results)), 2)

    def test_missing_terminal_names_the_omitted_case(self):
        with self.assertRaisesRegex(ValueError, r'missing=control\.b; unexpected=$'):
            verify_case_set(self.expected, self.results[:1])
        with self.assertRaisesRegex(ValueError, r'missing=control\.a,control\.b;'):
            verify_case_set(self.expected, [])

    def test_duplicate_terminal_is_not_a_replacement(self):
        with self.assertRaisesRegex(ValueError, r'duplicate coverage identifiers: control\.a$'):
            verify_case_set(self.expected, [self.results[0], self.results[0]])
        with self.assertRaisesRegex(ValueError, r'duplicate coverage identifiers: control\.b$'):
            verify_case_set(self.expected, self.results + [self.results[1]])

    def test_unexpected_case_cannot_replace_the_missing_case(self):
        changed = [self.results[0], {'case': 'control.c', 'status': 'PASS'}]
        with self.assertRaisesRegex(ValueError, r'missing=control\.b; unexpected=control\.c$'):
            verify_case_set(self.expected, changed)

    def test_failure_and_non_execution_are_not_passes(self):
        for state in ('FAIL', 'NOT_EXECUTED', 'PREREQUISITE_MISSING', 'UNKNOWN', True, None):
            with self.subTest(state=state), self.assertRaisesRegex(ValueError, r'without PASS: control\.b$'):
                verify_case_set(self.expected, [self.results[0], {'case': 'control.b', 'status': state}])

    def test_invalid_metadata_is_not_echoed(self):
        marker = 'private-sentinel\nforged-record'
        with self.assertRaises(ValueError) as error:
            verify_case_set([marker], [{'case': marker, 'status': 'PASS'}])
        self.assertNotIn(marker, str(error.exception))
        with self.assertRaisesRegex(ValueError, '^invalid campaign result fields$'):
            verify_case_set(self.expected, [dict(self.results[0], secret=marker)])

    def test_duplicate_schedule_is_rejected(self):
        with self.assertRaisesRegex(ValueError, r'duplicate coverage identifiers: control\.a$'):
            verify_case_set(['control.a', 'control.a'], [self.results[0]])

    def test_inventory_control_and_added_entry(self):
        self.assertEqual(verify_inventory_mapping(self.expected, reversed(self.expected)), 2)
        with self.assertRaisesRegex(ValueError, r'unmapped=control\.c; stale=$'):
            verify_inventory_mapping(self.expected + ['control.c'], self.expected)

    def test_removed_inventory_entry_is_stale(self):
        with self.assertRaisesRegex(ValueError, r'unmapped=; stale=control\.b$'):
            verify_inventory_mapping(self.expected[:1], self.expected)


if __name__ == '__main__':
    unittest.main()
