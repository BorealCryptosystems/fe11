# SPDX-License-Identifier: Apache-2.0
"""Synthetic metadata negatives exercise the supervisor, not a fake module."""
import unittest
from campaign_validation import verify_required_capabilities


class RequiredCapabilities(unittest.TestCase):
    def test_required_subset_accepts_unrelated_discovered_capabilities(self):
        self.assertEqual(verify_required_capabilities([0x250, 0x1080], [0, 0x1080, 0x250]), 2)

    def test_removed_capability_fails_without_modifying_schedule(self):
        required, discovered = [0x250, 0x1080], [0x250]
        schedule = ['control.a', 'control.b']
        with self.assertRaisesRegex(ValueError, '^required capabilities absent: 0x1080$'):
            verify_required_capabilities(required, discovered)
        self.assertEqual(required, [0x250, 0x1080])
        self.assertEqual(discovered, [0x250])
        self.assertEqual(schedule, ['control.a', 'control.b'])

    def test_empty_discovery_cannot_satisfy_required_capability(self):
        with self.assertRaisesRegex(ValueError, '^required capabilities absent: 0x250$'):
            verify_required_capabilities([0x250], [])

    def test_malformed_and_duplicate_inventories_are_not_capability_loss(self):
        for invalid in ([True], [-1], [1 << 64], ['0x250'], [0x250, 0x250]):
            with self.subTest(invalid=invalid):
                for required, discovered in ((invalid, []), ([0x250], invalid)):
                    with self.assertRaisesRegex(ValueError, '^invalid capability inventory$'):
                        verify_required_capabilities(required, discovered)
