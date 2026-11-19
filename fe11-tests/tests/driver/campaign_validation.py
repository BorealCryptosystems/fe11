# SPDX-License-Identifier: Apache-2.0
"""Reject incomplete or ambiguous coverage before publishing campaign totals."""
from collections import Counter
import re


def identities(values):
    """Case identifiers are public metadata, never free-form child output."""
    values = list(values)
    if not values or any(not isinstance(v, str) or
                         not re.fullmatch(r"[A-Za-z0-9._:@/+-]{1,512}", v) for v in values):
        raise ValueError("invalid coverage identifiers")
    counts = Counter(values)
    duplicates = sorted(v for v, count in counts.items() if count != 1)
    if duplicates:
        raise ValueError("duplicate coverage identifiers: " + ",".join(duplicates))
    return set(values)


def verify_case_set(expected, results):
    """Require exactly one successful terminal result for every scheduled case.

    Per-worker framing, provenance and cleanup must already have been validated
    by report_validation.verify_worker. This cross-case check adds completeness;
    it cannot establish that an unauthenticated result actually came from a run.
    Failed or unexecuted cases stay failures, even when the set itself is complete.
    """
    expected = identities(expected)
    results = list(results)
    if any(not isinstance(row, dict) or set(row) != {"case", "status"} for row in results):
        raise ValueError("invalid campaign result fields")
    actual = identities(row['case'] for row in results) if results else set()
    missing, unexpected = sorted(expected - actual), sorted(actual - expected)
    if missing or unexpected:
        raise ValueError("case set mismatch; missing=" + ",".join(missing)
                         + "; unexpected=" + ",".join(unexpected))
    failed = sorted(row['case'] for row in results if row['status'] != 'PASS')
    if failed:
        raise ValueError("cases without PASS: " + ",".join(failed))
    return len(actual)


def verify_inventory_mapping(inventory, mapped_entries):
    """Detect added, removed and duplicate public API/mechanism mapping entries.

    Both inputs must be produced independently: one from the current inventory,
    one from the explicit coverage mapping. Comparing a list to itself proves
    nothing about coverage. Multiple cases for one entry are grouped upstream.
    """
    inventory = identities(inventory)
    mapped = identities(mapped_entries)
    missing, stale = sorted(inventory - mapped), sorted(mapped - inventory)
    if missing or stale:
        raise ValueError("inventory mismatch; unmapped=" + ",".join(missing)
                         + "; stale=" + ",".join(stale))
    return len(inventory)


def verify_required_capabilities(required, discovered):
    """A missing prerequisite fails preparation; it never prunes scheduled cases.

    Unrelated discovered capabilities are allowed. Inputs are numeric capability
    identifiers, independent of module branding or human-readable names.
    """
    def checked(values):
        values = list(values)
        if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF
               for value in values) or len(values) != len(set(values)):
            raise ValueError('invalid capability inventory')
        return set(values)
    required, discovered = checked(required), checked(discovered)
    missing = sorted(required - discovered)
    if missing:
        raise ValueError('required capabilities absent: ' + ','.join(hex(v) for v in missing))
    return len(required)
