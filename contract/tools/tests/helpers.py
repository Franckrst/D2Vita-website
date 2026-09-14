"""Shared helpers for the contract test suite.

Run from the repository root:
    contract/.venv/bin/python -m unittest discover -s contract/tools/tests -t contract/tools
"""
import copy
import unittest

import check_schemas

KIB = 1024
MIB = 1024 * KIB

# Design section 4.5, column "Plafond (scelle)", in the design's own units.
# Tests use these names, never bare byte counts, so a wrong cap in the schema
# cannot be copied into the tests as well.
DESIGN_SEALED_CAPS = {
    "dump": 2 * MIB,
    "crash_txt": 64 * KIB,
    "crash_log": 64 * KIB,
    "boot_progress": 320 * KIB,
}

# The claim from section 4.4 of the design spec, verbatim.
SPEC_EXAMPLE_CLAIM = {
    "v": 1,
    "report_id": "01J9Z6T4Q8M3K7V2B5N0XWAYCD",
    "install_id": "4f3c9a0e8b7d6c5a4f3e2d1c0b9a8f7e",
    "build_id": "0.1.0+ab12cd34ef56",
    "channel": "release",
    "platform": {"model": "vita", "fw": "3.65"},
    "session": {"started_unix": 1789284000, "uptime_s": 967, "online": False},
    "kind": "halt",
    "features": {
        "code": 1420,
        "location": None,
        "frames": ["Game+0x1fedf4", "Game+0x451c23", "Game+0x44f570"],
    },
    "hints": ["guest_fault"],
    "artifacts": [
        {"name": "crash_txt", "bytes": 2210},
        {"name": "crash_log", "bytes": 3104},
        {"name": "boot_progress", "bytes": 262144},
    ],
}

FEATURES_BY_KIND = {
    "halt": SPEC_EXAMPLE_CLAIM["features"],
    "guest_fault": {
        "exception": "0xc0000005",
        "thread": "worker",
        "eip": "Game+0x1a2b3c",
        "frames": ["Game+0x1a2b3c", "Game+0x2b3c4d"],
    },
    "host_fault": {
        "stop_reason": "0x30004",
        "thread_name": "d2vita_main",
        "pc": {"region": "jit", "module": "jit", "offset": "0x2c4184"},
        "lr": {"region": "eboot", "module": "eboot", "offset": "0x1"},
        "guest_frames": ["Game+0x1fedf4"],
        "redaction": "clean",
    },
    "abnormal_exit": {
        "reason": "unshimmed_import",
        "code": None,
        "import": "KERNEL32.dll!SetFileTime",
        "frames": [],
    },
    "hang": {"stalled_beats": 3, "eip": "Game+0x12345", "runner_state": "running"},
}


def claim_of_kind(kind, **overrides):
    """A valid claim of the given kind (no hints), with top-level overrides."""
    claim = copy.deepcopy(SPEC_EXAMPLE_CLAIM)
    claim["kind"] = kind
    claim["features"] = copy.deepcopy(FEATURES_BY_KIND[kind])
    claim["hints"] = []
    if kind == "host_fault":
        claim["artifacts"].append({"name": "dump", "bytes": 1048576})
    claim.update(overrides)
    return claim


error_pointers = check_schemas.error_pointers


class SchemaTestCase(unittest.TestCase):
    schema_name = None  # e.g. "claim.v1"
    definition = None  # e.g. "SignatureSummary" for a $defs entry

    def validate(self, instance, definition=None):
        return check_schemas.schema_errors(
            self.schema_name, instance, definition or self.definition
        )

    def assertValid(self, instance, definition=None):
        errors = self.validate(instance, definition)
        self.assertEqual(
            [], [f"{check_schemas.json_pointer(e.absolute_path)}: {e.message}" for e in errors]
        )

    def assertInvalidAt(self, instance, pointer, definition=None):
        errors = self.validate(instance, definition)
        self.assertTrue(errors, f"expected a validation error at {pointer!r}")
        self.assertIn(pointer, error_pointers(errors))
