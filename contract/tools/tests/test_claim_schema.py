import copy

import check_schemas
from tests.helpers import SPEC_EXAMPLE_CLAIM, SchemaTestCase, claim_of_kind


class ClaimSchemaValidTest(SchemaTestCase):
    schema_name = "claim.v1"

    def test_schema_is_valid_draft_2020_12(self):
        check_schemas.check_schema_documents()

    def test_spec_example_is_valid(self):
        self.assertValid(SPEC_EXAMPLE_CLAIM)

    def test_one_valid_claim_per_kind(self):
        for kind in ("halt", "guest_fault", "host_fault", "abnormal_exit", "hang"):
            with self.subTest(kind=kind):
                self.assertValid(claim_of_kind(kind))

    def test_nullable_fields_accept_null(self):
        claim = claim_of_kind("host_fault")
        claim["features"]["stop_reason"] = None
        claim["features"]["thread_name"] = None
        claim["session"]["uptime_s"] = None
        self.assertValid(claim)
        hang = claim_of_kind("hang")
        hang["features"]["eip"] = None
        hang["features"]["runner_state"] = None
        self.assertValid(hang)

    def test_platform_unknown_values(self):
        self.assertValid(claim_of_kind("halt", platform={"model": "unknown", "fw": "unknown"}))
        self.assertValid(claim_of_kind("halt", platform={"model": "pstv", "fw": "3.74"}))

    def test_limits_are_inclusive(self):
        claim = claim_of_kind("halt")
        claim["features"]["frames"] = ["Game+0x%x" % (0x1000 + i) for i in range(16)]
        claim["features"]["code"] = 4294967295
        claim["artifacts"] = [
            {"name": "dump", "bytes": 2097152},
            {"name": "crash_txt", "bytes": 65536},
            {"name": "crash_log", "bytes": 88},
            {"name": "boot_progress", "bytes": 335872},
        ]
        self.assertValid(claim)
        host = claim_of_kind("host_fault")
        host["features"]["guest_frames"] = ["Game+0x%x" % (0x2000 + i) for i in range(8)]
        self.assertValid(host)

    def test_address_edge_forms(self):
        claim = claim_of_kind("halt")
        claim["features"]["frames"] = ["Game+0x0", "kernel32.dll+0xffffffff", "A" * 32 + "+0x1"]
        self.assertValid(claim)

    def test_integral_float_literal_is_an_integer(self):
        claim = claim_of_kind("halt")
        claim["features"]["code"] = 1420.0
        self.assertValid(claim)

    def test_hints_less_severe_than_kind(self):
        claim = claim_of_kind("host_fault", hints=["halt", "abnormal_exit", "guest_fault", "hang"])
        self.assertValid(claim)
        self.assertValid(claim_of_kind("abnormal_exit", hints=["hang", "guest_fault"]))

    def test_optional_redaction_count(self):
        self.assertValid(claim_of_kind("halt", redactions=0))
        self.assertValid(claim_of_kind("halt", redactions=12))

    def test_zero_artifacts_and_dirty_build(self):
        self.assertValid(claim_of_kind("hang", artifacts=[], build_id="12.0.3+0123456789ab-dirty"))


class ClaimSchemaInvalidTest(SchemaTestCase):
    schema_name = "claim.v1"

    def mutate(self, kind, fn):
        claim = claim_of_kind(kind)
        fn(claim)
        return claim

    def test_unknown_fields_rejected_everywhere(self):
        cases = {
            "": lambda c: c.update(extra=1),
            "/platform": lambda c: c["platform"].update(extra=1),
            "/session": lambda c: c["session"].update(extra=1),
            "/features": lambda c: c["features"].update(extra=1),
            "/artifacts/0": lambda c: c["artifacts"][0].update(extra=1),
        }
        for pointer, fn in cases.items():
            with self.subTest(pointer=pointer):
                self.assertInvalidAt(self.mutate("halt", fn), pointer)
        self.assertInvalidAt(
            self.mutate("host_fault", lambda c: c["features"]["pc"].update(extra=1)),
            "/features/pc",
        )

    def test_required_fields(self):
        for key in ("v", "report_id", "install_id", "build_id", "channel", "platform",
                    "session", "kind", "features", "hints", "artifacts"):
            with self.subTest(key=key):
                self.assertInvalidAt(self.mutate("halt", lambda c: c.pop(key)), "")
        self.assertInvalidAt(self.mutate("halt", lambda c: c["features"].pop("location")), "/features")

    def test_version(self):
        self.assertInvalidAt(claim_of_kind("halt", v=2), "/v")
        self.assertInvalidAt(claim_of_kind("halt", v=True), "/v")

    def test_report_id_is_uppercase_crockford_ulid(self):
        for bad in ("01j9z6t4q8m3k7v2b5n0xwaycd", "81J9Z6T4Q8M3K7V2B5N0XWAYCD",
                    "01J9Z6T4Q8M3K7V2B5N0XWAYCI", "01J9Z6T4Q8M3K7V2B5N0XWAYC",
                    "01J9Z6T4Q8M3K7V2B5N0XWAYCD\n"):
            with self.subTest(report_id=bad):
                self.assertInvalidAt(claim_of_kind("halt", report_id=bad), "/report_id")

    def test_install_id_is_32_lowercase_hex(self):
        for bad in ("4F3C9A0E8B7D6C5A4F3E2D1C0B9A8F7E", "4f3c9a0e8b7d6c5a4f3e2d1c0b9a8f7",
                    "4f3c9a0e8b7d6c5a4f3e2d1c0b9a8f7e\n"):
            with self.subTest(install_id=bad):
                self.assertInvalidAt(claim_of_kind("halt", install_id=bad), "/install_id")

    def test_build_id_format(self):
        for bad in ("0.1.0+ab12cd34ef5", "0.1+ab12cd34ef56", "0.1.0+AB12CD34EF56",
                    "0.1.0+ab12cd34ef56-dirt", "v0.1.0+ab12cd34ef56"):
            with self.subTest(build_id=bad):
                self.assertInvalidAt(claim_of_kind("halt", build_id=bad), "/build_id")

    def test_enums(self):
        self.assertInvalidAt(claim_of_kind("halt", channel="beta"), "/channel")
        self.assertInvalidAt(self.mutate("halt", lambda c: c.update(kind="segfault")), "/kind")
        self.assertInvalidAt(claim_of_kind("halt", platform={"model": "ps4", "fw": "3.65"}),
                             "/platform/model")
        self.assertInvalidAt(claim_of_kind("halt", platform={"model": "vita", "fw": "3.6"}),
                             "/platform/fw")
        self.assertInvalidAt(self.mutate("guest_fault", lambda c: c["features"].update(thread="gui")),
                             "/features/thread")
        self.assertInvalidAt(self.mutate("host_fault", lambda c: c["features"].update(redaction="partial")),
                             "/features/redaction")
        self.assertInvalidAt(self.mutate("host_fault", lambda c: c["features"]["pc"].update(region="heap")),
                             "/features/pc/region")
        self.assertInvalidAt(self.mutate("abnormal_exit", lambda c: c["features"].update(reason="crashed")),
                             "/features/reason")

    def test_session_types(self):
        self.assertInvalidAt(self.mutate("halt", lambda c: c["session"].update(online="no")),
                             "/session/online")
        self.assertInvalidAt(self.mutate("halt", lambda c: c["session"].update(started_unix=-1)),
                             "/session/started_unix")

    def test_addresses_are_normalized(self):
        for bad in ("Game+0x1FEDF4", "Game+0x01fedf4", "Game+1fedf4", "Game+0x", "Game+0x123456789",
                    "Ga me+0x1", "Game+0x1fedf4\n", "A" * 33 + "+0x1", "+0x1", "Game|x+0x1"):
            with self.subTest(address=bad):
                claim = claim_of_kind("halt")
                claim["features"]["frames"][0] = bad
                self.assertInvalidAt(claim, "/features/frames/0")

    def test_host_address_offset_is_normalized_hex(self):
        for bad in ("2c4184", "0x02c4184", "0X2c4184", "0x2C4184"):
            with self.subTest(offset=bad):
                claim = claim_of_kind("host_fault")
                claim["features"]["pc"]["offset"] = bad
                self.assertInvalidAt(claim, "/features/pc/offset")

    def test_frame_count_limits(self):
        claim = claim_of_kind("halt")
        claim["features"]["frames"] = ["Game+0x%x" % (0x1000 + i) for i in range(17)]
        self.assertInvalidAt(claim, "/features/frames")
        host = claim_of_kind("host_fault")
        host["features"]["guest_frames"] = ["Game+0x%x" % (0x1000 + i) for i in range(9)]
        self.assertInvalidAt(host, "/features/guest_frames")

    def test_features_must_match_kind(self):
        claim = claim_of_kind("guest_fault")
        claim["features"] = copy.deepcopy(claim_of_kind("halt")["features"])
        self.assertInvalidAt(claim, "/features")

    def test_halt_fields(self):
        for bad in (-1, 1420.5, "1420", 4294967296):
            with self.subTest(code=bad):
                self.assertInvalidAt(self.mutate("halt", lambda c: c["features"].update(code=bad)),
                                     "/features/code")
        for bad in ("src\\Codec.cpp:1377", "Codec.cpp", "Codec.cpp:01377", "Codec.cpp:1377\n", ""):
            with self.subTest(location=bad):
                self.assertInvalidAt(self.mutate("halt", lambda c: c["features"].update(location=bad)),
                                     "/features/location")

    def test_guest_fault_fields(self):
        for bad in ("0xC0000005", "c0000005", "access violation"):
            with self.subTest(exception=bad):
                self.assertInvalidAt(
                    self.mutate("guest_fault", lambda c: c["features"].update(exception=bad)),
                    "/features/exception")
        self.assertInvalidAt(self.mutate("guest_fault", lambda c: c["features"].update(eip=None)),
                             "/features/eip")

    def test_abnormal_exit_fields(self):
        for bad in ("KERNEL32.dll|SetFileTime", "KERNEL32.dll,SetFileTime", "a b", "", "x" * 129):
            with self.subTest(import_name=bad):
                self.assertInvalidAt(
                    self.mutate("abnormal_exit", lambda c: c["features"].update({"import": bad})),
                    "/features/import")

    def test_hang_fields(self):
        self.assertInvalidAt(self.mutate("hang", lambda c: c["features"].update(stalled_beats=1)),
                             "/features/stalled_beats")
        self.assertInvalidAt(self.mutate("hang", lambda c: c["features"].update(runner_state="a|b")),
                             "/features/runner_state")

    def test_host_fault_thread_name_is_printable_ascii(self):
        for bad in ("main\n", "x" * 33, "café"):
            with self.subTest(thread_name=bad):
                self.assertInvalidAt(
                    self.mutate("host_fault", lambda c: c["features"].update(thread_name=bad)),
                    "/features/thread_name")

    def test_hints_rules(self):
        self.assertInvalidAt(claim_of_kind("halt", hints=["halt"]), "/hints/0")
        self.assertInvalidAt(claim_of_kind("guest_fault", hints=["host_fault"]), "/hints/0")
        self.assertInvalidAt(claim_of_kind("hang", hints=["guest_fault"]), "/hints")
        self.assertInvalidAt(claim_of_kind("host_fault", hints=["hang", "hang"]), "/hints")
        self.assertInvalidAt(claim_of_kind("halt", hints=["crash"]), "/hints/0")

    def test_artifact_rules(self):
        duplicated = claim_of_kind("halt")
        duplicated["artifacts"].append({"name": "crash_txt", "bytes": 100})
        self.assertInvalidAt(duplicated, "/artifacts")
        unknown = claim_of_kind("halt")
        unknown["artifacts"][0]["name"] = "minidump"
        self.assertInvalidAt(unknown, "/artifacts/0/name")
        too_small = claim_of_kind("halt")
        too_small["artifacts"][0]["bytes"] = 87
        self.assertInvalidAt(too_small, "/artifacts/0/bytes")
        caps = {"dump": 2097152, "crash_txt": 65536, "crash_log": 65536, "boot_progress": 335872}
        for name, cap in caps.items():
            with self.subTest(name=name):
                claim = claim_of_kind("halt", artifacts=[{"name": name, "bytes": cap + 1}])
                self.assertInvalidAt(claim, "/artifacts/0/bytes")

    def test_redactions_must_be_non_negative_integer(self):
        self.assertInvalidAt(claim_of_kind("halt", redactions=-1), "/redactions")
        self.assertInvalidAt(claim_of_kind("halt", redactions="3"), "/redactions")


class PatternPortabilityTest(SchemaTestCase):
    """Patterns must mean the same thing in ECMA-262 (ajv) and in Python."""

    def test_every_pattern_is_anchored_and_ascii_only(self):
        patterns = list(check_schemas.iter_patterns())
        self.assertTrue(patterns)
        for where, pattern in patterns:
            with self.subTest(where=where, pattern=pattern):
                self.assertEqual([], check_schemas.pattern_portability_problems(pattern))

    def test_portability_lint_catches_problems(self):
        lint = check_schemas.pattern_portability_problems
        self.assertTrue(lint("[0-9]+$"))
        self.assertTrue(lint("^[0-9]+"))
        self.assertTrue(lint("^\\d+$"))
        self.assertTrue(lint("^a.b$"))
        self.assertTrue(lint("^[a-z]\\$"))
        self.assertEqual([], lint("^[a.$]{1,3}\\+0x$"))

    def test_no_format_keyword(self):
        # "format" is annotation-only by default in both validators: never rely on it.
        def keys(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    yield key
                    yield from keys(value)
            elif isinstance(node, list):
                for value in node:
                    yield from keys(value)

        for name, schema in check_schemas.load_schemas().items():
            with self.subTest(schema=name):
                self.assertNotIn("format", set(keys(schema)))
