import copy
import re
import unittest

import check_schemas
from tests.helpers import SPEC_EXAMPLE_CLAIM, claim_of_kind


def with_features(kind, **features):
    claim = claim_of_kind(kind)
    claim["features"].update(features)
    return claim


class SignatureIdTest(unittest.TestCase):
    # Expected values computed outside Python with coreutils:
    #   printf '%s' "$canon" | sha256sum | cut -d' ' -f1 | xxd -r -p | basenc --base32 | cut -c1-15
    def test_known_values(self):
        self.assertEqual("SDCQKIRCQBPDNL4Q", check_schemas.signature_id("hang|-"))
        self.assertEqual(
            "SZYGIRBIXGHOM3AH",
            check_schemas.signature_id("halt|1420|-|Game+0x1fedf4,Game+0x451c23,Game+0x44f570"),
        )
        self.assertEqual("SEHI6TEMRJJEWYFK", check_schemas.signature_id("hfault_sys|SceLibKernel|0x1f2c"))

    def test_shape(self):
        self.assertRegex(check_schemas.signature_id("anything"), r"\AS[A-Z2-7]{15}\Z")


class CanonTest(unittest.TestCase):
    def assertCanon(self, claim, expected):
        self.assertEqual(expected, check_schemas.canon(claim))

    def test_halt(self):
        self.assertCanon(SPEC_EXAMPLE_CLAIM, "halt|1420|-|Game+0x1fedf4,Game+0x451c23,Game+0x44f570")
        self.assertCanon(
            with_features("halt", code=904, location="Codec.cpp:1377",
                          frames=["Game+0x1", "Game+0x2", "Game+0x3", "Game+0x4", "Game+0x5"]),
            "halt|904|Codec.cpp:1377|Game+0x1,Game+0x2,Game+0x3")
        self.assertCanon(with_features("halt", code=316, frames=["Game+0x65420"]), "halt|316|-|Game+0x65420")
        self.assertCanon(with_features("halt", code=0, frames=[]), "halt|0|-|-")

    def test_integral_float_code_is_formatted_as_integer(self):
        self.assertCanon(with_features("halt", code=1632.0, frames=[]), "halt|1632|-|-")

    def test_guest_fault(self):
        self.assertCanon(claim_of_kind("guest_fault"), "gfault|0xc0000005|Game+0x1a2b3c|Game+0x1a2b3c,Game+0x2b3c4d")
        self.assertCanon(
            with_features("guest_fault", frames=["Game+0x1", "Game+0x2", "Game+0x3"]),
            "gfault|0xc0000005|Game+0x1a2b3c|Game+0x1,Game+0x2")
        self.assertCanon(with_features("guest_fault", exception=None, frames=[]), "gfault|-|Game+0x1a2b3c|-")

    def test_host_fault_by_pc_region(self):
        jit = claim_of_kind("host_fault")
        self.assertCanon(jit, "hfault_jit|0x30004|Game+0x1fedf4")
        self.assertCanon(
            with_features("host_fault", guest_frames=["Game+0x1", "Game+0x2", "Game+0x3", "Game+0x4"]),
            "hfault_jit|0x30004|Game+0x1,Game+0x2,Game+0x3")
        self.assertCanon(with_features("host_fault", stop_reason=None, guest_frames=[]), "hfault_jit|-|-")

        eboot = with_features("host_fault", pc={"region": "eboot", "module": "eboot", "offset": "0x2c4184"})
        self.assertCanon(eboot, "hfault|0.1.0+ab12cd34ef56|0x2c4184|0x1")

        sysmodule = with_features("host_fault",
                                  pc={"region": "sysmodule", "module": "SceLibKernel", "offset": "0x1f2c"})
        self.assertCanon(sysmodule, "hfault_sys|SceLibKernel|0x1f2c")

        unknown = with_features("host_fault", pc={"region": "unknown", "module": "unknown", "offset": "0x0"})
        self.assertCanon(unknown, "hfault_unknown|0.1.0+ab12cd34ef56|0x0|0x1")

    def test_eboot_signature_depends_on_build_but_sysmodule_does_not(self):
        pc = {"region": "eboot", "module": "eboot", "offset": "0x2c4184"}
        a = with_features("host_fault", pc=pc)
        b = copy.deepcopy(a)
        b["build_id"] = "0.1.1+0123456789ab"
        self.assertNotEqual(check_schemas.canon(a), check_schemas.canon(b))
        pc = {"region": "sysmodule", "module": "SceLibKernel", "offset": "0x1f2c"}
        a = with_features("host_fault", pc=pc)
        b = copy.deepcopy(a)
        b["build_id"] = "0.1.1+0123456789ab"
        self.assertEqual(check_schemas.canon(a), check_schemas.canon(b))

    def test_abnormal_exit_import_wins_over_code(self):
        self.assertCanon(claim_of_kind("abnormal_exit"), "exit|unshimmed_import|KERNEL32.dll!SetFileTime|-")
        self.assertCanon(with_features("abnormal_exit", code=5), "exit|unshimmed_import|KERNEL32.dll!SetFileTime|-")
        self.assertCanon(
            with_features("abnormal_exit", reason="exit_process", code=3221225477,
                          frames=["Game+0x1000", "Game+0x2000"], **{"import": None}),
            "exit|exit_process|3221225477|Game+0x1000")
        self.assertCanon(
            with_features("abnormal_exit", reason="fatal_app_exit", code=None, **{"import": None}),
            "exit|fatal_app_exit|-|-")
        self.assertCanon(
            with_features("abnormal_exit", reason="raise_exception", code=0, **{"import": None}),
            "exit|raise_exception|0|-")

    def test_hang(self):
        self.assertCanon(claim_of_kind("hang"), "hang|Game+0x12345")
        self.assertCanon(with_features("hang", eip=None), "hang|-")

    def test_fields_outside_the_template_do_not_matter(self):
        a = claim_of_kind("halt")
        b = copy.deepcopy(a)
        b.update(report_id="01J9Z6T4Q8M3K7V2B5N0XWAYCE", install_id="0" * 32, build_id="9.9.9+ffffffffffff",
                 channel="dev", hints=["hang"], artifacts=[], redactions=3)
        b["session"]["online"] = True
        self.assertEqual(check_schemas.canon(a), check_schemas.canon(b))

    def test_unknown_kind_is_rejected(self):
        claim = claim_of_kind("halt")
        claim["kind"] = "segfault"
        with self.assertRaises(ValueError):
            check_schemas.canon(claim)


class TemplateEngineTest(unittest.TestCase):
    def test_expressions(self):
        render = check_schemas.render_template
        claim = {"a": None, "b": 7, "c": "x", "l": ["p", "q", "r"], "e": [], "n": {"m": "deep"}}
        self.assertEqual("-|7|x|deep", render("{a}|{b}|{c}|{n.m}", claim))
        self.assertEqual("p,q|p,q,r|-", render("{l:2}|{l:5}|{e:3}", claim))
        self.assertEqual("7|x|-", render("{a ?? b}|{c ?? b}|{a ?? a}", claim))

    def test_bad_templates_raise(self):
        render = check_schemas.render_template
        for template in ("{missing}", "{n.missing}", "{l}", "{b:2}", "{n}", "{c:x}"):
            with self.subTest(template=template):
                with self.assertRaises((KeyError, TypeError, ValueError)):
                    render(template, {"b": 7, "c": "x", "l": ["p"], "n": {"m": "deep"}})


class RulesDocumentTest(unittest.TestCase):
    """signature-rules.v1.md and check_schemas.py must state the same rules."""

    def document(self):
        return (check_schemas.CONTRACT_DIR / "signature-rules.v1.md").read_text("utf-8")

    def test_template_table_matches_code(self):
        block = re.search(r"<!-- templates:begin -->\s*```text\n(.*?)```\s*<!-- templates:end -->",
                          self.document(), re.S)
        self.assertIsNotNone(block, "templates block not found")
        rows = [tuple(line.split(None, 1)) for line in block.group(1).splitlines() if line.strip()]
        expected = [(selector, template) for selector, template in check_schemas.SIGNATURE_TEMPLATES]
        self.assertEqual(expected, rows)

    def test_document_states_the_id_formula_and_version(self):
        text = self.document()
        self.assertIn('"S" + base32(sha256(utf8(canon)))[0:15]', text)
        self.assertIn(f"rules_version = {check_schemas.RULES_VERSION}", text)

    def test_document_states_the_schema_address_pattern(self):
        pattern = check_schemas.load_schemas()["claim.v1"]["$defs"]["Address"]["pattern"]
        self.assertIn(f"`{pattern}`", self.document())

    def test_address_examples_match_the_schema(self):
        block = re.search(r"<!-- address-examples:begin -->\s*```text\n(.*?)```\s*<!-- address-examples:end -->",
                          self.document(), re.S)
        self.assertIsNotNone(block, "address examples block not found")
        examples = re.findall(r"^(valid|invalid) +(\S+)", block.group(1), re.M)
        self.assertTrue({"valid", "invalid"} <= {verdict for verdict, _ in examples})
        for verdict, address in examples:
            with self.subTest(address=address):
                errors = check_schemas.schema_errors("claim.v1", address, "Address")
                self.assertEqual(verdict == "valid", not errors)

    def test_worked_example_matches_code(self):
        import base64
        import hashlib

        block = re.search(r"<!-- example:begin -->\s*```text\n(.*?)```\s*<!-- example:end -->",
                          self.document(), re.S)
        self.assertIsNotNone(block, "worked example block not found")
        values = dict(line.split(" = ", 1) for line in block.group(1).splitlines() if line.strip())
        values = {key.strip(): value.strip() for key, value in values.items()}
        canon = check_schemas.canon(SPEC_EXAMPLE_CLAIM)
        digest = hashlib.sha256(canon.encode()).digest()
        self.assertEqual(canon, values["canon"])
        self.assertEqual(digest.hex(), values["sha256"])
        self.assertEqual(base64.b32encode(digest).decode().rstrip("="), values["base32"])
        self.assertEqual(check_schemas.signature_id(canon), values["signature"])
