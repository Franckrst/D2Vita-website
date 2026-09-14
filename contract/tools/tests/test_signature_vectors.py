import contextlib
import copy
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import check_schemas
import gen_vectors
from tests.helpers import SPEC_EXAMPLE_CLAIM

SIGNATURE_FILES = ("signatures.v1.json", "claims-invalid.v1.json")


class SignatureVectorContentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = gen_vectors.build_signature_vectors()
        cls.cases = cls.document["cases"]

    def test_at_least_14_uniquely_named_cases(self):
        names = [case["name"] for case in self.cases]
        self.assertGreaterEqual(len(names), 14)
        self.assertEqual(len(names), len(set(names)))

    def test_first_case_is_the_spec_example(self):
        self.assertEqual("spec_example_halt", self.cases[0]["name"])
        self.assertEqual(SPEC_EXAMPLE_CLAIM, self.cases[0]["claim"])

    def test_coverage(self):
        selectors = {check_schemas.template_for(case["claim"]) for case in self.cases}
        self.assertEqual({template for _, template in check_schemas.SIGNATURE_TEMPLATES}, selectors)

        def features(kind):
            return [case["claim"]["features"] for case in self.cases if case["claim"]["kind"] == kind]

        self.assertTrue(any(f["location"] is None for f in features("halt")))
        self.assertTrue(any(f["location"] is not None for f in features("halt")))
        self.assertTrue(any(isinstance(f["code"], float) for f in features("halt")))
        for kind, key, n in (("halt", "frames", 3), ("guest_fault", "frames", 2),
                             ("host_fault", "guest_frames", 3), ("abnormal_exit", "frames", 1)):
            with self.subTest(kind=kind):
                lengths = {len(f[key]) for f in features(kind)}
                self.assertIn(0, lengths)  # frames absent
                self.assertTrue(any(0 < length < n for length in lengths) or n == 1)  # fewer than N
                self.assertTrue(any(length > n for length in lengths))  # more than N
        self.assertTrue(any(f["exception"] is None for f in features("guest_fault")))
        exits = features("abnormal_exit")
        self.assertTrue(any(f["import"] is not None and f["code"] is not None for f in exits))
        self.assertTrue(any(f["import"] is None and f["code"] is not None for f in exits))
        self.assertTrue(any(f["import"] is None and f["code"] is None for f in exits))
        self.assertTrue(any(f["import"] is None and f["code"] == 0 for f in exits))
        self.assertTrue(any(f["eip"] is None for f in features("hang")))
        self.assertTrue(any(f["stop_reason"] is None for f in features("host_fault")))

    def test_build_dependence_pairs(self):
        by_name = {case["name"]: case for case in self.cases}
        eboot = (by_name["host_fault_eboot"], by_name["host_fault_eboot_other_build"])
        self.assertNotEqual(eboot[0]["signature"], eboot[1]["signature"])
        sysmodule = (by_name["host_fault_sysmodule"], by_name["host_fault_sysmodule_other_build"])
        self.assertNotEqual(sysmodule[0]["claim"]["build_id"], sysmodule[1]["claim"]["build_id"])
        self.assertEqual(sysmodule[0]["signature"], sysmodule[1]["signature"])
        hang = (by_name["hang_with_eip"], by_name["hang_same_eip_other_details"])
        self.assertEqual(hang[0]["signature"], hang[1]["signature"])

    def test_generation_refuses_a_wrong_hand_written_canon(self):
        name, claim, expected = gen_vectors.SIGNATURE_CASES[1]
        broken = [(name, claim, expected + "x")]
        with self.assertRaises(gen_vectors.GenerationError):
            gen_vectors.build_signature_vectors(broken)


class VectorCheckerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def write(self, name, document):
        path = self.tmp / name
        path.write_text(json.dumps(document), "utf-8")
        return path

    def test_generated_vectors_pass(self):
        signatures = gen_vectors.build_signature_vectors()
        self.assertEqual(len(signatures["cases"]),
                         check_schemas.check_signature_vectors(self.write("s.json", signatures)))
        invalid = gen_vectors.build_invalid_claim_vectors(signatures)
        self.assertGreaterEqual(len(invalid["cases"]), 30)
        self.assertEqual(len(invalid["cases"]),
                         check_schemas.check_invalid_claim_vectors(self.write("i.json", invalid),
                                                                   self.write("s.json", signatures)))

    def test_signature_checker_detects_each_kind_of_drift(self):
        signatures = gen_vectors.build_signature_vectors()
        drifts = {
            "canon": lambda case: case.update(canon=case["canon"] + "x"),
            "signature": lambda case: case.update(signature="SAAAAAAAAAAAAAAA"),
            "claim": lambda case: case["claim"]["features"].update(code=1421),
            "invalid claim": lambda case: case["claim"].update(extra=True),
        }
        for label, drift in drifts.items():
            with self.subTest(drift=label):
                document = copy.deepcopy(signatures)
                drift(document["cases"][0])
                with self.assertRaises(check_schemas.VectorError):
                    check_schemas.check_signature_vectors(self.write("s.json", document))

    def test_invalid_claim_checker_detects_valid_or_misplaced_cases(self):
        signatures = gen_vectors.build_signature_vectors()
        invalid = gen_vectors.build_invalid_claim_vectors(signatures)
        signatures_path = self.write("s.json", signatures)
        now_valid = copy.deepcopy(invalid)
        now_valid["cases"][0]["claim"] = copy.deepcopy(signatures["cases"][0]["claim"])
        with self.assertRaises(check_schemas.VectorError):
            check_schemas.check_invalid_claim_vectors(self.write("i.json", now_valid), signatures_path)
        misplaced = copy.deepcopy(invalid)
        misplaced["cases"][0]["invalid_at"] = "/nowhere"
        with self.assertRaises(check_schemas.VectorError):
            check_schemas.check_invalid_claim_vectors(self.write("i.json", misplaced), signatures_path)
        orphan = copy.deepcopy(invalid)
        orphan["cases"][0]["base"] = "no_such_case"
        with self.assertRaises(check_schemas.VectorError):
            check_schemas.check_invalid_claim_vectors(self.write("i.json", orphan), signatures_path)


class GenVectorsCheckModeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = gen_vectors.main(list(argv))
        return code, out.getvalue() + err.getvalue()

    def test_generation_is_deterministic(self):
        self.assertEqual(gen_vectors.render_all(), gen_vectors.render_all())

    def test_committed_vectors_are_up_to_date(self):
        code, output = self.run_main("--check")
        self.assertEqual(0, code, output)

    def test_write_then_check_then_detect_any_drift(self):
        code, output = self.run_main("--dir", str(self.tmp))
        self.assertEqual(0, code, output)
        self.assertEqual(0, self.run_main("--check", "--dir", str(self.tmp))[0])
        for name in SIGNATURE_FILES:
            with self.subTest(file=name):
                path = self.tmp / name
                original = path.read_bytes()
                index = len(original) // 2
                path.write_bytes(original[:index] + bytes([original[index] ^ 0x01]) + original[index + 1 :])
                code, output = self.run_main("--check", "--dir", str(self.tmp))
                self.assertEqual(1, code)
                self.assertIn(name, output)
                path.write_bytes(original + b"\n")
                self.assertEqual(1, self.run_main("--check", "--dir", str(self.tmp))[0])
                path.unlink()
                self.assertEqual(1, self.run_main("--check", "--dir", str(self.tmp))[0])
                path.write_bytes(original)
        self.assertEqual(0, self.run_main("--check", "--dir", str(self.tmp))[0])
