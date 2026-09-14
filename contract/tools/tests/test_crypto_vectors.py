import base64
import contextlib
import io
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

import nacl.bindings as sodium
import nacl.exceptions
import nacl.signing

import check_schemas
import gen_vectors as g

ALL_FILES = ("signatures.v1.json", "claims-invalid.v1.json", "sealed.v1.json", "response-sig.v1.json")
L = 2**252 + 27742317777372353535851937790883648493  # Ed25519 group order


class SealedVectorsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = g.build_sealed_vectors()

    def test_positive_cases_cover_the_plan(self):
        cases = self.document["cases"]
        self.assertGreaterEqual(len(cases), 6)
        shapes = {(len(bytes.fromhex(case["plaintext_hex"])), case["chunk_size"]) for case in cases}
        sizes_vs_chunk = {(size - case_chunk if size >= case_chunk else -1) for size, case_chunk in shapes}
        self.assertIn((0, 65536), shapes)  # empty
        self.assertIn((1, 65536), shapes)  # one byte
        self.assertIn(0, sizes_vs_chunk)  # exactly chunk_size
        self.assertIn(1, sizes_vs_chunk)  # chunk_size + 1
        self.assertTrue(any(size // chunk + 1 >= 3 for size, chunk in shapes))  # three chunks or more
        self.assertIn((70000, 65536), shapes)
        names = [case["name"] for case in cases + self.document["negative_cases"]]
        self.assertEqual(len(names), len(set(names)))

    def test_each_positive_case_reproduces_and_opens(self):
        for case in self.document["cases"]:
            with self.subTest(case=case["name"]):
                sk = bytes.fromhex(case["recipient_sk_hex"])
                pk = bytes.fromhex(case["recipient_pk_hex"])
                eph_sk = bytes.fromhex(case["eph_sk_hex"])
                plaintext = bytes.fromhex(case["plaintext_hex"])
                sealed = bytes.fromhex(case["sealed_hex"])
                self.assertEqual(sodium.crypto_scalarmult_base(sk), pk)
                self.assertEqual(sodium.crypto_scalarmult_base(eph_sk).hex(), case["eph_pk_hex"])
                shared = sodium.crypto_scalarmult(eph_sk, pk)
                self.assertEqual(shared.hex(), case["shared_hex"])
                self.assertEqual(g.derive_key(shared, bytes.fromhex(case["eph_pk_hex"]), pk).hex(), case["key_hex"])
                self.assertEqual(g.key_id(pk).hex(), case["key_id_hex"])
                self.assertEqual(sealed, g.seal(plaintext, pk, eph_sk, bytes.fromhex(case["nonce_prefix_hex"]),
                                                case["chunk_size"]))
                self.assertEqual(g.sealed_size(len(plaintext), case["chunk_size"]), len(sealed))
                self.assertEqual(plaintext, g.open_sealed(sealed, sk))

    def test_negative_cases_fail_with_the_expected_kind(self):
        negatives = self.document["negative_cases"]
        self.assertGreaterEqual(len(negatives), 3)
        self.assertEqual({"truncated", "tampered", "wrong_key", "malformed"}, {c["expect"] for c in negatives})
        for case in negatives:
            with self.subTest(case=case["name"]):
                with self.assertRaises(g.OpenError) as caught:
                    g.open_sealed(bytes.fromhex(case["sealed_hex"]), bytes.fromhex(case["recipient_sk_hex"]))
                self.assertEqual(case["expect"], caught.exception.kind)

    def test_keys_need_clamping(self):
        # Implementations must clamp X25519 scalars themselves: some vector keys are not clamped.
        keys = [bytes.fromhex(case[field]) for case in self.document["cases"]
                for field in ("recipient_sk_hex", "eph_sk_hex")]
        self.assertTrue(any(key[0] & 7 and key[31] & 0x80 for key in keys))

    def test_generator_refuses_a_negative_case_that_opens(self):
        with self.assertRaises(g.GenerationError):
            g.check_negative_case({"name": "x", "recipient_sk_hex": self.document["cases"][1]["recipient_sk_hex"],
                                   "sealed_hex": self.document["cases"][1]["sealed_hex"], "expect": "tampered"})


class ResponseSignatureVectorsTest(unittest.TestCase):
    BODY_SCHEMAS = {
        "decision_upload": ("decision.v1", None),
        "decision_count_only": ("decision.v1", None),
        "error_rate_limited": ("admin.v1", "ErrorBody"),
        "error_not_accepting": ("admin.v1", "ErrorBody"),
        "error_exists": ("admin.v1", "ErrorBody"),
        "artifact_stored": ("decision.v1", "ArtifactStored"),
        "complete_response": ("decision.v1", "CompleteResponse"),
        "error_non_ascii_message": ("admin.v1", "ErrorBody"),
    }

    @classmethod
    def setUpClass(cls):
        cls.document = g.build_response_signature_vectors()

    def test_positive_cases_verify_and_reproduce(self):
        cases = self.document["cases"]
        self.assertGreaterEqual(len(cases), 3)
        for case in cases:
            with self.subTest(case=case["name"]):
                key = nacl.signing.SigningKey(bytes.fromhex(case["seed_hex"]))
                self.assertEqual(case["public_key_hex"], key.verify_key.encode().hex())
                body = case["body_utf8"].encode("utf-8")
                signature = base64.b64decode(case["signature_b64"], validate=True)
                self.assertEqual(88, len(case["signature_b64"]))
                self.assertEqual(signature, key.sign(body).signature)
                nacl.signing.VerifyKey(bytes.fromhex(case["public_key_hex"])).verify(body, signature)

    def test_bodies_are_contract_messages(self):
        by_name = {case["name"]: case for case in self.document["cases"]}
        self.assertTrue(any(ord(ch) > 0xFFFF for ch in by_name["error_non_ascii_message"]["body_utf8"]))
        self.assertEqual("", by_name["empty_body"]["body_utf8"])
        for name, (schema, definition) in self.BODY_SCHEMAS.items():
            with self.subTest(case=name):
                body = json.loads(by_name[name]["body_utf8"])
                self.assertEqual([], [e.message for e in check_schemas.schema_errors(schema, body, definition)])

    def test_report_bodies_name_their_report(self):
        by_name = {case["name"]: json.loads(case["body_utf8"]) for case in self.document["cases"] if case["body_utf8"]}
        report_id = by_name["decision_upload"]["report_id"]
        for name in ("decision_count_only", "artifact_stored", "complete_response", "error_exists"):
            with self.subTest(case=name):
                self.assertEqual(report_id, by_name[name]["report_id"])
        self.assertEqual("crash_txt", by_name["artifact_stored"]["name"])
        self.assertEqual("crash_txt", by_name["error_exists"]["artifact"])

    def test_negative_cases_are_rejected(self):
        negatives = self.document["negative_cases"]
        self.assertGreaterEqual(len(negatives), 3)
        for case in negatives:
            with self.subTest(case=case["name"]):
                self.assertEqual("invalid", case["expect"])
                with self.assertRaises(nacl.exceptions.BadSignatureError):
                    nacl.signing.VerifyKey(bytes.fromhex(case["public_key_hex"])).verify(
                        case["body_utf8"].encode("utf-8"), base64.b64decode(case["signature_b64"]))

    def test_non_canonical_s_case_is_s_plus_l(self):
        by_name = {case["name"]: case for case in self.document["negative_cases"]}
        forged = base64.b64decode(by_name["signature_s_plus_group_order"]["signature_b64"])
        original = base64.b64decode({c["name"]: c for c in self.document["cases"]}["decision_upload"]["signature_b64"])
        self.assertEqual(original[:32], forged[:32])
        self.assertEqual(int.from_bytes(original[32:], "little") + L, int.from_bytes(forged[32:], "little"))


class SealedFormatDocumentTest(unittest.TestCase):
    def test_annotated_example_matches_the_vector(self):
        text = (check_schemas.CONTRACT_DIR / "sealed-format.md").read_text("utf-8")
        block = re.search(r"<!-- example:begin -->\s*```text\n(.*?)```\s*<!-- example:end -->", text, re.S)
        self.assertIsNotNone(block, "example block not found")
        case = {c["name"]: c for c in g.build_sealed_vectors()["cases"]}["one_byte"]
        self.assertEqual(g.annotated_example(case), block.group(1))

    def test_annotated_example_rebuilds_the_sealed_bytes(self):
        case = {c["name"]: c for c in g.build_sealed_vectors()["cases"]}["one_byte"]
        dump_lines = [line for line in g.annotated_example(case).splitlines() if re.match(r"^[0-9a-f]{4}  ", line)]
        rebuilt = bytes.fromhex("".join(line[6:53].replace(" ", "") for line in dump_lines))
        self.assertEqual(bytes.fromhex(case["sealed_hex"]), rebuilt)


class AllVectorFilesCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = g.main(list(argv))
        return code, out.getvalue()

    def test_render_all_names_every_file(self):
        self.assertEqual(ALL_FILES, tuple(g.render_all()))

    def test_drift_in_any_file_is_detected(self):
        self.assertEqual(0, self.run_main("--dir", str(self.tmp))[0])
        for name in ALL_FILES:
            with self.subTest(file=name):
                path = self.tmp / name
                original = path.read_bytes()
                index = len(original) - 200
                path.write_bytes(original[:index] + bytes([original[index] ^ 0x02]) + original[index + 1 :])
                code, output = self.run_main("--check", "--dir", str(self.tmp))
                self.assertEqual(1, code)
                self.assertIn(name, output)
                path.write_bytes(original)
        self.assertEqual(0, self.run_main("--check", "--dir", str(self.tmp))[0])
