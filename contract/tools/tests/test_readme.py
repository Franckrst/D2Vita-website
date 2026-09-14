import re
import subprocess
import unittest

import check_schemas
import gen_vectors
from tests.helpers import DESIGN_SEALED_CAPS, KIB, MIB

CONTRACT_DIR = check_schemas.CONTRACT_DIR


class ReadmeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (CONTRACT_DIR / "README.md").read_text("utf-8")

    def test_every_tracked_file_is_described(self):
        listed = subprocess.run(["git", "ls-files", "--", "."], cwd=CONTRACT_DIR, check=True,
                                capture_output=True, text=True).stdout.split()
        vendored = {"tools/c_check/monocypher.c", "tools/c_check/monocypher.h",
                    "tools/c_check/monocypher-ed25519.c", "tools/c_check/monocypher-ed25519.h",
                    "tools/c_check/LICENCE.md", "tools/c_check/.gitignore", "README.md"}
        missing = [path for path in listed
                   if path not in vendored and not path.startswith("tools/tests/") and f"`{path}`" not in self.text]
        self.assertEqual([], missing)
        self.assertIn("`tools/tests/`", self.text)
        self.assertIn("Monocypher", self.text)

    def test_acceptance_commands(self):
        for command in ("python3 contract/tools/gen_vectors.py --check",
                        "python3 contract/tools/check_schemas.py",
                        "make -C contract/tools/c_check check",
                        "make -C contract venv",
                        "make -C contract check"):
            with self.subTest(command=command):
                self.assertIn(command, self.text)

    def test_version_rule(self):
        self.assertRegex(self.text, r"(?i)incompatible change.*v2")

    def test_error_code_table_matches_the_schema(self):
        block = re.search(r"<!-- error-codes:begin -->(.*?)<!-- error-codes:end -->", self.text, re.S)
        self.assertIsNotNone(block, "error code table not found")
        codes = re.findall(r"^\| `([a-z_]+)` \| ([0-9]{3}) \|", block.group(1), re.M)
        schema = check_schemas.load_schemas()["admin.v1"]["$defs"]["ErrorBody"]["properties"]["error"]["enum"]
        self.assertEqual(sorted(schema), sorted(code for code, _ in codes))

    def error_code_statuses(self):
        block = re.search(r"<!-- error-codes:begin -->(.*?)<!-- error-codes:end -->", self.text, re.S)
        return {code: status for code, status in re.findall(r"^\| `([a-z_]+)` \| ([0-9]{3}) \|", block.group(1), re.M)}

    def section(self, title):
        match = re.search(rf"^## {re.escape(title)}\n(.*?)(?=^## |\Z)", self.text, re.S | re.M)
        self.assertIsNotNone(match, f"section {title!r} not found")
        return match.group(1)

    def test_errors_named_anywhere_use_the_status_of_their_code(self):
        statuses = self.error_code_statuses()
        pairs = re.findall(r"\b([0-9]{3}) `([a-z_]+)`", self.text)
        self.assertGreater(len(pairs), 20)
        self.assertNotRegex(self.text, r"`[0-9]{3} [a-z_]+`")  # always 429 `rate_limited`
        for status, code in pairs:
            with self.subTest(code=code):
                self.assertEqual(statuses[code], status)

    def test_console_routes_list_their_errors(self):
        expected = {
            "POST /v1/claims": {"400 invalid_payload", "403 unknown_build", "413 payload_too_large",
                                "429 rate_limited", "503 not_accepting"},
            "PUT /v1/reports/{report_id}/artifacts/{name}": {"400 invalid_payload", "403 bad_token", "409 exists",
                                                             "413 payload_too_large", "429 rate_limited",
                                                             "503 not_accepting"},
            "POST /v1/reports/{report_id}/complete": {"400 invalid_payload", "403 bad_token", "409 incomplete",
                                                      "503 not_accepting"},
        }
        rows = {line.split("|")[1].strip().strip("`"): line.split("|")[-2]
                for line in self.section("Routes and messages").splitlines() if line.startswith("| `P")}
        for route, errors in expected.items():
            with self.subTest(route=route):
                self.assertIn(route, rows)
                self.assertEqual(errors, {f"{status} {code}"
                                          for status, code in re.findall(r"([0-9]{3}) `([a-z_]+)`", rows[route])})

    def test_retries_cover_every_console_route(self):
        retries = self.section("Retries")
        for route in ("POST /v1/claims", "PUT .../artifacts/{name}", "POST .../complete"):
            with self.subTest(route=route):
                self.assertIn(f"`{route}`", retries)
        self.assertIn("409 `exists`", retries)

    def test_schema_references_exist(self):
        schemas = check_schemas.load_schemas()
        references = re.findall(r"`((?:claim|decision|bug|admin)\.v1)(?:#([A-Za-z]+))?`", self.text)
        self.assertTrue(references)
        for schema, definition in references:
            with self.subTest(reference=f"{schema}#{definition}"):
                self.assertIn(schema, schemas)
                if definition:
                    self.assertIn(definition, schemas[schema]["$defs"])

    def test_response_binding_table(self):
        block = re.search(r"<!-- response-binding:begin -->(.*?)<!-- response-binding:end -->", self.text, re.S)
        self.assertIsNotNone(block, "response binding table not found")
        rows = re.findall(r"^\| `((?:decision|admin)\.v1)(?:#([A-Za-z]+))?` \| (.*) \|$", block.group(1), re.M)
        schemas = check_schemas.load_schemas()
        bodies = {(schema, definition or None) for schema, definition, _ in rows}
        self.assertEqual({("decision.v1", None), ("decision.v1", "ArtifactStored"),
                          ("decision.v1", "CompleteResponse"), ("admin.v1", "ErrorBody")}, bodies)
        for schema, definition, checks in rows:
            body = schemas[schema]["$defs"][definition] if definition else schemas[schema]
            fields = re.findall(r"`([a-z_]+)`", checks)
            with self.subTest(body=f"{schema}#{definition}"):
                self.assertIn("report_id", fields)
                for field in fields:
                    self.assertIn(field, body["properties"])
                    if definition != "ErrorBody":  # success bodies always carry what the console checks
                        self.assertIn(field, body["required"])

    def test_artifact_caps_table(self):
        block = re.search(r"<!-- artifact-caps:begin -->(.*?)<!-- artifact-caps:end -->", self.text, re.S)
        self.assertIsNotNone(block, "artifact caps table not found")
        rows = re.findall(r"^\| `([a-z_]+)` \| ([0-9]+) \(([0-9]+) (KiB|MiB)\) \| ([0-9]+) \|", block.group(1), re.M)
        self.assertEqual(sorted(DESIGN_SEALED_CAPS), sorted(name for name, *_ in rows))
        for name, sealed, value, unit, plaintext in rows:
            with self.subTest(artifact=name):
                cap = DESIGN_SEALED_CAPS[name]
                self.assertEqual(cap, int(sealed))
                self.assertEqual(cap, int(value) * {"KiB": KIB, "MiB": MIB}[unit])
                largest = int(plaintext)
                self.assertLessEqual(gen_vectors.sealed_size(largest), cap)
                self.assertGreater(gen_vectors.sealed_size(largest + 1), cap)

    def test_monocypher_checksum_matches(self):
        recorded = (CONTRACT_DIR / "tools/c_check/MONOCYPHER_SHA256").read_text().split()
        tarball_sum = recorded[recorded.index("monocypher-4.0.2.tar.gz") - 1]
        self.assertIn(tarball_sum, self.text)
