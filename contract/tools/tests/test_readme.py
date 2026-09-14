import re
import subprocess
import unittest

import check_schemas

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

    def test_schema_references_exist(self):
        schemas = check_schemas.load_schemas()
        references = re.findall(r"`((?:claim|decision|bug|admin)\.v1)(?:#([A-Za-z]+))?`", self.text)
        self.assertTrue(references)
        for schema, definition in references:
            with self.subTest(reference=f"{schema}#{definition}"):
                self.assertIn(schema, schemas)
                if definition:
                    self.assertIn(definition, schemas[schema]["$defs"])

    def test_monocypher_checksum_matches(self):
        recorded = (CONTRACT_DIR / "tools/c_check/MONOCYPHER_SHA256").read_text().split()
        tarball_sum = recorded[recorded.index("monocypher-4.0.2.tar.gz") - 1]
        self.assertIn(tarball_sum, self.text)
