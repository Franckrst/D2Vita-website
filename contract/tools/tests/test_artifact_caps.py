"""Sealed size caps of the artifacts, tied to design section 4.5."""
import json
import re

import check_schemas
from tests.helpers import DESIGN_SEALED_CAPS, KIB, MIB, SchemaTestCase, claim_of_kind

UNITS = {"KiB": KIB, "MiB": MIB}


def schema_caps(property_name):
    """{artifact name: maximum} for `bytes` or `max_bytes` in claim.v1#ArtifactSizeCaps."""
    caps = {}
    for branch in check_schemas.load_schemas()["claim.v1"]["$defs"]["ArtifactSizeCaps"]["allOf"]:
        name = branch["if"]["properties"]["name"]["const"]
        caps[name] = branch["then"]["properties"][property_name]["maximum"]
    return caps


def vector_cases(file_name):
    return json.loads((check_schemas.VECTOR_DIR / file_name).read_text("utf-8"))["cases"]


class ArtifactCapsTest(SchemaTestCase):
    def test_schema_caps_are_the_design_caps(self):
        self.assertEqual(DESIGN_SEALED_CAPS, schema_caps("bytes"))
        self.assertEqual(DESIGN_SEALED_CAPS, schema_caps("max_bytes"))

    def test_schema_description_states_the_design_caps(self):
        description = check_schemas.load_schemas()["claim.v1"]["$defs"]["ArtifactSizeCaps"]["description"]
        stated = {name: int(value) * UNITS[unit]
                  for name, value, unit in re.findall(r"\b([a-z_]+) ([0-9]+) (KiB|MiB)\b", description)}
        self.assertEqual(DESIGN_SEALED_CAPS, stated)

    def test_claim_offer_cap_is_inclusive(self):
        self.schema_name = "claim.v1"
        for name, cap in DESIGN_SEALED_CAPS.items():
            kind = "host_fault" if name == "dump" else "halt"
            with self.subTest(name=name):
                self.assertValid(claim_of_kind(kind, artifacts=[{"name": name, "bytes": cap}]))
                self.assertInvalidAt(claim_of_kind(kind, artifacts=[{"name": name, "bytes": cap + 1}]),
                                     "/artifacts/0/bytes")

    def test_decision_request_and_stored_caps_are_inclusive(self):
        self.schema_name = "decision.v1"
        for name, cap in DESIGN_SEALED_CAPS.items():
            with self.subTest(name=name):
                self.assertValid({"name": name, "max_bytes": cap}, "ArtifactRequest")
                self.assertInvalidAt({"name": name, "max_bytes": cap + 1}, "/max_bytes", "ArtifactRequest")
                stored = {"v": 1, "report_id": "01J9Z6T4Q8M3K7V2B5N0XWAYCD", "name": name, "bytes": cap}
                self.assertValid(stored, "ArtifactStored")
                self.assertInvalidAt(dict(stored, bytes=cap + 1), "/bytes", "ArtifactStored")

    def test_vectors_sit_on_both_sides_of_every_cap(self):
        # Implementations (ajv in the API) must see a claim offering exactly the
        # cap accepted, and one byte more rejected, for every artifact.
        at_cap = {offer["name"]: offer["bytes"]
                  for case in vector_cases("signatures.v1.json") if case["name"] == "host_fault_artifacts_at_caps"
                  for offer in case["claim"]["artifacts"]}
        self.assertEqual(DESIGN_SEALED_CAPS, at_cap)
        over_cap = {}
        for case in vector_cases("claims-invalid.v1.json"):
            match = re.fullmatch(r"artifact_([a-z_]+)_over_cap", case["name"])
            if match:
                index = int(case["invalid_at"].split("/")[2])
                self.assertEqual(match.group(1), case["claim"]["artifacts"][index]["name"])
                over_cap[match.group(1)] = case["claim"]["artifacts"][index]["bytes"]
        self.assertEqual({name: cap + 1 for name, cap in DESIGN_SEALED_CAPS.items()}, over_cap)
