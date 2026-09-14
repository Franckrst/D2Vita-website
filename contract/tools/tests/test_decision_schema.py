import copy

from tests.helpers import DESIGN_SEALED_CAPS, SchemaTestCase

UPLOAD_DECISION = {
    "v": 1,
    "report_id": "01J9Z6T4Q8M3K7V2B5N0XWAYCD",
    "signature": "SLG2YDMWX5VQ7H3K",  # "S" + 15 RFC 4648 base32 characters
    "action": "upload",
    "upload": {
        "token": "eyJyIjoiMDFKOVo2VDRROE0zSzdWMkI1TjBYV0FZQ0QifQ.c2lnbmF0dXJl",
        "expires_unix": 1789286000,
        "artifacts": [{"name": "crash_txt", "max_bytes": 65536}],
    },
    "retry_after_s": None,
    "disable_until_unix": None,
}

COUNT_ONLY_DECISION = {
    "v": 1,
    "report_id": "01J9Z6T4Q8M3K7V2B5N0XWAYCD",
    "signature": "SLG2YDMWX5VQ7H3K",
    "action": "count_only",
    "upload": None,
    "retry_after_s": None,
    "disable_until_unix": None,
}


def mutated(document, fn):
    document = copy.deepcopy(document)
    fn(document)
    return document


class DecisionSchemaTest(SchemaTestCase):
    schema_name = "decision.v1"

    def test_valid_decisions(self):
        self.assertValid(UPLOAD_DECISION)
        self.assertValid(COUNT_ONLY_DECISION)
        self.assertValid(mutated(COUNT_ONLY_DECISION, lambda d: d.update(retry_after_s=3600)))
        self.assertValid(mutated(COUNT_ONLY_DECISION, lambda d: d.update(disable_until_unix=1789300000)))

    def test_upload_grant_limits(self):
        full = mutated(UPLOAD_DECISION, lambda d: d["upload"].update(artifacts=[
            {"name": name, "max_bytes": cap} for name, cap in DESIGN_SEALED_CAPS.items()
        ]))
        self.assertValid(full)

    def test_signature_is_s_plus_15_rfc4648_base32(self):
        # The example of design section 5.2 ("S4KQ7M2X9D3T8B6A") uses 8 and 9,
        # which are not RFC 4648 base32 digits: it is illustrative only.
        for bad in ("S4KQ7M2X9D3T8B6A", "SLG2YDMWX5VQ7H3", "SLG2YDMWX5VQ7H3KA", "slg2ydmwx5vq7h3k",
                    "XLG2YDMWX5VQ7H3K"):
            with self.subTest(signature=bad):
                self.assertInvalidAt(mutated(COUNT_ONLY_DECISION, lambda d: d.update(signature=bad)),
                                     "/signature")

    def test_upload_object_iff_action_upload(self):
        self.assertInvalidAt(mutated(UPLOAD_DECISION, lambda d: d.update(upload=None)), "/upload")
        self.assertInvalidAt(
            mutated(COUNT_ONLY_DECISION, lambda d: d.update(upload=copy.deepcopy(UPLOAD_DECISION["upload"]))),
            "/upload")
        self.assertInvalidAt(mutated(COUNT_ONLY_DECISION, lambda d: d.update(action="later")), "/action")

    def test_all_keys_required_and_no_extra(self):
        for key in COUNT_ONLY_DECISION:
            with self.subTest(key=key):
                self.assertInvalidAt(mutated(COUNT_ONLY_DECISION, lambda d: d.pop(key)), "")
        self.assertInvalidAt(mutated(COUNT_ONLY_DECISION, lambda d: d.update(count=2)), "")
        self.assertInvalidAt(mutated(UPLOAD_DECISION, lambda d: d["upload"].update(url="x")), "/upload")

    def test_grant_artifacts(self):
        self.assertInvalidAt(mutated(UPLOAD_DECISION, lambda d: d["upload"].update(artifacts=[])),
                             "/upload/artifacts")
        self.assertInvalidAt(
            mutated(UPLOAD_DECISION, lambda d: d["upload"]["artifacts"].append({"name": "crash_txt", "max_bytes": 1000})),
            "/upload/artifacts")
        self.assertInvalidAt(
            mutated(UPLOAD_DECISION, lambda d: d["upload"]["artifacts"][0].update(max_bytes=65537)),
            "/upload/artifacts/0/max_bytes")
        self.assertInvalidAt(
            mutated(UPLOAD_DECISION, lambda d: d["upload"]["artifacts"][0].update(max_bytes=87)),
            "/upload/artifacts/0/max_bytes")
        self.assertInvalidAt(
            mutated(UPLOAD_DECISION, lambda d: d["upload"]["artifacts"][0].update(bytes=10)),
            "/upload/artifacts/0")

    def test_token_is_header_safe_and_bounded(self):
        for bad in ("a b", "", "x" * 1025, "tok\n", "t\xf6ken"):
            with self.subTest(token=bad):
                self.assertInvalidAt(mutated(UPLOAD_DECISION, lambda d: d["upload"].update(token=bad)),
                                     "/upload/token")

    def test_numbers(self):
        self.assertInvalidAt(mutated(COUNT_ONLY_DECISION, lambda d: d.update(retry_after_s=-1)),
                             "/retry_after_s")
        self.assertInvalidAt(mutated(COUNT_ONLY_DECISION, lambda d: d.update(disable_until_unix="soon")),
                             "/disable_until_unix")
        self.assertInvalidAt(mutated(UPLOAD_DECISION, lambda d: d["upload"].update(expires_unix=None)),
                             "/upload/expires_unix")
        self.assertInvalidAt(mutated(COUNT_ONLY_DECISION, lambda d: d.update(report_id="nope")), "/report_id")


class ConsoleUploadMessagesTest(SchemaTestCase):
    schema_name = "decision.v1"

    def test_artifact_stored(self):
        self.assertValid({"v": 1, "name": "crash_txt", "bytes": 2210}, "ArtifactStored")
        self.assertInvalidAt({"v": 1, "name": "crash_txt", "bytes": 70000}, "/bytes", "ArtifactStored")
        self.assertInvalidAt({"v": 1, "name": "crash_txt"}, "", "ArtifactStored")

    def test_complete_request(self):
        self.assertValid({"v": 1, "artifacts": ["crash_txt", "crash_log"]}, "CompleteRequest")
        self.assertInvalidAt({"v": 1, "artifacts": []}, "/artifacts", "CompleteRequest")
        self.assertInvalidAt({"v": 1, "artifacts": ["crash_txt", "crash_txt"]}, "/artifacts",
                             "CompleteRequest")
        self.assertInvalidAt({"v": 1, "artifacts": ["minidump"]}, "/artifacts/0", "CompleteRequest")
        self.assertInvalidAt({"v": 1, "artifacts": ["dump"], "report_id": "x"}, "", "CompleteRequest")

    def test_complete_response(self):
        self.assertValid({"v": 1, "sample_stored": True}, "CompleteResponse")
        self.assertValid({"v": 1, "sample_stored": False}, "CompleteResponse")
        self.assertInvalidAt({"v": 1, "sample_stored": "yes"}, "/sample_stored", "CompleteResponse")
        self.assertInvalidAt({"sample_stored": True}, "", "CompleteResponse")
