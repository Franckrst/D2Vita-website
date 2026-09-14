import copy

import check_schemas
from tests.helpers import SPEC_EXAMPLE_CLAIM, SchemaTestCase

SUMMARY = {
    "id": "SLG2YDMWX5VQ7H3K",
    "kind": "halt",
    "canon": "halt|1420|-|Game+0x1fedf4,Game+0x451c23,Game+0x44f570",
    "status": "open",
    "count": 31,
    "installs": 12,
    "first_seen_unix": 1789284000,
    "last_seen_unix": 1789290000,
    "sample_state": "stored",
    "fixed_in_version": None,
    "merged_into": None,
    "issue_url": None,
}

STORED_ARTIFACT = {
    "name": "crash_txt",
    "bytes": 2210,
    "sha256": "0f" * 32,
    "stored_unix": 1789284100,
}

DETAIL = dict(
    {"v": 1},
    **SUMMARY,
    rules_version=1,
    note=None,
    sample_report="01J9Z6T4Q8M3K7V2B5N0XWAYCD",
    lease_report=None,
    lease_expires_unix=None,
    sample_artifacts=[STORED_ARTIFACT],
    builds=[{"build_id": "0.1.0+ab12cd34ef56", "count": 31,
             "first_seen_unix": 1789284000, "last_seen_unix": 1789290000}],
    recent_reports=[{"report_id": "01J9Z6T4Q8M3K7V2B5N0XWAYCD", "build_id": "0.1.0+ab12cd34ef56",
                     "received_unix": 1789284050, "action": "upload"}],
)

REPORT = {
    "v": 1,
    "report_id": "01J9Z6T4Q8M3K7V2B5N0XWAYCD",
    "signature": "SLG2YDMWX5VQ7H3K",
    "install_hash": "ab" * 32,
    "received_unix": 1789284050,
    "rules_version": 1,
    "action": "upload",
    "completed_unix": 1789284200,
    "claim": SPEC_EXAMPLE_CLAIM,
    "artifacts": [STORED_ARTIFACT],
}

BUG_ITEM = {
    "id": "B01J9Z6T4Q8M3K7V2B5N0XWAYCD",
    "title": "Crash when opening the stash",
    "description": "Steps to reproduce",
    "version": "0.1.0",
    "contact": None,
    "lang": "fr",
    "status": "open",
    "issue_url": None,
    "created_unix": 1789284000,
}

CAPS = {
    "install_claims_per_day": 3,
    "install_artifact_bytes_per_day": 3145728,
    "prerelease_install_claims_per_day": 50,
    "prerelease_install_artifact_bytes_per_day": 52428800,
    "ip_claims_per_day": 10,
    "ip_bugs_per_day": 3,
    "global_claims_per_day": 2000,
    "global_artifact_bytes_per_day": 314572800,
    "global_new_signatures_per_day": 200,
    "global_bugs_per_day": 100,
}

USAGE = {"used": 5, "cap": 2000}


def mutated(document, fn):
    document = copy.deepcopy(document)
    fn(document)
    return document


class AdminSignatureDefinitionsTest(SchemaTestCase):
    schema_name = "admin.v1"

    def test_summary_and_list(self):
        self.assertValid(SUMMARY, "SignatureSummary")
        self.assertValid({"v": 1, "items": [SUMMARY], "next_cursor": "c2VjcmV0LWN1cnNvcg"}, "SignatureList")
        self.assertValid({"v": 1, "items": [], "next_cursor": None}, "SignatureList")
        self.assertInvalidAt(mutated(SUMMARY, lambda s: s.update(status="closed")), "/status",
                             "SignatureSummary")
        self.assertInvalidAt(mutated(SUMMARY, lambda s: s.update(sample_state="uploaded")),
                             "/sample_state", "SignatureSummary")
        self.assertInvalidAt(mutated(SUMMARY, lambda s: s.update(install_hash="ab" * 32)), "",
                             "SignatureSummary")
        self.assertInvalidAt({"v": 1, "items": [SUMMARY], "next_cursor": "bad cursor"}, "/next_cursor",
                             "SignatureList")

    def test_detail(self):
        self.assertValid(DETAIL, "SignatureDetail")
        self.assertValid(mutated(DETAIL, lambda d: d.update(status="regressed", sample_state="leased",
                                                            lease_report="01J9Z6T4Q8M3K7V2B5N0XWAYCE",
                                                            lease_expires_unix=1789291800,
                                                            fixed_in_version="0.1.2",
                                                            issue_url="https://github.com/Franckrst/D2Vita/issues/12",
                                                            merged_into="SAAAAAAAAAAAAAAA",
                                                            note="Same family as S...")),
                         "SignatureDetail")
        self.assertInvalidAt(mutated(DETAIL, lambda d: d.pop("builds")), "", "SignatureDetail")
        self.assertInvalidAt(mutated(DETAIL, lambda d: d.update(fixed_in_version="0.1")),
                             "/fixed_in_version", "SignatureDetail")
        self.assertInvalidAt(mutated(DETAIL, lambda d: d.update(issue_url="http://example.org/1")),
                             "/issue_url", "SignatureDetail")
        self.assertInvalidAt(mutated(DETAIL, lambda d: d["sample_artifacts"][0].update(sha256="AB" * 32)),
                             "/sample_artifacts/0/sha256", "SignatureDetail")

    def test_detail_repeats_every_summary_field(self):
        admin = check_schemas.load_schemas()["admin.v1"]["$defs"]
        summary = admin["SignatureSummary"]["properties"]
        detail = admin["SignatureDetail"]["properties"]
        for key, schema in summary.items():
            with self.subTest(key=key):
                self.assertEqual(schema, detail.get(key))
        self.assertLessEqual(set(admin["SignatureSummary"]["required"]),
                             set(admin["SignatureDetail"]["required"]))

    def test_patch(self):
        self.assertValid({"status": "fixed", "fixed_in_version": "0.2.0"}, "SignaturePatch")
        self.assertValid({"merged_into": "SAAAAAAAAAAAAAAA"}, "SignaturePatch")
        self.assertValid({"merged_into": None, "issue_url": None, "note": None}, "SignaturePatch")
        self.assertValid({"resample": True}, "SignaturePatch")
        self.assertInvalidAt({}, "", "SignaturePatch")
        self.assertInvalidAt({"status": "regressed"}, "/status", "SignaturePatch")
        self.assertInvalidAt({"count": 0}, "", "SignaturePatch")
        self.assertInvalidAt({"note": "x" * 2001}, "/note", "SignaturePatch")


class AdminReportDefinitionsTest(SchemaTestCase):
    schema_name = "admin.v1"

    def test_report_detail_embeds_a_valid_claim(self):
        self.assertValid(REPORT, "ReportDetail")
        self.assertValid(mutated(REPORT, lambda r: r.update(action="count_only", completed_unix=None,
                                                            artifacts=[])), "ReportDetail")
        self.assertInvalidAt(mutated(REPORT, lambda r: r["claim"]["features"].update(code="x")),
                             "/claim/features/code", "ReportDetail")
        self.assertInvalidAt(mutated(REPORT, lambda r: r.update(install_hash="xyz")), "/install_hash",
                             "ReportDetail")


class AdminBugDefinitionsTest(SchemaTestCase):
    schema_name = "admin.v1"

    def test_bug_item_list_detail(self):
        self.assertValid(BUG_ITEM, "BugItem")
        self.assertValid(mutated(BUG_ITEM, lambda b: b.update(contact="me@example.org", status="fixed",
                                                              issue_url="https://github.com/Franckrst/D2Vita/issues/3")),
                         "BugItem")
        self.assertValid({"v": 1, "items": [BUG_ITEM], "next_cursor": None}, "BugList")
        self.assertValid(dict({"v": 1}, **BUG_ITEM), "BugDetail")
        self.assertInvalidAt(mutated(BUG_ITEM, lambda b: b.update(turnstile_token="x")), "", "BugItem")
        self.assertInvalidAt(mutated(BUG_ITEM, lambda b: b.update(title="")), "/title", "BugItem")
        self.assertInvalidAt(mutated(BUG_ITEM, lambda b: b.update(status="new")), "/status", "BugItem")
        self.assertInvalidAt(BUG_ITEM, "", "BugDetail")

    def test_bug_patch(self):
        self.assertValid({"status": "ignored"}, "BugPatch")
        self.assertValid({"issue_url": "https://github.com/Franckrst/D2Vita/issues/3"}, "BugPatch")
        self.assertInvalidAt({}, "", "BugPatch")
        self.assertInvalidAt({"title": "x"}, "", "BugPatch")


class AdminOperationsDefinitionsTest(SchemaTestCase):
    schema_name = "admin.v1"

    def test_builds(self):
        registration = {"build_id": "0.1.0+ab12cd34ef56", "version": "0.1.0", "channel": "test"}
        self.assertValid(registration, "BuildRegistration")
        self.assertValid(dict({"v": 1, "registered_unix": 1789284000}, **registration), "BuildRecord")
        self.assertInvalidAt(dict(registration, channel="nightly"), "/channel", "BuildRegistration")
        self.assertInvalidAt(dict(registration, version="0.1.0-rc1"), "/version", "BuildRegistration")
        self.assertInvalidAt({"build_id": "0.1.0+ab12cd34ef56"}, "", "BuildRegistration")

    def test_stats(self):
        stats = {"v": 1, "day": "2026-09-14", "accepting": True,
                 "usage": {"claims": USAGE, "artifact_bytes": USAGE, "new_signatures": USAGE, "bugs": USAGE}}
        self.assertValid(stats, "Stats")
        self.assertInvalidAt(mutated(stats, lambda s: s.update(day="14/09/2026")), "/day", "Stats")
        self.assertInvalidAt(mutated(stats, lambda s: s["usage"].pop("bugs")), "/usage", "Stats")
        self.assertInvalidAt(mutated(stats, lambda s: s["usage"]["claims"].update(used=-1)),
                             "/usage/claims/used", "Stats")

    def test_settings(self):
        settings = {"v": 1, "accepting": True, "disable_until_unix": None, "caps": CAPS}
        self.assertValid(settings, "Settings")
        self.assertInvalidAt(mutated(settings, lambda s: s["caps"].pop("ip_bugs_per_day")), "/caps", "Settings")
        self.assertValid({"accepting": False, "disable_until_unix": 1789300000}, "SettingsUpdate")
        self.assertValid({"caps": {"install_claims_per_day": 5}}, "SettingsUpdate")
        self.assertInvalidAt({}, "", "SettingsUpdate")
        self.assertInvalidAt({"caps": {}}, "/caps", "SettingsUpdate")
        self.assertInvalidAt({"caps": {"per_hour": 5}}, "/caps", "SettingsUpdate")

    def test_forget_install_result(self):
        self.assertValid({"v": 1, "reports_deleted": 4, "artifacts_deleted": 2}, "ForgetInstallResult")
        self.assertInvalidAt({"v": 1, "reports_deleted": 4}, "", "ForgetInstallResult")


class ErrorBodyTest(SchemaTestCase):
    schema_name = "admin.v1"
    definition = "ErrorBody"

    def test_error_codes(self):
        for code in ("invalid_payload", "unauthorized", "unknown_build", "bad_token", "turnstile",
                     "not_found", "method_not_allowed", "payload_too_large", "internal_error"):
            with self.subTest(code=code):
                self.assertValid({"v": 1, "error": code, "message": "details"})
        self.assertInvalidAt({"v": 1, "error": "rate-limited", "message": ""}, "/error")
        self.assertInvalidAt({"v": 1, "error": "bad_token"}, "")
        self.assertInvalidAt({"v": 1, "error": "bad_token", "message": "m", "detail": "x"}, "")

    def test_rate_limited_requires_retry_after(self):
        self.assertValid({"v": 1, "error": "rate_limited", "message": "m", "retry_after_s": 3600})
        self.assertInvalidAt({"v": 1, "error": "rate_limited", "message": "m"}, "")
        self.assertInvalidAt({"v": 1, "error": "rate_limited", "message": "m", "retry_after_s": None},
                             "/retry_after_s")

    def test_request_identifiers(self):
        report_id = "01J9Z6T4Q8M3K7V2B5N0XWAYCD"
        self.assertValid({"v": 1, "error": "bad_token", "message": "m", "report_id": report_id})
        self.assertValid({"v": 1, "error": "payload_too_large", "message": "m", "report_id": report_id,
                          "artifact": "dump"})
        self.assertValid({"v": 1, "error": "rate_limited", "message": "m", "retry_after_s": 60,
                          "report_id": report_id})
        self.assertInvalidAt({"v": 1, "error": "bad_token", "message": "m", "report_id": "x"}, "/report_id")
        self.assertInvalidAt({"v": 1, "error": "bad_token", "message": "m", "report_id": report_id,
                              "artifact": "minidump"}, "/artifact")

    def test_exists_and_incomplete_name_their_report(self):
        report_id = "01J9Z6T4Q8M3K7V2B5N0XWAYCD"
        self.assertValid({"v": 1, "error": "exists", "message": "m", "report_id": report_id, "artifact": "crash_txt"})
        self.assertInvalidAt({"v": 1, "error": "exists", "message": "m", "report_id": report_id}, "")
        self.assertInvalidAt({"v": 1, "error": "exists", "message": "m", "artifact": "crash_txt"}, "")
        self.assertValid({"v": 1, "error": "incomplete", "message": "m", "report_id": report_id})
        self.assertInvalidAt({"v": 1, "error": "incomplete", "message": "m"}, "")

    def test_not_accepting_requires_disable_until(self):
        self.assertValid({"v": 1, "error": "not_accepting", "message": "m", "disable_until_unix": 1789300000})
        self.assertInvalidAt({"v": 1, "error": "not_accepting", "message": "m"}, "")
