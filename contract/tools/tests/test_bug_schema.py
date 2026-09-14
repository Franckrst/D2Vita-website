import copy

from tests.helpers import SchemaTestCase

BUG = {
    "title": "Crash when opening the stash",
    "description": "Steps:\n1. Open the stash\r\n2.\tCrash",
    "version": "0.1.0",
    "contact": "someone@example.org",
    "lang": "en",
    "turnstile_token": "0.AbCdEf-_ghIJ.klmnOP",
}


def mutated(fn):
    document = copy.deepcopy(BUG)
    fn(document)
    return document


class BugSchemaTest(SchemaTestCase):
    schema_name = "bug.v1"

    def test_valid_submissions(self):
        self.assertValid(BUG)
        self.assertValid(mutated(lambda b: b.pop("contact")))
        self.assertValid(mutated(lambda b: b.update(contact="")))
        self.assertValid(mutated(lambda b: b.update(lang="fr", title="Plantage \xe0 l'ouverture")))

    def test_lengths_count_code_points(self):
        emoji = "\U0001F525"  # one code point, two UTF-16 units
        self.assertValid(mutated(lambda b: b.update(title=emoji * 120)))
        self.assertInvalidAt(mutated(lambda b: b.update(title=emoji * 121)), "/title")
        self.assertValid(mutated(lambda b: b.update(description="d" * 4000, version="v" * 40,
                                                    contact="c" * 120)))

    def test_bounds(self):
        cases = {
            "/title": [("title", ""), ("title", "t" * 121), ("title", "two\nlines")],
            "/description": [("description", ""), ("description", "d" * 4001),
                             ("description", "nul\x00byte")],
            "/version": [("version", ""), ("version", "v" * 41), ("version", "0.1\t")],
            "/contact": [("contact", "c" * 121), ("contact", "a\nb")],
            "/lang": [("lang", "de"), ("lang", "FR")],
            "/turnstile_token": [("turnstile_token", ""), ("turnstile_token", "a b"),
                                 ("turnstile_token", "x" * 2049)],
        }
        for pointer, changes in cases.items():
            for key, value in changes:
                with self.subTest(key=key, value=value[:20]):
                    self.assertInvalidAt(mutated(lambda b: b.update({key: value})), pointer)

    def test_required_and_unknown_fields(self):
        for key in ("title", "description", "version", "lang", "turnstile_token"):
            with self.subTest(key=key):
                self.assertInvalidAt(mutated(lambda b: b.pop(key)), "")
        self.assertInvalidAt(mutated(lambda b: b.update(v=1)), "")
        self.assertInvalidAt(mutated(lambda b: b.update(email="x@example.org")), "")

    def test_bug_created(self):
        self.assertValid({"v": 1, "id": "B01J9Z6T4Q8M3K7V2B5N0XWAYCD"}, "BugCreated")
        self.assertValid({"v": 1, "id": "BAAAAAAAA"}, "BugCreated")
        for bad in ("S01J9Z6T4Q8M3K7V2B5N0XWAYCD", "B", "Babc12345", "B" + "A" * 32):
            with self.subTest(id=bad):
                self.assertInvalidAt({"v": 1, "id": bad}, "/id", "BugCreated")
        self.assertInvalidAt({"id": "BAAAAAAAA"}, "", "BugCreated")
