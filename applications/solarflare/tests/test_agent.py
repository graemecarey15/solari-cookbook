"""The agent: eval checks catch the failures they exist for, and traces save anywhere."""
import tempfile
import unittest
from pathlib import Path

from solarflare.agent.evaluate import load_case
from solarflare.agent.investigate import Investigation, save

SAMPLE = load_case(Path(__file__).resolve().parent.parent / "sample")

GOOD = {
    "summary": "Undetermined: ops-console's Functions took 351 requests in one minute; the data can't show the caller.",
    "where": "pages ops-console, 2026-09-25 20:12 UTC", "cause": "undetermined",
    "evidence": [{"fact": "351 requests at 20:12", "table": "functions_minute"}], "gaps": ["no hostname in Functions data"],
}


def failures(finding):
    return [name for name, check in SAMPLE.checks if not check(finding)]


class Checks(unittest.TestCase):
    def test_good_finding_passes(self):
        self.assertEqual(failures(GOOD), [])

    def test_leaning_toward_scanners_fails(self):
        # The wording a real Luna run produced before the rule was tightened.
        bad = {**GOOD, "summary": "The evidence points to likely scanner traffic on ops-console's custom domain."}
        self.assertEqual(failures(bad), ["doesn't lean toward an unproven suspect in the summary"])

    def test_blaming_the_wrong_suspect_fails(self):
        bad = {**GOOD, "cause": "bots_scanners_crawlers", "summary": "A PHP scanner hit editor.acme.example."}
        self.assertEqual(failures(bad), ["cause is undetermined", "doesn't blame editor"])

    def test_fact_without_table_fails(self):
        bad = {**GOOD, "evidence": [{"fact": "351 requests", "table": " "}]}
        self.assertEqual(failures(bad), ["every fact names its table"])


class Traces(unittest.TestCase):
    def test_saving_a_trace_creates_missing_folders(self):
        # On a fresh clone there's no data/ yet.
        with tempfile.TemporaryDirectory() as tmp:
            path = save(Investigation(question="q", model="m", finding={}), Path(tmp) / "data")
            self.assertTrue(path.exists())
            self.assertEqual(path.parent, Path(tmp) / "data" / "investigations")


if __name__ == "__main__":
    unittest.main()
