"""Summary's detection and output."""
import unittest
from datetime import date

from solarflare.options import database
from solarflare.tools.summary import detect, format_summary

from .fixtures import fake_account, worker_week

PERIOD = (date(2026, 1, 3), date(2026, 1, 4))


class Summary(unittest.TestCase):
    def setUp(self):
        self.tmp, self.folder = fake_account()
        worker_week(self.folder)
        self.summary = detect(database(self.folder), PERIOD)
        self.items = {i.title: i for i in self.summary.items}

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_jump_gets_a_question(self):
        mover = self.items["Billed usage jumped: worker api"]
        self.assertEqual(mover.level, "look")
        self.assertEqual(mover.question, "Why did billed requests for api jump to 500/day, from 100/day the week before?")
        self.assertTrue(any("Billed requests" in f for f in self.summary.facts))

    def test_a_launch_is_new_not_a_spike(self):
        # blog had no traffic before, and its first deploy was on 01-02.
        new = next(i for title, i in self.items.items() if title.startswith("New: pages blog"))
        self.assertEqual((new.level, new.question), ("routine", None))
        self.assertNotIn("Billed usage jumped: pages blog", self.items)

    def test_probes(self):
        # /wp-login.php on shop.example.com: a host a Worker route also serves, still getting through, and a 200.
        self.assertIn("Probes are still reaching Workers, so their code runs and can be billed", self.items)
        self.assertIn("Some probes for sensitive paths got a 200 response", self.items)

    def test_output_prints_the_investigate_command(self):
        text = format_summary(self.summary, "--date 2026-01-03")
        self.assertIn('       solarflare investigate --date 2026-01-03 "Why did billed requests for api jump', text)
        self.assertIn("NEEDS A LOOK", text)


if __name__ == "__main__":
    unittest.main()
