"""Usage limits: projection and the daily limit, without an account."""
import unittest
from datetime import date

from solarflare.tools.usage import compute


def row(resource, day, requests, cpu_ms=None):
    return {"resource": resource, "date": day, "requests": requests, "cpu_ms": cpu_ms}


class Usage(unittest.TestCase):
    def test_paid_projection_uses_full_days_only(self):
        # 10 full days of 500k requests, plus a partial today of 100k: 5.1M used.
        rows = [row("worker:api", f"2026-09-{d:02d}", 500_000, 1_000_000) for d in range(1, 11)]
        rows.append(row("worker:api", "2026-09-11", 100_000, 10))
        req, cpu = compute(rows, "paid", date(2026, 9, 11))
        self.assertEqual(req.used, 5_100_000)
        # Trend: the last 7 full days (500k/day), for the 19 days left after today.
        self.assertEqual(req.projected, 5_100_000 + 500_000 * 19)
        self.assertAlmostEqual(req.overage_usd, (req.projected - 10_000_000) / 1e6 * 0.30)
        self.assertEqual(req.top, [("worker:api", 5_100_000)])
        self.assertEqual(cpu.overage_usd, 0.0)  # 10M+ CPU ms projected, well under 30M

    def test_trend_stays_in_the_month(self):
        # On the 2nd, only the 1st is a full day of this month.
        rows = [row("worker:api", "2026-09-01", 1000), row("worker:api", "2026-09-02", 10)]
        req, _ = compute(rows, "paid", date(2026, 9, 2))
        self.assertEqual(req.projected, 1010 + 1000 * 28)

    def test_free_plan_reports_the_busiest_day(self):
        rows = [row("worker:api", "2026-09-10", 20_000), row("pages:site", "2026-09-11", 90_000),
                row("worker:api", "2026-09-11", 5_000)]
        (req,) = compute(rows, "free", date(2026, 9, 12))
        self.assertEqual((req.used, req.included), (95_000, 100_000))
        self.assertIn("2026-09-11", req.per)
        self.assertEqual(req.top[0], ("pages:site", 90_000))

    def test_unknown_plan(self):
        with self.assertRaises(ValueError):
            compute([], "enterprise", date(2026, 9, 1))


if __name__ == "__main__":
    unittest.main()
