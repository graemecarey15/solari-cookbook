"""Probe detection and the security report."""
import unittest
from datetime import date

from solarflare.options import database
from solarflare.tools.probes import SENSITIVE, HostProbes, Scan, scan, stopped_by
from solarflare.tools.security import Report, format_report, is_own, suggest_rules

from .fixtures import fake_account


class Probes(unittest.TestCase):
    def test_sensitive_paths(self):
        for probe in ("/.env", "/.amplifyrc", "/.config/gcloud/application_default_credentials.json", "/ai/credentials",
                      "/wp-login.php", "/terraform.tfstate.backup", "/settings.json", "/.git/config", "/sm.php"):
            self.assertTrue(SENSITIVE.search(probe), probe)
        for normal in ("/", "/blog/", "/assets/index-BQbuJ0_k.js", "/favicon.ico", "/.well-known/acme-challenge/x",
                       "/api/sessions/123/send"):
            self.assertFalse(SENSITIVE.search(normal), normal)

    def test_who_stopped_a_probe(self):
        self.assertEqual(stopped_by("block", "firewallCustom", 403), "blocked by your firewall rules")
        self.assertEqual(stopped_by("block", "firewallManaged", 403), "blocked by Cloudflare's managed rules")
        self.assertEqual(stopped_by("managed_challenge", "botFight", 403), "challenged by Bot Fight Mode")
        self.assertIsNone(stopped_by("unknown", "unknown", 404))     # the Worker's own 404: it ran
        self.assertIsNone(stopped_by("unknown", "unknown", 403))     # the Worker's own 403: it ran
        self.assertEqual(stopped_by(None, None, 403), "got a 403, probably a block")   # older data, no field
        self.assertIsNone(stopped_by(None, None, 200))


class Security(unittest.TestCase):
    def test_only_fetches_own_hosts(self):
        zones, served = ["example.com"], {"blog-x1.pages.dev"}
        for host in ("example.com", "shop.example.com", "example.com:443", "api.example.com:8443", "blog-x1.pages.dev"):
            self.assertTrue(is_own(host, zones, served), host)
        for host in ("evil.com", "example.com.evil.com", "notexample.com", "other.pages.dev", "evil.com:443"):
            self.assertFalse(is_own(host, zones, served), host)

    def test_names_probes_still_reaching_a_worker(self):
        tmp, folder = fake_account()
        try:
            result = scan(database(folder), date(2026, 1, 3), date(2026, 1, 4))
        finally:
            tmp.cleanup()
        # /wp-login.php on shop.example.com (a Worker route too) got through at 20:00, the last hour of data.
        self.assertEqual({h: p.leaking for h, p in result.hosts.items() if p.leaking},
                         {"shop.example.com": {"/wp-login.php": 200}})
        text = format_report(Report(result))
        self.assertIn("still getting through since 15:00 UTC: /wp-login.php (200)", text)
        self.assertIn("Suggested WAF custom rule for example.com", text)

    def test_rule_suggestion_widens_for_what_got_through(self):
        result = Scan(date(2026, 1, 3), date(2026, 1, 4), worker_hosts={
            "a.example.com": ("a", "example.com"), "b.example.com": ("b", "example.com"),
            "quiet.example.com": ("q", "example.com"), "c.other.com": ("c", "other.com")}, hosts={
            "a.example.com": HostProbes(worker="a", zone="example.com", leaking={
                "/.well-known/as.php": 6, "/_profiler/phpinfo": 1, "/app.asp": 2, "/.env": 3, "/totally/normal": 1}),
            "b.example.com": HostProbes(worker="b", zone="example.com"),
            "c.other.com": HostProbes(worker="c", zone="other.com"),
        })
        (sug,) = suggest_rules(result)
        # Every Worker host on the zone, including one no probe reached.
        self.assertEqual((sug.zone, sug.hosts), ("example.com", ["a.example.com", "b.example.com", "quiet.example.com"]))
        self.assertIn('"php" "env" "bak" "sql" "asp"', sug.expression)     # .php was already there; asp added
        self.assertIn('contains "phpinfo"', sug.expression)
        self.assertIn('not starts_with(http.request.uri.path, "/.well-known/")', sug.expression)
        self.assertEqual(sug.uncovered, ["/totally/normal"])


if __name__ == "__main__":
    unittest.main()
