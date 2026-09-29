"""The account's inventory and the SQLite tables built from a collected folder."""
import sqlite3
import unittest
from datetime import date

from solarflare.cloudflare.inventory import Inventory
from solarflare.cloudflare.tables import build, collected_period, is_current
from solarflare.options import database

from .fixtures import fake_account


class Tables(unittest.TestCase):
    def setUp(self):
        self.tmp, self.folder = fake_account()
        self.inv = Inventory.from_folder(self.folder)

    def tearDown(self):
        self.tmp.cleanup()

    def test_hosts_and_script_ids(self):
        owners: dict[str, set] = {}
        for h in self.inv.hosts:
            owners.setdefault(h.host, set()).add(h.resource.label)
        self.assertEqual(owners["api.example.com"], {"worker:api"})
        self.assertEqual(owners["blog-x1.pages.dev"], {"pages:blog"})
        # A Pages project and a Worker route both serve shop.example.com.
        self.assertEqual(owners["shop.example.com"], {"pages:shop", "worker:shop-auth"})
        self.assertEqual(self.inv.by_script_id("pages-worker--222-production").label, "pages:blog")
        self.assertEqual(self.inv.by_script_id("pages-worker--111-preview").label, "pages:shop")

    def test_pages_dev_hosts_are_outside_every_zone(self):
        zones = {h.host: h.zone for h in self.inv.hosts}
        self.assertIsNone(zones["blog-x1.pages.dev"])
        self.assertEqual(zones["shop.example.com"], "example.com")

    def test_tables(self):
        db = sqlite3.connect(build(self.folder, self.folder / "t.db"))
        one = lambda sql: db.execute(sql).fetchall()
        # Functions traffic is attributed by script id; an unknown id stays unattributed.
        self.assertEqual(one("SELECT project, requests FROM functions_minute ORDER BY requests DESC"),
                         [("blog", 351), (None, 1)])
        self.assertEqual(one("SELECT project, requests FROM functions_daily"), [("blog", 352)])
        self.assertEqual(one("SELECT host, path, requests FROM zone_requests"), [("shop.example.com", "/wp-login.php", 200)])
        # Full client IPs never reach the tables.
        self.assertEqual(one("SELECT ip_net FROM zone_requests"), [("192.0.2.0/24",)])
        self.assertNotIn("192.0.2.1'", str(one("SELECT * FROM zone_requests")))
        self.assertEqual(one("SELECT commit_message FROM deploys WHERE resource='blog'"), [("Add feed",)])
        # No author emails reach the agent.
        self.assertNotIn("someone@example.com", str(one("SELECT * FROM deploys")))
        # Every data table is described, including what it can't show.
        described = {r[0] for r in one("SELECT table_name FROM notes")}
        tables = {r[0] for r in one("SELECT name FROM sqlite_master WHERE type='table'")} - {"notes"}
        self.assertEqual(tables - described, set())

    def test_collected_period(self):
        self.assertEqual(collected_period(database(self.folder)), (date(2026, 1, 3), date(2026, 1, 4)))

    def test_old_databases_are_rebuilt(self):
        db = database(self.folder)
        self.assertTrue(is_current(db))
        con = sqlite3.connect(db)
        con.execute("PRAGMA user_version = 1")
        con.commit()
        con.close()
        self.assertFalse(is_current(db))
        self.assertTrue(is_current(database(self.folder)))   # rebuilt, even though no data file changed


if __name__ == "__main__":
    unittest.main()
