"""Collect everything about a period from Cloudflare into a folder of raw API
responses, plus manifest.json recording what was asked for and what came
back incomplete.

Fixed, read-only queries only. This runs outside the sandbox; the agent
never talks to Cloudflare.
"""
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .. import progress
from .api import Cloudflare, graphql_rows

# Retention on the Free plan, read from GraphQL `settings` (docs/PLAN.md).
ACCOUNT_RETENTION_DAYS = 90
ZONE_RETENTION_DAYS = 31
MAX_ROWS = 10_000
# Daily totals this far before the period, to know what "normal" looks like.
CONTEXT_DAYS = 14
ALL_PARTS = ("deploys", "usage", "traffic")

WORKERS_DAILY = """query($a: string!, $s: Time!, $e: Time!) { viewer { accounts(filter: {accountTag: $a}) {
  workersInvocationsAdaptive(limit: 10000, filter: {datetime_geq: $s, datetime_lt: $e}) {
    dimensions { scriptName date status } sum { requests errors subrequests } quantiles { cpuTimeP50 cpuTimeP99 } } } } }"""

WORKERS_HOURLY = """query($a: string!, $s: Time!, $e: Time!) { viewer { accounts(filter: {accountTag: $a}) {
  workersInvocationsAdaptive(limit: 10000, filter: {datetime_geq: $s, datetime_lt: $e}) {
    dimensions { scriptName datetimeHour status } sum { requests errors subrequests } } } } }"""

FUNCTIONS_DAILY = """query($a: string!, $s: Time!, $e: Time!) { viewer { accounts(filter: {accountTag: $a}) {
  pagesFunctionsInvocationsAdaptiveGroups(limit: 10000, filter: {datetime_geq: $s, datetime_lt: $e}) {
    dimensions { scriptName date } sum { requests errors } } } } }"""

FUNCTIONS_MINUTE = """query($a: string!, $s: Time!, $e: Time!) { viewer { accounts(filter: {accountTag: $a}) {
  pagesFunctionsInvocationsAdaptiveGroups(limit: 10000, filter: {datetime_geq: $s, datetime_lt: $e}) {
    dimensions { scriptName datetimeMinute } sum { requests errors } } } } }"""

ZONE_HOURLY = """query($z: string!, $s: Time!, $e: Time!) { viewer { zones(filter: {zoneTag: $z}) {
  httpRequestsAdaptiveGroups(limit: 10000, filter: {datetime_geq: $s, datetime_lt: $e}) {
    count dimensions { datetimeHour clientRequestHTTPHost edgeResponseStatus } } } } }"""

ZONE_REQUESTS = """query($z: string!, $s: Time!, $e: Time!) { viewer { zones(filter: {zoneTag: $z}) {
  httpRequestsAdaptiveGroups(limit: 10000, orderBy: [count_DESC], filter: {datetime_geq: $s, datetime_lt: $e}) {
    count dimensions { datetimeHour clientRequestHTTPHost clientRequestPath clientRequestHTTPMethodName
      edgeResponseStatus clientCountryName userAgent clientIP securityAction securitySource } } } } }"""


def _ts(d: date) -> str:
    return f"{d.isoformat()}T00:00:00Z"


def _days(start: date, end: date):
    d = start
    while d < end:
        yield d
        d += timedelta(days=1)


class Collector:
    def __init__(self, cf: Cloudflare, out: Path):
        self.cf = cf
        self.out = out
        self.truncated: list[str] = []
        self.skipped: list[str] = []

    def _save(self, name: str, data) -> None:
        (self.out / f"{name}.json").write_text(json.dumps(data, indent=1))

    def _graphql_by_day(self, name: str, query: str, scope: dict, start: date, end: date, label: str = "") -> None:
        """Query one day at a time (keeps each query under the row limit),
        and save the days merged into one response-shaped file."""
        rows = []
        days = list(_days(start, end))
        for i, d in enumerate(days, 1):
            progress.update(f"  {label or name}: day {i} of {len(days)} ({d})")
            day_rows = graphql_rows(self.cf.graphql(query, {**scope, "s": _ts(d), "e": _ts(d + timedelta(days=1))}))
            if len(day_rows) >= MAX_ROWS:
                self.truncated.append(f"{name} {d}: hit the {MAX_ROWS}-row limit, the rarest rows are missing")
            rows.extend(day_rows)
        self._save(name, {"rows": rows})

    def inventory(self, deploys: bool = True) -> str:
        """Resources and hostnames, and (unless deploys=False) deploy history. Returns the account id."""
        self.out.mkdir(parents=True, exist_ok=True)
        progress.start("  inventory")
        account = self.cf.account_id()
        workers = self.cf.get(f"/accounts/{account}/workers/scripts")
        zones = self.cf.get("/zones?per_page=50")
        pages = self.cf.get(f"/accounts/{account}/pages/projects")
        self._save("workers", workers)
        self._save("zones", zones)
        self._save("pages_projects", pages)
        self._save("worker_domains", self.cf.get(f"/accounts/{account}/workers/domains"))
        routes = {}
        for i, z in enumerate(zones["result"], 1):
            progress.update(f"  inventory: routes for zone {i} of {len(zones['result'])} ({z['name']})")
            routes[z["name"]] = self.cf.get(f"/zones/{z['id']}/workers/routes")
        self._save("worker_routes", routes)
        progress.done(f"  inventory: {len(workers['result'])} Workers, {len(pages['result'])} Pages projects, "
                      f"{len(zones['result'])} zones")

        self._account, self._zones = account, zones["result"]
        if not deploys:
            return account
        progress.start("  deploy history")
        wd, pd = {}, {}
        total = len(workers["result"]) + len(pages["result"])
        for i, w in enumerate(workers["result"], 1):
            progress.update(f"  deploy history: {i} of {total} ({w['id']})")
            wd[w["id"]] = self.cf.get(f"/accounts/{account}/workers/scripts/{w['id']}/deployments")
        for i, p in enumerate(pages["result"], len(workers["result"]) + 1):
            progress.update(f"  deploy history: {i} of {total} ({p['name']})")
            pd[p["name"]] = self.cf.get(f"/accounts/{account}/pages/projects/{p['name']}/deployments?per_page=25")
        self._save("worker_deployments", wd)
        self._save("pages_deployments", pd)
        progress.done(f"  deploy history: {total} resources")
        self._account, self._zones = account, zones["result"]
        return account

    def run(self, start: date, end: date, *, with_inventory: bool = True, parts: tuple = ALL_PARTS) -> dict:
        """Collect the period [start, end). parts picks what: deploys, usage (with daily context
        before the period), traffic. Inventory always comes along."""
        today = datetime.now(timezone.utc).date()
        self.out.mkdir(parents=True, exist_ok=True)
        if with_inventory or not hasattr(self, "_account"):
            self.inventory(deploys="deploys" in parts)
        account, zones = self._account, self._zones

        # Account metrics: daily with context, fine-grained for the period.
        acct = {"a": account}
        ctx_start = max(start - timedelta(days=CONTEXT_DAYS), today - timedelta(days=ACCOUNT_RETENTION_DAYS - 1))
        if "usage" in parts:
            self._usage(acct, ctx_start, start, end)
        zone_start = max(start, today - timedelta(days=ZONE_RETENTION_DAYS - 1))
        if "traffic" in parts:
            self._traffic(zones, zone_start, start, end)

        manifest = {
            "period": {"start": start.isoformat(), "end": end.isoformat()},
            "parts": ["inventory", *parts],
            "context_start": ctx_start.isoformat() if "usage" in parts else None,
            "zone_detail_start": zone_start.isoformat() if "traffic" in parts and zone_start < end else None,
            "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "truncated": self.truncated,
            "skipped": self.skipped,
        }
        self._save("manifest", manifest)
        return manifest

    def _usage(self, acct: dict, ctx_start: date, start: date, end: date) -> None:
        progress.start("  usage counts")
        self._graphql_by_day("workers_daily", WORKERS_DAILY, acct, ctx_start, end, "usage counts: Workers by day")
        self._graphql_by_day("functions_daily", FUNCTIONS_DAILY, acct, ctx_start, end, "usage counts: Pages Functions by day")
        self._graphql_by_day("workers_hourly", WORKERS_HOURLY, acct, start, end, "usage counts: Workers by hour")
        self._graphql_by_day("functions_minute", FUNCTIONS_MINUTE, acct, start, end, "usage counts: Pages Functions by minute")
        progress.done(f"  usage counts: {start} to {end - timedelta(days=1)}, plus daily figures back to {ctx_start}")

    def _traffic(self, zones: list, zone_start: date, start: date, end: date) -> None:
        # Zone traffic detail, only as far back as it's kept.
        if zone_start > start:
            self.skipped.append(f"zone traffic before {zone_start}: older than the {ZONE_RETENTION_DAYS}-day retention")
        progress.start("  traffic detail")
        for i, z in enumerate(zones, 1):
            if zone_start < end:
                label = f"traffic detail: zone {i} of {len(zones)} ({z['name']})"
                self._graphql_by_day(f"zone_{z['name']}_hourly", ZONE_HOURLY, {"z": z["id"]}, zone_start, end, label)
                self._graphql_by_day(f"zone_{z['name']}_requests", ZONE_REQUESTS, {"z": z["id"]}, zone_start, end, label)
        progress.done(f"  traffic detail: {len(zones)} zones")
