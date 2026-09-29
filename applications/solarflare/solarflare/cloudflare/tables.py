"""Turn a collected folder into one SQLite file of tidy tables: what the
agent queries inside the sandbox.

Built here, outside the sandbox, then uploaded as a single file. Every
table is described in `notes`, including what its source can't show, so
the agent can say "undetermined" instead of reaching for the data that
happens to be detailed.
"""
import hashlib
import ipaddress
import sqlite3
from datetime import date
from pathlib import Path

from . import saved
from .inventory import Inventory

# Bump whenever SCHEMA changes: databases built with an older version are rebuilt.
SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE notes (table_name TEXT, source TEXT, covers TEXT, cannot_show TEXT);
CREATE TABLE collection (key TEXT, value TEXT);
CREATE TABLE resources (kind TEXT, name TEXT, script_id TEXT);
CREATE TABLE hosts (host TEXT, resource_kind TEXT, resource TEXT, via TEXT, zone TEXT);
CREATE TABLE zones (zone TEXT, plan TEXT);
CREATE TABLE deploys (resource_kind TEXT, resource TEXT, time TEXT, environment TEXT, source TEXT,
                      trigger TEXT, branch TEXT, commit_hash TEXT, commit_message TEXT);
CREATE TABLE workers_daily (worker TEXT, date TEXT, status TEXT, requests INT, errors INT, subrequests INT,
                            cpu_ms_p50 REAL, cpu_ms_p99 REAL);
CREATE TABLE workers_hourly (worker TEXT, hour TEXT, status TEXT, requests INT, errors INT, subrequests INT);
CREATE TABLE functions_daily (project TEXT, script_id TEXT, date TEXT, requests INT, errors INT);
CREATE TABLE functions_minute (project TEXT, script_id TEXT, minute TEXT, requests INT, errors INT);
CREATE TABLE zone_hourly (zone TEXT, hour TEXT, host TEXT, status INT, requests INT);
CREATE TABLE zone_requests (zone TEXT, hour TEXT, host TEXT, path TEXT, method TEXT, status INT, country TEXT,
                            user_agent TEXT, ip_net TEXT, ip_id TEXT, security_action TEXT, security_source TEXT,
                            requests INT);
"""

NOTES = [
    ("collection", "manifest.json", "What was collected: period, when, anything truncated or skipped", ""),
    ("resources", "Workers + Pages REST APIs", "Every Worker and Pages project; script_id is the name used in analytics",
     "Workers' *.workers.dev address (not collected)"),
    ("hosts", "Workers domains/routes + Pages domains", "Which hostname is served by which resource; zone is NULL for *.pages.dev",
     ""),
    ("zones", "Zones API", "The account's domains and their plan", ""),
    ("deploys", "Workers deployments + Pages deployments APIs",
     "Workers: time, source, trigger (deployment vs secret change). Pages: time, branch, commit, message",
     "Workers commit info unless deployed from Git or with a message. Last 10 Workers / 25 Pages deploys only"),
    ("workers_daily", "workersInvocationsAdaptive", "Requests, errors, subrequests, CPU per Worker per day (billed usage)",
     "Path, user agent, country, IP"),
    ("workers_hourly", "workersInvocationsAdaptive", "Same, per hour, for the period only", "Path, user agent, country, IP"),
    ("functions_daily", "pagesFunctionsInvocationsAdaptiveGroups",
     "Requests and errors per Pages Functions script per day (billed usage); project mapped from script_id via the Pages API",
     "Path, user agent, country, IP; which hostname it came through"),
    ("functions_minute", "pagesFunctionsInvocationsAdaptiveGroups", "Same, per minute, for the period only",
     "Path, user agent, country, IP; which hostname it came through"),
    ("zone_hourly", "httpRequestsAdaptiveGroups", "All requests through your zones per hour, host, status",
     "Traffic via *.pages.dev or *.workers.dev (not in any zone)"),
    ("zone_requests", "httpRequestsAdaptiveGroups",
     "Requests through your zones by host, path, method, status, country, user agent, client network (per hour). "
     "ip_net is the client's /24 (IPv6 /48); ip_id is a hash, the same value for the same full IP. security_action "
     "(block, challenge...) and security_source (firewallCustom = your rules, firewallManaged = Cloudflare's, "
     "rateLimit...) say whether Cloudflare stopped it; 'unknown' means nothing did",
     "Traffic via *.pages.dev or *.workers.dev. Includes static files that don't run code and aren't billed, so "
     "it can show loud traffic that has nothing to do with a billed spike"),
]


def _ip(ip: str, salt: bytes) -> tuple[str | None, str | None]:
    """Full client IPs never leave this machine: keep the network and a
    salted hash, enough to group requests by client."""
    if not ip:
        return None, None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None, None
    net = ipaddress.ip_network(f"{ip}/{24 if addr.version == 4 else 48}", strict=False)
    return str(net), hashlib.sha256(salt + ip.encode()).hexdigest()[:10]


def build(folder: Path, db_path: Path) -> Path:
    db_path.unlink(missing_ok=True)
    db = sqlite3.connect(db_path)
    db.executescript(SCHEMA)
    db.executemany("INSERT INTO notes VALUES (?,?,?,?)", NOTES)

    manifest = saved.load(folder, "manifest") or {}
    db.executemany("INSERT INTO collection VALUES (?,?)", [
        ("period_start", (manifest.get("period") or {}).get("start")),
        ("period_end", (manifest.get("period") or {}).get("end")),
        ("collected_at", manifest.get("collected_at")),
        ("truncated", "; ".join(manifest.get("truncated") or []) or "none"),
        ("skipped", "; ".join(manifest.get("skipped") or []) or "none"),
    ])

    inv = Inventory.from_folder(folder)
    db.executemany("INSERT INTO resources VALUES (?,?,?)",
                   [(r.kind, r.name, s) for r in inv.resources for s in r.script_ids])
    db.executemany("INSERT INTO hosts VALUES (?,?,?,?,?)",
                   [(h.host, h.resource.kind, h.resource.name, h.via, h.zone) for h in inv.hosts])
    db.executemany("INSERT INTO zones VALUES (?,?)",
                   [(z["name"], (z.get("plan") or {}).get("name")) for z in saved.results(folder, "zones")])

    deploys = []
    for worker, resp in (saved.load(folder, "worker_deployments") or {}).items():
        for d in (resp.get("result") or {}).get("deployments") or []:
            trigger = (d.get("annotations") or {}).get("workers/triggered_by")
            message = (d.get("annotations") or {}).get("workers/message")
            # author_email is deliberately left out: the agent doesn't need it.
            deploys.append(("worker", worker, d.get("created_on"), None, d.get("source"), trigger, None, None, message))
    for project, resp in (saved.load(folder, "pages_deployments") or {}).items():
        for d in resp.get("result") or []:
            meta = (d.get("deployment_trigger") or {}).get("metadata") or {}
            deploys.append(("pages", project, d.get("created_on"), d.get("environment"),
                            (d.get("deployment_trigger") or {}).get("type"), None, meta.get("branch"),
                            meta.get("commit_hash"), (meta.get("commit_message") or "").split("\n")[0][:200]))
    db.executemany("INSERT INTO deploys VALUES (?,?,?,?,?,?,?,?,?)", deploys)

    db.executemany("INSERT INTO workers_daily VALUES (?,?,?,?,?,?,?,?)", [
        (r["dimensions"]["scriptName"], r["dimensions"]["date"], r["dimensions"].get("status"),
         r["sum"]["requests"], r["sum"]["errors"], r["sum"]["subrequests"],
         (r.get("quantiles") or {}).get("cpuTimeP50", 0) / 1000, (r.get("quantiles") or {}).get("cpuTimeP99", 0) / 1000)
        for r in saved.rows(folder, "workers_daily")])
    db.executemany("INSERT INTO workers_hourly VALUES (?,?,?,?,?,?)", [
        (r["dimensions"]["scriptName"], r["dimensions"]["datetimeHour"], r["dimensions"].get("status"),
         r["sum"]["requests"], r["sum"]["errors"], r["sum"]["subrequests"])
        for r in saved.rows(folder, "workers_hourly")])

    def project(script_id: str):
        r = inv.by_script_id(script_id)
        return r.name if r else None

    db.executemany("INSERT INTO functions_daily VALUES (?,?,?,?,?)", [
        (project(r["dimensions"]["scriptName"]), r["dimensions"]["scriptName"], r["dimensions"]["date"],
         r["sum"]["requests"], r["sum"]["errors"])
        for r in saved.rows(folder, "functions_daily")])
    db.executemany("INSERT INTO functions_minute VALUES (?,?,?,?,?)", [
        (project(r["dimensions"]["scriptName"]), r["dimensions"]["scriptName"], r["dimensions"]["datetimeMinute"],
         r["sum"]["requests"], r["sum"]["errors"])
        for r in saved.rows(folder, "functions_minute")])

    # Salt from the data itself: the same data always gives the same ip_id (so
    # recorded runs replay exactly), and without the data it can't be reversed.
    salt = hashlib.sha256(b"".join(f.read_bytes() for f in sorted(folder.glob("zone_*_requests.json")))).digest()
    for zone in inv.zones:
        db.executemany("INSERT INTO zone_hourly VALUES (?,?,?,?,?)", [
            (zone, r["dimensions"]["datetimeHour"], r["dimensions"]["clientRequestHTTPHost"],
             r["dimensions"]["edgeResponseStatus"], r["count"])
            for r in saved.rows(folder, f"zone_{zone}_hourly")])
        db.executemany("INSERT INTO zone_requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [
            (zone, d["datetimeHour"], d["clientRequestHTTPHost"], d["clientRequestPath"], d.get("clientRequestHTTPMethodName"),
             d["edgeResponseStatus"], d["clientCountryName"], d["userAgent"], *_ip(d["clientIP"], salt),
             d.get("securityAction"), d.get("securitySource"), r["count"])
            for r in saved.rows(folder, f"zone_{zone}_requests") for d in [r["dimensions"]]])

    # Not injectable: a constant int (PRAGMA values can't be bound as parameters).
    db.execute(f"PRAGMA user_version = {int(SCHEMA_VERSION)}")  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query, python.lang.security.audit.formatted-sql-query.formatted-sql-query
    db.commit()
    db.close()
    return db_path


def is_current(db_path: Path) -> bool:
    try:
        con = sqlite3.connect(db_path)
        try:
            return con.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        finally:
            con.close()
    except sqlite3.Error:
        return False


def collected_period(db_path: Path) -> tuple[date, date] | None:
    """The period a folder was collected for (end exclusive), from its manifest."""
    con = sqlite3.connect(db_path)
    try:
        row = dict(con.execute("SELECT key, value FROM collection").fetchall())
    finally:
        con.close()
    if row.get("period_start") and row.get("period_end"):
        return date.fromisoformat(row["period_start"]), date.fromisoformat(row["period_end"])
    return None
