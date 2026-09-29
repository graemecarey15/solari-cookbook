"""Probes: requests for paths only scanners ask for (.env, .git, wp-login...),
and what happened to them. One scan of the zone traffic, used by both summary
and security, so they count the same way."""
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

SENSITIVE = re.compile(
    r"(^|/)\.(?!well-known/)[A-Za-z0-9_-]|"              # any dotfile or dot-directory: .env, .git, .aws, .amplifyrc
    r"wp-(config|admin|login|content|includes)|\.php\d?($|\?)|phpinfo|xmlrpc|"
    r"credential|secret|terraform\.tfstate|(^|/)(config|settings)\.(json|js|ya?ml)|"
    r"(^|/)(backup|dump|db)\.(sql|zip|tar|gz)|/actuator|/server-status|/cgi-bin/",
    re.IGNORECASE,
)

# "Still getting through" means in the last hours of the period.
RECENT_HOURS = 6

# Cloudflare's securitySource values, as a person would say them.
SOURCES = {"firewallCustom": "your firewall rules", "firewallRules": "your firewall rules",
           "firewallManaged": "Cloudflare's managed rules", "rateLimit": "rate limiting",
           "botFight": "Bot Fight Mode", "bic": "Browser Integrity Check", "securityLevel": "the security level"}
PASSED = {None, "", "unknown", "allow", "skip", "log"}

OUTCOMES = ["stopped", "refused", "not_found", "redirected", "ok", "other"]
OUTCOME_LABELS = {"stopped": "stopped by Cloudflare", "refused": "refused by the site", "not_found": "not found",
                  "redirected": "redirected", "ok": "got a 200", "other": "other"}


def is_probe(path: str | None) -> bool:
    return bool(path) and bool(SENSITIVE.search(path))


def stopped_by(action: str | None, source: str | None, status: int) -> str | None:
    """Who stopped a request at Cloudflare's edge ("blocked by your firewall
    rules"), or None if it went through. Older data has no action: a 403 is then
    only probably a block, and says so."""
    if action is None:
        return "got a 403, probably a block" if status == 403 else None
    if action in PASSED:
        return None
    verb = "challenged" if "challenge" in action else "blocked" if action == "block" else action.replace("_", " ")
    return f"{verb} by {SOURCES.get(source or '', source or 'Cloudflare')}"


def outcome(stopped: bool, status: int) -> str:
    if stopped:
        return "stopped"
    if status in (404, 410):
        return "not_found"
    if status == 200:
        return "ok"
    if 300 <= status < 400:
        return "redirected"
    if status in (401, 403):
        return "refused"
    return "other"


def outcome_text(counts: dict) -> str:
    return ", ".join(f"{counts[o]:,} {OUTCOME_LABELS[o]}" for o in OUTCOMES if counts.get(o))


@dataclass
class HostProbes:
    worker: str | None = None      # the Worker serving this host, if any
    zone: str | None = None
    probes: int = 0
    reached: int = 0               # not stopped by Cloudflare (for a Worker host: its code ran)
    stopped: dict = field(default_factory=dict)      # "blocked by your firewall rules" -> n
    outcomes: dict = field(default_factory=dict)     # outcome -> n
    clients: set = field(default_factory=set)
    countries: dict = field(default_factory=dict)
    answered: dict = field(default_factory=dict)     # path -> n that got a 200
    leaking: dict = field(default_factory=dict)      # path -> n that reached this Worker recently

    @property
    def top_country(self) -> str:
        return max(self.countries, key=self.countries.get) if self.countries else "?"


@dataclass
class Scan:
    start: date
    end: date
    hosts: dict[str, HostProbes] = field(default_factory=dict)
    paths: dict[str, int] = field(default_factory=dict)
    recent_since: str = ""         # start of the "recent" window, an hour like 2026-09-28T17:00:00Z
    worker_hosts: dict = field(default_factory=dict)   # every Worker-served host -> (worker, zone), probed or not

    @property
    def total(self) -> int:
        return sum(h.probes for h in self.hosts.values())

    @property
    def outcomes(self) -> dict:
        out: dict = {}
        for h in self.hosts.values():
            for k, n in h.outcomes.items():
                out[k] = out.get(k, 0) + n
        return out

    def busiest(self, n: int) -> list[tuple[str, HostProbes]]:
        return sorted(self.hosts.items(), key=lambda kv: -kv[1].probes)[:n]

    @property
    def on_workers(self) -> dict[str, HostProbes]:
        return {host: h for host, h in self.hosts.items() if h.worker}

    @property
    def answered(self) -> list[tuple[str, str, int]]:
        """(host, path, probes) that got a 200, most-probed first."""
        return sorted(((host, p, n) for host, h in self.hosts.items() for p, n in h.answered.items()),
                      key=lambda x: -x[2])


def scan(db_file: Path, start: date, end: date) -> Scan:
    db = sqlite3.connect(db_file)
    s, e = start.isoformat(), end.isoformat()
    result = Scan(start, end)
    served = result.worker_hosts = {host: (worker, zone) for host, worker, zone in
                                    db.execute("SELECT host, resource, zone FROM hosts WHERE resource_kind='worker'")}
    last_hour = db.execute("SELECT MAX(hour) FROM zone_requests WHERE hour >= ? AND hour < ?", (s, e)).fetchone()[0]
    if last_hour:
        result.recent_since = (datetime.fromisoformat(last_hour.replace("Z", "+00:00"))
                               - timedelta(hours=RECENT_HOURS - 1)).strftime("%Y-%m-%dT%H:00:00Z")

    for host, hour, path, status, country, ip_id, action, source, n in db.execute(
            "SELECT host, hour, path, status, country, ip_id, security_action, security_source, requests "
            "FROM zone_requests WHERE hour >= ? AND hour < ?", (s, e)):
        # 5xx means the site behind Cloudflare failed: a health question, not a security one.
        if not is_probe(path) or status >= 500:
            continue
        worker, zone = served.get(host, (None, None))
        h = result.hosts.setdefault(host, HostProbes(worker=worker, zone=zone))
        h.probes += n
        h.clients.add(ip_id)
        h.countries[country] = h.countries.get(country, 0) + n
        result.paths[path] = result.paths.get(path, 0) + n
        by = stopped_by(action, source, status)
        if by:
            h.stopped[by] = h.stopped.get(by, 0) + n
        else:
            h.reached += n
            if worker and hour >= result.recent_since:
                h.leaking[path] = h.leaking.get(path, 0) + n
        kind = outcome(bool(by), status)
        h.outcomes[kind] = h.outcomes.get(kind, 0) + n
        if status == 200:
            h.answered[path] = h.answered.get(path, 0) + n
    db.close()
    return result


def worker_lines(result: Scan) -> list[str]:
    """One line per Worker-served host: what was stopped (and by what), what reached the
    Worker, and what's still getting through at the end of the period."""
    recent = result.recent_since[11:16]
    lines = []
    for host, h in sorted(result.on_workers.items(), key=lambda kv: -sum(kv[1].leaking.values())):
        how = ", ".join(f"{n:,} {by}" for by, n in sorted(h.stopped.items(), key=lambda kv: -kv[1]))
        lines.append(f"{host} ({h.worker}): {sum(h.stopped.values()):,} stopped" + (f" ({how})" if how else "")
                     + f", {h.reached:,} reached the Worker")
        if h.leaking:
            top = sorted(h.leaking.items(), key=lambda kv: -kv[1])[:5]
            more = f", and {len(h.leaking) - 5} more" if len(h.leaking) > 5 else ""
            lines.append(f"  still getting through since {recent} UTC: "
                         + ", ".join(f"{path} ({n})" for path, n in top) + more)
    return lines
