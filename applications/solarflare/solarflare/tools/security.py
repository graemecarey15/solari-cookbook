"""Security: who's scanning your sites, and whether anything sensitive is exposed.

From the probe scan (probes.py) it reports what happened to the probes and
which still reach code that runs. Every probe that got a 200 can be re-checked
(verify): the path is fetched again and compared with the host's answer to a
made-up path. The same answer means the site's fallback page, so nothing was
exposed; anything else is flagged with its type and size. Bodies are hashed
and sniffed, never printed or stored.

Probe paths are written by strangers, so they're untrusted input: only the
account's own hostnames are fetched, GET only, redirects not followed, short
timeouts, and a cap on how many are checked.
"""
import hashlib
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .probes import Scan, outcome_text, worker_lines

TIMEOUT = 10
MAX_BODY = 512 * 1024
USER_AGENT = "solarflare (read-only owner check)"
ENV_LIKE = re.compile(rb"^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S", re.MULTILINE)

# For WAF rule suggestions: extensions a Worker app never legitimately serves,
# and words only scanners ask for.
BAD_EXTENSIONS = ["php", "env", "bak", "sql", "asp", "aspx", "jsp", "cgi", "sh", "ini", "log", "old", "swp",
                  "yml", "yaml", "tfstate", "zip", "tar", "gz", "7z", "rar", "db", "sqlite"]
BASE_EXTENSIONS = ["php", "env", "bak", "sql"]
BAD_WORDS = ["phpinfo", "credential", "secret", "terraform.tfstate", "config.json", "settings.json", "actuator",
             "server-status", "cgi-bin", "xmlrpc", "phpmyadmin"]


# ---- re-checking probes that got a 200 ----

@dataclass
class Response:
    status: int | None
    content_type: str = ""
    size: int = 0
    digest: str = ""
    env_like: bool = False
    error: str = ""


@dataclass
class Check:
    host: str
    path: str
    probes: int
    verdict: str          # fallback, exposed?, not_served, error, skipped
    detail: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def fetch(host: str, path: str) -> Response:
    url = f"https://{host}{urllib.parse.quote(path, safe='/?=&%.-_~')}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with _opener.open(req, timeout=TIMEOUT) as resp:
            body = resp.read(MAX_BODY)
            status, ctype = resp.status, resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        body, status, ctype = e.read(MAX_BODY), e.code, e.headers.get("Content-Type", "")
    except Exception as e:
        return Response(None, error=type(e).__name__)
    return Response(status, ctype.split(";")[0], len(body), hashlib.sha256(body).hexdigest(),
                    bool(ENV_LIKE.search(body)))


def is_own(host: str, zones: list[str], inventory_hosts: set[str]) -> bool:
    """Only the account's own hostnames are ever fetched: anything on one of
    its zones, or a host its resources serve (e.g. *.pages.dev)."""
    name = host.lower().rsplit(":", 1)[0] if host.count(":") == 1 else host.lower()
    return name in inventory_hosts or any(name == z or name.endswith("." + z) for z in zones)


def _round_robin(answered: list[tuple[str, str, int]], limit: int) -> list[tuple[str, str, int]]:
    """Each host's most-probed paths in turn, so every host gets checked."""
    queues: dict[str, list] = {}
    for item in answered:
        queues.setdefault(item[0], []).append(item)
    picked = []
    while len(picked) < limit and any(queues.values()):
        for q in sorted(queues.values(), key=lambda q: -q[0][2] if q else 0):
            if q and len(picked) < limit:
                picked.append(q.pop(0))
    return picked


def verify(answered: list[tuple[str, str, int]], zones: list[str], inventory_hosts: set[str], max_checks: int,
           on_check=None) -> list[Check]:
    checks, fallbacks = [], {}
    for host, path, n in _round_robin(answered, max_checks):
        if not is_own(host, zones, inventory_hosts):
            checks.append(Check(host, path, n, "skipped", "not one of this account's hostnames"))
            continue
        if host not in fallbacks:
            fallbacks[host] = fetch(host, f"/solarflare-check-{secrets.token_hex(6)}")
        if on_check:
            on_check(host, path)
        base, got = fallbacks[host], fetch(host, path)
        if got.error or got.status is None:
            checks.append(Check(host, path, n, "error", got.error or "no response"))
        elif got.status != 200:
            checks.append(Check(host, path, n, "not_served", f"now answers {got.status}"))
        elif got.digest == base.digest or (got.content_type == base.content_type == "text/html"
                                           and base.status == 200 and not got.env_like
                                           and abs(got.size - base.size) <= 64):
            checks.append(Check(host, path, n, "fallback", f"same {got.content_type} page as a made-up path"))
        else:
            why = "looks like KEY=value lines" if got.env_like else "differs from the fallback page"
            checks.append(Check(host, path, n, "exposed?", f"{got.content_type or 'unknown type'}, {got.size:,} bytes, {why}"))
    return checks


# ---- WAF rule suggestions ----

@dataclass
class RuleSuggestion:
    zone: str
    hosts: list[str]
    expression: str
    uncovered: list[str]


def suggest_rules(result: Scan) -> list[RuleSuggestion]:
    """A complete WAF custom rule expression per zone, covering every Worker host
    on it, widened to catch the probes still getting through. Fixed logic: known
    bad extensions and scanner-only words; anything else is left for a person."""
    workers = result.on_workers
    out = []
    for zone in sorted({h.zone for h in workers.values() if h.leaking and h.zone}):
        hosts = sorted(host for host, (_, z) in result.worker_hosts.items() if z == zone)
        exts, words, uncovered = list(BASE_EXTENSIONS), [], []
        for path in (p for h in workers.values() if h.zone == zone for p in h.leaking):
            p = path.split("?")[0].lower()
            ext = p.rsplit(".", 1)[-1] if "." in p.rsplit("/", 1)[-1] else ""
            word = next((w for w in BAD_WORDS if w in p), None)
            if ext in BAD_EXTENSIONS:
                exts += [ext] if ext not in exts else []
            elif word:
                words += [word] if word not in words else []
            elif not ("/." in p and not p.startswith("/.well-known/")):   # dotfiles are already covered
                uncovered.append(path)
        quoted = lambda items: " ".join(f'"{x}"' for x in items)
        clauses = [f"http.request.uri.path.extension in {{{quoted(exts)}}}", 'http.request.uri.path contains "wp-"']
        clauses += [f'http.request.uri.path contains "{w}"' for w in words]
        clauses.append('(http.request.uri.path contains "/." and not starts_with(http.request.uri.path, "/.well-known/"))')
        expression = f"(http.host in {{{quoted(hosts)}}}\n and (" + "\n      or ".join(clauses) + "))"
        out.append(RuleSuggestion(zone, hosts, expression, uncovered))
    return out


# ---- the report ----

@dataclass
class Report:
    scan: Scan
    checks: list[Check] = field(default_factory=list)
    sample: bool = False          # made-up hostnames: nothing was re-fetched

    @property
    def exposed(self) -> list[Check]:
        return [c for c in self.checks if c.verdict == "exposed?"]


def format_report(rep: Report) -> str:
    s = rep.scan
    span = str(s.start) if (s.end - s.start).days == 1 else f"{s.start} to {s.end}"
    out = [f"Security, {span}", ""]
    out += _exposed_section(rep) + _scanning_section(rep) + _workers_section(rep)
    return "\n".join(out).rstrip()


def _exposed_section(rep: Report) -> list[str]:
    """Only worth a section of its own when something may actually be exposed."""
    if not rep.exposed:
        return []
    return (["NEEDS A LOOK NOW: probes got something other than your fallback page"]
            + [f"  https://{c.host}{c.path}  ({c.probes} probes): {c.detail}" for c in rep.exposed]
            + ["  Open these yourself. If a file is real, remove it and rotate anything in it.", ""])


def _scanning_section(rep: Report) -> list[str]:
    s = rep.scan
    if not s.total:
        return ["No probes for sensitive paths in this period.", ""]
    out = [f"Scanning: {s.total:,} probes for sensitive paths (.env, .git, wp-admin...) across {len(s.hosts)} hosts",
           f"  Outcome: {outcome_text(s.outcomes)}"]
    if s.outcomes.get("ok"):
        out.append("  " + _answered_text(rep))
        out += [f"  Couldn't check https://{c.host}{c.path}: {c.detail}"
                for c in rep.checks if c.verdict in ("error", "skipped")]
    out.append("  Busiest hosts:")
    out += [f"    {host}: {h.probes:,} from {len(h.clients)} clients, mostly {h.top_country} ({outcome_text(h.outcomes)})"
            for host, h in s.busiest(6)]
    top_paths = sorted(s.paths.items(), key=lambda kv: -kv[1])[:6]
    out += ["  Most probed: " + ", ".join(p for p, _ in top_paths), ""]
    return out


def _answered_text(rep: Report) -> str:
    lead = "A 200 usually means the site's fallback page, not the file."
    answered = len(rep.scan.answered)
    if rep.sample:
        return f"{lead} On your own account they're re-checked; the sample's hostnames are made up, so they aren't here."
    if not rep.checks:
        return f"{lead} Not re-checked (drop --no-verify to check them)."
    verdict = "all your site's normal fallback page, so nothing was exposed" if not rep.exposed else \
              f"{len(rep.exposed)} possibly exposed (above)"
    more = f"; --max-checks {min(answered, 200)} to check more" if answered > len(rep.checks) else ""
    return f"{lead} Of the {answered:,} distinct paths that got one, {len(rep.checks)} were re-checked: {verdict}{more}."


def _workers_section(rep: Report) -> list[str]:
    s = rep.scan
    if not s.on_workers:
        return []
    out = ["Probes on Worker-served hosts (a probe that reaches a Worker runs its code and can be billed):"]
    out += [f"  {line}" for line in worker_lines(s)]
    suggestions = suggest_rules(s)
    for sug in suggestions:
        out += ["", f"  Suggested WAF custom rule for {sug.zone} (Security > Security rules > custom rule, action "
                    "Block). It covers every Worker host on the zone; replace your current rule with it:"]
        out += ["    " + line for line in sug.expression.split("\n")]
        if sug.uncovered:
            out.append("    Not covered, decide yourself: " + ", ".join(sug.uncovered[:5]))
    if suggestions:
        out.append("  Check none of these patterns match real pages on those hosts before deploying.")
    else:
        out.append(f"  Nothing has reached a Worker since {s.recent_since[11:16]} UTC: whatever's blocking them is holding.")
    return out + [""]
