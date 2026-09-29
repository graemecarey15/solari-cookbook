"""What each command is for, how to use it, and examples. The single source
for `solarflare help`, `solarflare help <tool>` and each command's --help."""

from .cloudflare.api import token_help

INTRO = """solarflare: what's happening on your Cloudflare account.

Covers four areas: cost (billed usage), security (probes and exposure),
traffic patterns (bots, growth, loops) and deploys (what changed when you
shipped). Everything is read-only; it explains and recommends, it never
changes your account. AI analysis runs in a network-isolated Solari sandbox.

Setup, in .env (see .env.example):
  CLOUDFLARE_API_TOKEN             to read your account
{token}
  SOLARI_API_KEY, OPENAI_API_KEY   only for AI investigations
"""

# Shown in the overview. build, sql and eval still work and have --help pages,
# but aren't listed: they're for developing solarflare, not using it.
GROUPS = [
    ("Try it", ["sample"]),
    ("Check your account", ["summary", "usage", "security"]),
    ("Dig into something", ["investigate"]),
    ("Keep data", ["collect"]),
]

GUIDE = {
    "sample": {
        "line": "A tour of the bundled sample: a real incident, anonymized. No setup needed.",
        "run": ("solarflare sample", "summary, security, and (with a Solari key) an investigation replayed"),
        "when": "First time, or to see what solarflare does before connecting an account.",
        "about": """Runs `summary sample`, `security sample` and, if SOLARI_API_KEY
is set, a recorded investigation of the flagged burst, replayed live in a
Solari sandbox, with a short explanation before each.
Nothing calls Cloudflare or costs anything. Every tool also takes the word
`sample` in place of your account.""",
        "examples": [("solarflare summary sample", "Any tool, on the sample")],
    },
    "summary": {
        "line": "What happened on your account over a period.",
        "run": ('solarflare summary', 'no options: covers yesterday'),
        "optional": 'another period with --days N, --date D, or --from A --to B',
        "when": "Routine check, by hand or on a schedule. Start here.",
        "ways": [
            ("solarflare summary", "Your account, yesterday. Collects the data from Cloudflare first (about a minute; "
                                   "needs CLOUDFLARE_API_TOKEN)"),
            ("solarflare summary --days 7", "Your account, the last 7 days (or --date D, --from A --to B)"),
            ("solarflare summary sample", "The bundled sample incident, anonymized: "
                                                                      "no keys needed"),
        ],
        "about": """For each Worker and Pages project, compares the period with its own week
before, and looks for: billed usage that jumped (and bursts within a minute
or hour), resources that are new, error jumps, probes for sensitive paths
(blocked or getting through), and deploys. Prints what needs a look first,
then routine items. No AI: under each unexplained change it prints a
ready-to-run `investigate` command you can run (or edit) yourself; add
--investigate N to have it run them now (about a cent each; needs
SOLARI_API_KEY and OPENAI_API_KEY).""",
        "examples": [
            ("solarflare summary --investigate 2", "Also investigate up to 2 flagged changes now (for scheduled runs)"),
            ("solarflare summary --from 2026-09-20 --to 2026-09-26 --quiet", "A range, no progress lines"),
        ],
    },
    "investigate": {
        "line": "Why did something change? An agent works it out from the data.",
        "run": ('solarflare investigate "question"', 'no options: looks at yesterday'),
        "optional": 'another period with --days N, --date D, or --from A --to B; --model gpt-6-sol',
        "when": "Something looked off: a spike, an error jump, a cost you can't explain.",
        "ways": [
            ('solarflare investigate "why did requests jump?"', "Your account, yesterday (collects it first if needed)"),
            ('solarflare investigate --date 2026-09-25 "why did billed requests jump?"', "A specific day or period"),
            ('solarflare investigate sample "why did billed requests jump?"', "Investigate the sample live"),
        ],
        "about": """An agent queries the collected data step by step (inside a hardened Solari
sandbox, no network) and returns a finding: where, what kind of cause, how
sure it is, the evidence with the table each fact came from, suspects it
ruled out, what the data can't show, and what to do. "Undetermined" is a real
answer: it says what's missing rather than guessing. About a cent per run on
the default model; needs SOLARI_API_KEY and OPENAI_API_KEY. Ask as
specifically as you can: name the resource, the metric and the time if you
know them.""",
        "examples": [
            ('solarflare investigate "..." --model gpt-6-sol', "Deeper look (~50 cents vs ~1)"),
        ],
    },
    "usage": {
        "line": "What you used, how it's trending, and which resources drive it.",
        "run": ('solarflare usage', 'no options: covers this month so far'),
        "optional": 'another period with --days N, --date D, or --from A --to B; --plan paid (or free) for headroom',
        "ways": [
            ('solarflare usage', 'This month so far, compared with the same number of days before'),
            ('solarflare usage --days 30', 'The last 30 days (or --date D, --from A --to B)'),
            ('solarflare usage --plan paid', "Plus headroom against the Workers Paid plan's included usage"),
        ],
        "when": "Keeping an eye on usage and cost, or before something grows.",
        "about": """Requests (Workers and Pages Functions), Workers CPU time and errors for the
period, compared with the same length of time before it; a breakdown by
resource with each one's share and change; and requests by day. Add your
plan to also see headroom against its included usage, a month-end
projection and any estimated overage. Cloudflare's API doesn't expose plan
limits, so they come from a table dated to when it was last checked. No AI.""",
        "examples": [
        ],
    },
    "security": {
        "line": "Who's scanning your sites, and whether anything sensitive is exposed.",
        "run": ('solarflare security', 'no options: covers yesterday'),
        "optional": 'another period with --days N, --date D, or --from A --to B; --no-verify',
        "ways": [
            ('solarflare security', 'Your account, yesterday, re-checking probes that got a 200'),
            ('solarflare security --days 7', 'The last 7 days (or --date D, --from A --to B)'),
            ('solarflare security --no-verify', "Only what's in the traffic data: no requests to your sites"),
            ('solarflare security sample', 'The bundled sample: no keys needed'),
        ],
        "when": "Routine check, or after seeing odd requests. Exits with 1 if something may be exposed.",
        "about": """Finds requests probing for sensitive paths (.env, .git, wp-config,
credentials, .php backdoors...) in your zones' traffic. Every probe that got
a 200 is fetched again and compared with the host's answer to a made-up path:
the same answer means your fallback page, so nothing was exposed; anything
else is flagged with its type and size. Response bodies are never printed or
saved. Only your own hostnames are fetched, GET only, no redirects followed.
Also shows, for Worker-served hosts, how many probes reached the Worker (and
can be billed) versus were stopped by Cloudflare, and by what.""",
        "examples": [
        ],
    },
    "collect": {
        "line": "Save a period's Cloudflare data to a folder.",
        "run": ('solarflare collect --days N', 'save data (summary, security and investigate do this for you)'),
        "optional": '--date D or --from A --to B instead of --days, --out FOLDER',
        "when": "Keep an incident before retention drops it (31 days for traffic detail, 90 for counts).",
        "about": """Fixed, read-only queries: inventory, routes, deploys, Workers and Pages Functions
metrics, and traffic detail for every zone. Writes raw responses plus
manifest.json (what was asked for, anything truncated or skipped). The folder
holds real hostnames and client IPs: keep it out of git (data/ is ignored).""",
        "examples": [
            ("solarflare collect --date 2026-09-25", "One day, into data/saved/2026-09-25"),
            ("solarflare collect --from 2026-09-20 --to 2026-09-26", "A week"),
            ("solarflare collect --days 7", "The last 7 full days"),
        ],
    },
    "build": {
        "line": "Build the SQLite tables the agent queries, from a collected folder.",
        "when": "Mostly automatic; run it to see table sizes.",
        "about": """One SQLite file with tidy tables, plus `notes` (where each table's data comes
from and what it can't show). Client IPs are reduced to network + hash, so
full addresses never reach the model.""",
        "examples": [("solarflare build sample", "")],
    },
    "sql": {
        "line": "Query the tables yourself, locally or inside the Solari sandbox.",
        "when": "Checking a finding, or exploring. `SELECT * FROM notes` is the place to start.",
        "about": "Read-only SQL (SQLite). With --sandbox it runs exactly where the agent's queries run.",
        "examples": [
            ('solarflare sql sample "SELECT * FROM notes"', "What each table covers"),
            ('solarflare sql sample "SELECT project, minute, requests FROM functions_minute ORDER BY requests DESC LIMIT 5"', ""),
            ('solarflare sql sample --sandbox "SELECT COUNT(*) FROM zone_requests"', "In the sandbox"),
        ],
    },
    "eval": {
        "line": "Run investigate on a known case several times and check each finding.",
        "when": "After changing the agent's instructions or model: single good runs prove little.",
        "about": "Checks each finding against the known right answer; reports a pass rate and total cost.",
        "examples": [
            ("solarflare eval sample --runs 5", "The bundled sample case"),
            ("solarflare eval sample --runs 3 --model gpt-6-sol", "Another model"),
        ],
    },
}


def description(name: str) -> str:
    g = GUIDE.get(name)
    if not g:
        return ""
    lines = [g["line"]]
    if g.get("ways"):
        lines += ["", "Ways to run it:"]
        for cmd, what in g["ways"]:
            lines += [f"  {cmd}", f"      {what}"]
    return "\n".join(lines)


def epilog(name: str) -> str:
    g = GUIDE.get(name)
    if not g:
        return ""
    lines = ["What it does:", g["about"], "", "When: " + g["when"]]
    if g["examples"]:
        lines += ["", "More examples:" if g.get("ways") else "Examples:"]
    for cmd, what in g["examples"]:
        lines.append(f"  {cmd}" + (f"\n      {what}" if what else ""))
    return "\n".join(lines)


SOURCES = """Data comes from your account, collected fresh from Cloudflare on every run
(needs CLOUDFLARE_API_TOKEN). Use `collect` to keep a copy of a period.
"""

def overview(available: set[str]) -> str:
    out = [INTRO.format(token=token_help("    ")), SOURCES]
    for title, names in GROUPS:
        out.append(title + ":")
        for n in names:
            if n in available:
                g = GUIDE[n]
                out.append(f"  {n:12} {g['line']}")
                if g.get("run"):
                    cmd, note = g["run"]
                    out.append(f"  {'':12} {cmd:34} {note}")
                if g.get("optional"):
                    out.append(f"  {'':12} optional: {g['optional']}")
                out.append("")
    out.append("More on one tool, with options and examples:  solarflare <tool> --help")
    return "\n".join(out)
