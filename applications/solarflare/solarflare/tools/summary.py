"""Summary: what happened on the account over a period.

Detection is fixed SQL over the tables, no AI: billed usage against each
resource's own week, bursts, new resources, error jumps, probes and deploys.
Each unexplained change comes with a ready-to-run `investigate` question;
investigate_items() runs them instead, when asked to.
"""
import asyncio
import sqlite3
import textwrap
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

from .. import progress
from ..agent.investigate import InvestigationError, investigate, save
from ..agent.sandbox import SandboxError
from .probes import scan, worker_lines

BASELINE_DAYS = 7
MOVER_RATIO = 2.0          # period average vs baseline average
MOVER_MIN_DELTA = 50       # requests/day, so tiny resources don't flag on noise
BURST_SHARE = 0.5          # one minute (Pages) or hour (Workers) holding this much of the period
BURST_MIN = 100
ERROR_MIN = 10
ERROR_RATE = 0.05


@dataclass
class Item:
    level: str                  # "look" or "routine"
    areas: list[str]
    title: str
    lines: list[str] = field(default_factory=list)
    question: str | None = None # set when an investigation could explain it
    finding: dict | None = None


@dataclass
class Summary:
    start: date
    end: date                   # exclusive
    facts: list[str]
    items: list[Item]


# ---- detection ----

def detect(db_file: Path, period: tuple[date, date]) -> Summary:
    db = sqlite3.connect(db_file)
    start, end = period
    days, base = _days(start, end), _days(start - timedelta(days=BASELINE_DAYS), start)
    daily = _billed_daily(db)

    total = lambda span: _avg([sum(v.get(d, (0, 0))[0] for v in daily.values()) for d in span])
    t_now, t_base = total(days), total(base)
    change = f" ({(t_now / t_base - 1) * 100:+.0f}%)" if t_base else ""
    facts = [f"Billed requests (Workers + Pages Functions): {t_now:,.0f}/day vs {t_base:,.0f}/day the week before{change}"]

    items = _usage_items(db, daily, days, base, start, end)
    items += _probe_items(db_file, start, end)
    items += _deploy_items(db, start, end)
    db.close()
    return Summary(start, end, facts, items)


def _billed_daily(db) -> dict[tuple[str, str], dict[str, tuple[int, int]]]:
    """(kind, resource) -> {date: (requests, errors)} for billed usage."""
    out: dict = {}
    for kind, name, day, req, err in db.execute("""
            SELECT 'worker', worker, date, SUM(requests), SUM(errors) FROM workers_daily GROUP BY worker, date
            UNION ALL
            SELECT 'pages', COALESCE(project, script_id), date, SUM(requests), SUM(errors)
            FROM functions_daily GROUP BY COALESCE(project, script_id), date"""):
        out.setdefault((kind, name), {})[day] = (req or 0, err or 0)
    return out


def _usage_items(db, daily, days, base, start: date, end: date) -> list[Item]:
    first_deploy = {(k, r): t for k, r, t in db.execute(
        "SELECT resource_kind, resource, MIN(time) FROM deploys GROUP BY resource_kind, resource")}
    items = []
    for (kind, name), by_day in sorted(daily.items()):
        now = _avg([by_day.get(d, (0, 0))[0] for d in days])
        before = _avg([by_day.get(d, (0, 0))[0] for d in base])
        requests = sum(by_day.get(d, (0, 0))[0] for d in days)
        errors = sum(by_day.get(d, (0, 0))[1] for d in days)
        first = first_deploy.get((kind, name))

        if before == 0 and requests and first and first[:10] >= base[0]:
            # A launch, not a spike: it had no traffic because it didn't exist yet.
            items.append(Item("routine", ["deploys", "cost"],
                              f"New: {kind} {name}, first deployed {first[:16].replace('T', ' ')} UTC",
                              [f"{requests:,} requests since, {now:,.0f}/day"]))
            continue

        if now - before >= MOVER_MIN_DELTA and (before == 0 or now >= before * MOVER_RATIO):
            lines = [f"{now:,.0f} requests/day vs {before:,.0f}/day the week before"]
            burst = _burst(db, kind, name, start, end)
            if burst:
                n, total, unit, at = burst
                lines.append(f"{n:,} of {total:,} in a single {unit} ({at[11:16]} UTC {at[:10]})")
                question = f"Why did {name} take {n:,} requests in a single {unit} at {at[11:16]} UTC on {at[:10]}?"
            else:
                question = f"Why did billed requests for {name} jump to {now:,.0f}/day, from {before:,.0f}/day the week before?"
            items.append(Item("look", ["cost", "traffic_patterns"], f"Billed usage jumped: {kind} {name}", lines,
                              question=question))

        if errors >= ERROR_MIN and requests and errors / requests >= ERROR_RATE:
            items.append(Item("look", ["traffic_patterns"], f"Errors: {kind} {name}",
                              [f"{errors:,} errors out of {requests:,} requests ({errors / requests:.0%})"],
                              question=f"Why did {name} have {errors:,} errors ({errors / requests:.0%} of requests)?"))
    return items


BURST_QUERIES = {
    # One minute of a Pages project's Functions, or one hour of a Worker: the busiest, and the period's total.
    "pages": ("minute", """
        SELECT minute, SUM(requests),
               (SELECT SUM(requests) FROM functions_minute
                WHERE COALESCE(project, script_id) = ? AND minute >= ? AND minute < ?)
        FROM functions_minute WHERE COALESCE(project, script_id) = ? AND minute >= ? AND minute < ?
        GROUP BY minute ORDER BY 2 DESC LIMIT 1"""),
    "worker": ("hour", """
        SELECT hour, SUM(requests),
               (SELECT SUM(requests) FROM workers_hourly WHERE worker = ? AND hour >= ? AND hour < ?)
        FROM workers_hourly WHERE worker = ? AND hour >= ? AND hour < ?
        GROUP BY hour ORDER BY 2 DESC LIMIT 1"""),
}


def _burst(db, kind: str, name: str, start: date, end: date) -> tuple[int, int, str, str] | None:
    """(requests, total, unit, when) if one minute (Pages) or hour (Workers) holds most of the period."""
    s, e = start.isoformat(), end.isoformat()
    unit, query = BURST_QUERIES[kind]
    row = db.execute(query, (name, s, e, name, s, e)).fetchone()
    if row and row[2] and row[1] >= BURST_MIN and row[1] / row[2] >= BURST_SHARE:
        at, n, total = row
        return n, total, unit, at
    return None


def _probe_items(db_file: Path, start: date, end: date) -> list[Item]:
    result = scan(db_file, start, end)
    if not result.total:
        return []
    items = [Item("routine", ["security"],
                  f"Scanners probed {len(result.hosts)} of your hosts ({result.total:,} requests for sensitive paths "
                  "like .env, .git, wp-config)",
                  [f"{host}: {h.probes:,} from {len(h.clients)} clients, mostly {h.top_country}"
                   for host, h in result.busiest(5)])]

    if result.on_workers:
        lines = worker_lines(result)
        if any(h.leaking for h in result.on_workers.values()):
            items.append(Item("look", ["security", "cost"], "Probes are still reaching Workers, so their code runs "
                              "and can be billed", lines + ["`solarflare security` suggests a WAF rule to stop them."]))
        else:
            items.append(Item("routine", ["security"], "Probes on Worker-served hosts: none getting through at the "
                              "end of the period", lines))

    answered = {}
    for host, path, n in result.answered:
        answered.setdefault(host, [0, path])[0] += n
    if answered:
        top = sorted(answered.items(), key=lambda kv: -kv[1][0])[:6]
        items.append(Item("look", ["security"], "Some probes for sensitive paths got a 200 response",
                          [f"{host}: {n:,} (e.g. {path})" for host, (n, path) in top]
                          + ["Usually your fallback page, not the file. `solarflare security` re-checks each one."]))
    return items


def _deploy_items(db, start: date, end: date) -> list[Item]:
    rows = db.execute("""SELECT resource_kind, resource, time, trigger, commit_message FROM deploys
                         WHERE time >= ? AND time < ? ORDER BY time""", (start.isoformat(), end.isoformat())).fetchall()
    if not rows:
        return []
    return [Item("routine", ["deploys"], f"{len(rows)} deploy(s) in the period",
                 [f"{t[:16].replace('T', ' ')} {k} {r}" + (f" ({trig})" if trig and trig != "deployment" else "")
                  + (f": {msg}" if msg else "") for k, r, t, trig, msg in rows])]


def _avg(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _days(start: date, end: date) -> list[str]:
    return [(start + timedelta(days=i)).isoformat() for i in range((end - start).days)]


# ---- investigating flagged items (only with --investigate N) ----

def investigate_items(summary: Summary, db_file: Path, limit: int, model: str, traces: Path) -> None:
    todo = [i for i in summary.items if i.question][:limit]
    for n, item in enumerate(todo, 1):
        progress.note(f"Investigating {n} of {len(todo)}: {item.title}")
        try:
            inv = asyncio.run(investigate(item.question, db_file, model=model, on_step=progress.step_printer("    ")))
            item.finding = inv.finding
            save(inv, traces)
        except (InvestigationError, SandboxError) as e:
            item.lines.append(f"(Couldn't investigate: {e})")


# ---- output ----

def format_summary(s: Summary, source: str = "") -> str:
    """source: what goes after `solarflare investigate` so the printed commands look at the same data."""
    span = str(s.start) if (s.end - s.start).days == 1 else f"{s.start} to {s.end - timedelta(days=1)}"
    title = f"Your Cloudflare account, {span}"
    out = [title, "=" * len(title), ""]
    for fact in s.facts:
        out += _wrap(fact, "")

    looks = [i for i in s.items if i.level == "look"]
    routine = [i for i in s.items if i.level == "routine"]
    out += ["", "NEEDS A LOOK", "------------", ""] if looks else ["", "Nothing needs a look.", ""]
    for n, item in enumerate(looks, 1):
        out += _format_item(n, item, source)
    if routine:
        out += ["ROUTINE", "-------", ""]
    for n, item in enumerate(routine, len(looks) + 1):
        out += _format_item(n, item, source)
    if any(i.question and not i.finding for i in looks):
        out += _wrap("Investigations need SOLARI_API_KEY and OPENAI_API_KEY. Edit the question if you like, or add "
                     "--investigate N to have summary run them.", "")
    return "\n".join(out).rstrip()


def _format_item(n: int, item: Item, source: str) -> list[str]:
    out = [f"{n}. {item.title}   [{', '.join(item.areas)}]"]
    out += [f"     {line}" for line in item.lines]      # data lines stay whole; only prose wraps
    if item.finding:
        f = item.finding
        out += ["", "     Investigated:"]
        out += _wrap(f.get("summary", ""), "       ")
        out += _wrap(f"Cause: {f.get('cause')} (confidence in this finding: {f.get('confidence')})", "       ")
        out += _wrap(f"What to do: {f.get('recommendation', '')}", "       ")
    elif item.question:
        target = f"{source} " if source else ""
        out += ["", "     Find out why: run this (an AI investigation, about a cent):",
                f'       solarflare investigate {target}"{item.question}"']
    return out + [""]


def _wrap(text: str, indent: str, width: int = 100) -> list[str]:
    return textwrap.wrap(text, width=width, initial_indent=indent, subsequent_indent=indent) or [indent]
