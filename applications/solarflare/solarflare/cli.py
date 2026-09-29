"""The solarflare command line: the arguments, one short function per command,
and error handling. What each command is for, with examples, is in helptext.py."""
import argparse
import asyncio
import json
import os
import sqlite3
import sys
from datetime import timedelta
from pathlib import Path

from . import helptext, progress, tour
from .agent import evaluate
from .agent.investigate import InvestigationError, format_finding, investigate, replay, save
from .agent.sandbox import AnalysisSandbox, SandboxError
from .cloudflare.api import CloudflareError
from .cloudflare.collect import Collector
from .cloudflare.inventory import Inventory
from .cloudflare.saved import is_sample
from .cloudflare.tables import build, collected_period
from .options import (add_period, as_folder, cloudflare, collect_fresh, database, load_env, looks_like_folder,
                      missing_keys, period_flags, period_from, period_label, today, traces_dir, yesterday)
from .tools import probes, security, summary, usage

ALL_PARTS = ("deploys", "usage", "traffic")
INVESTIGATION_KEYS = ("OPENAI_API_KEY", "SOLARI_API_KEY")


class UsageError(Exception):
    """A mistake in how the command was called: printed as-is, no sample tip."""


# ---- the commands people run ----

def cmd_summary(args) -> int:
    folder, period = _data(args, ALL_PARTS)
    db = database(folder)
    progress.start("Detecting changes")
    s = summary.detect(db, period)
    flagged = [i for i in s.items if i.question]
    progress.done(f"Detecting changes: {len(s.items)} findings, {len(flagged)} with a question to investigate")

    missing = missing_keys(*INVESTIGATION_KEYS)
    if args.investigate and not missing:
        summary.investigate_items(s, db, args.investigate, args.model, traces_dir(folder))
    progress.total()
    print(summary.format_summary(s, source=args.folder or period_flags(s.start, s.end)))
    if args.investigate and missing:
        print(f"\nNot investigated: {' and '.join(missing)} {'is' if len(missing) == 1 else 'are'} not set. "
              "Add to .env, or leave out --investigate.")
    return 0


def cmd_security(args) -> int:
    folder, period = _data(args, ("traffic",))    # no usage counts or deploy history needed
    db = database(folder)
    progress.start("Finding probes")
    rep = security.Report(probes.scan(db, *period), sample=is_sample(folder))
    s = rep.scan
    progress.done(f"Finding probes: {s.total:,} across {len(s.hosts)} hosts, {len(s.answered):,} got a 200")

    if args.verify and s.answered and not rep.sample:
        inv = Inventory.from_folder(folder)
        n, count = min(args.max_checks, len(s.answered)), [0]

        def on_check(host, path):
            count[0] += 1
            progress.update(f"Re-checking probed paths that got a 200: {count[0]} of {n} ({host}{path[:50]})")
        progress.start("Re-checking probed paths that got a 200")
        rep.checks = security.verify(s.answered, inv.zones, {h.host for h in inv.hosts}, args.max_checks, on_check)
        progress.done(f"Re-checking: {len(rep.checks)} checked, {len(rep.exposed)} possibly exposed")
    progress.total()
    print(security.format_report(rep))
    return 1 if rep.exposed else 0


def cmd_usage(args) -> int:
    cf, now = cloudflare(), today()
    start, end = period_from(args) or (now.replace(day=1), now + timedelta(days=1))   # default: this month so far
    span = end - start
    progress.start("Fetching usage")
    current = usage.fetch_daily(cf, start, end)
    progress.update("Fetching usage: the period before, for comparison")
    before = usage.fetch_daily(cf, start - span, start)
    progress.done(f"Fetching usage: {start} to {end - timedelta(days=1)} and the {span.days} days before")
    print(usage.format_breakdown(usage.breakdown(current, before), start, end, top=args.top))

    plan = args.plan or os.environ.get("CLOUDFLARE_WORKERS_PLAN", "")
    if plan in ("free", "paid"):
        # Limits are about this month (Paid) or the last week (Free), whatever period was shown above.
        lim_start = now.replace(day=1) if plan == "paid" else now - timedelta(days=6)
        rows = usage.fetch_daily(cf, lim_start, now + timedelta(days=1))
        print("\n" + usage.format_usage(usage.compute(rows, plan, now), plan, now))
    else:
        print("\nAdd --plan paid (or --plan free), or CLOUDFLARE_WORKERS_PLAN in .env, to see headroom against "
              "your plan's limits.")
    return 0


def cmd_investigate(args) -> int:
    words = list(args.words)
    folder = as_folder(words.pop(0)) if words and looks_like_folder(words[0]) else None
    question = " ".join(words).strip()
    if args.replay:
        return _replay(folder or as_folder("sample"))
    if not question:
        raise UsageError('ask a question, e.g. solarflare investigate "why did requests jump yesterday?"')
    if folder is None:
        folder = collect_fresh(period_from(args) or yesterday(), ALL_PARTS)
    db = database(folder)

    progress.note(f"Investigating with {args.model} ({args.effort} effort) in a hardened Solari sandbox")
    inv = asyncio.run(investigate(question, db, model=args.model, effort=args.effort, max_steps=args.max_steps,
                                  on_step=progress.step_printer()))
    print("\n" + format_finding(inv))
    cost = f"${inv.cost_usd:.3f}" if inv.cost_usd is not None else "unknown cost"
    print(f"\n{len(inv.steps)} queries, {inv.input_tokens:,} in / {inv.output_tokens:,} out tokens, {cost}, "
          f"{inv.seconds:.0f}s. Trace: {save(inv, traces_dir(folder))}")
    return 0


def cmd_collect(args) -> int:
    period = period_from(args)
    if not period:
        raise UsageError("say which period: --date, --from/--to, or --days")
    out = Path(args.out or f"data/saved/{period_label(*period)}")
    manifest = Collector(cloudflare(), out).run(*period)
    print(f"Collected {period[0]} to {period[1] - timedelta(days=1)} into {out}")
    for line in manifest["truncated"] + manifest["skipped"]:
        print("  note:", line)
    return 0


def cmd_sample(args) -> int:
    return tour.run(main)


# ---- for developing solarflare (not listed in the help) ----

def cmd_build(args) -> int:
    folder = as_folder(args.folder)
    db = build(folder, Path(args.db) if args.db else folder / "solarflare.db")
    con = sqlite3.connect(db)
    for (table,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall():
        # Not injectable: a table name from sqlite_master of a database solarflare built; no user input.
        count = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query, python.lang.security.audit.formatted-sql-query.formatted-sql-query
        print(f"{table:18} {count:7} rows")
    print(f"\n{db} ({db.stat().st_size // 1024} KB)")
    return 0


def cmd_sql(args) -> int:
    db = database(as_folder(args.folder))
    if args.sandbox:
        async def in_sandbox():
            async with AnalysisSandbox(os.environ.get("SOLARI_API_KEY", ""), db) as sbx:
                return await sbx.query(args.query, limit=args.limit)
        result = asyncio.run(in_sandbox())
    else:
        con = sqlite3.connect(db)
        con.row_factory = sqlite3.Row
        rows = [dict(r) for r in con.execute(args.query).fetchmany(args.limit + 1)]
        result = {"rows": rows[:args.limit], "truncated": len(rows) > args.limit}
    for row in result["rows"]:
        print(json.dumps(row, default=str))
    if result["truncated"]:
        print(f"(more rows; showing {args.limit})", file=sys.stderr)
    return 0


def cmd_eval(args) -> int:
    folder = as_folder(args.folder)
    case = evaluate.load_case(folder)
    print(f"{folder}: {args.runs} runs with {args.model} ({args.effort})", file=sys.stderr)
    out = asyncio.run(evaluate.run(case, database(folder), folder, runs=args.runs, model=args.model, effort=args.effort))
    print(f"\n{out['passed']}/{out['runs']} runs passed every check, ${out['cost']:.3f} total")
    for name, ok in out["per_check"].items():
        print(f"  {ok}/{out['runs']}  {name}")
    return 0 if out["passed"] == out["runs"] else 1


# ---- shared by the commands ----

def _data(args, parts: tuple):
    """(folder, period): a given folder (the sample, or one saved with `collect`) and its
    period, or the period (default yesterday) collected fresh from your account."""
    period = period_from(args)
    if args.folder:
        folder = as_folder(args.folder)
        period = period or collected_period(database(folder))
        if not period:
            raise UsageError(f"{folder} doesn't record its period; pass --date or --from/--to")
        return folder, period
    period = period or yesterday()
    return collect_fresh(period, parts), period


def _replay(folder: Path) -> int:
    """A recorded investigation, re-run: its queries run live in the sandbox, its decisions are replayed."""
    recording = json.loads((folder / "replay.json").read_text())
    progress.note(f"Replaying a recorded {recording['model']} investigation. The model's steps are replayed; each "
                  "query runs live now,\nin a hardened Solari sandbox, and is checked against the recording.\n")
    progress.note(f"Question: {recording['question']}\n")

    def show(step):
        mark = "ok" if step["matches_recording"] else "DIFFERS from recording"
        rows = step["result"].get("rows", [])
        first = json.dumps(rows[0], default=str)[:100] if rows else step["result"].get("error", "(no rows)")
        progress.note(f"  · {step['purpose']}\n      {len(rows)} rows [{mark}]  {first}")

    inv = asyncio.run(replay(recording, database(folder), on_step=show))
    print("\n" + format_finding(inv))
    same = sum(1 for step in inv.steps if step["matches_recording"])
    print(f"\n{same}/{len(inv.steps)} live query results matched the recording, {inv.seconds:.0f}s in the sandbox. "
          f"(The recorded run cost ${recording.get('recorded_cost_usd', 0):.3f} in model calls; replaying costs none.)")
    return 0 if same == len(inv.steps) else 1


def try_instead(command: str) -> str:
    """The closest thing to `command` that runs on the bundled sample, with the keys that are set."""
    if command == "investigate" and not missing_keys(*INVESTIGATION_KEYS):
        return 'solarflare investigate sample "Why did billed requests jump on 2026-09-25?"'
    if command == "investigate" and not missing_keys("SOLARI_API_KEY"):
        return "solarflare sample     (includes an investigation replayed live in Solari)"
    if command == "security":
        return "solarflare security sample"
    return "solarflare summary sample"


# ---- arguments ----

def build_parser() -> tuple[argparse.ArgumentParser, dict]:
    p = argparse.ArgumentParser(prog="solarflare", description="What's happening on your Cloudflare account")
    sub = p.add_subparsers(dest="command", required=True)
    folder_help = "Read the sample (`sample`) or a folder saved with `collect` instead of your account"

    s = sub.add_parser("summary", help="What happened on your account over a period")
    s.add_argument("folder", nargs="?", help=folder_help)
    add_period(s, "yesterday")
    s.add_argument("--investigate", type=int, default=0, metavar="N",
                   help="Also investigate up to N flagged changes now (about a cent each). Default: print a "
                        "ready-to-run investigate command under each instead")
    s.add_argument("--model", default="gpt-6-luna", help="Model for investigations (default gpt-6-luna)")
    s.set_defaults(func=cmd_summary)

    u = sub.add_parser("usage", help="What you used, how it's trending, and which resources drive it")
    add_period(u, "this month so far")
    u.add_argument("--plan", choices=["free", "paid"], help="Your Workers plan, to add headroom against its limits "
                                                           "(or CLOUDFLARE_WORKERS_PLAN in .env)")
    u.add_argument("--top", type=int, default=10, help="How many resources to list (default 10)")
    u.set_defaults(func=cmd_usage)

    sc = sub.add_parser("security", help="Who's scanning your sites, and whether anything sensitive is exposed")
    sc.add_argument("folder", nargs="?", help=folder_help)
    add_period(sc, "yesterday")
    sc.add_argument("--no-verify", dest="verify", action="store_false",
                    help="Don't re-fetch probed paths that got a 200 (passive only)")
    sc.add_argument("--max-checks", type=int, default=30, help="Most paths to re-fetch (default 30)")
    sc.set_defaults(func=cmd_security)

    v = sub.add_parser("investigate", help="Why did something change? An agent works it out from the data")
    v.add_argument("words", nargs="*", metavar="[sample] question",
                   help="What to explain, in plain English (quote it). Optionally `sample` first, to "
                        "investigate that instead of your account")
    add_period(v, "yesterday")
    v.add_argument("--replay", action="store_true", help=argparse.SUPPRESS)   # what `solarflare sample` runs
    v.add_argument("--model", default="gpt-6-luna", help="gpt-6-luna (default, ~1 cent) or gpt-6-sol (deeper, ~50 cents)")
    v.add_argument("--effort", default="medium", choices=["none", "low", "medium", "high", "xhigh", "max"],
                   help="How hard the model reasons (default medium)")
    v.add_argument("--max-steps", type=int, default=25, help="Most model turns before giving up (default 25)")
    v.set_defaults(func=cmd_investigate)

    c = sub.add_parser("collect", help="Save a period's Cloudflare data to a folder")
    add_period(c, "none, say which")
    c.add_argument("--out", help="Folder (default: data/saved/<dates>)")
    c.set_defaults(func=cmd_collect)

    sub.add_parser("sample", help="A tour of the bundled sample incident: no setup needed").set_defaults(func=cmd_sample)

    b = sub.add_parser("build", help=argparse.SUPPRESS)
    b.add_argument("folder", help="A collected folder, or `sample`")
    b.add_argument("--db", help="Where to write the database (default: <folder>/solarflare.db)")
    b.set_defaults(func=cmd_build)

    q = sub.add_parser("sql", help=argparse.SUPPRESS)
    q.add_argument("folder", help="A collected folder, or `sample`")
    q.add_argument("query", help="One SQLite SELECT statement")
    q.add_argument("--sandbox", action="store_true", help="Run inside Solari (needs SOLARI_API_KEY)")
    q.add_argument("--limit", type=int, default=50, help="Most rows to show (default 50)")
    q.set_defaults(func=cmd_sql)

    e = sub.add_parser("eval", help=argparse.SUPPRESS)
    e.add_argument("folder", help="A folder with case.json (the question and what a right answer looks like)")
    e.add_argument("--runs", type=int, default=5, help="How many times to run it (default 5)")
    e.add_argument("--model", default="gpt-6-luna", help="Model to evaluate (default gpt-6-luna)")
    e.add_argument("--effort", default="medium", help="Reasoning effort (default medium)")
    e.set_defaults(func=cmd_eval)

    h = sub.add_parser("help", help="What each tool does, its options, and examples")
    h.add_argument("tool", nargs="?", help="A tool name, for its options and examples")
    h.set_defaults(func=None)

    for name, parser in sub.choices.items():
        if name != "help":
            parser.add_argument("--quiet", action="store_true", help="No progress lines, just the result")
        if name in helptext.GUIDE:
            # Same text for `solarflare <tool> --help` and `solarflare help <tool>`.
            parser.description = helptext.description(name)
            parser.epilog = helptext.epilog(name)
            parser.formatter_class = argparse.RawDescriptionHelpFormatter
    return p, sub.choices


def main(argv=None) -> int:
    load_env()
    parser, commands = build_parser()
    raw = sys.argv[1:] if argv is None else argv
    # `solarflare`, `solarflare --help` and `solarflare help` all show the overview.
    if not raw or raw[0] in ("-h", "--help"):
        print(helptext.overview(set(commands)))
        return 0
    args = parser.parse_args(argv)
    if args.command == "help":
        if args.tool in commands and args.tool != "help":
            commands[args.tool].print_help()
            return 0
        print((f"No tool called {args.tool!r}.\n\n" if args.tool else "") + helptext.overview(set(commands)))
        return 1 if args.tool else 0

    progress.quiet = getattr(args, "quiet", False)
    try:
        return args.func(args)
    except UsageError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except (CloudflareError, SandboxError, InvestigationError) as e:
        print(f"error: {e}", file=sys.stderr)
        if missing_keys("CLOUDFLARE_API_TOKEN", *INVESTIGATION_KEYS):
            print(f"\nTry it on the bundled sample instead:\n  {try_instead(args.command)}", file=sys.stderr)
        return 2
