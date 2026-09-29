"""Usage: what the account used in a period, how that compares with the
period before, which resources drive it, and (with a plan) the headroom
against the plan's included usage and where the month is heading.

Cloudflare's API doesn't expose plan limits, so they're a table here,
dated to when they were checked. Pages Functions are billed as Workers.
"""
import calendar
from dataclasses import dataclass, field
from datetime import date, timedelta

from ..cloudflare.api import Cloudflare, graphql_rows

LIMITS_CHECKED = "2026-09-28"
LIMITS_SOURCE = "https://developers.cloudflare.com/workers/platform/pricing/"
# (included, per, overage $ per million) per metric. None: no overage (hard limit).
LIMITS = {
    "free": {"requests": (100_000, "day", None)},
    "paid": {"requests": (10_000_000, "month", 0.30), "cpu_ms": (30_000_000, "month", 0.02)},
}
TREND_DAYS = 7

WORKERS = """query($a: string!, $s: Time!, $e: Time!) { viewer { accounts(filter: {accountTag: $a}) {
  workersInvocationsAdaptive(limit: 10000, filter: {datetime_geq: $s, datetime_lt: $e}) {
    dimensions { scriptName date } sum { requests cpuTimeUs errors } } } } }"""
FUNCTIONS = """query($a: string!, $s: Time!, $e: Time!) { viewer { accounts(filter: {accountTag: $a}) {
  pagesFunctionsInvocationsAdaptiveGroups(limit: 10000, filter: {datetime_geq: $s, datetime_lt: $e}) {
    dimensions { scriptName date } sum { requests errors } } } } }"""


@dataclass
class Line:
    metric: str
    used: float
    included: float
    per: str
    projected: float | None = None
    overage_usd: float | None = None
    top: list[tuple[str, float]] = field(default_factory=list)
    note: str = ""

    @property
    def pct(self) -> float:
        return self.used / self.included * 100 if self.included else 0.0


def fetch_daily(cf: Cloudflare, start: date, end: date) -> list[dict]:
    """[{resource, date, requests, cpu_ms}] for Workers and Pages Functions."""
    account = cf.account_id()
    v = {"a": account, "s": f"{start}T00:00:00Z", "e": f"{end}T00:00:00Z"}
    pages = {s: p["name"] for p in cf.get(f"/accounts/{account}/pages/projects")["result"]
             for s in (p.get("production_script_name"), p.get("preview_script_name")) if s}
    rows = [{"resource": f"worker:{r['dimensions']['scriptName']}", "date": r["dimensions"]["date"],
             "requests": r["sum"]["requests"], "cpu_ms": r["sum"]["cpuTimeUs"] / 1000, "errors": r["sum"]["errors"]}
            for r in graphql_rows(cf.graphql(WORKERS, v))]
    def pages_label(script_id: str) -> str:
        # An id no current project claims: usually a deleted project.
        return f"pages:{pages[script_id]}" if script_id in pages else f"pages:(unknown {script_id.split('--')[-1]})"

    rows += [{"resource": pages_label(r["dimensions"]["scriptName"]),
              "date": r["dimensions"]["date"], "requests": r["sum"]["requests"], "cpu_ms": None,
              "errors": r["sum"]["errors"]}
             for r in graphql_rows(cf.graphql(FUNCTIONS, v))]
    return rows


def compute(rows: list[dict], plan: str, today: date) -> list[Line]:
    """today is the current, incomplete day: counted in usage, left out of the trend."""
    if plan not in LIMITS:
        raise ValueError(f"Unknown plan {plan!r}; use one of {sorted(LIMITS)}")
    month_start = today.replace(day=1)
    days_in_month = calendar.monthrange(today.year, today.month)[1]
    remaining_days = days_in_month - today.day  # full days left after today
    trend_days = [(today - timedelta(days=i)).isoformat() for i in range(1, TREND_DAYS + 1)
                  if today - timedelta(days=i) >= month_start] or [today.isoformat()]

    def total(metric, days=None, resource=None):
        return sum(r[metric] or 0 for r in rows if (days is None or r["date"] in days)
                   and (resource is None or r["resource"] == resource))

    def top(metric, days=None):
        per = {}
        for r in rows:
            if (days is None or r["date"] in days) and r[metric]:
                per[r["resource"]] = per.get(r["resource"], 0) + r[metric]
        return sorted(per.items(), key=lambda kv: -kv[1])[:3]

    lines = []
    for metric, (included, per, overage) in LIMITS[plan].items():
        note = "Workers only: Cloudflare's analytics don't report Pages Functions CPU time." if metric == "cpu_ms" else ""
        if per == "day":
            # Daily limit: the busiest recent day is what matters.
            days = sorted({r["date"] for r in rows})
            busiest = max(days, key=lambda d: total(metric, [d])) if days else today.isoformat()
            lines.append(Line(metric, total(metric, [busiest]), included, f"day (busiest: {busiest})",
                              top=top(metric, [busiest]), note=note))
            continue
        used = total(metric)
        daily_trend = total(metric, trend_days) / len(trend_days)
        projected = used + daily_trend * remaining_days
        over = max(0.0, projected - included) / 1e6 * overage if overage is not None else None
        lines.append(Line(metric, used, included, "month", projected, over, top(metric), note))
    return lines


def format_usage(lines: list[Line], plan: str, today: date) -> str:
    unit = {"requests": "requests", "cpu_ms": "CPU ms"}
    span = f"{today:%B %Y} to date ({today})" if plan == "paid" else f"the last 7 days to {today}"
    out = [f"Workers {plan} plan, {span}", ""]
    for l in lines:
        flag = ""
        if l.projected is not None and l.projected > l.included:
            flag = "  <-- on course to exceed"
        elif l.pct >= 80:
            flag = "  <-- close to the limit"
        out.append(f"{unit[l.metric]}: {l.used:,.0f} of {l.included:,.0f} per {l.per} ({l.pct:.1f}%){flag}")
        if l.projected is not None:
            cost = f", about ${l.overage_usd:.2f} over" if l.overage_usd else ", within the included amount"
            out.append(f"  projected month end: {l.projected:,.0f}{cost}")
        if l.top:
            out.append("  mostly: " + ", ".join(f"{name} ({v:,.0f})" for name, v in l.top))
        if l.note:
            out.append(f"  {l.note}")
    out += ["", f"Limits as checked against {LIMITS_SOURCE} on {LIMITS_CHECKED}. "
                "KV, R2 and D1 aren't tracked yet."]
    return "\n".join(out)


@dataclass
class ResourceUsage:
    resource: str
    requests: int
    prev_requests: int
    cpu_ms: float | None
    errors: int


@dataclass
class Breakdown:
    requests: int
    prev_requests: int
    cpu_ms: float
    prev_cpu_ms: float
    errors: int
    resources: list[ResourceUsage]
    daily: list[tuple[str, int]]


def breakdown(rows: list[dict], prev_rows: list[dict]) -> Breakdown:
    def per_resource(rs):
        out: dict[str, dict] = {}
        for r in rs:
            d = out.setdefault(r["resource"], {"requests": 0, "cpu_ms": None, "errors": 0})
            d["requests"] += r["requests"]
            d["errors"] += r.get("errors") or 0
            if r["cpu_ms"] is not None:
                d["cpu_ms"] = (d["cpu_ms"] or 0) + r["cpu_ms"]
        return out

    now, prev = per_resource(rows), per_resource(prev_rows)
    resources = sorted((ResourceUsage(name, d["requests"], prev.get(name, {}).get("requests", 0), d["cpu_ms"], d["errors"])
                        for name, d in now.items()), key=lambda r: -r.requests)
    daily: dict[str, int] = {}
    for r in rows:
        daily[r["date"]] = daily.get(r["date"], 0) + r["requests"]
    return Breakdown(
        requests=sum(r["requests"] for r in rows), prev_requests=sum(r["requests"] for r in prev_rows),
        cpu_ms=sum(r["cpu_ms"] or 0 for r in rows), prev_cpu_ms=sum(r["cpu_ms"] or 0 for r in prev_rows),
        errors=sum(r.get("errors") or 0 for r in rows), resources=resources, daily=sorted(daily.items()))


def _pct(now: float, before: float) -> str:
    return f"{(now / before - 1) * 100:+.0f}%" if before else ("new" if now else "-")


def format_breakdown(b: Breakdown, start: date, end: date, top: int = 10) -> str:
    """end is exclusive."""
    days = (end - start).days
    out = [f"Usage, {start} to {end - timedelta(days=1)} ({days} days), vs the {days} days before", ""]
    out.append(f"Requests (Workers + Pages Functions): {b.requests:,}  ({_pct(b.requests, b.prev_requests)}; "
               f"{b.prev_requests:,} before)")
    out.append(f"Workers CPU: {b.cpu_ms:,.0f} ms  ({_pct(b.cpu_ms, b.prev_cpu_ms)})"
               + (f", {b.cpu_ms / sum(r.requests for r in b.resources if r.cpu_ms is not None):.1f} ms per request"
                  if any(r.cpu_ms for r in b.resources) else ""))
    out.append(f"Errors: {b.errors:,} ({b.errors / b.requests:.2%} of requests)" if b.requests else "Errors: 0")
    if b.resources:
        w = max(len(r.resource) for r in b.resources[:top])
        out += ["", f"{'By resource':{w + 2}} {'requests':>10} {'share':>6} {'change':>7} {'CPU ms':>12} {'errors':>7}"]
        for r in b.resources[:top]:
            cpu = f"{r.cpu_ms:,.0f}" if r.cpu_ms is not None else "-"
            out.append(f"  {r.resource:{w}} {r.requests:>10,} {r.requests / b.requests:>6.0%} "
                       f"{_pct(r.requests, r.prev_requests):>7} {cpu:>12} {r.errors:>7,}")
        if len(b.resources) > top:
            out.append(f"  ...and {len(b.resources) - top} more")
    if len(b.daily) > 1:
        peak = max(n for _, n in b.daily) or 1
        out += ["", "By day:"] + [f"  {d}  {'#' * max(1, round(n / peak * 30)) if n else ''} {n:,}" for d, n in b.daily]
    out.append("\nCPU is Workers only: Cloudflare's analytics don't report Pages Functions CPU time.")
    return "\n".join(out)
