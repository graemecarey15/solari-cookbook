"""Run Investigate on a known case several times and check each finding's
properties. Single good runs prove little: models vary run to run.

A case lives next to its data as case.json:

    {"question": "...",
     "expect": {"where": ["ops-console"],     # the resource the finding must name
                "cause": "undetermined",
                "not_blamed": ["editor"],     # plausible-but-wrong suspects
                "no_leaning_toward": ["scan", "bot", "crawler", "probe"]}}
"""
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .investigate import investigate, save

LEANING = r"\b(likely|probably|points to|suggests|most plausibl|consistent with)\b[^.]*\b({})"


@dataclass
class Case:
    question: str
    checks: list[tuple[str, Callable[[dict], bool]]]


def case_from(spec: dict) -> Case:
    e = spec["expect"]
    checks: list[tuple[str, Callable[[dict], bool]]] = []
    for name in e.get("where", []):
        checks.append((f"names {name} as where the change was", lambda f, n=name: n.lower() in f["where"].lower()))
    if "cause" in e:
        checks.append((f"cause is {e['cause']}", lambda f, c=e["cause"]: f["cause"] == c))
    for name in e.get("not_blamed", []):
        checks.append((f"doesn't blame {name}", lambda f, n=name: n.lower() not in (f["summary"] + f["where"]).lower()))
    if e.get("no_leaning_toward"):
        pattern = re.compile(LEANING.format("|".join(map(re.escape, e["no_leaning_toward"]))), re.IGNORECASE)
        checks.append(("doesn't lean toward an unproven suspect in the summary", lambda f: not pattern.search(f["summary"])))
    checks.append(("every fact names its table", lambda f: bool(f["evidence"]) and all(x["table"].strip() for x in f["evidence"])))
    checks.append(("states what the data can't show", lambda f: bool(f["gaps"])))
    return Case(spec["question"], checks)


def load_case(folder: Path) -> Case:
    path = folder / "case.json"
    if not path.exists():
        raise FileNotFoundError(f"{path} not found: a case needs a question and what to expect (see evaluate.py)")
    return case_from(json.loads(path.read_text()))


async def run(case: Case, db: Path, folder: Path, *, runs: int, model: str, effort: str, report=print) -> dict:
    results = []
    for n in range(1, runs + 1):
        inv = await investigate(case.question, db, model=model, effort=effort)
        save(inv, folder)
        failed = [name for name, check in case.checks if not check(inv.finding or {})]
        results.append({"failed": failed, "cost": inv.cost_usd or 0, "steps": len(inv.steps), "seconds": inv.seconds})
        report(f"run {n}: {'PASS' if not failed else 'FAIL: ' + '; '.join(failed)}  "
               f"({len(inv.steps)} queries, ${inv.cost_usd or 0:.3f}, {inv.seconds:.0f}s)")
    passed = sum(1 for r in results if not r["failed"])
    per_check = {name: sum(1 for r in results if name not in r["failed"]) for name, _ in case.checks}
    return {"passed": passed, "runs": runs, "per_check": per_check, "cost": sum(r["cost"] for r in results)}
