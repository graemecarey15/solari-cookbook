"""What a command looks at: keys from .env, the period, and the data folder
(the bundled sample, a saved folder, or your account collected fresh)."""
import atexit
import os
import shutil
import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from . import progress
from .cloudflare.api import Cloudflare
from .cloudflare.collect import Collector
from .cloudflare.tables import build, is_current

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample"
TRACES_HOME = Path("data")        # investigations on your account keep their traces in data/investigations/
TEMP_PREFIX = "solarflare-"


def load_env(path: Path = Path(".env")) -> None:
    """KEY=value lines from .env, without overriding the real environment."""
    if path.exists():
        for line in path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())


def missing_keys(*names: str) -> list[str]:
    return [n for n in names if not os.environ.get(n)]


def cloudflare() -> Cloudflare:
    return Cloudflare(os.environ.get("CLOUDFLARE_API_TOKEN", ""))


# ---- periods ----

def today() -> date:
    return datetime.now(timezone.utc).date()


def add_period(parser, default: str) -> None:
    g = parser.add_argument_group("period", f"Default: {default}.")
    g.add_argument("--date", help="One day, YYYY-MM-DD")
    g.add_argument("--from", dest="start", help="First day, YYYY-MM-DD (with --to)")
    g.add_argument("--to", dest="end", help="Last day, YYYY-MM-DD (inclusive; default: yesterday)")
    g.add_argument("--days", type=int, help="The last N full days, ending yesterday")


def period_from(args) -> tuple[date, date] | None:
    """(start, end exclusive) from --date / --from/--to / --days, or None if none was given."""
    yesterday = today() - timedelta(days=1)
    if args.date:
        d = date.fromisoformat(args.date)
        return d, d + timedelta(days=1)
    if args.days:
        return yesterday - timedelta(days=args.days - 1), today()
    if args.start:
        last = date.fromisoformat(args.end) if args.end else yesterday
        return date.fromisoformat(args.start), last + timedelta(days=1)
    return None


def yesterday() -> tuple[date, date]:
    return today() - timedelta(days=1), today()


def period_label(start: date, end: date) -> str:
    """2026-09-25, or 2026-09-20_2026-09-26 for a range."""
    last = end - timedelta(days=1)
    return str(start) if start == last else f"{start}_{last}"


def period_flags(start: date, end: date) -> str:
    """The options that select this period again, for commands we print."""
    last = end - timedelta(days=1)
    return f"--date {start}" if start == last else f"--from {start} --to {last}"


# ---- data folders ----

def as_folder(value: str) -> Path:
    """A folder argument: an existing path, or the word `sample` from anywhere."""
    if not Path(value).is_dir() and value == "sample":
        return SAMPLE_DIR
    return Path(value)


def looks_like_folder(word: str) -> bool:
    return word == "sample" or Path(word).is_dir()


def collect_fresh(period: tuple[date, date], parts: tuple) -> Path:
    """Collect the period from your account into a temporary folder, deleted when the command ends."""
    cf = cloudflare()                       # fails fast, before announcing anything, if there's no token
    folder = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX))
    atexit.register(shutil.rmtree, folder, ignore_errors=True)
    progress.note(f"Collecting {period_label(*period).replace('_', ' to ')} from Cloudflare")
    Collector(cf, folder).run(*period, parts=parts)
    return folder


def database(folder: Path) -> Path:
    """The folder's SQLite tables, (re)built when missing, out of date, or older than the data."""
    db = folder / "solarflare.db"
    data = [f for f in folder.glob("*.json") if f.name not in ("case.json", "replay.json")]
    if not db.exists() or not is_current(db) or any(f.stat().st_mtime > db.stat().st_mtime for f in data):
        progress.start("Building tables")
        build(folder, db)
        progress.done(f"Building tables: {db.stat().st_size // 1024:,} KB")
    return db


def traces_dir(folder: Path) -> Path:
    """Where investigation traces go: beside a saved folder or the sample, else data/."""
    return TRACES_HOME if folder.name.startswith(TEMP_PREFIX) else folder
