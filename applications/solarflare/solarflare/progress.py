"""Progress lines on stderr, so long runs show what they're doing without
mixing into the report on stdout.

In a terminal, `update` rewrites one line in place (counters like
"day 12 of 15"); `done` leaves a finished line with how long it took. When
stderr isn't a terminal, only `done` and `note` lines are written. `quiet`
turns everything off.
"""
import sys
import time

quiet = False
_start = time.monotonic()
_phase_start = _start
_open_line = False


def _tty() -> bool:
    return sys.stderr.isatty()


def _write(text: str, end: str = "\n") -> None:
    global _open_line
    if _open_line and _tty():
        sys.stderr.write("\r\033[K")
    sys.stderr.write(text + end)
    sys.stderr.flush()
    _open_line = end == ""


def start(text: str) -> None:
    """Begin a phase."""
    global _phase_start
    _phase_start = time.monotonic()
    if not quiet and _tty():
        _write(text + "...", end="")


def update(text: str) -> None:
    """Replace the current line (terminal only)."""
    if not quiet and _tty():
        _write(text, end="")


def done(text: str) -> None:
    """Finish a phase, with its duration."""
    if not quiet:
        _write(f"{text}  ({time.monotonic() - _phase_start:.0f}s)")


def note(text: str) -> None:
    """A standalone line (e.g. each investigation step)."""
    if not quiet:
        _write(text)


def total(text: str = "Done") -> None:
    if not quiet:
        _write(f"{text} in {time.monotonic() - _start:.0f}s")


def step_printer(indent: str = "  "):
    """For investigations: prints each step as it happens (number, time, purpose, rows back)."""
    started, count = time.monotonic(), [0]

    def show(step):
        count[0] += 1
        rows = step["result"].get("rows")
        got = f"{len(rows)} rows" if rows is not None else "error, retrying"
        note(f"{indent}step {count[0]} ({time.monotonic() - started:.0f}s): {step['purpose']}  [{got}]")
    return show
