"""Reading a collected folder: the raw API responses `collect` saved, one JSON file each."""
import json
from pathlib import Path


def load(folder: Path, name: str, default=None):
    path = folder / f"{name}.json"
    return json.loads(path.read_text()) if path.exists() else default


def rows(folder: Path, name: str) -> list:
    """Analytics rows, saved as {"rows": [...]}."""
    return (load(folder, name) or {}).get("rows") or []


def results(folder: Path, name: str) -> list:
    """The `result` list of a saved REST response."""
    return (load(folder, name) or {}).get("result") or []


def zone_names(folder: Path) -> list[str]:
    return [z["name"] for z in results(folder, "zones")]


def is_sample(folder: Path) -> bool:
    """Anonymized samples have made-up hostnames: nothing in them can be fetched."""
    return bool((load(folder, "manifest") or {}).get("sample"))
