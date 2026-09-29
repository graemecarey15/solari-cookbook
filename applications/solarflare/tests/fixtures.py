"""A small made-up account, as `collect` would save it (no real data in the repo).

- example.com, with a Worker `api` on api.example.com and a Worker route for
  `shop-auth` on shop.example.com/auth/*
- Pages projects `shop` (also on shop.example.com) and `blog` (only on
  blog-x1.pages.dev), `blog` first deployed on 2026-01-02
- 2026-01-03: blog's Functions take 351 requests in one minute, and a scanner
  gets a 200 for /wp-login.php on shop.example.com
"""
import json
import tempfile
from pathlib import Path

DAY = "2026-01-03"


def write(folder: Path, name: str, data) -> None:
    (folder / f"{name}.json").write_text(json.dumps(data))


def fake_account() -> tuple[tempfile.TemporaryDirectory, Path]:
    tmp = tempfile.TemporaryDirectory()
    folder = Path(tmp.name)
    write(folder, "zones", {"result": [{"id": "z1", "name": "example.com", "plan": {"name": "Free Website"}}]})
    write(folder, "workers", {"result": [{"id": "api"}, {"id": "shop-auth"}, {"id": "shop-cart"}]})
    write(folder, "worker_domains", {"result": [{"hostname": "api.example.com", "service": "api"}]})
    write(folder, "worker_routes", {"example.com": {"result": [{"pattern": "shop.example.com/auth/*", "script": "shop-auth"}]}})
    write(folder, "pages_projects", {"result": [
        {"name": "shop", "production_script_name": "pages-worker--111-production",
         "preview_script_name": "pages-worker--111-preview", "domains": ["shop.pages.dev", "shop.example.com"]},
        {"name": "blog", "production_script_name": "pages-worker--222-production", "domains": ["blog-x1.pages.dev"]},
    ]})
    write(folder, "worker_deployments", {"api": {"result": {"deployments": [
        {"created_on": "2026-01-01T00:00:00Z", "source": "wrangler", "author_email": "someone@example.com",
         "annotations": {"workers/triggered_by": "deployment"}}]}}})
    write(folder, "pages_deployments", {"blog": {"result": [
        {"created_on": "2026-01-02T00:00:00Z", "environment": "production",
         "deployment_trigger": {"type": "github:push",
                                "metadata": {"branch": "main", "commit_hash": "abc", "commit_message": "Add feed\n\ndetails"}}}]}})
    write(folder, "functions_daily", {"rows": [
        {"dimensions": {"scriptName": "pages-worker--222-production", "date": DAY}, "sum": {"requests": 352, "errors": 0}}]})
    write(folder, "functions_minute", {"rows": [
        {"dimensions": {"scriptName": "pages-worker--222-production", "datetimeMinute": f"{DAY}T20:12:00Z"},
         "sum": {"requests": 351, "errors": 0}},
        {"dimensions": {"scriptName": "pages-worker--999-production", "datetimeMinute": f"{DAY}T20:13:00Z"},
         "sum": {"requests": 1, "errors": 0}},
    ]})
    write(folder, "zone_example.com_requests", {"rows": [
        {"count": 200, "dimensions": {"datetimeHour": f"{DAY}T20:00:00Z", "clientRequestHTTPHost": "shop.example.com",
                                      "clientRequestPath": "/wp-login.php", "clientRequestHTTPMethodName": "GET",
                                      "edgeResponseStatus": 200, "clientCountryName": "HK", "userAgent": "",
                                      "clientIP": "192.0.2.1"}},
    ]})
    write(folder, "manifest", {"period": {"start": DAY, "end": "2026-01-04"}})
    return tmp, folder


def worker_week(folder: Path) -> None:
    """Worker `api`: 100 requests/day for a week, then 500 on 2026-01-03."""
    rows = [{"dimensions": {"scriptName": "api", "date": f"2025-12-{d}", "status": "success"},
             "sum": {"requests": 100, "errors": 0, "subrequests": 0}} for d in range(27, 32)]
    rows += [{"dimensions": {"scriptName": "api", "date": f"2026-01-0{d}", "status": "success"},
              "sum": {"requests": 100 if d < 3 else 500, "errors": 0, "subrequests": 0}} for d in (1, 2, 3)]
    write(folder, "workers_daily", {"rows": rows})
