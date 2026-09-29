"""Read-only Cloudflare API client: REST for inventory and deploys, GraphQL
for analytics. Standard library only."""
import json
import urllib.error
import urllib.request

API = "https://api.cloudflare.com/client/v4"

# The token solarflare needs: a custom token, every permission Read-only.
# (scope, permission, what solarflare uses it for)
TOKEN_PERMISSIONS = [
    ("Account", "Account Analytics", "requests, errors and CPU for each Worker and Pages project"),
    ("Account", "Workers Scripts", "your Workers, their custom domains, and deploy history"),
    ("Account", "Cloudflare Pages", "your Pages projects, their domains, and deploy history"),
    ("Zone", "Zone", "your domains"),
    ("Zone", "Analytics", "traffic detail: host, path, status, country, user agent"),
    ("Zone", "Workers Routes", "which routes send traffic to which Worker"),
]
TOKEN_WHERE = "Cloudflare dashboard > My Profile > API Tokens > Create Token > Create Custom Token"


def token_help(indent: str = "  ") -> str:
    """How to make the token: where, and which permissions (all Read)."""
    lines = [f"{indent}Create it at: {TOKEN_WHERE}", f"{indent}Permissions, all Read:"]
    for scope in ("Account", "Zone"):
        names = ", ".join(p for sc, p, _ in TOKEN_PERMISSIONS if sc == scope)
        lines.append(f"{indent}  {scope + ':':9}{names}")
    return "\n".join(lines)


class CloudflareError(Exception):
    pass


class Cloudflare:
    def __init__(self, token: str, timeout: int = 60):
        if not token:
            raise CloudflareError("No Cloudflare API token. Add CLOUDFLARE_API_TOKEN to .env: a custom, "
                                  "read-only token.\n" + token_help())
        self._token = token
        self._timeout = timeout

    def _call(self, path: str, body=None) -> dict:
        req = urllib.request.Request(
            API + path,
            method="POST" if body is not None else "GET",
            data=json.dumps(body).encode() if body is not None else None,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": "solarflare",
            },
        )
        try:
            # Not user-controlled: the fixed Cloudflare API base plus a path built in this package.
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                return json.load(resp)
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:500]
            raise CloudflareError(f"{e.code} on {path}: {detail}") from None

    def get(self, path: str) -> dict:
        """A REST GET. Returns the whole response, so callers can save it raw."""
        out = self._call(path)
        if not out.get("success", True):
            raise CloudflareError(f"{path}: {out.get('errors')}")
        return out

    def graphql(self, query: str, variables: dict) -> dict:
        out = self._call("/graphql", {"query": query, "variables": variables})
        if out.get("errors"):
            raise CloudflareError("GraphQL: " + "; ".join(e.get("message", "?") for e in out["errors"]))
        return out

    def account_id(self) -> str:
        accounts = self.get("/accounts")["result"]
        if len(accounts) != 1:
            raise CloudflareError(f"Token can see {len(accounts)} accounts; scope it to exactly one.")
        return accounts[0]["id"]


def graphql_rows(response: dict) -> list:
    """The row list from a single-dataset GraphQL response."""
    viewer = response["data"]["viewer"]
    scope = viewer.get("accounts") or viewer.get("zones") or [{}]
    return next(iter(scope[0].values()), []) if scope else []
