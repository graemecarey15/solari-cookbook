"""The hardened Solari sandbox the agent's analysis runs in.

No outbound network (isolation="hardened"), no credentials inside. Our code
drives it from outside: the database goes in with files.write, queries run
with run_code, results come back as output. Output is data: displayed,
never executed.
"""
import json
from pathlib import Path

from solari_sandbox import SandboxClient

BASE_URL = "https://api.getsolari.com"
DB_PATH = "/tmp/solarflare.db"

# Runs once in the sandbox's kernel. q() prints results as JSON so our side
# parses them rather than scraping text.
PRELUDE = f"""
import json, sqlite3
db = sqlite3.connect({DB_PATH!r})
db.row_factory = sqlite3.Row
def q(sql, params=(), limit=200):
    cur = db.execute(sql, params)
    rows = [dict(r) for r in cur.fetchmany(limit + 1)]
    print(json.dumps({{"rows": rows[:limit], "truncated": len(rows) > limit}}, default=str))
"""


class SandboxError(Exception):
    pass


class AnalysisSandbox:
    """async with AnalysisSandbox(key, db_file) as sbx: await sbx.query("SELECT ...")"""

    def __init__(self, api_key: str, db_file: Path, idle_timeout_ms: int = 10 * 60_000):
        if not api_key:
            raise SandboxError("No Solari API key. Set SOLARI_API_KEY (https://console.getsolari.com).")
        self._key = api_key
        self._db_file = db_file
        self._idle_timeout_ms = idle_timeout_ms
        self._client = None
        self._sbx = None
        self._ctx = None

    async def __aenter__(self):
        self._client = SandboxClient(api_key=self._key, base_url=BASE_URL)
        await self._client.__aenter__()
        self._sbx = await self._client.create(
            template="base",
            isolation="hardened",
            cpu=1,
            mem_mb=2048,
            timeout_ms=self._idle_timeout_ms,
            lifecycle={"onTimeout": "kill"},
        )
        try:
            await self._sbx.connect()
            await self._sbx.files.write(DB_PATH, self._db_file.read_bytes())
            self._ctx = await self._sbx.create_code_context("python")
            await self.run(PRELUDE)
        except BaseException:
            await self.close()
            raise
        return self

    async def __aexit__(self, *exc):
        await self.close()

    async def close(self):
        if self._sbx is not None:
            await self._sbx.kill()   # kill, not close: close leaves the VM running until its timeout
            self._sbx = None
        if self._client is not None:
            await self._client.__aexit__(None, None, None)
            self._client = None

    @property
    def sandbox_id(self) -> str:
        return self._sbx.sandboxId

    async def run(self, code: str) -> str:
        """Run Python in the kernel; returns stdout. Raises on errors."""
        res = await self._sbx.run_code(code, context_id=self._ctx)
        if res.error:
            raise SandboxError(str(res.error))
        return "".join(getattr(i, "text", "") or "" for i in res.results if getattr(i, "type", "") in ("stdout", "result"))

    async def query(self, sql: str, limit: int = 200) -> dict:
        out = await self.run(f"q({sql!r}, limit={int(limit)})")
        return json.loads(out.strip().splitlines()[-1])
