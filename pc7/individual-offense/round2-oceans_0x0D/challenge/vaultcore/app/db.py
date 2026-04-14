from __future__ import annotations
import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
"""

class DB:
    def __init__(self, path: str):
        self.path = path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self.path)
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()
        await self._conn.execute("PRAGMA journal_mode=WAL;")
        await self._conn.execute("PRAGMA synchronous=NORMAL;")
        await self._conn.execute("PRAGMA busy_timeout=3000;")

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()

    @property
    def conn(self) -> aiosqlite.Connection:
        assert self._conn is not None
        return self._conn

    async def get(self, k: str) -> str | None:
        cur = await self.conn.execute("SELECT v FROM kv WHERE k=?", (k,))
        row = await cur.fetchone()
        await cur.close()
        return row[0] if row else None

    async def set(self, k: str, v: str) -> None:
        await self.conn.execute(
            "INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (k, v),
        )
        await self.conn.commit()
