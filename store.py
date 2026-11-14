import sqlite3, time, json, threading
from pathlib import Path

DB = Path.home() / ".smc-scraper" / "scraper.db"
DB.parent.mkdir(parents=True, exist_ok=True)


class Store:
    def __init__(self, path=DB):
        self.path = path
        self.lock = threading.Lock()
        self._init()

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def _init(self):
        with self._conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS hosts (
              ip TEXT PRIMARY KEY,
              first_seen INTEGER,
              last_seen INTEGER,
              sources TEXT DEFAULT '[]',
              firmware TEXT,
              family TEXT,
              verdict TEXT DEFAULT 'unchecked',
              verdict_at INTEGER,
              key_src TEXT,
              note TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_verdict ON hosts(verdict);
            CREATE INDEX IF NOT EXISTS idx_last_seen ON hosts(last_seen);

            CREATE TABLE IF NOT EXISTS source_health (
              name TEXT PRIMARY KEY,
              last_run INTEGER,
              last_status TEXT,
              last_count INTEGER,
              error TEXT,
              runs INTEGER DEFAULT 0,
              yielded INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts INTEGER,
              kind TEXT,
              ip TEXT,
              detail TEXT
            );
            """)

    # ---- hosts ----
    def upsert_host(self, ip, source):
        now = int(time.time())
        with self.lock, self._conn() as c:
            row = c.execute("SELECT sources FROM hosts WHERE ip=?", (ip,)).fetchone()
            if row:
                srcs = json.loads(row["sources"] or "[]")
                if source not in srcs:
                    srcs.append(source)
                c.execute("UPDATE hosts SET last_seen=?, sources=? WHERE ip=?",
                          (now, json.dumps(srcs), ip))
                return False
            c.execute("INSERT INTO hosts(ip, first_seen, last_seen, sources) VALUES(?,?,?,?)",
                      (ip, now, now, json.dumps([source])))
            return True

    def set_verdict(self, ip, verdict, firmware="", family="", key_src="", note=""):
        now = int(time.time())
        with self.lock, self._conn() as c:
            c.execute("""UPDATE hosts SET verdict=?, verdict_at=?, firmware=?,
                         family=?, key_src=?, note=? WHERE ip=?""",
                      (verdict, now, firmware, family, key_src, note, ip))
            c.execute("INSERT INTO events(ts, kind, ip, detail) VALUES(?,?,?,?)",
                      (now, "verdict", ip, f"{verdict}|{firmware}|{family}"))

    def by_verdict(self, verdict, limit=100):
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM hosts WHERE verdict=? ORDER BY verdict_at DESC LIMIT ?",
                (verdict, limit)).fetchall()]

    def unchecked(self, limit=1000):
        with self._conn() as c:
            return [r["ip"] for r in c.execute(
                "SELECT ip FROM hosts WHERE verdict='unchecked' OR verdict='possible' "
                "ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()]

    def stats(self):
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
            by = {r["verdict"]: r[1] for r in c.execute(
                "SELECT verdict, COUNT(*) FROM hosts GROUP BY verdict")}
            srcs = [dict(r) for r in c.execute("SELECT * FROM source_health").fetchall()]
            return {"total": total, "by_verdict": by, "sources": srcs}

    # ---- source health ----
    def mark_source(self, name, status, count=0, error=""):
        now = int(time.time())
        with self.lock, self._conn() as c:
            c.execute("""INSERT INTO source_health(name,last_run,last_status,last_count,error,runs,yielded)
                         VALUES(?,?,?,?,?,1,?)
                         ON CONFLICT(name) DO UPDATE SET
                           last_run=excluded.last_run, last_status=excluded.last_status,
                           last_count=excluded.last_count, error=excluded.error,
                           runs=runs+1, yielded=yielded+excluded.yielded""",
                      (name, now, status, count, error, count))
