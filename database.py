"""Gömülü SQLite veritabani — Docker/Postgres gerekmez."""
from __future__ import annotations

import configparser
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

from paths import app_dir, config_path, resource_dir

_lock = threading.RLock()
_initialized = False


def db_path() -> Path:
    path = config_path()
    if path.exists():
        parser = configparser.ConfigParser()
        parser.read(path, encoding="utf-8")
        if parser.has_section("database") and parser.has_option("database", "path"):
            raw = parser.get("database", "path").strip()
            if raw:
                p = Path(raw)
                return p if p.is_absolute() else (app_dir() / p)
    return app_dir() / "data" / "events.db"


def _dict_factory(cursor, row):
    return {col[0]: row[i] for i, col in enumerate(cursor.description)}


def _connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(path),
        check_same_thread=False,
        timeout=60,
        detect_types=sqlite3.PARSE_DECLTYPES,
    )
    conn.row_factory = _dict_factory
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=60000")
    return conn


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        INTEGER NOT NULL,
    log_name        TEXT NOT NULL,
    category        TEXT,
    source_name     TEXT,
    level           TEXT NOT NULL,
    task            TEXT,
    opcode          TEXT,
    keywords        TEXT,
    error_code      TEXT,
    computer_name   TEXT,
    user_sid        TEXT,
    record_id       INTEGER,
    time_created    TEXT NOT NULL,
    description     TEXT,
    message         TEXT,
    raw_xml         TEXT,
    inserted_at     TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_time_created ON events (time_created DESC);
CREATE INDEX IF NOT EXISTS idx_events_level ON events (level);
CREATE INDEX IF NOT EXISTS idx_events_log_name ON events (log_name);
CREATE INDEX IF NOT EXISTS idx_events_category ON events (category);
CREATE INDEX IF NOT EXISTS idx_events_source_name ON events (source_name);
CREATE INDEX IF NOT EXISTS idx_events_event_id ON events (event_id);
CREATE INDEX IF NOT EXISTS idx_events_error_code ON events (error_code);

CREATE UNIQUE INDEX IF NOT EXISTS idx_events_unique
    ON events (event_id, log_name, computer_name, time_created);
"""


def init_db() -> Path:
    """Sema yoksa olusturur. Donen: db dosya yolu."""
    global _initialized
    with _lock:
        path = db_path()
        conn = _connect()
        try:
            conn.executescript(SCHEMA_SQL)
            conn.commit()
            # eski migrate.sql Postgres icindi; SQLite semasi tek seferde tam
            schema_marker = resource_dir() / "schema_sqlite.sql"
            if schema_marker.exists():
                pass
        finally:
            conn.close()
        _initialized = True
        return path


class CursorWrapper:
    """psycopg2 tarzı %s placeholder'lari ? ye cevirir."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        self._cur = conn.cursor()

    def execute(self, sql: str, params=None):
        sql = sql.replace("%s", "?")
        self._cur.execute(sql, params or [])
        return self

    def executemany(self, sql: str, seq_of_params):
        sql = sql.replace("%s", "?")
        self._cur.executemany(sql, seq_of_params)
        return self

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def close(self):
        self._cur.close()


@contextmanager
def get_db_cursor():
    """
    Kullanim:
        with get_db_cursor() as cur:
            cur.execute("SELECT ...", params)
            rows = cur.fetchall()
    """
    if not _initialized:
        init_db()
    with _lock:
        conn = _connect()
        cur = CursorWrapper(conn)
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()


def get_connection() -> sqlite3.Connection:
    """Collector icin ham baglanti (manuel commit)."""
    if not _initialized:
        init_db()
    return _connect()


def wait_for_db(timeout_seconds: int = 60) -> None:
    init_db()
