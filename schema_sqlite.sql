-- Referans SQLite semasi (database.init_db icinde de uygulanir)
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
