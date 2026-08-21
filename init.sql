-- Windows Event Log kayıtları — tam içerik
CREATE TABLE IF NOT EXISTS events (
    id              BIGSERIAL PRIMARY KEY,
    event_id        INTEGER NOT NULL,
    log_name        VARCHAR(50) NOT NULL,       -- System, Application, Security
    category        VARCHAR(100),                -- Sistem / Uygulama / Güvenlik
    source_name     VARCHAR(255),                -- Olayı üreten servis/uygulama
    level           VARCHAR(20) NOT NULL,        -- Critical, Error, Warning, Information
    task            VARCHAR(255),                -- Task / görev kategorisi
    opcode          VARCHAR(100),
    keywords        TEXT,
    error_code      VARCHAR(64),                 -- Varsa hata / sonuç kodu
    computer_name   VARCHAR(255),
    user_sid        VARCHAR(255),
    record_id       BIGINT,                      -- EventRecordID
    time_created    TIMESTAMPTZ NOT NULL,
    description     TEXT,                        -- Formatlanmış açıklama
    message         TEXT,                        -- EventData özeti
    raw_xml         TEXT,                        -- Ham event XML
    inserted_at     TIMESTAMPTZ DEFAULT now()
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
