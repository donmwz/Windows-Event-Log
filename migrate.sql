-- Mevcut DB'ye yeni kolonları ekler (container zaten oluşturulmuşsa çalıştır)
ALTER TABLE events ADD COLUMN IF NOT EXISTS category VARCHAR(100);
ALTER TABLE events ADD COLUMN IF NOT EXISTS task VARCHAR(255);
ALTER TABLE events ADD COLUMN IF NOT EXISTS opcode VARCHAR(100);
ALTER TABLE events ADD COLUMN IF NOT EXISTS keywords TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS error_code VARCHAR(64);
ALTER TABLE events ADD COLUMN IF NOT EXISTS user_sid VARCHAR(255);
ALTER TABLE events ADD COLUMN IF NOT EXISTS record_id BIGINT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS description TEXT;

CREATE INDEX IF NOT EXISTS idx_events_category ON events (category);
CREATE INDEX IF NOT EXISTS idx_events_error_code ON events (error_code);

-- Eski kayıtlarda category boşsa log_name'den doldur
UPDATE events SET category = CASE log_name
    WHEN 'System' THEN 'Sistem'
    WHEN 'Application' THEN 'Uygulama'
    WHEN 'Security' THEN 'Güvenlik'
    ELSE log_name
END
WHERE category IS NULL;
