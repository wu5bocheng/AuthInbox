CREATE TABLE IF NOT EXISTS raw_mails (
    id INTEGER PRIMARY KEY,
    message_id TEXT UNIQUE,
    from_addr TEXT,
    to_addr TEXT,
    subject TEXT,
    raw TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    processed INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS code_mails (
    id INTEGER PRIMARY KEY,
    message_id TEXT UNIQUE,
    from_addr TEXT,
    from_org TEXT,
    to_addr TEXT,
    topic TEXT,
    code TEXT,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (message_id) REFERENCES raw_mails(message_id)
);

CREATE TABLE IF NOT EXISTS email_settings (
    email TEXT PRIMARY KEY,
    is_private INTEGER DEFAULT 1,  -- 1 for private, 0 for public
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_raw_message_id ON raw_mails (message_id);
CREATE INDEX IF NOT EXISTS idx_code_message_id ON code_mails (message_id);
CREATE INDEX IF NOT EXISTS idx_email_settings ON email_settings (email);
