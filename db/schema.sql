-- 寄件者規則：pattern 可為完整地址、@domain，或含 % 萬用字元（例如 mailserveralert@%）
CREATE TABLE IF NOT EXISTS sender_rules (
    id          SERIAL PRIMARY KEY,
    pattern     VARCHAR(255) NOT NULL UNIQUE,
    list_type   VARCHAR(20)  NOT NULL CHECK (list_type IN ('blacklist', 'suspicious', 'trusted')),
    description TEXT
);

-- 內容關鍵字與風險分數（10 / 15 / 20）
CREATE TABLE IF NOT EXISTS phishing_keywords (
    id       SERIAL PRIMARY KEY,
    keyword  VARCHAR(255) NOT NULL UNIQUE,
    score    INTEGER      NOT NULL CHECK (score > 0),
    category VARCHAR(50)  NOT NULL,
    source   VARCHAR(20)  NOT NULL
);

-- 威脅情資快取：具外部證據的帳號／網域／URL。執行時由後端 upsert，非人工維護。
-- init_db.py 不會 TRUNCATE 這張表（它是執行期資料，不是 CSV 來源）。
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    id              SERIAL PRIMARY KEY,
    indicator_type  VARCHAR(10)  NOT NULL CHECK (indicator_type IN ('EMAIL', 'DOMAIN', 'URL')),
    indicator_value TEXT         NOT NULL,
    source          VARCHAR(20)  NOT NULL CHECK (source IN ('IPQS', 'VIRUSTOTAL')),
    verdict         VARCHAR(20)  NOT NULL CHECK (verdict IN ('CONFIRMED_RISK', 'REVOKED')),
    threat_category TEXT,
    evidence        JSONB        NOT NULL,
    first_seen      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_verified   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ,
    UNIQUE (indicator_type, indicator_value, source)
);
