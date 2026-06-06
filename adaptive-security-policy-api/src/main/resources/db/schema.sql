-- =====================================================================
--  Adaptive Security Policy — schema PostgreSQL (referinta)
--
--  NOTA: cu spring.jpa.hibernate.ddl-auto=update, Hibernate creeaza
--  singur aceste tabele din clasele @Entity la pornirea aplicatiei.
--  Scriptul e pentru: documentatie (lucrare) si pentru cazul in care
--  treci pe ddl-auto=validate + gestionezi schema manual.
--
--  Ordinea conteaza: tracked_ip se creeaza prima (celelalte o
--  referentiaza prin FK). Nu e rulat automat de Spring (e in db/,
--  nu in radacina classpath-ului).
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. tracked_ip — tabela master: o linie per IP observat + starea curenta
-- ---------------------------------------------------------------------
CREATE TABLE tracked_ip (
    id                BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip_address        VARCHAR(45)  NOT NULL UNIQUE,
    current_status    VARCHAR(20)  NOT NULL DEFAULT 'WARNING'
                          CHECK (current_status IN ('WARNING','BLOCKED','CLEARED')),
    failed_attempts   INTEGER      NOT NULL DEFAULT 0,
    attempt_baseline  INTEGER      NOT NULL DEFAULT 0,
    country           VARCHAR(60),
    city              VARCHAR(80),
    threat_score      INTEGER,
    whitelisted       BOOLEAN      NOT NULL DEFAULT FALSE,
    first_seen        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- 2. block_record — o linie per "episod" de blocare (TTL + repeat-offender)
-- ---------------------------------------------------------------------
CREATE TABLE block_record (
    id            BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip_id         BIGINT       NOT NULL,
    status        VARCHAR(20)  NOT NULL
                      CHECK (status IN ('ACTIVE','EXPIRED','REMOVED')),
    chain         VARCHAR(20),
    source        VARCHAR(10)  NOT NULL
                      CHECK (source IN ('AUTO','MANUAL')),
    reason        TEXT,
    blocked_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    unblocked_at  TIMESTAMPTZ,
    CONSTRAINT fk_block_ip FOREIGN KEY (ip_id) REFERENCES tracked_ip (id)
);

CREATE INDEX idx_block_status ON block_record (status);
CREATE INDEX idx_block_ip     ON block_record (ip_id);

-- ---------------------------------------------------------------------
-- 3. audit_log — jurnal append-only (user din Keycloak sau SYSTEM)
-- ---------------------------------------------------------------------
CREATE TABLE audit_log (
    id          BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action      VARCHAR(30)  NOT NULL
                    CHECK (action IN ('BLOCK','UNBLOCK','WARN','KNOCK',
                                      'CONFIG_CHANGE','WHITELIST_ADD','WHITELIST_REMOVE')),
    user_type   VARCHAR(10)  NOT NULL
                    CHECK (user_type IN ('USER','SYSTEM')),
    user_id     VARCHAR(64),                 -- Keycloak "sub"; NULL cand user_type = SYSTEM
    username    VARCHAR(60)  NOT NULL,        -- snapshot ('system' sau preferred_username)
    ip_id       BIGINT,                       -- nullable (ex. CONFIG_CHANGE n-are IP)
    details     TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT fk_audit_ip FOREIGN KEY (ip_id) REFERENCES tracked_ip (id)
);

CREATE INDEX idx_audit_created ON audit_log (created_at);
CREATE INDEX idx_audit_action  ON audit_log (action);
