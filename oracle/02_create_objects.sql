-- ============================================================================
-- Oracle Password Hash Monitoring Objects
-- Creates tables and sequences for tracking password changes
-- Run as HASHCAT_MONITOR user
-- ============================================================================

-- Configuration table for hashcat server settings
CREATE TABLE hashcat_config (
    config_key      VARCHAR2(100) PRIMARY KEY,
    config_value    VARCHAR2(4000),
    description     VARCHAR2(500),
    created_date    DATE DEFAULT SYSDATE,
    modified_date   DATE DEFAULT SYSDATE
) TABLESPACE USERS;

-- Insert default configuration
INSERT INTO hashcat_config (config_key, config_value, description) VALUES
    ('HASHCAT_SERVER_URL', 'http://t2ru-hashcat-t-01:8443/api/v1/hashes', 'Hashcat server endpoint for receiving hashes');
INSERT INTO hashcat_config (config_key, config_value, description) VALUES
    ('HASHCAT_SERVER_TOKEN', 'your-api-token-here', 'Authentication token for hashcat server');
INSERT INTO hashcat_config (config_key, config_value, description) VALUES
    ('SOURCE_SYSTEM', 'ORACLE_PROD', 'Identifier for this Oracle database');
INSERT INTO hashcat_config (config_key, config_value, description) VALUES
    ('ENABLED', 'Y', 'Enable/disable hash monitoring (Y/N)');
INSERT INTO hashcat_config (config_key, config_value, description) VALUES
    ('EXCLUDED_USERS', 'SYS,SYSTEM,HASHCAT_MONITOR', 'Comma-separated list of users to exclude');
INSERT INTO hashcat_config (config_key, config_value, description) VALUES
    ('HTTP_TIMEOUT', '30', 'HTTP request timeout in seconds');

COMMIT;

-- Table to track last known password change time per user
-- Uses Oracle's ptime (password change timestamp) to detect changes
CREATE TABLE hashcat_user_state (
    username        VARCHAR2(128) PRIMARY KEY,
    last_ptime      DATE,           -- last known password change time from sys.user$
    last_checked    DATE DEFAULT SYSDATE,
    created_date    DATE DEFAULT SYSDATE
) TABLESPACE USERS;

-- Table to log hash changes (history)
CREATE TABLE hashcat_hash_changes (
    change_id       NUMBER PRIMARY KEY,
    username        VARCHAR2(128) NOT NULL,
    old_hash        VARCHAR2(4000),
    new_hash        VARCHAR2(4000),
    hash_type       VARCHAR2(50),
    change_date     DATE DEFAULT SYSDATE,
    sent_to_server  CHAR(1) DEFAULT 'N',
    send_date       DATE,
    send_status     VARCHAR2(100),
    http_response   VARCHAR2(4000)
) TABLESPACE USERS;

CREATE SEQUENCE hashcat_change_seq START WITH 1 INCREMENT BY 1 NOCACHE;

-- Table to log all operations
CREATE TABLE hashcat_log (
    log_id          NUMBER PRIMARY KEY,
    log_date        TIMESTAMP DEFAULT SYSTIMESTAMP,
    log_level       VARCHAR2(10),
    module_name     VARCHAR2(100),
    message         VARCHAR2(4000),
    error_code      NUMBER,
    error_message   VARCHAR2(4000)
) TABLESPACE USERS;

CREATE SEQUENCE hashcat_log_seq START WITH 1 INCREMENT BY 1 NOCACHE;

-- Index for faster lookups
CREATE INDEX idx_hash_changes_sent ON hashcat_hash_changes(sent_to_server, change_date);
CREATE INDEX idx_hash_changes_user ON hashcat_hash_changes(username);
CREATE INDEX idx_log_date ON hashcat_log(log_date);

PROMPT Objects created successfully in USERS tablespace
PROMPT Note: hashcat_user_state tracks password change times (ptime), not actual hashes
