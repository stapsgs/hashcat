-- ============================================================================
-- Oracle Password Hash Monitoring Package (API-compatible)
-- Sends password hash changes to the Hashcat FastAPI server using the
-- expected JSON schema and API key header (X-API-Key).
-- Run as HASHCAT_MONITOR user
-- ============================================================================

CREATE OR REPLACE PACKAGE hashcat_monitor_pkg AS
    c_version CONSTANT VARCHAR2(10) := '1.2.0';

    -- Log levels
    c_log_debug CONSTANT VARCHAR2(10) := 'DEBUG';
    c_log_info  CONSTANT VARCHAR2(10) := 'INFO';
    c_log_warn  CONSTANT VARCHAR2(10) := 'WARN';
    c_log_error CONSTANT VARCHAR2(10) := 'ERROR';

    -- Main procedures
    PROCEDURE run_monitor;
    PROCEDURE detect_hash_changes;
    PROCEDURE send_pending_hashes;
    PROCEDURE cleanup_old_logs(p_days_to_keep IN NUMBER DEFAULT 90);

    -- Utility functions
    FUNCTION get_config(p_key IN VARCHAR2) RETURN VARCHAR2;
    FUNCTION is_user_excluded(p_username IN VARCHAR2) RETURN BOOLEAN;
    FUNCTION get_hash_type(p_hash IN VARCHAR2) RETURN VARCHAR2;

    -- Logging procedure
    PROCEDURE log_message(
        p_level   IN VARCHAR2,
        p_module  IN VARCHAR2,
        p_message IN VARCHAR2,
        p_error_code    IN NUMBER DEFAULT NULL,
        p_error_message IN VARCHAR2 DEFAULT NULL
    );

END hashcat_monitor_pkg;
/

CREATE OR REPLACE PACKAGE BODY hashcat_monitor_pkg AS

    -- ========================================================================
    -- Helper functions
    -- ========================================================================

    FUNCTION get_config(p_key IN VARCHAR2) RETURN VARCHAR2 IS
        v_value VARCHAR2(4000);
    BEGIN
        SELECT config_value INTO v_value
        FROM hashcat_config
        WHERE config_key = p_key;
        RETURN v_value;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RETURN NULL;
    END get_config;

    FUNCTION is_user_excluded(p_username IN VARCHAR2) RETURN BOOLEAN IS
        v_excluded_users VARCHAR2(4000);
    BEGIN
        v_excluded_users := get_config('EXCLUDED_USERS');
        IF v_excluded_users IS NULL THEN
            RETURN FALSE;
        END IF;
        RETURN INSTR(',' || UPPER(v_excluded_users) || ',',
                     ',' || UPPER(p_username) || ',') > 0;
    END is_user_excluded;

    FUNCTION get_hash_type(p_hash IN VARCHAR2) RETURN VARCHAR2 IS
    BEGIN
        IF p_hash IS NULL THEN
            RETURN 'NONE';
        ELSIF p_hash LIKE 'S:%' THEN
            RETURN 'SHA1';   -- Oracle 11g+ SHA-1 based
        ELSIF p_hash LIKE 'T:%' OR p_hash LIKE 'H:%' THEN
            RETURN 'SHA512'; -- Oracle 12c+ SHA-512 based
        ELSIF LENGTH(p_hash) = 30 THEN
            RETURN 'DES';    -- Oracle 10g and earlier DES-based
        ELSIF LENGTH(p_hash) = 16 AND REGEXP_LIKE(p_hash, '^[A-F0-9]+$') THEN
            RETURN 'DES';
        ELSE
            RETURN 'UNKNOWN';
        END IF;
    END get_hash_type;

    FUNCTION json_escape(p_str IN VARCHAR2) RETURN VARCHAR2 IS
    BEGIN
        IF p_str IS NULL THEN
            RETURN '';
        END IF;
        RETURN REPLACE(
                   REPLACE(
                       REPLACE(
                           REPLACE(
                               REPLACE(p_str, '\', '\\'),
                               '"', '\"'),
                           CHR(10), '\n'),
                       CHR(13), '\r'),
                   CHR(9), '\t');
    END json_escape;

    FUNCTION derive_hashcat_mode(p_hash_value IN VARCHAR2) RETURN VARCHAR2 IS
    BEGIN
        IF p_hash_value LIKE 'S:%' THEN
            RETURN '112';    -- Oracle 11g SHA1
        ELSIF p_hash_value LIKE 'T:%' OR p_hash_value LIKE 'H:%' THEN
            RETURN '12300';  -- Oracle 12c SHA512
        ELSIF LENGTH(p_hash_value) = 16 AND REGEXP_LIKE(p_hash_value, '^[A-F0-9]+$') THEN
            RETURN '3100';   -- Oracle 10g DES
        ELSE
            RETURN 'unknown';
        END IF;
    END derive_hashcat_mode;

    PROCEDURE log_message(
        p_level   IN VARCHAR2,
        p_module  IN VARCHAR2,
        p_message IN VARCHAR2,
        p_error_code    IN NUMBER DEFAULT NULL,
        p_error_message IN VARCHAR2 DEFAULT NULL
    ) IS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        INSERT INTO hashcat_log (
            log_id, log_level, module_name, message, error_code, error_message
        ) VALUES (
            hashcat_log_seq.NEXTVAL, p_level, p_module,
            SUBSTR(p_message, 1, 4000), p_error_code,
            SUBSTR(p_error_message, 1, 4000)
        );
        COMMIT;
    END log_message;

    -- ========================================================================
    -- Send all pending hashes for a user to the Hashcat API (batched payload)
    -- ========================================================================
    PROCEDURE send_user_hashes_to_server(
        p_username       IN VARCHAR2,
        p_account_status IN VARCHAR2
    ) IS
        v_url             VARCHAR2(4000);
        v_token           VARCHAR2(4000);
        v_source          VARCHAR2(100);
        v_db_name         VARCHAR2(100);
        v_timeout         NUMBER;
        v_request         UTL_HTTP.REQ;
        v_response        UTL_HTTP.RESP;
        v_response_text   CLOB;
        v_buffer          VARCHAR2(32767);
        v_payload         CLOB;
        v_export_id       VARCHAR2(32);
        v_timestamp       VARCHAR2(30);
        v_first_hash      BOOLEAN := TRUE;
        v_hash_count      NUMBER := 0;

        -- Cursor for all pending hashes for this user
        CURSOR c_user_hashes IS
            SELECT change_id, new_hash, hash_type
            FROM hashcat_hash_changes
            WHERE username = p_username
              AND sent_to_server = 'N'
              AND new_hash IS NOT NULL
            ORDER BY change_id;

        TYPE t_change_ids IS TABLE OF NUMBER INDEX BY PLS_INTEGER;
        v_change_ids t_change_ids;
        v_idx PLS_INTEGER := 0;
    BEGIN
        v_url     := get_config('HASHCAT_SERVER_URL');
        v_token   := get_config('HASHCAT_SERVER_TOKEN');
        v_source  := NVL(get_config('SOURCE_SYSTEM'), SYS_CONTEXT('USERENV', 'SERVER_HOST'));
        v_db_name := NVL(SYS_CONTEXT('USERENV', 'DB_NAME'), 'UNKNOWN');
        v_timeout := NVL(TO_NUMBER(get_config('HTTP_TIMEOUT')), 30);

        IF v_url IS NULL THEN
            log_message(c_log_error, 'SEND_HASH',
                       'HASHCAT_SERVER_URL not configured');
            RETURN;
        END IF;

        v_export_id := RAWTOHEX(SYS_GUID());
        v_timestamp := TO_CHAR(SYSTIMESTAMP, 'YYYY-MM-DD"T"HH24:MI:SS.FF3TZH:TZM');

        DBMS_LOB.CREATETEMPORARY(v_payload, TRUE);

        -- Build JSON header
        DBMS_LOB.APPEND(v_payload, '{');
        DBMS_LOB.APPEND(v_payload, '"export_id":"' || v_export_id || '",');
        DBMS_LOB.APPEND(v_payload, '"source_server":"' || json_escape(v_source) || '",');
        DBMS_LOB.APPEND(v_payload, '"source_database":"' || json_escape(v_db_name) || '",');
        DBMS_LOB.APPEND(v_payload, '"timestamp":"' || v_timestamp || '",');
        DBMS_LOB.APPEND(v_payload, '"hashes":[');

        -- Add all hashes for this user
        FOR rec IN c_user_hashes LOOP
            IF NOT v_first_hash THEN
                DBMS_LOB.APPEND(v_payload, ',');
            END IF;
            v_first_hash := FALSE;

            DBMS_LOB.APPEND(v_payload, '{');
            DBMS_LOB.APPEND(v_payload, '"username":"' || json_escape(p_username) || '",');
            DBMS_LOB.APPEND(v_payload, '"hash_value":"' || json_escape(rec.new_hash) || '",');
            DBMS_LOB.APPEND(v_payload, '"hash_type":"' || json_escape(rec.hash_type) || '",');
            DBMS_LOB.APPEND(v_payload, '"hashcat_mode":"' || json_escape(derive_hashcat_mode(rec.new_hash)) || '",');
            DBMS_LOB.APPEND(v_payload, '"server_name":"' || json_escape(v_source) || '",');
            DBMS_LOB.APPEND(v_payload, '"db_name":"' || json_escape(v_db_name) || '",');
            DBMS_LOB.APPEND(v_payload, '"password_versions":"",');
            DBMS_LOB.APPEND(v_payload, '"account_status":"' || json_escape(p_account_status) || '"');
            DBMS_LOB.APPEND(v_payload, '}');

            -- Track change IDs for update
            v_idx := v_idx + 1;
            v_change_ids(v_idx) := rec.change_id;
            v_hash_count := v_hash_count + 1;
        END LOOP;

        DBMS_LOB.APPEND(v_payload, ']}');

        -- Send HTTP request
        UTL_HTTP.SET_TRANSFER_TIMEOUT(v_timeout);
        v_request := UTL_HTTP.BEGIN_REQUEST(v_url, 'POST', 'HTTP/1.1');
        UTL_HTTP.SET_HEADER(v_request, 'Content-Type', 'application/json');
        UTL_HTTP.SET_HEADER(v_request, 'X-API-Key', v_token);
        UTL_HTTP.SET_HEADER(v_request, 'Content-Length', DBMS_LOB.GETLENGTH(v_payload));

        UTL_HTTP.WRITE_TEXT(v_request, v_payload);

        v_response := UTL_HTTP.GET_RESPONSE(v_request);

        v_response_text := EMPTY_CLOB();
        DBMS_LOB.CREATETEMPORARY(v_response_text, TRUE);

        BEGIN
            LOOP
                UTL_HTTP.READ_LINE(v_response, v_buffer, TRUE);
                DBMS_LOB.APPEND(v_response_text, v_buffer);
            END LOOP;
        EXCEPTION
            WHEN UTL_HTTP.END_OF_BODY THEN
                NULL;
        END;

        UTL_HTTP.END_RESPONSE(v_response);

        -- Update all change records for this user
        FOR i IN 1 .. v_change_ids.COUNT LOOP
            UPDATE hashcat_hash_changes
            SET sent_to_server = 'Y',
                send_date = SYSDATE,
                send_status = 'HTTP ' || v_response.status_code,
                http_response = SUBSTR(v_response_text, 1, 4000)
            WHERE change_id = v_change_ids(i);
        END LOOP;

        log_message(c_log_info, 'SEND_HASH',
                   'Sent ' || v_hash_count || ' hashes for user ' || p_username ||
                   ', HTTP status: ' || v_response.status_code);

        DBMS_LOB.FREETEMPORARY(v_payload);
        DBMS_LOB.FREETEMPORARY(v_response_text);

    EXCEPTION
        WHEN OTHERS THEN
            DECLARE
                v_error_msg VARCHAR2(4000) := SQLERRM;
                v_error_code NUMBER := SQLCODE;
            BEGIN
                -- Mark all as error
                UPDATE hashcat_hash_changes
                SET send_status = 'ERROR: ' || v_error_msg,
                    send_date = SYSDATE
                WHERE username = p_username
                  AND sent_to_server = 'N';

                log_message(c_log_error, 'SEND_HASH',
                           'Failed to send hashes for user ' || p_username,
                           v_error_code, v_error_msg);
            END;
    END send_user_hashes_to_server;

    -- ========================================================================
    -- Detect password hash changes using ptime (password change timestamp)
    -- ========================================================================
    PROCEDURE detect_hash_changes IS
        v_count       NUMBER := 0;
        v_last_ptime  DATE;
        v_exists      NUMBER;
    BEGIN
        log_message(c_log_info, 'DETECT_CHANGES', 'Starting hash change detection (ptime-based)');

        -- Iterate over all users with their password change time
        FOR rec IN (
            SELECT u.name AS username,
                   u.password AS password_hash,
                   u.spare4 AS spare4_hash,
                   u.ptime AS password_change_time,
                   du.account_status
            FROM sys.user$ u
            JOIN dba_users du ON u.name = du.username
            WHERE u.type# = 1
              AND u.name NOT LIKE '%$%'
        ) LOOP
            IF is_user_excluded(rec.username) THEN
                CONTINUE;
            END IF;

            -- Check if we have a record for this user
            SELECT COUNT(*), MAX(last_ptime)
            INTO v_exists, v_last_ptime
            FROM hashcat_user_state
            WHERE username = rec.username;

            -- New user or password changed (ptime is newer than last known)
            IF v_exists = 0 OR v_last_ptime IS NULL OR
               (rec.password_change_time IS NOT NULL AND rec.password_change_time > v_last_ptime) THEN

                -- Process all hashes for this user
                DECLARE
                    TYPE hash_rec IS RECORD (hash_value VARCHAR2(4000), hash_type VARCHAR2(50));
                    TYPE hash_tab IS TABLE OF hash_rec INDEX BY PLS_INTEGER;
                    TYPE hash_seen_tab IS TABLE OF BOOLEAN INDEX BY VARCHAR2(4000);

                    hashes      hash_tab;
                    seen_hashes hash_seen_tab;
                    idx         PLS_INTEGER := 0;

                    PROCEDURE add_hash(p_hash IN VARCHAR2) IS
                        v_hash VARCHAR2(4000);
                    BEGIN
                        IF p_hash IS NULL THEN
                            RETURN;
                        END IF;
                        IF p_hash LIKE 'H:%' THEN
                            v_hash := 'T:' || SUBSTR(p_hash, 3);
                        ELSE
                            v_hash := p_hash;
                        END IF;
                        IF seen_hashes.EXISTS(v_hash) THEN
                            RETURN;
                        END IF;
                        seen_hashes(v_hash) := TRUE;
                        idx := idx + 1;
                        hashes(idx).hash_value := v_hash;
                        hashes(idx).hash_type := get_hash_type(v_hash);
                    END;

                    PROCEDURE add_split_hashes(p_value IN VARCHAR2) IS
                        v_part VARCHAR2(4000);
                        n PLS_INTEGER := 1;
                    BEGIN
                        LOOP
                            v_part := REGEXP_SUBSTR(p_value, '[^;]+', 1, n);
                            EXIT WHEN v_part IS NULL;
                            add_hash(v_part);
                            n := n + 1;
                        END LOOP;
                    END;
                BEGIN
                    -- Extract all hash types from spare4 and password fields
                    add_split_hashes(rec.spare4_hash);
                    add_hash(rec.password_hash);

                    IF idx = 0 THEN
                        GOTO next_user;
                    END IF;

                    -- Insert change records for each hash type
                    FOR i IN 1 .. idx LOOP
                        INSERT INTO hashcat_hash_changes (
                            change_id, username, old_hash, new_hash,
                            hash_type, sent_to_server
                        ) VALUES (
                            hashcat_change_seq.NEXTVAL, rec.username, NULL,
                            hashes(i).hash_value, hashes(i).hash_type, 'N'
                        );
                    END LOOP;

                    v_count := v_count + 1;

                    IF v_exists = 0 THEN
                        log_message(c_log_info, 'DETECT_CHANGES',
                                   'New user detected: ' || rec.username);
                    ELSE
                        log_message(c_log_info, 'DETECT_CHANGES',
                                   'Password change detected for user: ' || rec.username ||
                                   ' (ptime: ' || TO_CHAR(rec.password_change_time, 'YYYY-MM-DD HH24:MI:SS') || ')');
                    END IF;
                END;

                -- Update or insert user state
                MERGE INTO hashcat_user_state s
                USING (SELECT rec.username AS username,
                              rec.password_change_time AS ptime FROM dual) src
                ON (s.username = src.username)
                WHEN MATCHED THEN
                    UPDATE SET last_ptime = src.ptime, last_checked = SYSDATE
                WHEN NOT MATCHED THEN
                    INSERT (username, last_ptime, last_checked, created_date)
                    VALUES (src.username, src.ptime, SYSDATE, SYSDATE);

            ELSE
                -- No change, just update last_checked
                UPDATE hashcat_user_state
                SET last_checked = SYSDATE
                WHERE username = rec.username;
            END IF;

            <<next_user>>
            NULL;
        END LOOP;

        COMMIT;
        log_message(c_log_info, 'DETECT_CHANGES',
                   'Hash change detection completed. Users with changes: ' || v_count);

    EXCEPTION
        WHEN OTHERS THEN
            ROLLBACK;
            log_message(c_log_error, 'DETECT_CHANGES',
                       'Error detecting hash changes', SQLCODE, SQLERRM);
            RAISE;
    END detect_hash_changes;

    -- ========================================================================
    -- Send pending hashes to hashcat server (grouped by user)
    -- ========================================================================
    PROCEDURE send_pending_hashes IS
        v_user_count NUMBER := 0;
        v_hash_count NUMBER := 0;
    BEGIN
        log_message(c_log_info, 'SEND_PENDING', 'Starting to send pending hashes');

        IF get_config('ENABLED') != 'Y' THEN
            log_message(c_log_info, 'SEND_PENDING', 'Monitoring is disabled');
            RETURN;
        END IF;

        -- Group by username and send all hashes for each user in one request
        FOR rec IN (
            SELECT h.username,
                   du.account_status,
                   COUNT(*) AS hash_count
            FROM hashcat_hash_changes h
            LEFT JOIN dba_users du
                ON du.username = h.username
            WHERE h.sent_to_server = 'N'
              AND h.new_hash IS NOT NULL
            GROUP BY h.username, du.account_status
            ORDER BY MIN(h.change_date)
        ) LOOP
            send_user_hashes_to_server(
                p_username       => rec.username,
                p_account_status => rec.account_status
            );
            v_user_count := v_user_count + 1;
            v_hash_count := v_hash_count + rec.hash_count;
            COMMIT;
        END LOOP;

        log_message(c_log_info, 'SEND_PENDING',
                   'Finished sending hashes. Users: ' || v_user_count ||
                   ', Total hashes: ' || v_hash_count);

    EXCEPTION
        WHEN OTHERS THEN
            log_message(c_log_error, 'SEND_PENDING',
                       'Error sending pending hashes', SQLCODE, SQLERRM);
            RAISE;
    END send_pending_hashes;

    -- ========================================================================
    -- Main monitor procedure (called by scheduler)
    -- ========================================================================
    PROCEDURE run_monitor IS
    BEGIN
        log_message(c_log_info, 'RUN_MONITOR',
                   'Starting hashcat monitor v' || c_version);

        IF get_config('ENABLED') != 'Y' THEN
            log_message(c_log_info, 'RUN_MONITOR', 'Monitoring is disabled');
            RETURN;
        END IF;

        detect_hash_changes;
        send_pending_hashes;

        log_message(c_log_info, 'RUN_MONITOR', 'Monitor run completed successfully');

    EXCEPTION
        WHEN OTHERS THEN
            log_message(c_log_error, 'RUN_MONITOR',
                       'Monitor run failed', SQLCODE, SQLERRM);
    END run_monitor;

    -- ========================================================================
    -- Cleanup old log entries
    -- ========================================================================
    PROCEDURE cleanup_old_logs(p_days_to_keep IN NUMBER DEFAULT 90) IS
        v_deleted NUMBER;
    BEGIN
        DELETE FROM hashcat_log
        WHERE log_date < SYSTIMESTAMP - p_days_to_keep;
        v_deleted := SQL%ROWCOUNT;

        DELETE FROM hashcat_hash_changes
        WHERE change_date < SYSDATE - p_days_to_keep
          AND sent_to_server = 'Y';
        v_deleted := v_deleted + SQL%ROWCOUNT;

        COMMIT;

        log_message(c_log_info, 'CLEANUP',
                   'Cleanup completed. Deleted ' || v_deleted || ' old records');
    EXCEPTION
        WHEN OTHERS THEN
            ROLLBACK;
            log_message(c_log_error, 'CLEANUP',
                       'Cleanup failed', SQLCODE, SQLERRM);
    END cleanup_old_logs;

END hashcat_monitor_pkg;
/

SHOW ERRORS PACKAGE hashcat_monitor_pkg;
SHOW ERRORS PACKAGE BODY hashcat_monitor_pkg;

PROMPT Package HASHCAT_MONITOR_PKG created successfully
