-- ============================================================================
-- Helper Views for Monitoring
-- Run as HASHCAT_MONITOR user
-- ============================================================================

-- View: Recent hash changes
CREATE OR REPLACE VIEW v_hashcat_recent_changes AS
SELECT
    hc.change_id,
    hc.username,
    hc.hash_type,
    hc.change_date,
    hc.sent_to_server,
    hc.send_date,
    hc.send_status
FROM hashcat_hash_changes hc
WHERE hc.change_date > SYSDATE - 7
ORDER BY hc.change_date DESC;

-- View: Current user status (based on ptime tracking)
CREATE OR REPLACE VIEW v_hashcat_user_status AS
SELECT
    us.username,
    du.account_status,
    us.created_date AS first_seen,
    us.last_ptime AS last_password_change,
    us.last_checked,
    (SELECT COUNT(*) FROM hashcat_hash_changes hc
     WHERE hc.username = us.username) AS total_changes
FROM hashcat_user_state us
LEFT JOIN dba_users du ON du.username = us.username
ORDER BY us.last_checked DESC;

-- View: Pending hashes to send
CREATE OR REPLACE VIEW v_hashcat_pending AS
SELECT
    change_id,
    username,
    hash_type,
    change_date
FROM hashcat_hash_changes
WHERE sent_to_server = 'N'
ORDER BY change_date;

-- View: Recent log entries
CREATE OR REPLACE VIEW v_hashcat_logs AS
SELECT
    log_id,
    log_date,
    log_level,
    module_name,
    message,
    error_code,
    error_message
FROM hashcat_log
WHERE log_date > SYSTIMESTAMP - INTERVAL '1' DAY
ORDER BY log_date DESC;

-- View: Job status summary
CREATE OR REPLACE VIEW v_hashcat_job_status AS
SELECT
    job_name,
    state,
    enabled,
    last_start_date,
    last_run_duration,
    next_run_date,
    run_count,
    failure_count
FROM user_scheduler_jobs
WHERE job_name LIKE 'HASHCAT%';

-- View: Statistics summary
CREATE OR REPLACE VIEW v_hashcat_stats AS
SELECT
    'Total Users Monitored' AS metric,
    TO_CHAR(COUNT(*)) AS value
FROM hashcat_user_state
UNION ALL
SELECT
    'Total Hash Changes' AS metric,
    TO_CHAR(COUNT(*)) AS value
FROM hashcat_hash_changes
UNION ALL
SELECT
    'Pending to Send' AS metric,
    TO_CHAR(COUNT(*)) AS value
FROM hashcat_hash_changes
WHERE sent_to_server = 'N'
UNION ALL
SELECT
    'Successfully Sent' AS metric,
    TO_CHAR(COUNT(*)) AS value
FROM hashcat_hash_changes
WHERE sent_to_server = 'Y'
UNION ALL
SELECT
    'Changes Today' AS metric,
    TO_CHAR(COUNT(*)) AS value
FROM hashcat_hash_changes
WHERE change_date > TRUNC(SYSDATE);

PROMPT Helper views created successfully
PROMPT
PROMPT Available views:
PROMPT   - v_hashcat_recent_changes  : Recent password changes (last 7 days)
PROMPT   - v_hashcat_user_status     : Current status of all monitored users
PROMPT   - v_hashcat_pending         : Hashes waiting to be sent
PROMPT   - v_hashcat_logs            : Recent log entries (last 24 hours)
PROMPT   - v_hashcat_job_status      : Scheduler job status
PROMPT   - v_hashcat_stats           : Quick statistics summary
