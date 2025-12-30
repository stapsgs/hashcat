-- ============================================================================
-- Helper Views for Monitoring
-- Run as HASHCAT_MONITOR user
-- ============================================================================

-- View: Current user status (based on ptime tracking)
CREATE OR REPLACE VIEW v_hashcat_user_status AS
SELECT
    us.username,
    du.account_status,
    us.created_date AS first_seen,
    us.last_ptime AS last_password_change,
    us.last_checked
FROM hashcat_user_state us
LEFT JOIN dba_users du ON du.username = us.username
ORDER BY us.last_checked DESC;

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
    'Users Checked Today' AS metric,
    TO_CHAR(COUNT(*)) AS value
FROM hashcat_user_state
WHERE last_checked > TRUNC(SYSDATE)
UNION ALL
SELECT
    'Log Entries (24h)' AS metric,
    TO_CHAR(COUNT(*)) AS value
FROM hashcat_log
WHERE log_date > SYSTIMESTAMP - INTERVAL '1' DAY
UNION ALL
SELECT
    'Errors (24h)' AS metric,
    TO_CHAR(COUNT(*)) AS value
FROM hashcat_log
WHERE log_date > SYSTIMESTAMP - INTERVAL '1' DAY
  AND log_level = 'ERROR';

PROMPT Helper views created successfully
PROMPT
PROMPT Available views:
PROMPT   - v_hashcat_user_status  : Current status of all monitored users
PROMPT   - v_hashcat_logs         : Recent log entries (last 24 hours)
PROMPT   - v_hashcat_job_status   : Scheduler job status
PROMPT   - v_hashcat_stats        : Quick statistics summary
