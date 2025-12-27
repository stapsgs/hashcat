-- ============================================================================
-- Oracle Scheduler Job Configuration
-- Creates scheduled job for running hash monitor
-- Run as HASHCAT_MONITOR user
-- ============================================================================

-- Drop existing job if present
BEGIN
    DBMS_SCHEDULER.DROP_JOB(job_name => 'HASHCAT_MONITOR_JOB', force => TRUE);
EXCEPTION
    WHEN OTHERS THEN NULL;
END;
/

-- Drop existing cleanup job if present
BEGIN
    DBMS_SCHEDULER.DROP_JOB(job_name => 'HASHCAT_CLEANUP_JOB', force => TRUE);
EXCEPTION
    WHEN OTHERS THEN NULL;
END;
/

-- ============================================================================
-- Main monitoring job - runs every 5 minutes
-- ============================================================================
BEGIN
    DBMS_SCHEDULER.CREATE_JOB(
        job_name        => 'HASHCAT_MONITOR_JOB',
        job_type        => 'PLSQL_BLOCK',
        job_action      => 'BEGIN hashcat_monitor_pkg.run_monitor; END;',
        start_date      => SYSTIMESTAMP,
        repeat_interval => 'FREQ=MINUTELY; INTERVAL=5',
        end_date        => NULL,
        enabled         => FALSE,
        auto_drop       => FALSE,
        comments        => 'Monitors password hash changes and sends to hashcat server'
    );

    -- Set job attributes
    DBMS_SCHEDULER.SET_ATTRIBUTE(
        name      => 'HASHCAT_MONITOR_JOB',
        attribute => 'MAX_FAILURES',
        value     => 5
    );

    DBMS_SCHEDULER.SET_ATTRIBUTE(
        name      => 'HASHCAT_MONITOR_JOB',
        attribute => 'MAX_RUN_DURATION',
        value     => INTERVAL '10' MINUTE
    );

    DBMS_SCHEDULER.SET_ATTRIBUTE(
        name      => 'HASHCAT_MONITOR_JOB',
        attribute => 'RESTART_ON_FAILURE',
        value     => FALSE
    );

    DBMS_OUTPUT.PUT_LINE('Monitor job created successfully');
END;
/

-- ============================================================================
-- Cleanup job - runs daily at 2 AM
-- ============================================================================
BEGIN
    DBMS_SCHEDULER.CREATE_JOB(
        job_name        => 'HASHCAT_CLEANUP_JOB',
        job_type        => 'PLSQL_BLOCK',
        job_action      => 'BEGIN hashcat_monitor_pkg.cleanup_old_logs(90); END;',
        start_date      => TRUNC(SYSTIMESTAMP) + INTERVAL '2' HOUR,
        repeat_interval => 'FREQ=DAILY; BYHOUR=2; BYMINUTE=0',
        end_date        => NULL,
        enabled         => FALSE,
        auto_drop       => FALSE,
        comments        => 'Cleans up old log entries (90 days retention)'
    );

    DBMS_OUTPUT.PUT_LINE('Cleanup job created successfully');
END;
/

-- ============================================================================
-- Job management procedures
-- ============================================================================

PROMPT
PROMPT =========================================================
PROMPT Jobs created but NOT enabled. Use these commands to manage:
PROMPT =========================================================
PROMPT
PROMPT -- Enable monitor job (runs every 5 minutes):
PROMPT EXEC DBMS_SCHEDULER.ENABLE('HASHCAT_MONITOR_JOB');
PROMPT
PROMPT -- Disable monitor job:
PROMPT EXEC DBMS_SCHEDULER.DISABLE('HASHCAT_MONITOR_JOB');
PROMPT
PROMPT -- Enable cleanup job (runs daily):
PROMPT EXEC DBMS_SCHEDULER.ENABLE('HASHCAT_CLEANUP_JOB');
PROMPT
PROMPT -- Run monitor manually:
PROMPT EXEC hashcat_monitor_pkg.run_monitor;
PROMPT
PROMPT -- Check job status:
PROMPT SELECT job_name, state, last_start_date, next_run_date
PROMPT FROM user_scheduler_jobs;
PROMPT
PROMPT -- View job run history:
PROMPT SELECT job_name, status, actual_start_date, run_duration
PROMPT FROM user_scheduler_job_run_details
PROMPT ORDER BY actual_start_date DESC;
PROMPT
PROMPT =========================================================
