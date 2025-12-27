-- ============================================================================
-- Uninstall Script for Oracle Password Hash Monitor
-- Run as HASHCAT_MONITOR user (objects) or SYSDBA (user drop)
-- ============================================================================

SET SERVEROUTPUT ON

PROMPT ============================================================
PROMPT Oracle Password Hash Monitor - Uninstallation
PROMPT ============================================================

-- Stop and drop scheduler jobs
PROMPT Dropping scheduler jobs...
BEGIN
    DBMS_SCHEDULER.STOP_JOB(job_name => 'HASHCAT_MONITOR_JOB', force => TRUE);
EXCEPTION WHEN OTHERS THEN NULL;
END;
/

BEGIN
    DBMS_SCHEDULER.DROP_JOB(job_name => 'HASHCAT_MONITOR_JOB', force => TRUE);
EXCEPTION WHEN OTHERS THEN NULL;
END;
/

BEGIN
    DBMS_SCHEDULER.STOP_JOB(job_name => 'HASHCAT_CLEANUP_JOB', force => TRUE);
EXCEPTION WHEN OTHERS THEN NULL;
END;
/

BEGIN
    DBMS_SCHEDULER.DROP_JOB(job_name => 'HASHCAT_CLEANUP_JOB', force => TRUE);
EXCEPTION WHEN OTHERS THEN NULL;
END;
/

-- Drop views
PROMPT Dropping views...
DROP VIEW v_hashcat_stats;
DROP VIEW v_hashcat_job_status;
DROP VIEW v_hashcat_logs;
DROP VIEW v_hashcat_pending;
DROP VIEW v_hashcat_user_status;
DROP VIEW v_hashcat_recent_changes;

-- Drop package
PROMPT Dropping package...
DROP PACKAGE hashcat_monitor_pkg;

-- Drop tables
PROMPT Dropping tables...
DROP TABLE hashcat_log;
DROP TABLE hashcat_hash_changes;
DROP TABLE hashcat_user_state;
DROP TABLE hashcat_config;

-- Drop sequences
PROMPT Dropping sequences...
DROP SEQUENCE hashcat_log_seq;
DROP SEQUENCE hashcat_change_seq;

PROMPT ============================================================
PROMPT Objects removed successfully.
PROMPT
PROMPT To completely remove the user, run as SYSDBA:
PROMPT   DROP USER HASHCAT_MONITOR CASCADE;
PROMPT
PROMPT To remove the ACL, run as SYSDBA:
PROMPT   EXEC DBMS_NETWORK_ACL_ADMIN.DROP_ACL('hashcat_server.xml');
PROMPT ============================================================
