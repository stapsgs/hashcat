-- ============================================================================
-- Master Installation Script for Oracle Password Hash Monitor
-- ============================================================================
--
-- USAGE:
-- 1. First, run 01_create_user.sql as SYSDBA to create the user
-- 2. Then, connect as HASHCAT_MONITOR and run this script
--
-- Example:
--   sqlplus / as sysdba @01_create_user.sql
--   sqlplus hashcat_monitor/YourPassword @install_all.sql
--
-- ============================================================================

SET ECHO ON
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT ============================================================
PROMPT Oracle Password Hash Monitor - Installation
PROMPT ============================================================

PROMPT
PROMPT Step 1: Creating tables and sequences...
@@02_create_objects.sql

PROMPT
PROMPT Step 2: Creating PL/SQL package...
@@03_create_package.sql

PROMPT
PROMPT Step 3: Creating scheduler jobs...
@@04_create_scheduler_job.sql

PROMPT
PROMPT Step 4: Creating helper views...
@@05_helper_views.sql

PROMPT
PROMPT ============================================================
PROMPT Installation completed successfully!
PROMPT ============================================================
PROMPT
PROMPT IMPORTANT: Before enabling the jobs, configure these settings:
PROMPT
PROMPT 1. Update the hashcat server URL:
PROMPT    UPDATE hashcat_config SET config_value = 'http://your-server:8080/api/hashes'
PROMPT    WHERE config_key = 'HASHCAT_SERVER_URL';
PROMPT
PROMPT 2. Set the API token:
PROMPT    UPDATE hashcat_config SET config_value = 'your-actual-token'
PROMPT    WHERE config_key = 'HASHCAT_SERVER_TOKEN';
PROMPT
PROMPT 3. Set the source system name:
PROMPT    UPDATE hashcat_config SET config_value = 'YOUR_DB_NAME'
PROMPT    WHERE config_key = 'SOURCE_SYSTEM';
PROMPT
PROMPT 4. Add any users to exclude:
PROMPT    UPDATE hashcat_config SET config_value = 'SYS,SYSTEM,HASHCAT_MONITOR,USER1'
PROMPT    WHERE config_key = 'EXCLUDED_USERS';
PROMPT
PROMPT 5. Enable monitoring:
PROMPT    COMMIT;
PROMPT    EXEC DBMS_SCHEDULER.ENABLE('HASHCAT_MONITOR_JOB');
PROMPT    EXEC DBMS_SCHEDULER.ENABLE('HASHCAT_CLEANUP_JOB');
PROMPT
PROMPT 6. Test manually:
PROMPT    EXEC hashcat_monitor_pkg.run_monitor;
PROMPT    SELECT * FROM v_hashcat_stats;
PROMPT    SELECT * FROM v_hashcat_logs;
PROMPT ============================================================
