# Oracle Password Hash Monitoring - Installation Guide

## Overview

This directory contains scripts for monitoring and exporting Oracle password hashes to the hashcat server for password strength testing.

**Hashcat Server:** `t2ru-hashcat-t-01:8443`

## Two Approaches Available

### Approach 1: Change Monitoring (Recommended)
Monitors password changes and sends only changed hashes to hashcat server.

**Scripts:** `01_create_user.sql` through `05_helper_views.sql`

**Features:**
- Detects password changes by comparing snapshots
- Sends only new/changed hashes (reduces load)
- Maintains history of all changes
- Configurable excluded users
- Built-in logging and cleanup

### Approach 2: Bulk Export
Exports all password hashes on schedule.

**Scripts:** `hash_export_pkg.sql` or `hash_export_encrypted_pkg.sql`

**Features:**
- Full export of all hashes
- Optional GPG encryption
- Simpler setup

---

## Installation: Change Monitoring (Approach 1)

### Prerequisites
- Oracle 11g or higher
- SYSDBA access for user creation
- Network access to hashcat server

### Step 1: Create Monitoring User (as SYSDBA)

```sql
sqlplus / as sysdba

-- Review and run user creation script
@01_create_user.sql
```

This creates:
- User `HASHCAT_MONITOR` with password `ChangeMe123!`
- Grants: `SELECT ON sys.user$`, `UTL_HTTP`, `CREATE JOB`
- Network ACL for hashcat server

**Important:** Change the password after installation!

```sql
ALTER USER HASHCAT_MONITOR IDENTIFIED BY "YourSecurePassword";
```

### Step 2: Install Objects (as HASHCAT_MONITOR)

```sql
sqlplus hashcat_monitor/ChangeMe123!

-- Run master installation script
@install_all.sql
```

Or run scripts individually:
```sql
@02_create_objects.sql    -- Tables, sequences, config
@03_create_package.sql    -- PL/SQL monitoring package
@04_create_scheduler_job.sql  -- Scheduler jobs
@05_helper_views.sql      -- Helper views
```

### Step 3: Configure Settings

```sql
-- View current configuration
SELECT config_key, config_value FROM hashcat_config;

-- Update API token (get from hashcat server admin)
UPDATE hashcat_config
SET config_value = 'your-actual-api-token'
WHERE config_key = 'HASHCAT_SERVER_TOKEN';

-- Set source system identifier
UPDATE hashcat_config
SET config_value = 'PROD_DB_01'
WHERE config_key = 'SOURCE_SYSTEM';

-- Add users to exclude (comma-separated)
UPDATE hashcat_config
SET config_value = 'SYS,SYSTEM,HASHCAT_MONITOR,DBSNMP,OUTLN'
WHERE config_key = 'EXCLUDED_USERS';

COMMIT;
```

### Step 4: Test Manually

```sql
-- Run monitor manually
EXEC hashcat_monitor_pkg.run_monitor;

-- Check results
SELECT * FROM v_hashcat_stats;
SELECT * FROM v_hashcat_logs;
SELECT * FROM v_hashcat_pending;
```

### Step 5: Enable Scheduled Jobs

```sql
-- Enable monitor job (runs every 5 minutes)
EXEC DBMS_SCHEDULER.ENABLE('HASHCAT_MONITOR_JOB');

-- Enable cleanup job (runs daily at 2 AM)
EXEC DBMS_SCHEDULER.ENABLE('HASHCAT_CLEANUP_JOB');

-- Verify jobs are enabled
SELECT job_name, state, next_run_date FROM user_scheduler_jobs;
```

---

## Installation: Bulk Export (Approach 2)

### Basic Export (No Encryption)

```sql
sqlplus / as sysdba

-- Create ACL and job
@setup_acl_and_job.sql

-- Install package
@hash_export_pkg.sql

-- Test
EXEC hash_export_pkg.export_hashes;
```

### Encrypted Export (GPG)

```sql
sqlplus / as sysdba

-- Install encrypted package
@hash_export_encrypted_pkg.sql

-- Setup ACL, directories, scheduler
@setup_encrypted_export.sql
```

---

## Monitoring and Troubleshooting

### Check Job Status
```sql
SELECT job_name, state, last_start_date, next_run_date, failure_count
FROM user_scheduler_jobs
WHERE job_name LIKE 'HASHCAT%';
```

### View Recent Logs
```sql
SELECT * FROM v_hashcat_logs ORDER BY log_date DESC;
```

### View Pending Hashes
```sql
SELECT * FROM v_hashcat_pending;
```

### View Statistics
```sql
SELECT * FROM v_hashcat_stats;
```

### Manually Retry Failed Sends
```sql
EXEC hashcat_monitor_pkg.send_pending_hashes;
```

### Disable Monitoring
```sql
-- Disable jobs
EXEC DBMS_SCHEDULER.DISABLE('HASHCAT_MONITOR_JOB');
EXEC DBMS_SCHEDULER.DISABLE('HASHCAT_CLEANUP_JOB');

-- Or set config flag
UPDATE hashcat_config SET config_value = 'N' WHERE config_key = 'ENABLED';
COMMIT;
```

---

## Uninstallation

```sql
-- Connect as HASHCAT_MONITOR
@uninstall.sql

-- Then as SYSDBA to drop user
DROP USER HASHCAT_MONITOR CASCADE;
```

---

## File Reference

| File | Description |
|------|-------------|
| `01_create_user.sql` | Creates HASHCAT_MONITOR user with grants |
| `02_create_objects.sql` | Tables, sequences, default config |
| `03_create_package.sql` | Main monitoring PL/SQL package |
| `04_create_scheduler_job.sql` | Scheduler job definitions |
| `05_helper_views.sql` | Convenience views for monitoring |
| `install_all.sql` | Master script (runs 02-05) |
| `uninstall.sql` | Removes all objects |
| `hash_export_pkg.sql` | Bulk export package (basic) |
| `hash_export_encrypted_pkg.sql` | Bulk export with GPG |
| `setup_acl_and_job.sql` | ACL/job for basic export |
| `setup_encrypted_export.sql` | Setup for encrypted export |

---

## Configuration Reference

| Config Key | Default | Description |
|------------|---------|-------------|
| `HASHCAT_SERVER_URL` | `http://t2ru-hashcat-t-01:8443/api/v1/hashes` | API endpoint |
| `HASHCAT_SERVER_TOKEN` | `your-api-token-here` | API authentication token |
| `SOURCE_SYSTEM` | `ORACLE_PROD` | Identifier for this database |
| `ENABLED` | `Y` | Enable/disable monitoring |
| `EXCLUDED_USERS` | `SYS,SYSTEM,HASHCAT_MONITOR` | Users to skip |
| `HTTP_TIMEOUT` | `30` | HTTP timeout in seconds |
