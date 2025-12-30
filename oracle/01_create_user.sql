--  ============================================================================
-- Oracle Password Hash Monitoring User Setup
-- Creates HASHCAT_MONITOR user with necessary privileges
-- Run as SYSDBA
--  ============================================================================

-- Configuration variables (adjust as needed)
DEFINE monitor_user = 'HASHCAT_MONITOR'
DEFINE monitor_password = 'ChangeMe123!'
DEFINE default_tablespace = 'USERS'
DEFINE temp_tablespace = 'TEMP'

-- Drop user if exists (uncomment if needed)
-- DROP USER &monitor_user CASCADE;

-- Create monitoring user
CREATE USER &monitor_user
    IDENTIFIED BY "&monitor_password"
    DEFAULT TABLESPACE &default_tablespace
    TEMPORARY TABLESPACE &temp_tablespace
    QUOTA UNLIMITED ON &default_tablespace;

-- Basic session privileges
GRANT CREATE SESSION TO &monitor_user;
GRANT CREATE TABLE TO &monitor_user;
GRANT CREATE SEQUENCE TO &monitor_user;
GRANT CREATE PROCEDURE TO &monitor_user;
GRANT CREATE JOB TO &monitor_user;

-- Required for reading password hashes from sys.user$
GRANT SELECT ON sys.user$ TO &monitor_user;
GRANT SELECT ON dba_users TO &monitor_user;

-- Required for UTL_HTTP to send data to hashcat server
GRANT EXECUTE ON UTL_HTTP TO &monitor_user;
GRANT EXECUTE ON UTL_ENCODE TO &monitor_user;

-- Required for DBMS_SCHEDULER
GRANT CREATE JOB TO &monitor_user;
GRANT MANAGE SCHEDULER TO &monitor_user;

-- Required for network access (12c+)
-- Create ACL for hashcat server communication
BEGIN
    DBMS_NETWORK_ACL_ADMIN.CREATE_ACL(
        acl         => 'hashcat_server.xml',
        description => 'ACL for Hashcat Server Communication',
        principal   => '&monitor_user',
        is_grant    => TRUE,
        privilege   => 'connect'
    );

    DBMS_NETWORK_ACL_ADMIN.ADD_PRIVILEGE(
        acl       => 'hashcat_server.xml',
        principal => '&monitor_user',
        is_grant  => TRUE,
        privilege => 'resolve'
    );

    -- Assign ACL to hashcat server host (adjust IP/hostname as needed)
    DBMS_NETWORK_ACL_ADMIN.ASSIGN_ACL(
        acl  => 'hashcat_server.xml',
        host => '192.168.64.7',
        lower_port => 80,
        upper_port => 8443
    );

    COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        -- ACL may already exist in 12c+ with APPEND_HOST_ACE
        NULL;
END;
/

-- For Oracle 12c and later, use APPEND_HOST_ACE instead
BEGIN
    DBMS_NETWORK_ACL_ADMIN.APPEND_HOST_ACE(
        host       => '192.168.64.7',
        lower_port => 80,
        upper_port => 8443,
        ace        => xs$ace_type(
            privilege_list => xs$name_list('http'),
            principal_name => '&monitor_user',
            principal_type => xs_acl.ptype_db
        )
    );
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Note: ACL configuration may need manual adjustment for your Oracle version');
END;
/

PROMPT User &monitor_user created successfully
PROMPT Remember to change the default password!
