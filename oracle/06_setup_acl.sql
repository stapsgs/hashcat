-- ============================================================================
-- Oracle 12.1 Network ACL Setup for Hashcat Monitor
-- Run as SYSDBA
-- ============================================================================

SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT ============================================================
PROMPT Network ACL Configuration for HASHCAT_MONITOR
PROMPT ============================================================

-- ============================================================================
-- STEP 1: Check existing ACLs
-- ============================================================================
PROMPT
PROMPT Step 1: Checking existing ACLs...

SELECT host, lower_port, upper_port, acl
FROM dba_host_acls
WHERE host IN ('192.168.64.7', 't2ru-hashcat-t-01', '*');

SELECT host, ace_order, principal, privilege, grant_type
FROM dba_host_aces
WHERE host IN ('192.168.64.7', 't2ru-hashcat-t-01', '*')
ORDER BY host, ace_order;

-- ============================================================================
-- STEP 2: Remove old ACL for 192.168.64.7
-- ============================================================================
PROMPT
PROMPT Step 2: Removing old ACL for 192.168.64.7...

BEGIN
    -- Remove all ACEs for old host
    DBMS_NETWORK_ACL_ADMIN.REMOVE_HOST_ACE(
        host       => '192.168.64.7',
        lower_port => NULL,
        upper_port => NULL,
        ace        => xs$ace_type(
            privilege_list => xs$name_list('connect', 'resolve'),
            principal_name => 'HASHCAT_MONITOR',
            principal_type => xs_acl.ptype_db
        ),
        remove_empty_acl => TRUE
    );
    DBMS_OUTPUT.PUT_LINE('Removed ACL for 192.168.64.7');
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Note: ' || SQLERRM);
END;
/

-- Try removing with specific ports too
BEGIN
    DBMS_NETWORK_ACL_ADMIN.REMOVE_HOST_ACE(
        host       => '192.168.64.7',
        lower_port => 80,
        upper_port => 8443,
        ace        => xs$ace_type(
            privilege_list => xs$name_list('connect', 'resolve'),
            principal_name => 'HASHCAT_MONITOR',
            principal_type => xs_acl.ptype_db
        ),
        remove_empty_acl => TRUE
    );
    DBMS_OUTPUT.PUT_LINE('Removed port-specific ACL for 192.168.64.7');
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Note: ' || SQLERRM);
END;
/

-- ============================================================================
-- STEP 3: Create new ACL for t2ru-hashcat-t-01
-- ============================================================================
PROMPT
PROMPT Step 3: Creating ACL for t2ru-hashcat-t-01...

BEGIN
    DBMS_NETWORK_ACL_ADMIN.APPEND_HOST_ACE(
        host       => 't2ru-hashcat-t-01',
        lower_port => 8443,
        upper_port => 8443,
        ace        => xs$ace_type(
            privilege_list => xs$name_list('connect', 'resolve'),
            principal_name => 'HASHCAT_MONITOR',
            principal_type => xs_acl.ptype_db
        )
    );
    DBMS_OUTPUT.PUT_LINE('Created ACL for t2ru-hashcat-t-01:8443');
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE = -24244 THEN
            DBMS_OUTPUT.PUT_LINE('ACL already exists for this host/port');
        ELSE
            RAISE;
        END IF;
END;
/

-- ============================================================================
-- STEP 4: Verify new configuration
-- ============================================================================
PROMPT
PROMPT Step 4: Verifying new ACL configuration...

PROMPT
PROMPT Current Host ACLs:
SELECT host, lower_port, upper_port, acl
FROM dba_host_acls
WHERE host = 't2ru-hashcat-t-01';

PROMPT
PROMPT Current Host ACEs:
SELECT host, ace_order, principal, privilege, grant_type
FROM dba_host_aces
WHERE host = 't2ru-hashcat-t-01'
ORDER BY ace_order;

-- ============================================================================
-- STEP 5: Test connectivity (run as HASHCAT_MONITOR)
-- ============================================================================
PROMPT
PROMPT ============================================================
PROMPT ACL Setup Complete!
PROMPT ============================================================
PROMPT
PROMPT To test connectivity, connect as HASHCAT_MONITOR and run:
PROMPT
PROMPT   SET SERVEROUTPUT ON
PROMPT   DECLARE
PROMPT       v_req  UTL_HTTP.REQ;
PROMPT       v_resp UTL_HTTP.RESP;
PROMPT   BEGIN
PROMPT       v_req := UTL_HTTP.BEGIN_REQUEST('http://t2ru-hashcat-t-01:8443/health');
PROMPT       v_resp := UTL_HTTP.GET_RESPONSE(v_req);
PROMPT       DBMS_OUTPUT.PUT_LINE('Success! Status: ' || v_resp.status_code);
PROMPT       UTL_HTTP.END_RESPONSE(v_resp);
PROMPT   END;
PROMPT   /
PROMPT
PROMPT ============================================================
