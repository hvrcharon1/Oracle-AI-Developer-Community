-- =============================================================================
-- Example VPD Policy: IAM Role-Based Row-Level Security
-- Purpose : Control row visibility using OCI IAM Application Roles
--           surfaced in CLIENTCONTEXT.IAM_DOMAIN_APP_ROLES.
-- Rules   : DB_ADMIN role  -> all rows
--           DATA_ANALYST   -> rows for EMEA region only
--           Default        -> deny all (1=0)
-- Author  : Inspired by Jeff Smith (@thatjeffsmith)
--           https://www.thatjeffsmith.com/archive/2026/05/who-is-using-your-oracle-data-ai-and-how-to-secure-it/
-- =============================================================================

CREATE OR REPLACE FUNCTION <SCHEMA>.sales_role_policy (
  p_schema IN VARCHAR2,
  p_object IN VARCHAR2
) RETURN VARCHAR2 AS
  v_roles VARCHAR2(4000) := SYS_CONTEXT('CLIENTCONTEXT', 'IAM_DOMAIN_APP_ROLES');
BEGIN
  -- Full access for administrators
  IF INSTR(v_roles, 'DB_ADMIN') > 0 THEN
    RETURN NULL;
  END IF;

  -- EMEA-scoped access for analysts
  IF INSTR(v_roles, 'DATA_ANALYST') > 0 THEN
    RETURN 'region = ''EMEA''';
  END IF;

  -- Deny all for unrecognised roles or absent context
  RETURN '1=0';
END sales_role_policy;
/

BEGIN
  DBMS_RLS.ADD_POLICY(
    object_schema   => '<SCHEMA>',
    object_name     => 'SALES',
    policy_name     => 'SALES_ROLE_VISIBILITY',
    function_schema => '<SCHEMA>',
    policy_function => 'SALES_ROLE_POLICY',
    statement_types => 'SELECT, UPDATE, DELETE',
    update_check    => TRUE,
    policy_type     => DBMS_RLS.DYNAMIC,
    enable          => TRUE
  );
END;
/
