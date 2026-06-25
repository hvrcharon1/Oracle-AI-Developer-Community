-- =============================================================================
-- Example VPD Policy: Email-Domain-Based Row-Level Security
-- Purpose : Restrict customer data visibility based on the authenticated
--           user's email domain (read from CLIENTCONTEXT.OAUTH_SUB).
-- Rule    : Internal users (@mycompany.com) see all rows.
--           All other identities (external, partner, unidentified)
--           see only rows where the customer has opted into SMS contact.
-- Requires: A CUSTOMERS table with a JSON column named CONTACT_PREFERENCES,
--           e.g. {"sms": true, "email": false}
-- Author  : Derived from Jeff Smith (@thatjeffsmith)
--           https://www.thatjeffsmith.com/archive/2026/05/who-is-using-your-oracle-data-ai-and-how-to-secure-it/
-- =============================================================================

-- Step 1: Create the policy function
-- Replace <SCHEMA> with the owning schema.
CREATE OR REPLACE FUNCTION <SCHEMA>.customers_sms_policy (
  p_schema IN VARCHAR2,
  p_object IN VARCHAR2
) RETURN VARCHAR2 AS
  v_oauth_sub VARCHAR2(4000) := SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_SUB');
BEGIN
  -- Internal users: no restriction
  IF v_oauth_sub IS NOT NULL
     AND LOWER(v_oauth_sub) LIKE '%@mycompany.com'
  THEN
    RETURN NULL; -- no predicate => all rows visible
  END IF;

  -- External / unknown: SMS opt-in rows only
  RETURN q'[JSON_VALUE(contact_preferences, '$.sms') = 'true']';
END customers_sms_policy;
/

-- Step 2: Attach the policy to the table
BEGIN
  DBMS_RLS.ADD_POLICY(
    object_schema   => '<SCHEMA>',
    object_name     => 'CUSTOMERS',
    policy_name     => 'CUSTOMERS_SMS_VISIBILITY',
    function_schema => '<SCHEMA>',
    policy_function => 'CUSTOMERS_SMS_POLICY',
    statement_types => 'SELECT, UPDATE, DELETE',
    update_check    => TRUE,
    policy_type     => DBMS_RLS.DYNAMIC,
    enable          => TRUE
  );
END;
/

-- Step 3: Verify the policy is active
SELECT policy_name, policy_function, enable, sel, upd, del
FROM dba_policies
WHERE object_name  = 'CUSTOMERS'
  AND object_owner = UPPER('<SCHEMA>');
