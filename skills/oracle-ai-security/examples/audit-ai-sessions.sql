-- =============================================================================
-- Example: Targeted Audit Policy for AI / MCP Agent Sessions
-- Purpose : Create an Oracle Unified Audit policy that logs SELECT access
--           on a sensitive table only when the session originates from an
--           AI/MCP client (identified by OAUTH_CLIENT_NAME being non-null).
-- Author  : Inspired by Jeff Smith (@thatjeffsmith)
--           https://www.thatjeffsmith.com/archive/2026/05/who-is-using-your-oracle-data-ai-and-how-to-secure-it/
-- =============================================================================

-- Create the audit policy scoped to AI-originated sessions
CREATE AUDIT POLICY ai_sensitive_access
  ACTIONS SELECT ON <SCHEMA>.<TABLE_NAME>
  WHEN q'[SYS_CONTEXT('CLIENTCONTEXT','OAUTH_CLIENT_NAME') IS NOT NULL]'
  EVALUATE PER SESSION;

-- Enable the policy
AUDIT POLICY ai_sensitive_access;

-- Check unified audit trail for recent AI agent access
SELECT
  event_timestamp,
  dbusername,
  unified_audit_policies,
  action_name,
  object_schema,
  object_name,
  sql_text
FROM unified_audit_trail
WHERE unified_audit_policies LIKE '%AI_SENSITIVE_ACCESS%'
ORDER BY event_timestamp DESC
FETCH FIRST 50 ROWS ONLY;
