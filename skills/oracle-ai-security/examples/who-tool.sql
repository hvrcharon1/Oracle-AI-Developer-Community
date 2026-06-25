-- =============================================================================
-- MCP Custom Tool: "who" / "whoami"
-- Purpose : Inspect the full OAuth identity available in the current
--           OCI AI Database MCP Server session.
-- Usage   : Register this SQL as a custom tool named "who" in OCI Database Tools.
--           Call it from any MCP-compatible AI agent to confirm identity
--           before running queries on sensitive data.
-- Author  : Derived from Jeff Smith (@thatjeffsmith)
--           https://www.thatjeffsmith.com/archive/2026/05/who-is-using-your-oracle-data-ai-and-how-to-secure-it/
-- =============================================================================
SELECT
  SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA')             AS current_schema,
  SYS_CONTEXT('USERENV', 'SESSION_USER')                AS session_user,
  SYS_CONTEXT('USERENV', 'PROXY_USER')                  AS proxy_user,
  SYS_CONTEXT('USERENV', 'AUTHENTICATED_IDENTITY')      AS authenticated_identity,
  SYS_CONTEXT('USERENV', 'AUTHENTICATION_METHOD')       AS authentication_method,
  SYS_CONTEXT('USERENV', 'ENTERPRISE_IDENTITY')         AS enterprise_identity,
  SYS_CONTEXT('USERENV', 'PROXY_ENTERPRISE_IDENTITY')   AS proxy_enterprise_identity,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_SUB_TYPE')        AS oauth_sub_type,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_SUB')             AS oauth_sub,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_USER_OCID')       AS oauth_user_ocid,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_CLIENT_OCID')     AS oauth_client_ocid,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_CLIENT_NAME')     AS oauth_client_name,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_CA_OCID')         AS oauth_ca_ocid,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_CA_NAME')         AS oauth_ca_name,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_DOMAIN_ID')       AS oauth_domain_id,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_DOMAIN_NAME')     AS oauth_domain_name,
  SYS_CONTEXT('CLIENTCONTEXT', 'IAM_DOMAIN_APP_ROLES')  AS iam_domain_app_roles,
  SYS_CONTEXT('CLIENTCONTEXT', 'RESOURCE_OCID')         AS resource_ocid,
  SYS_CONTEXT('CLIENTCONTEXT', 'RESOURCE_COMPARTMENT_OCID') AS resource_compartment_ocid
FROM DUAL;
