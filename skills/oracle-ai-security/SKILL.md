# SKILL: Oracle AI Security — Identity Propagation, SYS_CONTEXT & Row-Level Security via MCP

## Overview

This skill teaches an AI agent (connected to Oracle Database through an OCI AI Database MCP Server or any Oracle-compatible MCP/REST integration) how to:

1. Discover **who the calling user is** by reading OAuth identity values surfaced in `SYS_CONTEXT`.
2. Understand the **full session identity model** (database user, proxy user, enterprise identity, OAuth subject, OCI OCIDs, IAM roles).
3. Create and validate **Row-Level Security (VPD) policies** that automatically filter data based on the caller's identity — with zero changes required in the application or agent layer.
4. Test, troubleshoot, and iterate on security policies through natural-language interaction.
5. Follow **best practices** for AI-driven database access in multi-tenant and multi-identity environments.

---

## When to Use This Skill

Trigger this skill when any of the following apply:

- The user asks "who is querying my database?", "can I restrict data by user?", "how do I implement row-level security for AI agents?", or similar.
- The deployment uses **OCI Database Tools MCP Servers** (serverless, Oracle-managed) or any HTTPS-streaming MCP server that authenticates via OAuth2.
- The user wants to enforce **data access rules at the database layer** rather than the application tier.
- The user is combining **AI/NL2SQL agents** with sensitive Oracle data and needs to prevent data leakage.
- The user mentions **VPD**, **DBMS_RLS**, **SYS_CONTEXT**, **CLIENTCONTEXT**, **OAuth2**, **OBO (On-Behalf-Of)**, or **IAM roles** in the context of Oracle Database.
- The user wants to create **custom MCP Tools** that expose controlled, pre-vetted SQL or PL/SQL.

---

## Core Concepts

### 1. How Identity Flows into the Database

When an AI agent connects to an Oracle Database through an OCI AI Database MCP Server:

- The end user authenticates via OAuth2 (e.g., Azure Entra ID, OCI IAM, Active Directory).
- The MCP Server acts **on behalf of** (OBO) the authenticated user.
- The OAuth2 access token is unpacked by the MCP layer and its claims are **injected into the database session's `CLIENTCONTEXT`** automatically — no logon trigger, no custom context package, no `DBMS_SESSION.SET_CONTEXT` calls needed.
- Every SQL statement executed in that session carries the identity of the real human (or agent) at the other end of the OAuth flow.

This solves the classic "pooled connection" problem: instead of the database seeing only a generic service account, it sees the individual caller's identity on every query.

---

### 2. Reading Session Identity with `SYS_CONTEXT`

Use the following SQL to inspect the full identity available in any MCP-authenticated session. This is a good starting point for debugging or building a diagnostic MCP Tool:

```sql
SELECT
  SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA')            AS current_schema,
  SYS_CONTEXT('USERENV', 'SESSION_USER')               AS session_user,
  SYS_CONTEXT('USERENV', 'PROXY_USER')                 AS proxy_user,
  SYS_CONTEXT('USERENV', 'AUTHENTICATED_IDENTITY')     AS authenticated_identity,
  SYS_CONTEXT('USERENV', 'AUTHENTICATION_METHOD')      AS authentication_method,
  SYS_CONTEXT('USERENV', 'ENTERPRISE_IDENTITY')        AS enterprise_identity,
  SYS_CONTEXT('USERENV', 'PROXY_ENTERPRISE_IDENTITY')  AS proxy_enterprise_identity,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_SUB_TYPE')       AS oauth_sub_type,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_SUB')            AS oauth_sub,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_USER_OCID')      AS oauth_user_ocid,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_CLIENT_OCID')    AS oauth_client_ocid,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_CLIENT_NAME')    AS oauth_client_name,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_CA_OCID')        AS oauth_ca_ocid,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_CA_NAME')        AS oauth_ca_name,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_DOMAIN_ID')      AS oauth_domain_id,
  SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_DOMAIN_NAME')    AS oauth_domain_name,
  SYS_CONTEXT('CLIENTCONTEXT', 'IAM_DOMAIN_APP_ROLES') AS iam_domain_app_roles,
  SYS_CONTEXT('CLIENTCONTEXT', 'RESOURCE_OCID')        AS resource_ocid,
  SYS_CONTEXT('CLIENTCONTEXT', 'RESOURCE_COMPARTMENT_OCID') AS resource_compartment_ocid
FROM DUAL;
```

**Key fields to remember:**

| Context Key | Description |
|---|---|
| `USERENV.SESSION_USER` | The database schema/user used to open the connection |
| `USERENV.AUTHENTICATED_IDENTITY` | The enterprise/federated identity that authenticated |
| `CLIENTCONTEXT.OAUTH_SUB` | The OAuth subject — typically the user's email or unique ID |
| `CLIENTCONTEXT.OAUTH_USER_OCID` | The OCI OCID of the authenticated user |
| `CLIENTCONTEXT.IAM_DOMAIN_APP_ROLES` | IAM app roles assigned to the user (comma-separated) |
| `CLIENTCONTEXT.OAUTH_CLIENT_NAME` | The MCP client application that initiated the call |

---

### 3. Custom MCP Tools for Identity Inspection

You can expose the identity query above as a **custom MCP Tool** called `who` (or `whoami`). This allows an AI agent to call it explicitly:

- Tool name: `who`
- SQL: The `SELECT ... FROM DUAL` query above
- Description: "Returns the authenticated identity and OAuth context for the current MCP session."

When the agent calls `who`, the MCP Server executes the fixed SQL and returns identity details — the LLM does not generate any SQL and cannot manipulate the query.

---

### 4. Row-Level Security (VPD) — Enforcing Access at the Data Layer

Oracle's **Virtual Private Database (VPD)**, implemented through `DBMS_RLS`, silently rewrites every SQL query against a protected table to add a `WHERE` clause predicate. The predicate is computed by a PL/SQL policy function that can read `SYS_CONTEXT` values.

#### Why VPD over application-layer security?

- The database enforces the rule for **every access path**: direct SQL, NL2SQL agents, reports, ETL jobs, ad-hoc queries.
- The agent cannot bypass it — even if an LLM generates a `SELECT *`, the WHERE clause is injected before the optimizer sees the query.
- No application code changes are needed when the policy changes.

---

#### Step-by-Step: Implementing a VPD Policy

**Step 1 — Define the business rule as a PL/SQL policy function.**

The function receives the schema and object name and returns a `VARCHAR2` predicate string. Returning `NULL` means "no restriction" (all rows visible). Returning a SQL fragment means that fragment is appended as `AND <predicate>` to every query.

```sql
CREATE OR REPLACE FUNCTION <schema>.my_vpd_policy (
  p_schema IN VARCHAR2,
  p_object IN VARCHAR2
) RETURN VARCHAR2 AS
  v_oauth_sub VARCHAR2(4000) := SYS_CONTEXT('CLIENTCONTEXT', 'OAUTH_SUB');
  v_app_roles VARCHAR2(4000) := SYS_CONTEXT('CLIENTCONTEXT', 'IAM_DOMAIN_APP_ROLES');
BEGIN
  -- Rule: Internal staff (@mycompany.com) see everything
  IF v_oauth_sub IS NOT NULL
     AND LOWER(v_oauth_sub) LIKE '%@mycompany.com'
  THEN
    RETURN NULL; -- no predicate = all rows
  END IF;

  -- Rule: Users with the 'PREMIUM_ACCESS' IAM role see all rows
  IF INSTR(v_app_roles, 'PREMIUM_ACCESS') > 0 THEN
    RETURN NULL;
  END IF;

  -- Default: limit to rows explicitly opted in (example: SMS consent)
  RETURN q'[JSON_VALUE(contact_preferences, '$.sms') = 'true']';
END my_vpd_policy;
/
```

**Step 2 — Attach the policy to the table.**

```sql
BEGIN
  DBMS_RLS.ADD_POLICY(
    object_schema   => '<schema>',
    object_name     => '<table_name>',
    policy_name     => 'MY_VPD_POLICY',
    function_schema => '<schema>',
    policy_function => 'MY_VPD_POLICY',
    statement_types => 'SELECT, UPDATE, DELETE',
    update_check    => TRUE,
    policy_type     => DBMS_RLS.DYNAMIC,
    enable          => TRUE
  );
END;
/
```

**Parameter guidance:**

| Parameter | Recommended Value | Reason |
|---|---|---|
| `statement_types` | `'SELECT, UPDATE, DELETE'` | Restricts reads **and** writes |
| `update_check` | `TRUE` | Prevents editing a row in a way that removes it from the user's visibility |
| `policy_type` | `DBMS_RLS.DYNAMIC` | Re-evaluates per query; prevents cached predicates from leaking across pooled sessions |

**Step 3 — Test the policy.**

Have the AI agent run the same query under two different OAuth identities and compare row counts. Expected outcomes:

- Identity matching the privileged condition → full row count
- Any other identity → filtered row count based on the predicate

---

### 5. Useful VPD Management Queries

Check active VPD policies on a table:

```sql
SELECT policy_name, policy_function, enable, sel, upd, del
FROM dba_policies
WHERE object_name = UPPER('<table_name>')
  AND object_owner = UPPER('<schema>');
```

Disable a policy temporarily for testing:

```sql
BEGIN
  DBMS_RLS.ENABLE_POLICY(
    object_schema => '<schema>',
    object_name   => '<table_name>',
    policy_name   => 'MY_VPD_POLICY',
    enable        => FALSE
  );
END;
/
```

Drop a policy:

```sql
BEGIN
  DBMS_RLS.DROP_POLICY(
    object_schema => '<schema>',
    object_name   => '<table_name>',
    policy_name   => 'MY_VPD_POLICY'
  );
END;
/
```

---

### 6. NL2SQL Agent Patterns for Secure Data Access

When an AI agent is generating SQL against a VPD-protected table, guide it with these rules:

- **Never bypass VPD** by querying data dictionary views directly or switching schemas without authorization.
- **Always confirm identity** before returning sensitive data. Use the `who` tool or `SYS_CONTEXT('CLIENTCONTEXT','OAUTH_SUB')` in the query.
- **Prefer Reports over ad-hoc NL2SQL** for sensitive objects. Oracle MCP Reports run pre-approved, fixed SQL — the LLM calls the report, not a generated query. This ensures VPD is respected through a predictable code path.
- **Trust row counts** as a security signal: if a count returns unexpectedly few rows, the caller's identity may not have full access — this is correct behavior, not a bug.
- **Do not reveal predicate logic** to end users. The VPD policy function is an internal control; agents should not expose the underlying WHERE clause to callers.

---

### 7. On-Behalf-Of (OBO) OAuth Flow

When an AI agent (e.g., a Cline extension, Claude, a custom agent) connects to an OCI MCP Server:

1. The user is prompted to sign in once via the identity provider (Azure Entra, OCI IAM, etc.).
2. The user grants the MCP client permission to act on their behalf.
3. The MCP Server propagates the user's OAuth token — not the agent's token — into the database session.
4. All subsequent tool calls in that session carry the **end-user identity**, not a generic service account.

This means data-access policies are enforced per-human, even when mediated by an AI agent.

---

### 8. IAM Role-Based Access Patterns

The `IAM_DOMAIN_APP_ROLES` context value contains comma-separated IAM app roles assigned to the authenticated user. You can branch policy logic on these:

```sql
-- Grant full access to users with ADMIN role
IF INSTR(SYS_CONTEXT('CLIENTCONTEXT','IAM_DOMAIN_APP_ROLES'), 'DB_ADMIN') > 0 THEN
  RETURN NULL;
END IF;

-- Grant restricted access to ANALYST role
IF INSTR(SYS_CONTEXT('CLIENTCONTEXT','IAM_DOMAIN_APP_ROLES'), 'DATA_ANALYST') > 0 THEN
  RETURN 'region = ''EMEA''';
END IF;

-- Default: deny all
RETURN '1=0';
```

Returning `'1=0'` is the Oracle VPD pattern for "deny all rows" — the query returns zero rows without an error.

---

### 9. Auditing AI-Driven Access

Since the database knows who every caller is, you can use Oracle Unified Auditing to log sensitive queries by identity:

```sql
CREATE AUDIT POLICY ai_sensitive_access
  ACTIONS SELECT ON <schema>.<table_name>
  WHEN q'[SYS_CONTEXT('CLIENTCONTEXT','OAUTH_CLIENT_NAME') IS NOT NULL]'
  EVALUATE PER SESSION;

AUDIT POLICY ai_sensitive_access;
```

This creates a targeted audit trail specifically for sessions originating from AI MCP clients, without auditing every other access.

---

## Common Troubleshooting Scenarios

### "SYS_CONTEXT('CLIENTCONTEXT','OAUTH_SUB') is NULL"

- The session was not established through an OAuth-aware MCP Server.
- The connection may be a direct JDBC/SQL*Net connection using a database password (not OAuth).
- Check `AUTHENTICATION_METHOD` to confirm how the session was opened.

### "VPD policy returns wrong row count"

- Confirm `policy_type => DBMS_RLS.DYNAMIC` is set. STATIC policies cache predicates and can leak across pooled sessions.
- Verify the `OAUTH_SUB` value matches exactly what the policy function expects (check case sensitivity).
- Run the identity diagnostic query (`SELECT ... FROM DUAL`) in the same session before running the data query.

### "Policy function raises an error"

- Oracle raises ORA-28110 if the policy function itself errors. Check for NULL handling in your function.
- Always guard against NULL `OAUTH_SUB`: default to the most restrictive predicate when identity is absent.

### "Agent generated SQL that returned more rows than expected"

- Check whether the table actually has the VPD policy attached (`SELECT * FROM dba_policies WHERE object_name = '<TABLE>').
- Confirm the policy is enabled (`enable = YES`).
- Verify the session is going through the MCP Server (not a direct connection).

---

## Quick Reference: Decision Tree for AI Agent Data Access

```
User asks agent to query sensitive data
          |
          v
  Is data access via OCI MCP Server?
     YES ──────────────────────────> OAUTH_SUB is populated in CLIENTCONTEXT
      |                                        |
      |                                        v
      |                              Does a VPD policy exist on the table?
      |                                 YES ──> Database enforces row-level filter automatically
      |                                 NO  ──> All rows returned; consider adding VPD
      |
     NO ──> Direct DB connection; OAUTH_SUB is NULL
                  |
                  v
            Application-layer security only (not recommended for AI agents)
            Consider migrating to MCP Server + VPD
```

---

## Prompt Templates for AI Agents

Use these as system prompt additions or few-shot examples when configuring agents that operate on Oracle Database:

**Identity Check Prompt:**
> Before querying any table in the `<schema>` schema, first call the `who` tool to confirm the session identity. If `OAUTH_SUB` is null, do not proceed with queries on sensitive tables and inform the user that their identity could not be verified.

**Row Count Validation Prompt:**
> After running a query on a VPD-protected table, note the row count in your response. If the user reports a different expected count, explain that row-level security may be filtering results based on their identity — do not attempt to bypass or work around this filtering.

**Report-over-NL2SQL Prompt:**
> For tables listed in `<sensitive_tables_list>`, do not generate ad-hoc SQL. Instead, use the available Report tools. If no matching report exists, tell the user that direct SQL access is restricted and suggest they contact their database administrator.

---

## Related Oracle Features

| Feature | Purpose |
|---|---|
| `DBMS_RLS` | Add, drop, enable, disable VPD policies |
| `SYS_CONTEXT` | Read session environment and client context values |
| Oracle Unified Auditing | Audit-trail for data access by identity |
| DBMS_SESSION.SET_CONTEXT | Manually set context values (not needed with OCI MCP Servers) |
| OCI Database Tools | Oracle-managed, serverless MCP Server infrastructure |
| Oracle Reports (MCP) | Pre-approved SQL exposed as MCP tools — safer than ad-hoc NL2SQL |
| JSON_VALUE | Query JSON columns inside VPD predicates (e.g., consent flags) |
| Oracle Proxy Authentication | Allow one DB user to proxy as another while preserving audit identity |

---

## References

- Original article: [Who is using your Oracle data (AI!), and how to secure it!](https://www.thatjeffsmith.com/archive/2026/05/who-is-using-your-oracle-data-ai-and-how-to-secure-it/) — Jeff Smith, May 28 2026
- [OCI Database Tools MCP Server announcement](https://blogs.oracle.com/database/gain-agentic-access-to-any-oracle-database-in-the-cloud-with-native-enterprise-grade-managed-mcp-servers-in-oci)
- [Oracle VPD Documentation](https://docs.oracle.com/en/database/oracle/oracle-database/21/dbseg/using-oracle-vpd-to-control-data-access.html)
- [DBMS_RLS Reference](https://docs.oracle.com/en/database/oracle/oracle-database/21/arpls/DBMS_RLS.html)
- [SYS_CONTEXT Reference](https://docs.oracle.com/en/database/oracle/oracle-database/21/sqlrf/SYS_CONTEXT.html)
