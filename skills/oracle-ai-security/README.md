# Oracle AI Security — Identity, SYS_CONTEXT & Row-Level Security

> **Skill for AI agents integrated with Oracle Database and OCI AI Database MCP Servers.**

## What This Skill Does

This skill enables any AI model or agent connected to Oracle Database (via an OCI AI Database MCP Server or compatible integration) to:

- Identify **who** is calling the database in any session using `SYS_CONTEXT` and OAuth context values propagated by the MCP layer.
- Build and manage **Row-Level Security (VPD) policies** (`DBMS_RLS`) that automatically filter data based on the caller's authenticated identity — with no application-layer changes required.
- Create **custom MCP Tools** for identity inspection and pre-approved SQL execution.
- Implement **IAM role-based access controls** directly in the database using OCI IAM App Roles.
- Set up **targeted audit policies** for AI-originated database sessions.
- Follow best practices for **NL2SQL safety**, including when to use Reports instead of ad-hoc SQL.

## Files in This Skill

```
skills/oracle-ai-security/
├── SKILL.md                              ← Main skill definition (this is the file AI agents load)
├── README.md                             ← This file
└── examples/
    ├── who-tool.sql                      ← SQL for the "who" identity inspection MCP Tool
    ├── vpd-email-domain-policy.sql       ← VPD policy based on email domain from OAUTH_SUB
    ├── vpd-iam-role-policy.sql           ← VPD policy based on OCI IAM App Roles
    └── audit-ai-sessions.sql             ← Unified Audit policy targeting MCP/AI sessions
```

## How to Use

1. **For AI agents / MCP clients**: Point your agent's skill or system prompt loader at `SKILL.md`. The agent will follow the decision trees, use the diagnostic SQL, and generate VPD-compliant code.
2. **For database administrators**: Use the SQL files in `examples/` directly in SQL*Plus, SQLcl, or Oracle SQL Developer. Replace `<SCHEMA>` and `<TABLE_NAME>` placeholders.
3. **For OCI Database Tools users**: Copy the SQL from `who-tool.sql` into a new Custom Tool in your MCP Server configuration.

## Prerequisites

- Oracle Database 19c or later (for JSON_VALUE in VPD predicates)
- OCI AI Database MCP Server (OCI Database Tools) — or any HTTPS-streaming MCP Server with OAuth2 identity propagation
- `DBA` or `EXECUTE ON DBMS_RLS` privilege to create VPD policies
- `AUDIT ADMIN` privilege to create audit policies
- Federated identity (Azure Entra ID, OCI IAM, Active Directory) connected to your OCI tenancy

---

## Attribution & Credits

This skill was derived from the following article:

**"Who is using your Oracle data (AI!), and how to secure it!"**  
By **Jeff Smith** ([@thatjeffsmith](https://twitter.com/thatjeffsmith))  
Published: May 28, 2026  
URL: [https://www.thatjeffsmith.com/archive/2026/05/who-is-using-your-oracle-data-ai-and-how-to-secure-it/](https://www.thatjeffsmith.com/archive/2026/05/who-is-using-your-oracle-data-ai-and-how-to-secure-it/)

Jeff Smith is a Distinguished Product Manager at Oracle, focused on Oracle Database Tools (SQL Developer, SQLcl, Oracle Database Actions, OCI Database Tools). His blog, [ThatJeffSmith.com](https://www.thatjeffsmith.com), covers practical Oracle Database development and administration topics.

The original article explains how OCI AI Database MCP Servers propagate OAuth identity into `SYS_CONTEXT`, and demonstrates a complete VPD implementation that restricts customer data visibility based on the caller's email domain — without any application-tier changes.

> All SQL examples and architectural patterns in this skill are adapted from or directly inspired by Jeff Smith's original work. See the article for screenshots, live demos, and additional context.

---

*Skill added to [Oracle-AI-Developer-Community](https://github.com/hvrcharon1/Oracle-AI-Developer-Community) · June 2026*
