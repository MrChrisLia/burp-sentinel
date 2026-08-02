---
id: WSTG-ATHZ-03
name: Testing for Privilege Escalation
description: Auto-generated from OWASP WSTG (WSTG-ATHZ-03).
confidence: high
rationale: Evidence-driven mapping for Testing for Privilege Escalation.
manual_only: false
wstg_ids: [WSTG-ATHZ-03]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
  path_contains: ["/admin", "/role", "/permission", "/member", "/user", "/account", "/project"]
  query_params: ["id", "user_id", "account_id", "project_id", "org_id", "tenant_id"]
tasks:
  - Validate objective: Identify injection points related to privilege manipulation.
  - Validate objective: Fuzz or otherwise attempt to bypass security measures.
---

Category: Authorization Testing (WSTG-ATHZ)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation
