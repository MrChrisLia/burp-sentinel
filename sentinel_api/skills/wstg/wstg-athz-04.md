---
id: WSTG-ATHZ-04
name: Testing for Insecure Direct Object References
description: Auto-generated from OWASP WSTG (WSTG-ATHZ-04).
confidence: high
rationale: Evidence-driven mapping for Testing for Insecure Direct Object References.
manual_only: false
wstg_ids: [WSTG-ATHZ-04]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
  path_contains: ["/admin", "/role", "/permission", "/member", "/user", "/account", "/project", "/users/", "/accounts/", "/projects/", "/tenant", "/org"]
  query_params: ["id", "user_id", "account_id", "project_id", "org_id", "tenant_id"]
tasks:
  - Validate objective: Identify points where object references may occur.
  - Validate objective: Assess the access control measures and if they're vulnerable to IDOR.
---

Category: Authorization Testing (WSTG-ATHZ)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
