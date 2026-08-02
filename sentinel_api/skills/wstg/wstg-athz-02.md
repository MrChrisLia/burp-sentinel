---
id: WSTG-ATHZ-02
name: Testing for Bypassing Authorization Schema
description: Auto-generated from OWASP WSTG (WSTG-ATHZ-02).
confidence: high
rationale: Evidence-driven mapping for Testing for Bypassing Authorization Schema.
manual_only: false
wstg_ids: [WSTG-ATHZ-02]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
  path_contains: ["/admin", "/role", "/permission", "/member", "/user", "/account", "/project"]
  query_params: ["id", "user_id", "account_id", "project_id", "org_id", "tenant_id"]
tasks:
  - Validate objective: Assess if unauthenticated, horizontal, or vertical access is possible.
---

Category: Authorization Testing (WSTG-ATHZ)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema
