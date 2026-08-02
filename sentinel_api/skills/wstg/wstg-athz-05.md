---
id: WSTG-ATHZ-05
name: Testing for OAuth Weaknesses
description: Auto-generated from OWASP WSTG (WSTG-ATHZ-05).
confidence: high
rationale: Evidence-driven mapping for Testing for OAuth Weaknesses.
manual_only: false
wstg_ids: [WSTG-ATHZ-05]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
  path_contains: ["/admin", "/role", "/permission", "/member", "/user", "/account", "/project", "/oauth", "/callback", "/authorize", "/token"]
  query_params: ["id", "user_id", "account_id", "project_id", "org_id", "tenant_id"]
tasks:
  - Validate objective: Determine if OAuth2 implementation is vulnerable or using a deprecated or custom implementation.
---

Category: Authorization Testing (WSTG-ATHZ)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses
