---
id: WSTG-ATHN-04
name: Testing for Bypassing Authentication Schema
description: Auto-generated from OWASP WSTG (WSTG-ATHN-04).
confidence: high
rationale: Evidence-driven mapping for Testing for Bypassing Authentication Schema.
manual_only: false
wstg_ids: [WSTG-ATHN-04]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Ensure that authentication is applied across all services that require it.
---

Category: Authentication Testing (WSTG-ATHN)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema
