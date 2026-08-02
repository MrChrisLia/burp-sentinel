---
id: WSTG-ATHN-11
name: Testing Multi-Factor Authentication (MFA)
description: Auto-generated from OWASP WSTG (WSTG-ATHN-11).
confidence: high
rationale: Evidence-driven mapping for Testing Multi-Factor Authentication (MFA).
manual_only: false
wstg_ids: [WSTG-ATHN-11]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Identify the type of MFA used by the application.
  - Validate objective: Determine whether the MFA implementation is robust and secure.
  - Validate objective: Attempt to bypass the MFA.
---

Category: Authentication Testing (WSTG-ATHN)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication
