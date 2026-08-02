---
id: WSTG-SESS-11
name: Testing for Concurrent Sessions
description: Auto-generated from OWASP WSTG (WSTG-SESS-11).
confidence: high
rationale: Evidence-driven mapping for Testing for Concurrent Sessions.
manual_only: false
wstg_ids: [WSTG-SESS-11]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Evaluate the application's session management by assessing the handling of multiple active sessions for a single user account.
---

Category: Session Management Testing (WSTG-SESS)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/11-Testing_for_Concurrent_Sessions
