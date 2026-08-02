---
id: WSTG-SESS-07
name: Testing Session Timeout
description: Auto-generated from OWASP WSTG (WSTG-SESS-07).
confidence: high
rationale: Evidence-driven mapping for Testing Session Timeout.
manual_only: false
wstg_ids: [WSTG-SESS-07]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Validate that a hard session timeout exists.
---

Category: Session Management Testing (WSTG-SESS)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/07-Testing_Session_Timeout
