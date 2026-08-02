---
id: WSTG-SESS-08
name: Testing for Session Puzzling
description: Auto-generated from OWASP WSTG (WSTG-SESS-08).
confidence: high
rationale: Evidence-driven mapping for Testing for Session Puzzling.
manual_only: false
wstg_ids: [WSTG-SESS-08]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Identify all session variables.
  - Validate objective: Break the logical flow of session generation.
---

Category: Session Management Testing (WSTG-SESS)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling
