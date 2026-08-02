---
id: WSTG-SESS-06
name: Testing for Logout Functionality
description: Auto-generated from OWASP WSTG (WSTG-SESS-06).
confidence: high
rationale: Evidence-driven mapping for Testing for Logout Functionality.
manual_only: false
wstg_ids: [WSTG-SESS-06]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Assess the logout UI.
  - Validate objective: Analyze the session timeout and if the session is properly killed after logout.
---

Category: Session Management Testing (WSTG-SESS)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality
