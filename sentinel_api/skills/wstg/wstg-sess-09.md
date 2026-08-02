---
id: WSTG-SESS-09
name: Testing for Session Hijacking
description: Auto-generated from OWASP WSTG (WSTG-SESS-09).
confidence: high
rationale: Evidence-driven mapping for Testing for Session Hijacking.
manual_only: false
wstg_ids: [WSTG-SESS-09]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Identify vulnerable session cookies.
  - Validate objective: Hijack vulnerable cookies and assess the risk level.
---

Category: Session Management Testing (WSTG-SESS)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/09-Testing_for_Session_Hijacking
