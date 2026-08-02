---
id: WSTG-SESS-03
name: Testing for Session Fixation
description: Auto-generated from OWASP WSTG (WSTG-SESS-03).
confidence: high
rationale: Evidence-driven mapping for Testing for Session Fixation.
manual_only: false
wstg_ids: [WSTG-SESS-03]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Analyze the authentication mechanism and its flow.
  - Validate objective: Force cookies and assess the impact.
---

Category: Session Management Testing (WSTG-SESS)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation
