---
id: WSTG-ATHN-05
name: Testing for Vulnerable Remember Password
description: Auto-generated from OWASP WSTG (WSTG-ATHN-05).
confidence: high
rationale: Evidence-driven mapping for Testing for Vulnerable Remember Password.
manual_only: false
wstg_ids: [WSTG-ATHN-05]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Validate that the generated session is managed securely and do not put the user's credentials in danger.
---

Category: Authentication Testing (WSTG-ATHN)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/05-Testing_for_Vulnerable_Remember_Password
