---
id: WSTG-ATHN-09
name: Testing for Weak Password Change or Reset Functionalities
description: Auto-generated from OWASP WSTG (WSTG-ATHN-09).
confidence: high
rationale: Evidence-driven mapping for Testing for Weak Password Change or Reset Functionalities.
manual_only: false
wstg_ids: [WSTG-ATHN-09]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Determine whether the password change and reset functionality allows accounts to be compromised.
---

Category: Authentication Testing (WSTG-ATHN)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities
