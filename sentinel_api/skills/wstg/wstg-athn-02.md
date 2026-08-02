---
id: WSTG-ATHN-02
name: Testing for Default Credentials
description: Auto-generated from OWASP WSTG (WSTG-ATHN-02).
confidence: high
rationale: Evidence-driven mapping for Testing for Default Credentials.
manual_only: false
wstg_ids: [WSTG-ATHN-02]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Determine whether the application has any user accounts with default passwords.
  - Validate objective: Review whether new user accounts are created with weak or predictable passwords.
---

Category: Authentication Testing (WSTG-ATHN)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials
