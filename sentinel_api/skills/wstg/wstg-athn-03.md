---
id: WSTG-ATHN-03
name: Testing for Weak Lock Out Mechanism
description: Auto-generated from OWASP WSTG (WSTG-ATHN-03).
confidence: high
rationale: Evidence-driven mapping for Testing for Weak Lock Out Mechanism.
manual_only: false
wstg_ids: [WSTG-ATHN-03]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Evaluate the account lockout mechanism's ability to mitigate brute force password guessing.
  - Validate objective: Evaluate the unlock mechanism's resistance to unauthorized account unlocking.
---

Category: Authentication Testing (WSTG-ATHN)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism
