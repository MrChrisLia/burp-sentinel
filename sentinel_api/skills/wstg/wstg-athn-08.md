---
id: WSTG-ATHN-08
name: Testing for Weak Security Question Answer
description: Auto-generated from OWASP WSTG (WSTG-ATHN-08).
confidence: high
rationale: Evidence-driven mapping for Testing for Weak Security Question Answer.
manual_only: false
wstg_ids: [WSTG-ATHN-08]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Determine the complexity and how straight-forward the questions are.
  - Validate objective: Assess possible user answers and brute force capabilities.
---

Category: Authentication Testing (WSTG-ATHN)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/08-Testing_for_Weak_Security_Question_Answer
