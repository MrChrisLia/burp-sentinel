---
id: WSTG-ATHN-10
name: Testing for Weaker Authentication in Alternative Channel
description: Auto-generated from OWASP WSTG (WSTG-ATHN-10).
confidence: high
rationale: Evidence-driven mapping for Testing for Weaker Authentication in Alternative Channel.
manual_only: false
wstg_ids: [WSTG-ATHN-10]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Identify alternative authentication channels.
  - Validate objective: Assess the security measures used and if any bypasses exists on the alternative channels.
---

Category: Authentication Testing (WSTG-ATHN)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/10-Testing_for_Weaker_Authentication_in_Alternative_Channel
