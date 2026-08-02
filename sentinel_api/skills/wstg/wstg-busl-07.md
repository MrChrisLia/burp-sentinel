---
id: WSTG-BUSL-07
name: Test Defenses Against Application Misuse
description: Auto-generated from OWASP WSTG (WSTG-BUSL-07).
confidence: high
rationale: Evidence-driven mapping for Test Defenses Against Application Misuse.
manual_only: false
wstg_ids: [WSTG-BUSL-07]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE"]
tasks:
  - Validate objective: Generate notes from all tests conducted against the system.
  - Validate objective: Review which tests had a different functionality based on aggressive input.
  - Validate objective: Understand the defenses in place and verify if they are enough to protect the system against bypassing techniques.
---

Category: Business Logic Testing (WSTG-BUSL)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/07-Test_Defenses_Against_Application_Misuse
