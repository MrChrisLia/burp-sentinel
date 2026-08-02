---
id: WSTG-BUSL-06
name: Testing for the Circumvention of Work Flows
description: Auto-generated from OWASP WSTG (WSTG-BUSL-06).
confidence: high
rationale: Evidence-driven mapping for Testing for the Circumvention of Work Flows.
manual_only: false
wstg_ids: [WSTG-BUSL-06]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE"]
tasks:
  - Validate objective: Review the project documentation for methods to skip or go through steps in the application process in a different order from the intended business logic flow.
  - Validate objective: Develop a misuse case and try to circumvent every logic flow identified.
---

Category: Business Logic Testing (WSTG-BUSL)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows
