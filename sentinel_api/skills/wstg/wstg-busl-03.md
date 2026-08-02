---
id: WSTG-BUSL-03
name: Test Integrity Checks
description: Auto-generated from OWASP WSTG (WSTG-BUSL-03).
confidence: high
rationale: Evidence-driven mapping for Test Integrity Checks.
manual_only: false
wstg_ids: [WSTG-BUSL-03]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE"]
tasks:
  - Validate objective: Review the project documentation for components of the system that move, store, or handle data.
  - Validate objective: Determine what type of data is logically acceptable by the component and what types the system should guard against.
  - Validate objective: Determine who should be allowed to modify or read that data in each component.
---

Category: Business Logic Testing (WSTG-BUSL)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/03-Test_Integrity_Checks
