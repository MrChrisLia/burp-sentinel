---
id: WSTG-BUSL-01
name: Test Business Logic Data Validation
description: Auto-generated from OWASP WSTG (WSTG-BUSL-01).
confidence: high
rationale: Evidence-driven mapping for Test Business Logic Data Validation.
manual_only: false
wstg_ids: [WSTG-BUSL-01]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE"]
tasks:
  - Validate objective: Identify data injection points.
  - Validate objective: Validate that all checks are occurring on the backend and can't be bypassed.
  - Validate objective: Attempt to break the format of the expected data and analyze how the application is handling it.
---

Category: Business Logic Testing (WSTG-BUSL)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation
