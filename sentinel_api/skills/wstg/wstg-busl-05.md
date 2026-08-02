---
id: WSTG-BUSL-05
name: Test Number of Times a Function Can Be Used Limits
description: Auto-generated from OWASP WSTG (WSTG-BUSL-05).
confidence: high
rationale: Evidence-driven mapping for Test Number of Times a Function Can Be Used Limits.
manual_only: false
wstg_ids: [WSTG-BUSL-05]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE"]
tasks:
  - Validate objective: Identify functions that must set limits to the times they can be called.
  - Validate objective: Assess if there is a logical limit set on the functions and if it is properly validated.
---

Category: Business Logic Testing (WSTG-BUSL)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits
