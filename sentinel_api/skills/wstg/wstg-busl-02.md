---
id: WSTG-BUSL-02
name: Test Ability to Forge Requests
description: Auto-generated from OWASP WSTG (WSTG-BUSL-02).
confidence: high
rationale: Evidence-driven mapping for Test Ability to Forge Requests.
manual_only: false
wstg_ids: [WSTG-BUSL-02]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE"]
tasks:
  - Validate objective: Review the project documentation looking for guessable, predictable, or hidden functionality of fields.
  - Validate objective: Insert logically valid data in order to bypass normal business logic workflow.
---

Category: Business Logic Testing (WSTG-BUSL)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests
