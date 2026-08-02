---
id: WSTG-APIT-03
name: API Broken Function Level Authorization
description: Auto-generated from OWASP WSTG (WSTG-APIT-03).
confidence: high
rationale: Evidence-driven mapping for API Broken Function Level Authorization.
manual_only: false
wstg_ids: [WSTG-APIT-03]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
  path_contains: ["/api"]
tasks:
  - Validate objective: The goal of this test is to determine if the API enforces **role or privilege-based access control** to restrict users from accessing or executing functions they are not authorized to use. This ensures that function-level security boundaries are properly enforced.
---

Category: API Testing (WSTG-APIT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/04-API_Broken_Function_Level_Authorization
