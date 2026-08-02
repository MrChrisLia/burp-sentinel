---
id: WSTG-APIT-02
name: API Broken Object Level Authorization
description: Auto-generated from OWASP WSTG (WSTG-APIT-02).
confidence: high
rationale: Evidence-driven mapping for API Broken Object Level Authorization.
manual_only: false
wstg_ids: [WSTG-APIT-02]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
  path_contains: ["/api", "/users/", "/accounts/", "/projects/", "/tenant", "/org"]
  query_params: ["id", "user_id", "account_id", "project_id", "org_id", "tenant_id"]
tasks:
  - Validate objective: The objective of this test is to identify whether the API enforces proper **object-level authorization** checks, ensuring that users can only access and manipulate objects they are authorized to interact with.
---

Category: API Testing (WSTG-APIT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization
