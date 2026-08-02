---
id: WSTG-APIT-99
name: Testing GraphQL
description: Auto-generated from OWASP WSTG (WSTG-APIT-99).
confidence: high
rationale: Evidence-driven mapping for Testing GraphQL.
manual_only: false
wstg_ids: [WSTG-APIT-99]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
  path_contains: ["/api", "/graphql"]
  route_types: ["graphql"]
  route_contains: ["/graphql"]
tasks:
  - Validate objective: Assess that a secure and production-ready configuration is deployed.
  - Validate objective: Validate all input fields against generic attacks.
  - Validate objective: Ensure that proper access controls are applied.
---

Category: API Testing (WSTG-APIT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/99-Testing_GraphQL
