---
id: WSTG-APIT-01
name: API Reconnaissance
description: Auto-generated from OWASP WSTG (WSTG-APIT-01).
confidence: high
rationale: Evidence-driven mapping for API Reconnaissance.
manual_only: false
wstg_ids: [WSTG-APIT-01]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
  path_contains: ["/api"]
tasks:
  - Validate objective: Find all API endpoints supported by the backend server code, documented or undocumented.
  - Validate objective: Find all parameters for each endpoint supported by the backend server, documented or undocumented.
  - Validate objective: Discover interesting data related to APIs in HTML and JavaScript sent to clients.
---

Category: API Testing (WSTG-APIT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-API_Reconnaissance
