---
id: WSTG-BUSL-09
name: Test Upload of Malicious Files
description: Auto-generated from OWASP WSTG (WSTG-BUSL-09).
confidence: high
rationale: Evidence-driven mapping for Test Upload of Malicious Files.
manual_only: false
wstg_ids: [WSTG-BUSL-09]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE"]
  path_contains: ["/upload", "/file", "/files"]
tasks:
  - Validate objective: Identify the file upload functionality.
  - Validate objective: Review the project documentation to identify what file types are considered acceptable, and what types would be considered dangerous or malicious.
  - Validate objective: If documentation is not available then consider what would be appropriate based on the purpose of the application.
---

Category: Business Logic Testing (WSTG-BUSL)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files
