---
id: WSTG-BUSL-08
name: Test Upload of Unexpected File Types
description: Auto-generated from OWASP WSTG (WSTG-BUSL-08).
confidence: high
rationale: Evidence-driven mapping for Test Upload of Unexpected File Types.
manual_only: false
wstg_ids: [WSTG-BUSL-08]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE"]
  path_contains: ["/upload", "/file", "/files"]
tasks:
  - Validate objective: Review the project documentation for file types that are rejected by the system.
  - Validate objective: Verify that the unwelcomed file types are rejected and handled safely.
  - Validate objective: Verify that file batch uploads are secure and do not allow any bypass against the set security measures.
---

Category: Business Logic Testing (WSTG-BUSL)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types
