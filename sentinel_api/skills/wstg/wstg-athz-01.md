---
id: WSTG-ATHZ-01
name: Testing Directory Traversal File Include
description: Auto-generated from OWASP WSTG (WSTG-ATHZ-01).
confidence: high
rationale: Evidence-driven mapping for Testing Directory Traversal File Include.
manual_only: false
wstg_ids: [WSTG-ATHZ-01]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
  path_contains: ["/admin", "/role", "/permission", "/member", "/user", "/account", "/project", "/download", "/export", "/file", "/files"]
  query_params: ["id", "user_id", "account_id", "project_id", "org_id", "tenant_id"]
tasks:
  - Validate objective: Identify injection points that pertain to path traversal.
  - Validate objective: Assess bypassing techniques and identify the extent of path traversal.
---

Category: Authorization Testing (WSTG-ATHZ)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include
