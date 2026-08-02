"""OWASP WSTG skills loader and evidence-driven selector.

Primary source:
- https://github.com/OWASP/wstg
- https://raw.githubusercontent.com/OWASP/wstg/master/checklists/checklist.json
"""
from __future__ import annotations

import json
import os
import re
from functools import lru_cache

from sentinel_api import markdown_skills


def _catalog_path() -> str:
    env = os.getenv("SENTINEL_WSTG_CHECKLIST_PATH", "").strip()
    if env:
        return env
    return os.path.join(os.path.dirname(__file__), "data", "wstg_checklist.json")


@lru_cache(maxsize=1)
def _load_tests() -> dict[str, dict]:
    path = _catalog_path()
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    categories = data.get("categories", {})
    tests: dict[str, dict] = {}
    for category_name, category in categories.items():
        for test in category.get("tests", []) or []:
            test_id = str(test.get("id", "")).strip()
            if not test_id:
                continue
            tests[test_id] = {
                "id": test_id,
                "name": str(test.get("name", "")).strip(),
                "category_id": str(category.get("id", "")).strip(),
                "category_name": category_name,
                "reference": str(test.get("reference", "")).strip(),
                "objectives": [str(x).strip() for x in (test.get("objectives", []) or []) if str(x).strip()],
            }
    return tests


def _path_has(path: str, *parts: str) -> bool:
    low = (path or "").lower()
    return any(p in low for p in parts)


def _first_non_empty(values: list[str], fallback: str) -> str:
    for value in values:
        value = (value or "").strip()
        if value:
            return value
    return fallback


def _materialize(test_id: str, rationale: str, confidence: str = "medium") -> dict | None:
    t = _load_tests().get(test_id)
    if not t:
        return None
    return {
        "id": t["id"],
        "name": t["name"],
        "category_id": t["category_id"],
        "category_name": t["category_name"],
        "reference": t["reference"],
        "objectives": t["objectives"][:3],
        "rationale": rationale,
        "confidence": confidence,
    }


def recommend_for_request(req: dict, resp: dict | None = None, js_findings: list[dict] | None = None) -> list[dict]:
    path = (req.get("path") or "").lower()
    method = (req.get("method") or "").upper()
    query_params = [str(x).lower() for x in (req.get("query_params", []) or [])]
    route_norm = (req.get("normalized_path") or path).lower()
    js_findings = js_findings or []
    out: dict[str, dict] = {}

    def add(test_id: str, rationale: str, confidence: str = "medium") -> None:
        rec = _materialize(test_id, rationale, confidence)
        if not rec:
            return
        current = out.get(test_id)
        if not current:
            out[test_id] = rec
            return
        if confidence == "high" and current.get("confidence") != "high":
            current["confidence"] = "high"

    # Always-on mapping/coverage skills.
    add("WSTG-INFO-04", "Endpoint/host traffic observed; maintain attack-surface inventory.")
    add("WSTG-INFO-06", "Observed request parameters and paths indicate testable entry points.")

    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        add("WSTG-BUSL-02", f"State-changing method ({method}) observed; verify forged-request resistance.")
        add("WSTG-INPV-03", f"State-changing method ({method}) observed; verify HTTP verb tampering controls.")

    numeric_or_uuid_segment = any(
        re.fullmatch(r"\d+", s or "") or re.fullmatch(r"[0-9a-fA-F-]{32,36}", s or "")
        for s in path.split("/")
        if s
    )
    if "{id}" in route_norm or numeric_or_uuid_segment or any("id" in p for p in query_params):
        add("WSTG-ATHZ-04", "Object identifiers observed in path/parameters; test IDOR/BOLA.", "high")
        add("WSTG-APIT-02", "Object-level access boundary is testable from observed identifiers.", "high")

    if _path_has(path, "auth", "login", "logout", "session", "oauth", "token", "password"):
        add("WSTG-ATHN-04", "Authentication-related endpoint observed; test auth bypass conditions.", "high")
        add("WSTG-SESS-01", "Session/auth flows observed; validate session lifecycle and coupling.")
        add("WSTG-SESS-06", "Logout/session endpoints observed; verify invalidation behavior.")
        add("WSTG-SESS-07", "Session endpoints observed; validate timeout and renewal handling.")
    if _path_has(path, "mfa", "2fa", "otp"):
        add("WSTG-ATHN-11", "MFA indicators observed; validate multi-step auth enforcement.", "high")

    if _path_has(path, "admin", "role", "permission", "member", "invite"):
        add("WSTG-IDNT-01", "Role/permission semantics observed; validate role definitions.")
        add("WSTG-ATHZ-02", "Privileged control paths observed; test authz bypass.")
        add("WSTG-ATHZ-03", "Privileged control paths observed; test privilege escalation.")

    if _path_has(path, "upload", "file"):
        add("WSTG-BUSL-08", "Upload functionality observed; validate unexpected file type handling.", "high")
        add("WSTG-BUSL-09", "Upload functionality observed; validate malicious file handling.", "high")
    if _path_has(path, "download", "export"):
        add("WSTG-ATHZ-01", "Download/export endpoint observed; test traversal and file include controls.")

    if "graphql" in path:
        add("WSTG-APIT-99", "GraphQL endpoint observed; validate schema and authz controls.", "high")

    if any(p in {"redirect", "redirect_uri", "next", "url", "return", "return_to"} for p in query_params):
        add("WSTG-CLNT-04", "Redirect-like parameter observed; test client-side redirect safety.")

    if req.get("websocket_upgrade"):
        add("WSTG-CLNT-10", "WebSocket upgrade observed; validate socket auth/authz.")

    if any(f.get("finding_type") == "secret" for f in js_findings):
        add("WSTG-INFO-05", "JavaScript contained secret-like indicators; perform frontend leakage review.", "high")
        add("WSTG-CLNT-02", "JavaScript execution surface includes sensitive artifacts; test script abuse patterns.")
    if any(f.get("finding_type") == "obfuscation" for f in js_findings):
        add("WSTG-INFO-05", "Obfuscated/minified JavaScript observed; inspect for hidden routes/leaks.")
    if any(f.get("finding_type") == "endpoint" and "graphql" in str(f.get("category", "")).lower() for f in js_findings):
        add("WSTG-APIT-99", "JS-discovered GraphQL endpoint found; validate GraphQL security controls.")

    status_code = int((resp or {}).get("status_code") or 0)
    if status_code >= 500:
        add("WSTG-ERRH-01", f"Server error response ({status_code}) observed; test error handling leakage.", "high")
    if status_code in {301, 302, 303, 307, 308}:
        add("WSTG-CLNT-04", f"Redirect response ({status_code}) observed; test open redirect behavior.")

    recommendations = list(out.values())

    # Merge user-injected Markdown skills.
    for skill in markdown_skills.match_skills_for_request(req, resp, js_findings):
        recommendations.append(
            {
                "id": skill["id"],
                "name": skill["name"],
                "category_id": "SENTINEL-SKILL",
                "category_name": "Sentinel Custom Skill",
                "reference": "",
                "objectives": skill.get("tasks", [])[:3],
                "rationale": skill.get("rationale") or skill.get("description") or "Matched custom markdown skill trigger.",
                "confidence": skill.get("confidence", "medium"),
                "source_file": skill.get("source_file", ""),
                "linked_wstg_ids": skill.get("wstg_ids", []),
            }
        )

    # Deduplicate by ID while preserving highest confidence.
    dedup: dict[str, dict] = {}
    for rec in recommendations:
        rid = rec.get("id", "")
        if not rid:
            continue
        current = dedup.get(rid)
        if not current:
            dedup[rid] = rec
            continue
        if rec.get("confidence") == "high":
            current["confidence"] = "high"
    return list(dedup.values())


def recommend_for_snapshot(snapshot: dict, limit: int = 12) -> list[dict]:
    endpoints = snapshot.get("endpoints", []) or []
    js_findings = snapshot.get("js_findings", []) or []
    routes = snapshot.get("discovered_routes", []) or []
    redirects = snapshot.get("redirect_events", []) or []

    combined: dict[str, dict] = {}
    for endpoint in endpoints:
        req_like = {
            "method": endpoint.get("method", ""),
            "path": endpoint.get("normalized_path", endpoint.get("path", "")),
            "query_params": [],
            "normalized_path": endpoint.get("normalized_path", ""),
            "websocket_upgrade": False,
        }
        recs = recommend_for_request(req_like, None, js_findings=[])
        for rec in recs:
            existing = combined.get(rec["id"])
            if not existing:
                combined[rec["id"]] = rec
                continue
            if rec.get("confidence") == "high":
                existing["confidence"] = "high"

    if routes:
        route_str = " ".join(str(r.get("route", "")).lower() for r in routes[:80])
        if "graphql" in route_str:
            rec = _materialize("WSTG-APIT-99", "GraphQL routes discovered in traffic/JS mapping.", "high")
            if rec:
                combined[rec["id"]] = rec
        if "ws://" in route_str or "wss://" in route_str:
            rec = _materialize("WSTG-CLNT-10", "WebSocket routes discovered in traffic/JS mapping.")
            if rec:
                combined[rec["id"]] = rec

    if js_findings:
        source = _first_non_empty(
            [f"{x.get('source_host', '')}{x.get('source_path', '')}" for x in js_findings],
            "javascript bundle",
        )
        if any(f.get("finding_type") == "secret" for f in js_findings):
            rec = _materialize("WSTG-INFO-05", f"JavaScript finding(s) from {source} indicate potential information leakage.", "high")
            if rec:
                combined[rec["id"]] = rec
        if any(f.get("finding_type") == "obfuscation" for f in js_findings):
            rec = _materialize("WSTG-CLNT-02", f"Obfuscated/minified JavaScript from {source} warrants script-execution surface checks.")
            if rec:
                combined[rec["id"]] = rec

    if redirects:
        rec = _materialize("WSTG-CLNT-04", "Redirect chains observed in scope; validate open-redirect protections.", "high")
        if rec:
            combined[rec["id"]] = rec

    # Merge user-injected Markdown skills as global catalog entries so every
    # scope has the full skill set available.
    for skill in markdown_skills.load_markdown_skills():
        rid = skill.get("id", "")
        if not rid:
            continue
        merged = {
            "id": rid,
            "name": skill.get("name", rid),
            "category_id": "SENTINEL-SKILL",
            "category_name": "Sentinel Custom Skill",
            "reference": "",
            "objectives": (skill.get("tasks", []) or [])[:3],
            "rationale": skill.get("rationale") or skill.get("description") or "Matched custom markdown skill trigger.",
            "confidence": skill.get("confidence", "medium"),
            "source_file": skill.get("source_file", ""),
            "linked_wstg_ids": skill.get("wstg_ids", []),
        }
        existing = combined.get(rid)
        if not existing:
            combined[rid] = merged
        elif merged.get("confidence") == "high":
            existing["confidence"] = "high"

    # Keep stable ordering by ID to avoid noisy UI diffs.
    ordered = sorted(combined.values(), key=lambda x: x["id"])
    return ordered[:max(1, limit)]
