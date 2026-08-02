"""Load user-provided Markdown skills and match them against traffic evidence.

Skill files are Markdown with YAML frontmatter. Example:

---
id: SENTINEL-CUSTOM-001
name: Admin Export Abuse Checks
confidence: medium
rationale: Admin/export endpoints observed.
triggers:
  methods: [GET, POST]
  path_contains: ["/admin", "/export"]
  query_params: [id]
  js_finding_types: [endpoint]
tasks:
  - Replay endpoint with lower-privileged role.
  - Swap identifiers and compare response differences.
wstg_ids: [WSTG-ATHZ-04, WSTG-APIT-02]
---
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml


def _skills_dir() -> str:
    env = os.getenv("SENTINEL_SKILLS_DIR", "").strip()
    if env:
        return env
    return os.path.join(os.path.dirname(__file__), "skills")


def skills_dir() -> str:
    return _skills_dir()


def _extract_frontmatter(markdown: str) -> tuple[dict, str]:
    text = markdown.replace("\r\n", "\n")
    if not text.startswith("---\n"):
        return {}, markdown
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}, markdown
    block = text[4:end]
    body = text[end + 5 :]
    try:
        data = yaml.safe_load(block) or {}
    except Exception:
        return {}, markdown
    if not isinstance(data, dict):
        return {}, markdown
    return data, body


def _clean_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        item = value.strip()
        return [item] if item else []
    if not isinstance(value, list):
        return []
    out = []
    for x in value:
        s = str(x).strip()
        if s:
            out.append(s)
    return out


@lru_cache(maxsize=1)
def load_markdown_skills() -> list[dict]:
    root = Path(_skills_dir())
    if not root.exists() or not root.is_dir():
        return []

    skills: list[dict] = []
    for file in sorted(root.rglob("*.md")):
        try:
            raw = file.read_text(encoding="utf-8")
        except OSError:
            continue
        meta, body = _extract_frontmatter(raw)
        if not meta:
            continue
        skill_id = str(meta.get("id", "")).strip()
        name = str(meta.get("name", "") or meta.get("title", "")).strip()
        if not skill_id or not name:
            continue

        triggers = meta.get("triggers", {}) or {}
        if not isinstance(triggers, dict):
            triggers = {}

        skills.append(
            {
                "id": skill_id,
                "name": name,
                "description": str(meta.get("description", "")).strip(),
                "rationale": str(meta.get("rationale", "")).strip(),
                "confidence": str(meta.get("confidence", "medium")).strip().lower() or "medium",
                "manual_only": bool(meta.get("manual_only", False)),
                "wstg_ids": _clean_list(meta.get("wstg_ids")),
                "triggers": {
                    "methods": [m.upper() for m in _clean_list(triggers.get("methods"))],
                    "path_contains": [x.lower() for x in _clean_list(triggers.get("path_contains"))],
                    "query_params": [x.lower() for x in _clean_list(triggers.get("query_params"))],
                    "status_codes": [str(x).strip() for x in _clean_list(triggers.get("status_codes"))],
                    "js_finding_types": [x.lower() for x in _clean_list(triggers.get("js_finding_types"))],
                    "js_categories": [x.lower() for x in _clean_list(triggers.get("js_categories"))],
                    "route_types": [x.lower() for x in _clean_list(triggers.get("route_types"))],
                    "route_contains": [x.lower() for x in _clean_list(triggers.get("route_contains"))],
                    "requires_auth": triggers.get("requires_auth"),
                },
                "tasks": _clean_list(meta.get("tasks")),
                "source_file": str(file),
                "body": body.strip(),
            }
        )
    return skills


def reload_markdown_skills() -> list[dict]:
    load_markdown_skills.cache_clear()
    return load_markdown_skills()


def _request_matches(skill: dict, req: dict, resp: dict | None, js_findings: list[dict]) -> bool:
    if skill.get("manual_only"):
        return False
    triggers = skill.get("triggers", {})
    method = str(req.get("method", "")).upper()
    path = str(req.get("path", "")).lower()
    query_params = [str(x).lower() for x in (req.get("query_params", []) or [])]
    status_code = str(int((resp or {}).get("status_code") or 0))
    js_types = {str(f.get("finding_type", "")).lower() for f in (js_findings or [])}
    js_categories = {str(f.get("category", "")).lower() for f in (js_findings or [])}
    auth_observed = bool(req.get("auth_header_present") or req.get("cookies_present"))

    methods = triggers.get("methods", [])
    if methods and method not in methods:
        return False

    path_contains = triggers.get("path_contains", [])
    if path_contains and not any(token in path for token in path_contains):
        return False

    required_q = triggers.get("query_params", [])
    if required_q and not any(p in query_params for p in required_q):
        return False

    status_codes = triggers.get("status_codes", [])
    if status_codes and status_code not in status_codes:
        return False

    required_js_types = triggers.get("js_finding_types", [])
    if required_js_types and not any(t in js_types for t in required_js_types):
        return False

    required_js_categories = triggers.get("js_categories", [])
    if required_js_categories and not any(c in js_categories for c in required_js_categories):
        return False

    req_auth = triggers.get("requires_auth")
    if isinstance(req_auth, bool) and auth_observed != req_auth:
        return False

    return True


def match_skills_for_request(req: dict, resp: dict | None = None, js_findings: list[dict] | None = None) -> list[dict]:
    js_findings = js_findings or []
    out: list[dict] = []
    for skill in load_markdown_skills():
        if _request_matches(skill, req, resp, js_findings):
            out.append(skill)
    return out


def match_skills_for_snapshot(snapshot: dict) -> list[dict]:
    endpoints = snapshot.get("endpoints", []) or []
    js_findings = snapshot.get("js_findings", []) or []
    routes = snapshot.get("discovered_routes", []) or []

    route_types = {str(r.get("route_type", "")).lower() for r in routes}
    route_text = " ".join(str(r.get("route", "")).lower() for r in routes)

    matched_ids: set[str] = set()
    out: list[dict] = []
    for skill in load_markdown_skills():
        triggers = skill.get("triggers", {})
        need_route_types = triggers.get("route_types", [])
        need_route_contains = triggers.get("route_contains", [])
        route_ok = True
        if need_route_types and not any(rt in route_types for rt in need_route_types):
            route_ok = False
        if need_route_contains and not any(token in route_text for token in need_route_contains):
            route_ok = False
        if not route_ok:
            continue

        # If endpoint-like triggers exist, any matching endpoint should activate the skill.
        endpoint_match = False
        for e in endpoints:
            req_like = {
                "method": e.get("method", ""),
                "path": e.get("path", e.get("normalized_path", "")),
                "query_params": [],
                "auth_header_present": bool(e.get("auth_observed")),
                "cookies_present": bool(e.get("auth_observed")),
            }
            if _request_matches(skill, req_like, None, js_findings):
                endpoint_match = True
                break

        # Skills with only JS/route-based conditions may not need endpoint evidence.
        if not endpoint_match:
            has_endpoint_conditions = bool(
                triggers.get("methods", [])
                or triggers.get("path_contains", [])
                or triggers.get("query_params", [])
                or isinstance(triggers.get("requires_auth"), bool)
            )
            if has_endpoint_conditions:
                continue
            if not _request_matches(
                skill,
                {"method": "", "path": "", "query_params": [], "auth_header_present": False, "cookies_present": False},
                None,
                js_findings,
            ):
                continue

        if skill["id"] in matched_ids:
            continue
        matched_ids.add(skill["id"])
        out.append(skill)
    return out
