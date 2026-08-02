"""Domain and endpoint classification helpers used by analyze/import flows."""
from __future__ import annotations

from urllib.parse import urlparse

from sentinel_api import parser

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
_ID_PARAM_HINTS = (
    "id", "user_id", "account_id", "org_id", "organization_id",
    "tenant_id", "project_id", "invoice_id", "order_id",
)
_SENSITIVE_PATH_HINTS = (
    "admin", "billing", "payment", "export", "upload", "download", "internal", "mfa",
)
_ROLE_HINTS = ("role", "permission", "is_admin", "owner")
_ROLE_NAMES = ("owner", "admin", "member", "viewer", "user", "guest")
_THIRD_PARTY_HINTS = (
    "stripe", "sentry", "segment", "hotjar", "google-analytics", "doubleclick", "mixpanel",
)
_ASSET_HINTS = ("cdn", "static", "assets", "img", "images", "fonts")
_FILE_HINTS = ("files", "uploads", "download")
_OBJECT_HINTS = (
    "user", "users", "account", "accounts", "organization", "organizations", "org", "tenant",
    "project", "projects", "membership", "memberships", "member", "members", "invitation",
    "invitations", "invoice", "invoices", "plan", "plans", "subscription", "subscriptions",
    "session", "sessions", "auth", "token", "tokens", "billing", "payment", "payments", "file", "files",
)


def _host_from_url(url: str | None) -> str:
    if not url:
        return ""
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def classify_host(req: dict, resp: dict | None = None) -> str:
    """Classify domain using passive signals from request/response."""
    host = (req.get("host") or "").lower()
    path = (req.get("path") or "").lower()
    content_type = (resp or {}).get("content_type", "").lower()

    if not host:
        return "unknown"
    if req.get("websocket_upgrade") or host.startswith("ws.") or host.startswith("wss."):
        return "websocket"
    if "graphql" in host or "graphql" in path:
        return "graphql"
    if any(h in host for h in _THIRD_PARTY_HINTS):
        return "third_party"
    if any(h in host for h in _FILE_HINTS) or any(h in path for h in _FILE_HINTS):
        return "file_storage"
    if any(h in host for h in _ASSET_HINTS) or path.endswith((".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2")):
        return "asset"
    if "auth" in host or any(x in path for x in ("/login", "/logout", "/session", "/oauth", "/mfa")):
        return "auth"
    if "api" in host:
        return "likely_first_party_api"
    if "text/html" in content_type and req.get("method") == "GET":
        return "frontend"
    if req.get("origin") and _host_from_url(req.get("origin")) and _host_from_url(req.get("origin")) != host:
        return "likely_first_party_api"
    if req.get("referer") and _host_from_url(req.get("referer")) and _host_from_url(req.get("referer")) != host:
        return "likely_first_party_api"
    return "unknown"


def relationship_from_headers(req: dict, resp: dict | None = None) -> dict | None:
    """Infer frontend->API host relationship from Origin/Referer/CORS evidence."""
    target = (req.get("host") or "").lower()
    if not target:
        return None

    origin_host = _host_from_url(req.get("origin"))
    referer_host = _host_from_url(req.get("referer"))
    source = origin_host or referer_host
    if not source or source == target:
        return None

    evidence: list[str] = []
    if req.get("referer"):
        evidence.append(f"Referer: {req['referer']}")
    if req.get("origin"):
        evidence.append(f"Origin: {req['origin']}")

    cors = (resp or {}).get("cors_headers", {})
    allow_origin = cors.get("access-control-allow-origin")
    if allow_origin:
        evidence.append(f"CORS allows {allow_origin}")

    confidence = "high" if allow_origin and (origin_host in allow_origin or allow_origin == "*") else "medium"
    return {
        "source": source,
        "target": target,
        "relationship_type": "frontend_calls_api",
        "evidence": evidence,
        "confidence": confidence,
    }


def risk_score(req: dict) -> int:
    score = 0
    if req.get("auth_header_present") or req.get("cookies_present"):
        score += 2
    if "{id}" in parser.normalize_path(req.get("path", "")):
        score += 2
    if req.get("method") in _STATE_CHANGING:
        score += 1
    low = (req.get("path") or "").lower()
    if any(h in low for h in _SENSITIVE_PATH_HINTS):
        score += 2
    keys = req.get("body_shape", {}).get("keys", []) if isinstance(req.get("body_shape"), dict) else []
    if any(any(r in k.lower() for r in _ROLE_HINTS) for k in keys):
        score += 2
    if "graphql" in low:
        score += 1
    return score


def sensitive_parameters(req: dict) -> list[str]:
    params = [p for p in req.get("query_params", []) if any(h in p.lower() for h in _ID_PARAM_HINTS)]
    if "{id}" in parser.normalize_path(req.get("path", "")):
        params.append("path_object_id")
    keys = req.get("body_shape", {}).get("keys", []) if isinstance(req.get("body_shape"), dict) else []
    for key in keys:
        if any(h in key.lower() for h in _ID_PARAM_HINTS + _ROLE_HINTS):
            params.append(key)
    return sorted(set(params))


def guess_feature(path: str) -> str:
    norm = parser.normalize_path(path)
    for seg in norm.split("/"):
        if seg and seg not in ("api", "v1", "v2", "{id}"):
            return seg
    return "unknown"


def infer_roles(req: dict, resp: dict | None = None) -> list[str]:
    roles: set[str] = set()
    path = (req.get("path") or "").lower()
    keys = req.get("body_shape", {}).get("keys", []) if isinstance(req.get("body_shape"), dict) else []
    resp_keys = (resp or {}).get("body_shape", {}).get("keys", []) if isinstance((resp or {}).get("body_shape"), dict) else []

    for role in _ROLE_NAMES:
        if f"/{role}" in path or f"_{role}" in path:
            roles.add(role)
    for key in list(keys) + list(resp_keys):
        low = str(key).lower()
        for role in _ROLE_NAMES:
            if role in low:
                roles.add(role)
    return sorted(roles)


def infer_business_objects(req: dict, resp: dict | None = None) -> list[str]:
    objects: set[str] = set()
    path = parser.normalize_path(req.get("path", ""))
    segments = [s.lower() for s in path.split("/") if s]
    req_keys = req.get("body_shape", {}).get("keys", []) if isinstance(req.get("body_shape"), dict) else []
    resp_keys = (resp or {}).get("body_shape", {}).get("keys", []) if isinstance((resp or {}).get("body_shape"), dict) else []

    for seg in segments:
        if seg in {"api", "v1", "v2", "{id}"}:
            continue
        if seg in _OBJECT_HINTS:
            objects.add(seg[:-1] if seg.endswith("s") and len(seg) > 3 else seg)
    for key in req.get("query_params", []):
        low = key.lower()
        if low.endswith("_id"):
            objects.add(low[:-3])
    for key in list(req_keys) + list(resp_keys):
        low = str(key).lower()
        if low in _OBJECT_HINTS:
            objects.add(low[:-1] if low.endswith("s") and len(low) > 3 else low)
        elif low.endswith("_id") and len(low) > 3:
            objects.add(low[:-3])
    objects.update(sensitive_parameters(req))
    return sorted(x for x in objects if x)
