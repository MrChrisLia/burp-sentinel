"""Proxy import and JavaScript intelligence extraction.

This module extracts:
- JavaScript-discovered routes/endpoints
- Potential hardcoded secrets/API keys/tokens
- Obfuscation/minification signals
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Iterable
from urllib.parse import urlparse

from sentinel_api import parser

_ROUTE_PATTERN = re.compile(
    r"(?:https?://[a-zA-Z0-9._:-]+(?:/[a-zA-Z0-9._~!$&()*+,;=:@%/-]*)?|"
    r"wss?://[a-zA-Z0-9._:-]+(?:/[a-zA-Z0-9._~!$&()*+,;=:@%/-]*)?|"
    r"/(?:api|graphql|admin|internal|uploads?|downloads?|export)[a-zA-Z0-9._~!$&()*+,;=:@%/-]*)"
)

_CALL_ROUTE_PATTERN = re.compile(
    r"(?:fetch|axios(?:\.[a-z]+)?)\s*\(\s*['\"]([^'\"]{4,500})['\"]",
    re.I,
)

_BASE64_QUOTED_PATTERN = re.compile(r"['\"]([A-Za-z0-9+/]{24,}={0,2})['\"]")
_HEX_ESCAPE_PATTERN = re.compile(r"\\x([0-9a-fA-F]{2})")
_UNICODE_ESCAPE_PATTERN = re.compile(r"\\u([0-9a-fA-F]{4})")

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("stripe_live_key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b"), "high"),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "high"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "high"),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), "high"),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "medium"),
]

_GENERIC_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(api[_-]?key|apikey|secret|token|client[_-]?secret|access[_-]?token)\b
    \s*[:=]\s*
    ['\"]([A-Za-z0-9_\-./+=]{10,250})['\"]
    """
)

_STATIC_PATH_SUFFIXES = (
    ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
)


def _clean_route(route: str) -> str:
    route = route.strip().strip('"\'`')
    # Truncate if parser captured surrounding code fragments.
    for sep in ("'", '"', "`", " ", "\n", "\r", "\t", "(", ")", "{", "}", ","):
        idx = route.find(sep)
        if idx > 0:
            route = route[:idx]
            break
    # Drop common trailing punctuation from JS strings.
    while route and route[-1] in ",;.)]'\"":
        route = route[:-1]
    return route


def _looks_like_javascript(content_type: str, body: str) -> bool:
    ct = (content_type or "").lower()
    if "javascript" in ct or "ecmascript" in ct:
        return True
    if not body:
        return False
    if "<html" in body[:300].lower():
        return False
    hints = ("function(", "=>", "const ", "let ", "var ", "webpack", "sourceMappingURL", "__webpack_require__")
    return any(h in body for h in hints)


def _beautify_js(text: str) -> str:
    if not text:
        return ""
    out = text
    out = out.replace(";", ";\n")
    out = out.replace("{", "{\n").replace("}", "\n}\n")
    out = out.replace(",function", ",\nfunction")
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out


def _decode_escaped_js(text: str) -> str:
    if not text:
        return ""
    out = _HEX_ESCAPE_PATTERN.sub(lambda m: chr(int(m.group(1), 16)), text)
    out = _UNICODE_ESCAPE_PATTERN.sub(lambda m: chr(int(m.group(1), 16)), out)
    return out


def _decode_base64_candidates(text: str, limit: int = 40) -> list[str]:
    decoded: list[str] = []
    for m in _BASE64_QUOTED_PATTERN.finditer(text):
        if len(decoded) >= limit:
            break
        token = m.group(1)
        try:
            raw = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        if not raw or len(raw) < 8 or len(raw) > 4000:
            continue
        try:
            candidate = raw.decode("utf-8", errors="ignore")
        except ValueError:
            continue
        if not candidate:
            continue
        printable_ratio = sum(32 <= ord(c) <= 126 or c in "\n\r\t" for c in candidate) / max(len(candidate), 1)
        if printable_ratio < 0.9:
            continue
        if any(h in candidate.lower() for h in ("/api", "token", "secret", "graphql", "admin", "internal", "http://", "https://")):
            decoded.append(candidate)
    return decoded


def _collect_texts_for_analysis(body: str) -> tuple[str, list[str]]:
    beautified = _beautify_js(body)
    unescaped = _decode_escaped_js(body)
    b64 = _decode_base64_candidates(body)
    texts = [body, beautified, unescaped] + b64
    joined = "\n".join(x for x in texts if x)
    obfuscation_signals: list[str] = []
    if "\\x" in body or "\\u00" in body:
        obfuscation_signals.append("escaped-hex-or-unicode-strings")
    if b64:
        obfuscation_signals.append("embedded-base64-strings")
    if body.count("\n") < 8 and len(body) > 4000:
        obfuscation_signals.append("likely-minified-js")
    if re.search(r"\beval\s*\(", body):
        obfuscation_signals.append("eval-usage")
    return joined, obfuscation_signals


def _classify_route(path: str, full_route: str) -> str:
    if full_route.startswith(("ws://", "wss://")):
        return "websocket"
    pl = path.lower()
    if "graphql" in pl:
        return "graphql"
    if any(x in pl for x in ("admin", "internal", "export", "upload", "download", "debug", "config")):
        return "sensitive"
    return "api"


def _is_static_path(path: str) -> bool:
    p = path.lower().split("?", 1)[0]
    return p.endswith(_STATIC_PATH_SUFFIXES)


def _extract_route_candidates(text: str) -> list[str]:
    found: list[str] = []
    found.extend(_ROUTE_PATTERN.findall(text))
    found.extend(m.group(1) for m in _CALL_ROUTE_PATTERN.finditer(text))
    return found


def _route_records_from_candidates(candidates: Iterable[str]) -> list[dict]:
    discovered: dict[str, dict] = {}
    for raw in candidates:
        route = _clean_route(raw)
        if len(route) < 4:
            continue
        if not route.startswith(("/", "http://", "https://", "ws://", "wss://")):
            continue
        parsed_url = urlparse(route if route.startswith(("http://", "https://", "ws://", "wss://")) else f"https://placeholder{route}")
        path = parsed_url.path or route
        if not path or _is_static_path(path):
            continue

        route_type = _classify_route(path, route)
        discovered[route] = {
            "route": route,
            "route_type": route_type,
            "host": parsed_url.hostname,
            "normalized_path": parser.normalize_path(path),
        }
    return sorted(discovered.values(), key=lambda x: x["route"])


def _mask_secret(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return "[redacted]"
    return f"{v[:4]}...{v[-4:]}"


def _looks_placeholder_secret(value: str) -> bool:
    v = value.strip().lower()
    if len(v) < 10:
        return True
    if any(x in v for x in ("example", "sample", "dummy", "test", "changeme", "replace", "your_", "<", ">")):
        return True
    if len(set(v)) <= 3:
        return True
    return False


def _extract_secret_findings(text: str) -> list[dict]:
    out: dict[tuple[str, str], dict] = {}
    for category, pattern, confidence in _SECRET_PATTERNS:
        for m in pattern.finditer(text):
            raw = m.group(0)
            if _looks_placeholder_secret(raw):
                continue
            indicator = _mask_secret(raw)
            key = (category, indicator)
            out[key] = {
                "finding_type": "secret",
                "category": category,
                "indicator": indicator,
                "confidence": confidence,
                "evidence": f"{category}: {indicator}",
            }

    for m in _GENERIC_SECRET_ASSIGNMENT.finditer(text):
        kind = (m.group(1) or "").lower()
        raw = (m.group(2) or "").strip()
        if _looks_placeholder_secret(raw):
            continue
        indicator = f"{kind}={_mask_secret(raw)}"
        key = ("generic_hardcoded_secret", indicator)
        out[key] = {
            "finding_type": "secret",
            "category": "generic_hardcoded_secret",
            "indicator": indicator,
            "confidence": "medium",
            "evidence": f"hardcoded {kind}",
        }
    return sorted(out.values(), key=lambda x: (x["category"], x["indicator"]))


def _route_findings_from_routes(routes: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for r in routes:
        route = r.get("route", "")
        route_type = r.get("route_type", "api")
        if route_type in {"sensitive", "graphql", "websocket"}:
            findings.append(
                {
                    "finding_type": "endpoint",
                    "category": f"hidden_{route_type}_endpoint",
                    "indicator": route,
                    "confidence": "medium",
                    "evidence": f"JavaScript route: {route}",
                }
            )
    return findings


def analyze_javascript(response: str) -> dict:
    parsed = parser.parse_response(response, include_body=True)
    content_type = parsed.get("content_type", "")
    body = parsed.get("body", "")
    if not body or not _looks_like_javascript(content_type, body):
        return {"routes": [], "findings": [], "obfuscation_signals": []}

    analysis_text, obfuscation_signals = _collect_texts_for_analysis(body)
    routes = _route_records_from_candidates(_extract_route_candidates(analysis_text))

    findings: list[dict] = []
    findings.extend(_extract_secret_findings(analysis_text))
    findings.extend(_route_findings_from_routes(routes))
    findings.extend(
        {
            "finding_type": "obfuscation",
            "category": "javascript_obfuscation_signal",
            "indicator": sig,
            "confidence": "medium",
            "evidence": sig,
        }
        for sig in obfuscation_signals
    )

    unique: dict[tuple[str, str, str], dict] = {}
    for f in findings:
        key = (f.get("finding_type", ""), f.get("category", ""), f.get("indicator", ""))
        unique[key] = f
    findings_sorted = sorted(unique.values(), key=lambda x: (x["finding_type"], x["category"], x["indicator"]))
    return {"routes": routes, "findings": findings_sorted, "obfuscation_signals": obfuscation_signals}


def extract_js_routes(response: str) -> list[dict]:
    """Backward-compatible helper used by existing call sites/tests."""
    return analyze_javascript(response).get("routes", [])
