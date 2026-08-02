package com.burpsentinel;

import burp.api.montoya.MontoyaApi;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class SentinelClient {
    private final MontoyaApi api;

    public SentinelClient(MontoyaApi api) {
        this.api = api;
    }

    public SyncResult sendProxyImport(String baseUrl, String scopeName, List<SentinelSyncController.CapturedItem> items) {
        if (baseUrl.isEmpty() || scopeName.isEmpty() || items.isEmpty()) {
            return new SyncResult(false, "Missing baseUrl/scopeName/items", 0, false);
        }

        String payload = JsonUtil.proxyImportPayload(scopeName, items);
        byte[] body = payload.getBytes(StandardCharsets.UTF_8);
        String endpoint = stripTrailingSlash(baseUrl) + "/proxy/import";

        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(endpoint).toURL().openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(8000);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setFixedLengthStreamingMode(body.length);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
            }

            int code = conn.getResponseCode();
            if (code >= 200 && code < 300) {
                return new SyncResult(true, "ok", code, false);
            }
            String responseText = readBody(conn);
            String msg = "Sentinel /proxy/import returned HTTP " + code + formatRetryAfter(conn) + ": " + truncate(responseText);
            api.logging().logToError(msg);
            return new SyncResult(false, msg, code, isRateLimited(code, responseText));
        } catch (IOException e) {
            api.logging().logToError("Sentinel /proxy/import request failed", e);
            return new SyncResult(false, "I/O error: " + e.getMessage(), 0, false);
        }
    }

    public ApiResult getAppSummary(String baseUrl, String scopeName) {
        // URLEncoder uses '+' for spaces, which is correct for query params
        // but not for path segments. FastAPI path params expect '%20'.
        String encodedScope = URLEncoder.encode(scopeName, StandardCharsets.UTF_8).replace("+", "%20");
        String endpoint = stripTrailingSlash(baseUrl) + "/app-summary/" + encodedScope;
        return request("GET", endpoint, null);
    }

    public ApiResult generateQuests(String baseUrl, String scopeName) {
        String endpoint = stripTrailingSlash(baseUrl) + "/generate-quests";
        String payload = "{\"scope_name\":\"" + JsonUtil.escape(scopeName) + "\",\"quest_type\":\"auto\"}";
        return request("POST", endpoint, payload);
    }

    public ApiResult listScopes(String baseUrl) {
        String endpoint = stripTrailingSlash(baseUrl) + "/scopes";
        return request("GET", endpoint, null);
    }

    public ApiResult createScope(String baseUrl, String scopeName) {
        String endpoint = stripTrailingSlash(baseUrl) + "/scopes";
        String payload = "{\"scope_name\":\"" + JsonUtil.escape(scopeName) + "\"}";
        return request("POST", endpoint, payload);
    }

    public ApiResult deleteScope(String baseUrl, String scopeName) {
        String encodedScope = URLEncoder.encode(scopeName, StandardCharsets.UTF_8).replace("+", "%20");
        String endpoint = stripTrailingSlash(baseUrl) + "/scopes/" + encodedScope;
        return request("DELETE", endpoint, null);
    }

    public ApiResult getScopeHosts(String baseUrl, String scopeName) {
        String encodedScope = URLEncoder.encode(scopeName, StandardCharsets.UTF_8).replace("+", "%20");
        String endpoint = stripTrailingSlash(baseUrl) + "/scopes/" + encodedScope + "/hosts";
        return request("GET", endpoint, null, 15_000);
    }

    public ApiResult setIncludedHosts(String baseUrl, String scopeName, List<String> hosts) {
        if (baseUrl.isEmpty() || scopeName.isEmpty() || hosts.isEmpty()) {
            return new ApiResult(false, 0, "Missing baseUrl/scopeName/hosts", false);
        }
        StringBuilder hostsJson = new StringBuilder("[");
        for (int i = 0; i < hosts.size(); i++) {
            if (i > 0) {
                hostsJson.append(",");
            }
            hostsJson.append("\"").append(JsonUtil.escape(hosts.get(i))).append("\"");
        }
        hostsJson.append("]");
        String payload = "{"
                + "\"hosts\":" + hostsJson + ","
                + "\"in_scope\":true,"
                + "\"exclusive\":true"
                + "}";
        String encodedScope = URLEncoder.encode(scopeName, StandardCharsets.UTF_8).replace("+", "%20");
        String endpoint = stripTrailingSlash(baseUrl) + "/scopes/" + encodedScope + "/hosts";
        return request("POST", endpoint, payload, 15_000);
    }

    public ApiResult analyzeRequest(
            String baseUrl,
            String scopeName,
            String knownRole,
            String requestRaw,
            String responseRaw,
            String sourceTool
    ) {
        String endpoint = stripTrailingSlash(baseUrl) + "/analyze-request";
        String payload = "{"
                + "\"scope_name\":\"" + JsonUtil.escape(scopeName) + "\","
                + "\"known_role\":\"" + JsonUtil.escape(knownRole) + "\","
                + "\"request\":\"" + JsonUtil.escape(requestRaw) + "\","
                + "\"response\":\"" + JsonUtil.escape(responseRaw) + "\","
                + "\"source_tool\":\"" + JsonUtil.escape(sourceTool) + "\""
                + "}";
        return request("POST", endpoint, payload);
    }

    public ApiResult chat(String baseUrl, String scopeName, String message) {
        String endpoint = stripTrailingSlash(baseUrl) + "/chat";
        String payload = "{"
                + "\"scope_name\":\"" + JsonUtil.escape(scopeName) + "\","
                + "\"message\":\"" + JsonUtil.escape(message) + "\""
                + "}";
        return request("POST", endpoint, payload, 90_000);
    }

    private ApiResult request(String method, String endpoint, String payload) {
        return request(method, endpoint, payload, 10_000);
    }

    private ApiResult request(String method, String endpoint, String payload, int readTimeoutMs) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(endpoint).toURL().openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(readTimeoutMs);
            conn.setRequestMethod(method);
            conn.setRequestProperty("Accept", "application/json");

            if ("POST".equals(method)) {
                byte[] body = payload == null ? new byte[0] : payload.getBytes(StandardCharsets.UTF_8);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                conn.setFixedLengthStreamingMode(body.length);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(body);
                }
            }

            int code = conn.getResponseCode();
            String responseText = readBody(conn);
            boolean ok = code >= 200 && code < 300;
            boolean rateLimited = isRateLimited(code, responseText);
            if (!ok) {
                api.logging().logToError(method + " " + endpoint + " returned HTTP " + code + formatRetryAfter(conn) + ": " + truncate(responseText));
            }
            return new ApiResult(ok, code, responseText, rateLimited);
        } catch (SocketTimeoutException e) {
            api.logging().logToError(method + " " + endpoint + " timed out", e);
            return new ApiResult(false, 0, "I/O timeout after " + (readTimeoutMs / 1000) + "s waiting for backend response.", false);
        } catch (IOException e) {
            api.logging().logToError(method + " " + endpoint + " request failed", e);
            return new ApiResult(false, 0, "I/O error: " + e.getMessage(), false);
        }
    }

    private static String stripTrailingSlash(String url) {
        if (url.endsWith("/")) {
            return url.substring(0, url.length() - 1);
        }
        return url;
    }

    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        if (s.length() <= 280) {
            return s;
        }
        return s.substring(0, 280) + "...";
    }

    private static String readBody(HttpURLConnection conn) throws IOException {
        InputStream stream = conn.getErrorStream() != null ? conn.getErrorStream() : conn.getInputStream();
        if (stream == null) {
            return "";
        }
        byte[] data = stream.readAllBytes();
        return new String(data, StandardCharsets.UTF_8);
    }

    private static boolean isRateLimited(int statusCode, String body) {
        if (statusCode == 429) {
            return true;
        }
        if (body == null) {
            return false;
        }
        String low = body.toLowerCase();
        return low.contains("rate limit") || low.contains("too many requests");
    }

    private static String formatRetryAfter(HttpURLConnection conn) {
        String retryAfter = conn.getHeaderField("Retry-After");
        if (retryAfter == null || retryAfter.isBlank()) {
            return "";
        }
        return " (Retry-After: " + retryAfter.trim() + ")";
    }

    public record SyncResult(boolean success, String message, int statusCode, boolean rateLimited) {}
    public record ApiResult(boolean success, int statusCode, String body, boolean rateLimited) {}
}
