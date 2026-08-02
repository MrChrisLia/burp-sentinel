package com.burpsentinel;

import java.util.List;

public final class JsonUtil {
    private JsonUtil() {}

    public static String proxyImportPayload(String scopeName, List<SentinelSyncController.CapturedItem> items) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"scope_name\":\"").append(escape(scopeName)).append("\",");
        sb.append("\"items\":[");

        for (int i = 0; i < items.size(); i++) {
            SentinelSyncController.CapturedItem it = items.get(i);
            if (i > 0) {
                sb.append(',');
            }
            sb.append('{')
                    .append("\"request\":\"").append(escape(it.request())).append("\",")
                    .append("\"response\":\"").append(escape(it.response())).append("\",")
                    .append("\"tool\":\"").append(escape(it.tool())).append("\",")
                    .append("\"timestamp\":\"").append(escape(it.timestamp())).append("\"")
                    .append('}');
        }
        sb.append(']');
        sb.append('}');
        return sb.toString();
    }

    public static String escape(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }
}
