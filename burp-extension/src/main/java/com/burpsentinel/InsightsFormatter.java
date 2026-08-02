package com.burpsentinel;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class InsightsFormatter {
    private InsightsFormatter() {}

    public static String appSummary(String json) {
        StringBuilder out = new StringBuilder();
        out.append("App Understanding:\n");
        out.append("- ").append(value(json, "app_summary", "No summary yet.")).append("\n\n");

        appendList(out, "Frontend Hosts", arrayValues(json, "frontend_hosts"));
        appendList(out, "Likely API Hosts", arrayValues(json, "likely_api_hosts"));
        appendList(out, "Third-Party Hosts", arrayValues(json, "third_party_hosts"));
        appendList(out, "Observed Features", arrayValues(json, "observed_features"));
        appendList(out, "Important Objects", arrayValues(json, "important_objects"));
        appendList(out, "Likely Roles", arrayValues(json, "likely_roles"));
        appendList(out, "Highest Value Tests", arrayValues(json, "highest_value_tests"));
        appendList(out, "Recommended WSTG Skills", arrayValues(json, "wstg_recommended_skills"));
        appendList(out, "Untested Areas", arrayValues(json, "untested_areas"));
        appendList(out, "JS Secret Findings", arrayValues(json, "javascript_secret_findings"));
        appendList(out, "JS Hidden Endpoints", arrayValues(json, "javascript_hidden_endpoints"));
        appendList(out, "JS Obfuscation Signals", arrayValues(json, "javascript_obfuscation_signals"));
        appendList(out, "Redirect Targets", arrayValues(json, "redirect_targets"));

        String count = number(json, "endpoint_count");
        String redirectCount = number(json, "redirect_count");
        String jsCount = number(json, "javascript_findings_count");
        if (!count.isEmpty()) {
            out.append("Endpoint Count: ").append(count).append("\n");
            if ("0".equals(count.trim())) {
                out.append("\nWhy this may be empty:\n");
                out.append("- No synced traffic for this scope yet\n");
                out.append("- Scope name mismatch between sync and summary view\n");
                out.append("- All relevant hosts are currently excluded in domain filters\n");
            }
        }
        if (!jsCount.isEmpty()) {
            out.append("JavaScript Finding Count: ").append(jsCount).append("\n");
        }
        if (!redirectCount.isEmpty()) {
            out.append("Redirect Count: ").append(redirectCount).append("\n");
        }
        return out.toString();
    }

    public static String generatedQuests(String json) {
        StringBuilder out = new StringBuilder();
        out.append("Sentinel Generated Quests\n");
        out.append("======================\n\n");

        List<QuestBlock> quests = questBlocks(json);
        if (quests.isEmpty()) {
            out.append("No quests generated yet.\n");
            return out.toString();
        }

        int idx = 1;
        for (QuestBlock quest : quests) {
            out.append(idx++).append(". ").append(quest.name).append("\n");
            if (!quest.reason.isEmpty()) {
                out.append("   Reason: ").append(quest.reason).append("\n");
            }
            for (String task : quest.tasks) {
                out.append("   [ ] ").append(task).append("\n");
            }
            out.append("\n");
        }
        return out.toString();
    }

    public static String analyzedRequest(String json) {
        StringBuilder out = new StringBuilder();
        out.append("Sentinel Request Analysis\n");
        out.append("=======================\n\n");

        out.append("Endpoint Summary:\n");
        out.append("- ").append(value(json, "endpoint_summary", "No summary available.")).append("\n\n");

        out.append("Feature: ").append(value(json, "feature", "unknown")).append("\n");
        out.append("Workflow: ").append(value(json, "workflow", "unknown")).append("\n");
        String risk = number(json, "risk_score");
        if (!risk.isEmpty()) {
            out.append("Risk Score: ").append(risk).append("\n");
        }
        out.append("\n");

        appendList(out, "Sensitive Parameters", arrayValues(json, "sensitive_parameters"));
        appendList(out, "Likely Roles", arrayValues(json, "likely_roles"));

        List<RiskBlock> risks = riskBlocks(json);
        out.append("Likely Risks:\n");
        if (risks.isEmpty()) {
            out.append("- None detected from current evidence\n\n");
        } else {
            for (RiskBlock r : risks) {
                out.append("- ").append(r.category);
                if (!r.confidence.isEmpty()) {
                    out.append(" (confidence: ").append(r.confidence).append(")");
                }
                out.append("\n  Reason: ").append(r.reason).append("\n");
            }
            out.append("\n");
        }

        List<TestBlock> tests = testBlocks(json);
        out.append("Suggested Manual Tests:\n");
        if (tests.isEmpty()) {
            out.append("- None yet\n");
        } else {
            for (TestBlock test : tests) {
                out.append("- ").append(test.name).append("\n");
                if (!test.reason.isEmpty()) {
                    out.append("  Why: ").append(test.reason).append("\n");
                }
                for (String step : test.steps) {
                    out.append("  • ").append(step).append("\n");
                }
            }
        }

        return out.toString();
    }

    private static void appendList(StringBuilder out, String title, List<String> values) {
        out.append(title).append(":\n");
        if (values.isEmpty()) {
            out.append("- (none)\n\n");
            return;
        }
        for (String v : values) {
            out.append("- ").append(v).append("\n");
        }
        out.append("\n");
    }

    private static String value(String json, String key, String fallback) {
        Matcher m = Pattern.compile("\\\"" + Pattern.quote(key) + "\\\"\\s*:\\s*\\\"(.*?)\\\"", Pattern.DOTALL).matcher(json);
        if (!m.find()) {
            return fallback;
        }
        return unescape(m.group(1));
    }

    private static String number(String json, String key) {
        Matcher m = Pattern.compile("\\\"" + Pattern.quote(key) + "\\\"\\s*:\\s*([0-9]+)").matcher(json);
        return m.find() ? m.group(1) : "";
    }

    private static List<String> arrayValues(String json, String key) {
        Matcher m = Pattern.compile("\\\"" + Pattern.quote(key) + "\\\"\\s*:\\s*\\[(.*?)]", Pattern.DOTALL).matcher(json);
        if (!m.find()) {
            return List.of();
        }
        String inner = m.group(1);
        Matcher str = Pattern.compile("\\\"(.*?)\\\"", Pattern.DOTALL).matcher(inner);
        List<String> values = new ArrayList<>();
        while (str.find()) {
            values.add(unescape(str.group(1)));
        }
        return values;
    }

    private static List<QuestBlock> questBlocks(String json) {
        List<QuestBlock> out = new ArrayList<>();
        Matcher m = Pattern.compile("\\{\\s*\\\"name\\\"\\s*:\\s*\\\"(.*?)\\\".*?\\\"reason\\\"\\s*:\\s*\\\"(.*?)\\\".*?\\\"tasks\\\"\\s*:\\s*\\[(.*?)]\\s*}", Pattern.DOTALL).matcher(json);
        while (m.find()) {
            String name = unescape(m.group(1));
            String reason = unescape(m.group(2));
            String tasksBlob = m.group(3);
            List<String> tasks = new ArrayList<>();
            Matcher taskMatcher = Pattern.compile("\\\"description\\\"\\s*:\\s*\\\"(.*?)\\\"", Pattern.DOTALL).matcher(tasksBlob);
            while (taskMatcher.find()) {
                tasks.add(unescape(taskMatcher.group(1)));
            }
            out.add(new QuestBlock(name, reason, tasks));
        }
        return out;
    }

    private static List<RiskBlock> riskBlocks(String json) {
        List<RiskBlock> out = new ArrayList<>();
        Matcher m = Pattern.compile("\\{\\s*\\\"category\\\"\\s*:\\s*\\\"(.*?)\\\".*?\\\"reason\\\"\\s*:\\s*\\\"(.*?)\\\".*?\\\"confidence\\\"\\s*:\\s*\\\"(.*?)\\\".*?}", Pattern.DOTALL).matcher(json);
        while (m.find()) {
            out.add(new RiskBlock(unescape(m.group(1)), unescape(m.group(2)), unescape(m.group(3))));
        }
        return out;
    }

    private static List<TestBlock> testBlocks(String json) {
        List<TestBlock> out = new ArrayList<>();
        Matcher m = Pattern.compile("\\{\\s*\\\"name\\\"\\s*:\\s*\\\"(.*?)\\\".*?\\\"reason\\\"\\s*:\\s*\\\"(.*?)\\\".*?\\\"manual_steps\\\"\\s*:\\s*\\[(.*?)]", Pattern.DOTALL).matcher(json);
        while (m.find()) {
            String name = unescape(m.group(1));
            String reason = unescape(m.group(2));
            List<String> steps = new ArrayList<>();
            Matcher stepMatcher = Pattern.compile("\\\"(.*?)\\\"", Pattern.DOTALL).matcher(m.group(3));
            while (stepMatcher.find()) {
                steps.add(unescape(stepMatcher.group(1)));
            }
            out.add(new TestBlock(name, reason, steps));
        }
        return out;
    }

    private static String unescape(String s) {
        return s
                .replace("\\n", "\n")
                .replace("\\r", "")
                .replace("\\t", "\t")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
    }

    private record QuestBlock(String name, String reason, List<String> tasks) {}
    private record RiskBlock(String category, String reason, String confidence) {}
    private record TestBlock(String name, String reason, List<String> steps) {}
}
