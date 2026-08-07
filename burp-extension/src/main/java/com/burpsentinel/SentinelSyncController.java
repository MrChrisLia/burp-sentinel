package com.burpsentinel;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.KeyStroke;
import javax.swing.JOptionPane;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import javax.swing.JTextPane;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class SentinelSyncController {
    private static final long IDLE_SYNC_SUPPRESS_MS = 60_000L;

    private final MontoyaApi api;
    private final SentinelClient client;
    private final ScheduledExecutorService scheduler;

    private final JPanel panel;
    private final JTextField backendField;
    private final JLabel currentScopeValue;
    private final JTextField roleField;
    private final JTextField intervalField;
    private final JTextField domainFilterField;
    private final JCheckBox includeExistingBox;
    private final JCheckBox runningBox;
    private final JTextArea logs;
    private final JTextArea insights;
    private final JTextPane chatTranscript;
    private final JTextField chatInput;
    private final JButton chatSendButton;

    private final DefaultTableModel hostTableModel;
    private final JTable hostTable;
    private final TableRowSorter<DefaultTableModel> hostSorter;
    private final Map<String, HostRule> hostRules;

    private volatile int lastSyncedId = 0;
    private volatile int lastObservedRequestId = 0;
    private volatile long lastNewRequestSeenAtMs = System.currentTimeMillis();
    private volatile boolean syncSuppressedForIdle = false;
    private volatile boolean started = false;
    private volatile int chatPlaceholderOffset = -1;

    public SentinelSyncController(MontoyaApi api) {
        this.api = api;
        this.client = new SentinelClient(api);
        this.scheduler = Executors.newSingleThreadScheduledExecutor();
        this.hostRules = new ConcurrentHashMap<>();

        this.backendField = new JTextField("http://localhost:8000", 24);
        this.currentScopeValue = new JLabel("Burp Project");
        this.currentScopeValue.setHorizontalAlignment(SwingConstants.LEFT);
        this.roleField = new JTextField("member", 10);
        this.intervalField = new JTextField("3", 4);
        this.domainFilterField = new JTextField("", 18);
        this.includeExistingBox = new JCheckBox("Sync Existing History On Start", true);
        this.runningBox = new JCheckBox("Auto Sync Running", false);
        this.logs = new JTextArea();
        this.logs.setEditable(false);
        this.logs.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        this.insights = new JTextArea();
        this.insights.setEditable(false);
        this.insights.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        this.chatTranscript = new JTextPane();
        this.chatTranscript.setEditable(false);
        this.chatTranscript.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        this.chatTranscript.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        this.chatInput = new JTextField(24);
        this.chatSendButton = new JButton("Send");

        this.hostTableModel = new DefaultTableModel(new Object[]{"Include", "Host", "Seen"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0) {
                    return Boolean.class;
                }
                if (columnIndex == 2) {
                    return Integer.class;
                }
                return String.class;
            }
        };
        this.hostTable = new JTable(hostTableModel);
        this.hostTable.setFillsViewportHeight(true);
        this.hostTable.setRowHeight(24);
        this.hostTable.getColumnModel().getColumn(0).setMaxWidth(70);
        this.hostTable.getColumnModel().getColumn(2).setMaxWidth(70);

        this.hostSorter = new TableRowSorter<>(hostTableModel);
        this.hostTable.setRowSorter(hostSorter);

        bindHostTableEvents();
        bindDomainFilter();
        this.panel = buildUi();
    }

    public JPanel ui() {
        return panel;
    }

    public void start() {
        if (started) {
            return;
        }
        started = true;

        registerContextMenu();
        refreshHostsFromHistory();
        lastObservedRequestId = currentMaxId();
        lastNewRequestSeenAtMs = System.currentTimeMillis();
        syncSuppressedForIdle = false;

        if (!includeExistingBox.isSelected()) {
            lastSyncedId = currentMaxId();
            log("Starting from current tip of history. lastSyncedId=" + lastSyncedId);
        }

        scheduler.scheduleWithFixedDelay(this::syncOnceSafe, 2, intervalSeconds(), TimeUnit.SECONDS);
    }

    /** Right-click "Send to Sentinel" in the Proxy history (and anywhere else
     * Burp exposes selected request/response pairs). */
    private void registerContextMenu() {
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                if (event.selectedRequestResponses().isEmpty()) {
                    return List.of();
                }
                javax.swing.JMenuItem item = new javax.swing.JMenuItem("Send to Sentinel");
                item.addActionListener(e -> sendSelectionToSentinel(event.selectedRequestResponses()));
                return List.of(item);
            }
        });
    }

    /** Push explicitly selected requests/responses into the current scope —
     * same backend import pipeline the auto-sync uses. */
    private void sendSelectionToSentinel(List<HttpRequestResponse> messages) {
        if (messages == null || messages.isEmpty()) {
            return;
        }
        String baseUrl = backendField.getText().trim();
        String scope = currentScope();
        if (baseUrl.isEmpty() || scope.isEmpty()) {
            log("Send to Sentinel: no scope selected. Create/select a scope first.");
            setInsights("No scope selected.\n\nCreate or load a scope in the Sentinel Insights tab first.");
            return;
        }
        List<CapturedItem> items = new ArrayList<>();
        for (HttpRequestResponse hrr : messages) {
            String requestRaw = hrr.request() == null ? "" : hrr.request().toString();
            String responseRaw = (hrr.hasResponse() && hrr.response() != null) ? hrr.response().toString() : "";
            items.add(new CapturedItem(requestRaw, responseRaw, "context-menu", ""));
        }
        SentinelClient.SyncResult result = client.sendProxyImport(baseUrl, scope, items);
        if (result.success()) {
            log("Sent " + items.size() + " item(s) to Sentinel (scope \"" + scope + "\").");
            pushHostRulesToBackend();
        } else {
            log("Send to Sentinel failed (HTTP " + result.statusCode() + ").");
            setInsights("Failed to send to Sentinel.\n\n" + result.message());
        }
    }

    private JPanel buildUi() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel config = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        config.setBorder(BorderFactory.createTitledBorder("Connection & Scope"));
        config.add(new JLabel("Sentinel Backend"));
        config.add(backendField);
        config.add(new JLabel("Current Scope"));
        currentScopeValue.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 8));
        config.add(currentScopeValue);
        config.add(new JLabel("Role"));
        config.add(roleField);
        config.add(new JLabel("Interval (s)"));
        config.add(intervalField);
        config.add(includeExistingBox);
        config.add(runningBox);

        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        actionRow.setBorder(BorderFactory.createTitledBorder("Actions"));

        JComboBox<String> syncActions = new JComboBox<>(new String[]{
                "Sync Now",
                "Reset Cursor"
        });
        JButton runSync = new JButton("Run");
        runSync.addActionListener(e -> runSyncAction(String.valueOf(syncActions.getSelectedItem())));

        JComboBox<String> scopeActions = new JComboBox<>(new String[]{
                "Load Scope",
                "Save Scope As...",
                "Create Scope",
                "Delete Scope"
        });
        JButton runScope = new JButton("Run");
        runScope.addActionListener(e -> runInBackground(() -> runScopeAction(String.valueOf(scopeActions.getSelectedItem()))));

        JComboBox<String> insightActions = new JComboBox<>(new String[]{
                "View App Summary",
                "Generate Quests",
                "Analyze Latest"
        });
        JButton runInsight = new JButton("Run");
        runInsight.addActionListener(e -> runInBackground(() -> runInsightAction(String.valueOf(insightActions.getSelectedItem()))));

        actionRow.add(new JLabel("Sync:"));
        actionRow.add(syncActions);
        actionRow.add(runSync);
        actionRow.add(new JLabel("Scope:"));
        actionRow.add(scopeActions);
        actionRow.add(runScope);
        actionRow.add(new JLabel("Insights:"));
        actionRow.add(insightActions);
        actionRow.add(runInsight);

        JPanel hostPanel = new JPanel(new BorderLayout(6, 6));
        hostPanel.setBorder(BorderFactory.createTitledBorder("Domains / Subdomains"));

        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        filterRow.add(new JLabel("Filter:"));
        filterRow.add(domainFilterField);
        JButton clearFilter = new JButton("Clear");
        clearFilter.addActionListener(e -> domainFilterField.setText(""));
        filterRow.add(clearFilter);
        JComboBox<String> domainActions = new JComboBox<>(new String[]{
                "Only Include Filter Matches",
                "Include Filter Matches",
                "Exclude Filter Matches",
                "Include Selected",
                "Exclude Selected",
                "Include All",
                "Exclude All",
                "Refresh Domains"
        });
        JButton runDomainAction = new JButton("Apply");
        runDomainAction.addActionListener(e -> runDomainAction(String.valueOf(domainActions.getSelectedItem())));
        filterRow.add(domainActions);
        filterRow.add(runDomainAction);
        filterRow.add(Box.createHorizontalStrut(8));
        filterRow.add(new JLabel("Shortcut: select row and press 'x' to include/exclude"));

        hostPanel.add(filterRow, BorderLayout.NORTH);
        hostPanel.add(new JScrollPane(hostTable), BorderLayout.CENTER);

        JScrollPane insightsPane = new JScrollPane(insights);
        insightsPane.setBorder(BorderFactory.createTitledBorder("Sentinel Insights"));

        JPanel chatPanel = new JPanel(new BorderLayout(6, 6));
        chatPanel.setBorder(BorderFactory.createTitledBorder("Sentinel Chat"));
        JScrollPane chatScroll = new JScrollPane(chatTranscript);
        chatPanel.add(chatScroll, BorderLayout.CENTER);

        JPanel chatInputRow = new JPanel(new BorderLayout(6, 6));
        chatInputRow.add(chatInput, BorderLayout.CENTER);
        chatInputRow.add(chatSendButton, BorderLayout.EAST);
        chatPanel.add(chatInputRow, BorderLayout.SOUTH);

        chatSendButton.addActionListener(e -> sendChatMessage());
        chatInput.addActionListener(e -> sendChatMessage());

        JSplitPane insightsChatSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, insightsPane, chatPanel);
        insightsChatSplit.setResizeWeight(0.58);

        JScrollPane logPane = new JScrollPane(logs);
        logPane.setBorder(BorderFactory.createTitledBorder("Sync Logs"));

        JSplitPane lowerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, insightsChatSplit, logPane);
        lowerSplit.setResizeWeight(0.72);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, hostPanel, lowerSplit);
        mainSplit.setResizeWeight(0.4);

        JPanel top = new JPanel(new BorderLayout());
        top.add(config, BorderLayout.CENTER);
        top.add(actionRow, BorderLayout.SOUTH);

        root.add(top, BorderLayout.NORTH);
        root.add(mainSplit, BorderLayout.CENTER);
        return root;
    }

    private void bindHostTableEvents() {
        hostTableModel.addTableModelListener(e -> {
            if (e.getType() != TableModelEvent.UPDATE || e.getColumn() != 0) {
                return;
            }
            int modelRow = e.getFirstRow();
            if (modelRow < 0 || modelRow >= hostTableModel.getRowCount()) {
                return;
            }
            String host = String.valueOf(hostTableModel.getValueAt(modelRow, 1));
            boolean include = Boolean.TRUE.equals(hostTableModel.getValueAt(modelRow, 0));
            hostRules.compute(host, (k, v) -> {
                HostRule rule = v == null ? new HostRule() : v;
                rule.include = include;
                return rule;
            });
            pushHostRulesToBackend();
        });

        hostTable.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                .put(KeyStroke.getKeyStroke('x'), "toggleInclude");
        hostTable.getActionMap().put("toggleInclude", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                toggleSelectedHosts();
            }
        });
    }

    private void bindDomainFilter() {
        domainFilterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                applyDomainFilter();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                applyDomainFilter();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                applyDomainFilter();
            }
        });
    }

    private void applyDomainFilter() {
        String text = domainFilterField.getText().trim();
        if (text.isEmpty()) {
            hostSorter.setRowFilter(null);
            return;
        }
        hostSorter.setRowFilter(RowFilter.regexFilter("(?i)" + PatternSafe.quote(text), 1));
    }

    private void runSyncAction(String action) {
        if ("Reset Cursor".equals(action)) {
            lastSyncedId = currentMaxId();
            log("Cursor reset. lastSyncedId=" + lastSyncedId);
            return;
        }
        syncOnceManual();
    }

    private void runScopeAction(String action) {
        if ("Load Scope".equals(action)) {
            loadExistingScope();
            return;
        }
        if ("Save Scope As...".equals(action)) {
            saveScopeAs();
            return;
        }
        if ("Create Scope".equals(action)) {
            createScopeInteractive();
            return;
        }
        deleteScopeInteractive();
    }

    private void runInsightAction(String action) {
        if ("Generate Quests".equals(action)) {
            generateAndViewQuests();
            return;
        }
        if ("Analyze Latest".equals(action)) {
            analyzeLatestCaptured();
            return;
        }
        syncAndFetchAppSummary();
    }

    private void runDomainAction(String action) {
        switch (action) {
            case "Only Include Filter Matches" -> includeOnlyFilteredHosts();
            case "Include Filter Matches" -> setFilteredHostsIncluded(true);
            case "Exclude Filter Matches" -> setFilteredHostsIncluded(false);
            case "Include Selected" -> setSelectedHostsIncluded(true);
            case "Exclude Selected" -> setSelectedHostsIncluded(false);
            case "Include All" -> setAllHostsIncluded(true);
            case "Exclude All" -> setAllHostsIncluded(false);
            default -> refreshHostsFromHistory();
        }
    }

    private void includeOnlyFilteredHosts() {
        int visibleCount = hostTable.getRowCount();
        if (visibleCount == 0) {
            log("No visible hosts under current filter.");
            return;
        }

        // First exclude everything.
        for (Map.Entry<String, HostRule> entry : hostRules.entrySet()) {
            entry.getValue().include = false;
        }
        // Then include only currently visible filtered rows.
        for (int viewRow = 0; viewRow < visibleCount; viewRow++) {
            int modelRow = hostTable.convertRowIndexToModel(viewRow);
            String host = String.valueOf(hostTableModel.getValueAt(modelRow, 1));
            hostRules.compute(host, (k, v) -> {
                HostRule rule = v == null ? new HostRule() : v;
                rule.include = true;
                return rule;
            });
        }
        refreshHostTable();
        log("Included only hosts visible in filter. Excluded all others.");
        pushHostRulesToBackend();
    }

    private void setFilteredHostsIncluded(boolean include) {
        int visibleCount = hostTable.getRowCount();
        if (visibleCount == 0) {
            log("No visible hosts under current filter.");
            return;
        }
        for (int viewRow = 0; viewRow < visibleCount; viewRow++) {
            int modelRow = hostTable.convertRowIndexToModel(viewRow);
            String host = String.valueOf(hostTableModel.getValueAt(modelRow, 1));
            hostRules.compute(host, (k, v) -> {
                HostRule rule = v == null ? new HostRule() : v;
                rule.include = include;
                return rule;
            });
        }
        refreshHostTable();
        log((include ? "Included" : "Excluded") + " hosts visible in current filter.");
        pushHostRulesToBackend();
    }

    private void setAllHostsIncluded(boolean include) {
        if (hostRules.isEmpty()) {
            return;
        }
        for (Map.Entry<String, HostRule> entry : hostRules.entrySet()) {
            entry.getValue().include = include;
        }
        refreshHostTable();
        log((include ? "Included" : "Excluded") + " all known hosts.");
        pushHostRulesToBackend();
    }

    private void syncOnceSafe() {
        try {
            if (!runningBox.isSelected()) {
                return;
            }
            if (shouldSuppressAutoSyncForIdle()) {
                return;
            }
            syncOnce();
        } catch (Exception e) {
            log("Sync error: " + e.getMessage());
            api.logging().logToError("Sentinel sync error", e);
        }
    }

    private boolean shouldSuppressAutoSyncForIdle() {
        int currentMax = currentMaxId();
        long now = System.currentTimeMillis();

        if (currentMax > lastObservedRequestId) {
            lastObservedRequestId = currentMax;
            lastNewRequestSeenAtMs = now;
            if (syncSuppressedForIdle) {
                syncSuppressedForIdle = false;
                log("New request detected. Auto sync resumed.");
            }
            return false;
        }

        if ((now - lastNewRequestSeenAtMs) >= IDLE_SYNC_SUPPRESS_MS) {
            if (!syncSuppressedForIdle) {
                syncSuppressedForIdle = true;
                log("No new requests for 60s. Auto sync paused until new traffic appears.");
            }
            return true;
        }
        return false;
    }

    private void syncOnce() {
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (history.isEmpty()) {
            log("No Proxy history items found. Nothing to sync.");
            return;
        }

        history.sort(Comparator.comparingInt(ProxyHttpRequestResponse::id));

        SyncBatch batch = collectBatch(history, false, 25);
        List<CapturedItem> pending = batch.pending();
        int maxResponseIdInBatch = batch.maxResponseId();
        int skippedByRule = batch.skippedByRule();

        log("Sync scan: history=" + history.size()
                + ", with_response_after_cursor=" + batch.withResponseAfterCursor()
                + ", included=" + pending.size()
                + ", skipped=" + skippedByRule
                + ", scope=\"" + currentScope() + "\"");

        if (pending.isEmpty()) {
            if (maxResponseIdInBatch > lastSyncedId) {
                lastSyncedId = maxResponseIdInBatch;
                if (skippedByRule > 0) {
                    log("Skipped " + skippedByRule + " excluded host item(s). Cursor=" + lastSyncedId);
                }
            } else {
                log("No eligible request/response pairs to sync in current cursor window.");
            }
            return;
        }

        SentinelClient.SyncResult result = client.sendProxyImport(
                backendField.getText().trim(),
                currentScope(),
                pending
        );
        if (result.success()) {
            lastSyncedId = maxResponseIdInBatch;
            String msg = "Synced " + pending.size() + " item(s). Cursor=" + lastSyncedId;
            if (skippedByRule > 0) {
                msg += " (skipped " + skippedByRule + " excluded host item(s))";
            }
            log(msg);
        } else {
            if (result.rateLimited()) {
                handleRateLimit("Auto Sync", result.message());
            } else {
                log("Sync failed (" + result.message() + "). Will retry pending items.");
            }
        }
    }

    private SyncBatch collectBatch(List<ProxyHttpRequestResponse> history, boolean ignoreCursor, int limit) {
        List<CapturedItem> pending = new ArrayList<>();
        int maxResponseIdInBatch = lastSyncedId;
        int skippedByRule = 0;
        int withResponseAfterCursor = 0;

        for (ProxyHttpRequestResponse item : history) {
            int id = item.id();
            if (!ignoreCursor && id <= lastSyncedId) {
                continue;
            }
            if (!item.hasResponse()) {
                continue;
            }
            withResponseAfterCursor++;

            String requestRaw = item.finalRequest().toString();
            String responseRaw = item.response().toString();
            String host = extractHost(requestRaw);
            registerHostSeen(host);
            maxResponseIdInBatch = Math.max(maxResponseIdInBatch, id);

            if (!isHostIncluded(host)) {
                skippedByRule++;
                continue;
            }

            ZonedDateTime ts = item.time();
            pending.add(new CapturedItem(requestRaw, responseRaw, "proxy", ts == null ? "" : ts.toString()));
            if (pending.size() >= limit) {
                break;
            }
        }
        return new SyncBatch(pending, maxResponseIdInBatch, skippedByRule, withResponseAfterCursor);
    }

    private void backfillForSummary() {
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (history.isEmpty()) {
            return;
        }
        history.sort(Comparator.comparingInt(ProxyHttpRequestResponse::id).reversed());
        SyncBatch batch = collectBatch(history, true, 100);
        if (batch.pending().isEmpty()) {
            log("Summary backfill: no eligible pairs found in recent history.");
            return;
        }

        SentinelClient.SyncResult result = client.sendProxyImport(
                backendField.getText().trim(),
                currentScope(),
                batch.pending()
        );
        if (result.success()) {
            log("Summary backfill synced " + batch.pending().size() + " recent item(s).");
        } else {
            if (result.rateLimited()) {
                handleRateLimit("Summary Backfill", result.message());
            } else {
                log("Summary backfill failed (" + result.message() + ").");
            }
        }
    }

    private void fetchAppSummary() {
        SentinelClient.ApiResult result = client.getAppSummary(backendField.getText().trim(), currentScope());
        if (result.success()) {
            setInsights(InsightsFormatter.appSummary(result.body()));
            log("Loaded app summary.");
        } else {
            setInsights("Failed to load app summary.\n\n" + result.body());
            if (result.rateLimited()) {
                handleRateLimit("View App Summary", result.body());
            } else {
                log("Failed to load app summary (HTTP " + result.statusCode() + ").");
            }
        }
    }

    private void syncAndFetchAppSummary() {
        syncOnceManual();
        backfillForSummary();
        fetchAppSummary();
    }

    private void generateAndViewQuests() {
        SentinelClient.ApiResult result = client.generateQuests(backendField.getText().trim(), currentScope());
        if (result.success()) {
            setInsights(InsightsFormatter.generatedQuests(result.body()));
            log("Generated quests.");
        } else {
            setInsights("Failed to generate quests.\n\n" + result.body());
            if (result.rateLimited()) {
                handleRateLimit("Generate Quests", result.body());
            } else {
                log("Failed to generate quests (HTTP " + result.statusCode() + ").");
            }
        }
    }

    private void analyzeLatestCaptured() {
        ProxyHttpRequestResponse latest = null;
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        history.sort(Comparator.comparingInt(ProxyHttpRequestResponse::id).reversed());

        for (ProxyHttpRequestResponse item : history) {
            if (!item.hasResponse()) {
                continue;
            }
            String host = extractHost(item.finalRequest().toString());
            if (!isHostIncluded(host)) {
                continue;
            }
            latest = item;
            break;
        }

        if (latest == null) {
            setInsights("No captured request/response available (or all hosts excluded).");
            return;
        }

        SentinelClient.ApiResult result = client.analyzeRequest(
                backendField.getText().trim(),
                currentScope(),
                roleField.getText().trim(),
                latest.finalRequest().toString(),
                latest.response().toString(),
                "proxy"
        );
        if (result.success()) {
            setInsights(InsightsFormatter.analyzedRequest(result.body()));
            log("Analyzed latest captured request/response.");
        } else {
            setInsights("Failed to analyze latest.\n\n" + result.body());
            if (result.rateLimited()) {
                handleRateLimit("Analyze Latest", result.body());
            } else {
                log("Failed to analyze latest (HTTP " + result.statusCode() + ").");
            }
        }
    }

    private void loadExistingScope() {
        SentinelClient.ApiResult result = client.listScopes(backendField.getText().trim());
        if (!result.success()) {
            if (result.rateLimited()) {
                handleRateLimit("Load Scope", result.body());
            } else {
                log("Failed to list scopes (HTTP " + result.statusCode() + ").");
                setInsights("Failed to list scopes.\n\n" + result.body());
            }
            return;
        }

        List<String> scopes = extractScopeNames(result.body());
        if (scopes.isEmpty()) {
            setInsights("No existing scopes found. Create one first.");
            log("No scopes returned by backend.");
            return;
        }

        SwingUtilities.invokeLater(() -> {
            Object selected = JOptionPane.showInputDialog(
                    panel,
                    "Select a scope to load:",
                    "Load Scope",
                    JOptionPane.PLAIN_MESSAGE,
                    null,
                    scopes.toArray(),
                    currentScope()
            );
            if (selected != null) {
                setCurrentScope(String.valueOf(selected));
                log("Loaded scope: " + selected);
                applySavedHostRules(String.valueOf(selected));
            }
        });
    }

    /** Restore the saved per-host filter for a scope into the host table so
     * the UI and the backend agree on what is in scope. Hosts not present in
     * the saved filter are unchecked (excluded). */
    private void applySavedHostRules(String scope) {
        String baseUrl = backendField.getText().trim();
        if (baseUrl.isEmpty() || scope.isEmpty()) {
            return;
        }
        SentinelClient.ApiResult result = client.getScopeHosts(baseUrl, scope);
        if (!result.success()) {
            log("Failed to load saved domain filter (HTTP " + result.statusCode() + ").");
            return;
        }
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\"host\"\\s*:\\s*\"([^\"]+)\"[^}]*?\"in_scope\"\\s*:\\s*(\\d+)")
                .matcher(result.body());
        Set<String> saved = new HashSet<>();
        while (m.find()) {
            String host = m.group(1).toLowerCase();
            boolean include = "1".equals(m.group(2));
            saved.add(host);
            hostRules.compute(host, (k, v) -> {
                HostRule rule = v == null ? new HostRule() : v;
                rule.include = include;
                return rule;
            });
        }
        // Everything not in the saved filter is out of scope for this scope.
        for (Map.Entry<String, HostRule> entry : hostRules.entrySet()) {
            if (!saved.contains(entry.getKey())) {
                entry.getValue().include = false;
            }
        }
        refreshHostTable();
        log("Loaded saved domain filter for scope \"" + scope + "\" (" + saved.size() + " host(s)).");
    }

    private void createScopeInteractive() {
        SwingUtilities.invokeLater(() -> {
            String scope = JOptionPane.showInputDialog(
                    panel,
                    "Enter a new scope name:",
                    currentScope()
            );
            if (scope == null) {
                return;
            }
            String normalized = scope.trim();
            if (normalized.isEmpty()) {
                setInsights("Scope name cannot be empty.");
                return;
            }
            createOrEnsureScope(normalized, true, "Create Scope");
        });
    }

    private void saveScopeAs() {
        SwingUtilities.invokeLater(() -> {
            String scope = JOptionPane.showInputDialog(
                    panel,
                    "Save/switch scope as:",
                    currentScope()
            );
            if (scope == null) {
                return;
            }
            String normalized = scope.trim();
            if (normalized.isEmpty()) {
                setInsights("Scope name cannot be empty.");
                return;
            }
            createOrEnsureScope(normalized, true, "Save Scope");
        });
    }

    private void createOrEnsureScope(String scope, boolean switchToScope, String actionName) {
        if (scope.isEmpty()) {
            return;
        }
        SentinelClient.ApiResult result = client.createScope(backendField.getText().trim(), scope);
        if (result.success()) {
            if (switchToScope) {
                setCurrentScope(scope);
            }
            log(actionName + " complete: " + scope);
            setInsights("Scope ready: " + scope + "\n\nYou can now sync traffic into this scope.");
            pushHostRulesToBackend();
        } else {
            if (result.rateLimited()) {
                handleRateLimit(actionName, result.body());
            } else {
                log("Failed to create scope (HTTP " + result.statusCode() + ").");
                setInsights("Failed to create scope.\n\n" + result.body());
            }
        }
    }

    private void deleteScopeInteractive() {
        SentinelClient.ApiResult listResult = client.listScopes(backendField.getText().trim());
        if (!listResult.success()) {
            if (listResult.rateLimited()) {
                handleRateLimit("Delete Scope", listResult.body());
            } else {
                log("Failed to list scopes for delete (HTTP " + listResult.statusCode() + ").");
                setInsights("Failed to list scopes.\n\n" + listResult.body());
            }
            return;
        }

        List<String> scopes = extractScopeNames(listResult.body());
        if (scopes.isEmpty()) {
            setInsights("No existing scopes found to delete.");
            return;
        }

        Object selected = JOptionPane.showInputDialog(
                panel,
                "Select a scope to delete:",
                "Delete Scope",
                JOptionPane.WARNING_MESSAGE,
                null,
                scopes.toArray(),
                currentScope()
        );
        if (selected == null) {
            return;
        }
        String scope = String.valueOf(selected).trim();
        if (scope.isEmpty()) {
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(
                panel,
                "Delete scope \"" + scope + "\" and all its Sentinel data?",
                "Delete Scope",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
        );
        if (confirm != JOptionPane.YES_OPTION) {
            return;
        }

        SentinelClient.ApiResult result = client.deleteScope(backendField.getText().trim(), scope);
        if (result.success()) {
            log("Deleted scope: " + scope);
            if (scope.equals(currentScope())) {
                setCurrentScope("Burp Project");
            }
            setInsights("Scope deleted: " + scope + "\n\nChoose/create another scope to continue.");
        } else {
            if (result.rateLimited()) {
                handleRateLimit("Delete Scope", result.body());
            } else {
                log("Failed to delete scope (HTTP " + result.statusCode() + ").");
                setInsights("Failed to delete scope.\n\n" + result.body());
            }
        }
    }

    private String currentScope() {
        return currentScopeValue.getText().trim();
    }

    private void setCurrentScope(String scopeName) {
        String normalized = scopeName == null ? "" : scopeName.trim();
        if (normalized.isEmpty()) {
            return;
        }
        SwingUtilities.invokeLater(() -> currentScopeValue.setText(normalized));
    }

    private void handleRateLimit(String action, String details) {
        String banner = "RATE LIMIT: Sentinel or its provider returned a rate-limit response.";
        log(banner + " Action=" + action + ". Back off and retry later.");
        setInsights(
                "Rate Limit Encountered\n"
                        + "======================\n\n"
                        + "Action: " + action + "\n"
                        + "Status: request throttled\n\n"
                        + "What to do:\n"
                        + "- wait and retry\n"
                        + "- reduce sync/analysis frequency\n"
                        + "- adjust provider/API plan limits if needed\n\n"
                        + "Details:\n" + details
        );
    }

    private void sendChatMessage() {
        String message = chatInput.getText().trim();
        if (message.isEmpty()) {
            return;
        }
        String scope = currentScope();
        String backend = backendField.getText().trim();
        appendChatLine("Me", message);
        chatInput.setText("");
        setChatSending(true);
        appendChatLine("Sentinel", "is thinking…", true);
        runInBackground(() -> {
            SentinelClient.ApiResult result = client.chat(backend, scope, message);
            if (result.success()) {
                String answer = extractJsonStringValue(result.body(), "answer");
                if (answer.isEmpty()) {
                    answer = result.body();
                }
                appendChatLine("Sentinel", answer);
                log("Chat reply received.");
            } else {
                appendChatLine("Sentinel", "Chat request failed: HTTP " + result.statusCode() + ". " + result.body());
                if (result.rateLimited()) {
                    handleRateLimit("Chat", result.body());
                } else {
                    log("Chat request failed (HTTP " + result.statusCode() + ").");
                }
            }
            setChatSending(false);
        });
    }

    private void runInBackground(Runnable task) {
        new Thread(task, "sentinel-ui-action").start();
    }

    private void syncOnceManual() {
        try {
            syncOnce();
        } catch (Exception e) {
            log("Manual sync before summary failed: " + e.getMessage());
            api.logging().logToError("Sentinel manual sync error", e);
        }
    }

    private void setInsights(String body) {
        SwingUtilities.invokeLater(() -> {
            insights.setText(body);
            insights.setCaretPosition(0);
        });
    }

    private void appendChatLine(String speaker, String text) {
        appendChatLine(speaker, text, false);
    }

    /** Chatroom-style transcript: user messages right-aligned in blue,
     * Sentinel messages left-aligned in green. A "thinking" placeholder is
     * replaced in place when the real reply arrives. */
    private void appendChatLine(String speaker, String text, boolean thinking) {
        SwingUtilities.invokeLater(() -> {
            StyledDocument doc = chatTranscript.getStyledDocument();
            try {
                boolean isUser = "Me".equals(speaker);
                // A real reply (or error) replaces the pending placeholder.
                if (!thinking && !isUser && chatPlaceholderOffset >= 0) {
                    int off = chatPlaceholderOffset;
                    chatPlaceholderOffset = -1;
                    doc.remove(off, doc.getLength() - off);
                }
                if (doc.getLength() > 0) {
                    doc.insertString(doc.getLength(), "\n\n", null);
                }
                int start = doc.getLength();
                String prefix = (isUser ? "Me" : "Sentinel") + ": ";
                Style label = chatTranscript.addStyle(isUser ? "userLabel" : "aiLabel", null);
                StyleConstants.setBold(label, true);
                StyleConstants.setForeground(label, isUser ? new Color(0x1565C0) : new Color(0x2E7D32));
                Style body = chatTranscript.addStyle(isUser ? "userBody" : (thinking ? "thinkingBody" : "aiBody"), null);
                StyleConstants.setForeground(body, isUser ? new Color(0x0D47A1) : (thinking ? new Color(0x9E9E9E) : new Color(0x1B5E20)));
                StyleConstants.setItalic(body, thinking);
                doc.insertString(start, prefix, label);
                doc.insertString(doc.getLength(), text, body);
                Style align = chatTranscript.addStyle(isUser ? "userAlign" : "aiAlign", null);
                StyleConstants.setAlignment(align, isUser ? StyleConstants.ALIGN_RIGHT : StyleConstants.ALIGN_LEFT);
                doc.setParagraphAttributes(start, doc.getLength() - start, align, false);
                if (thinking) {
                    chatPlaceholderOffset = start;
                }
            } catch (BadLocationException ignored) {
            }
            chatTranscript.setCaretPosition(chatTranscript.getDocument().getLength());
        });
    }

    private void setChatSending(boolean sending) {
        SwingUtilities.invokeLater(() -> {
            chatSendButton.setEnabled(!sending);
            chatInput.setEnabled(!sending);
        });
    }

    private List<String> extractScopeNames(String json) {
        List<String> names = new ArrayList<>();
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\"name\"\\s*:\\s*\"(.*?)\"")
                .matcher(json);
        while (m.find()) {
            names.add(m.group(1).replace("\\\\\"", "\""));
        }
        return names;
    }

    private String extractJsonStringValue(String json, String key) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\"" + java.util.regex.Pattern.quote(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"", java.util.regex.Pattern.DOTALL)
                .matcher(json);
        if (!m.find()) {
            return "";
        }
        return m.group(1)
                .replace("\\n", "\n")
                .replace("\\r", "")
                .replace("\\t", "\t")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
    }

    private void refreshHostsFromHistory() {
        for (ProxyHttpRequestResponse item : api.proxy().history()) {
            String host = extractHost(item.finalRequest().toString());
            if (!host.isEmpty()) {
                hostRules.compute(host, (k, v) -> v == null ? new HostRule() : v);
            }
        }
        refreshHostTable();
        log("Domain list refreshed. Known hosts=" + hostRules.size());
        pushHostRulesToBackend();
    }

    private void setSelectedHostsIncluded(boolean include) {
        int[] viewRows = hostTable.getSelectedRows();
        if (viewRows.length == 0) {
            return;
        }
        for (int viewRow : viewRows) {
            int modelRow = hostTable.convertRowIndexToModel(viewRow);
            hostTableModel.setValueAt(include, modelRow, 0);
        }
        refreshHostTable();
    }

    private void toggleSelectedHosts() {
        int[] viewRows = hostTable.getSelectedRows();
        if (viewRows.length == 0) {
            return;
        }
        for (int viewRow : viewRows) {
            int modelRow = hostTable.convertRowIndexToModel(viewRow);
            boolean current = Boolean.TRUE.equals(hostTableModel.getValueAt(modelRow, 0));
            hostTableModel.setValueAt(!current, modelRow, 0);
        }
        refreshHostTable();
    }

    private void registerHostSeen(String host) {
        if (host.isEmpty()) {
            return;
        }
        hostRules.compute(host, (k, v) -> {
            HostRule rule = v == null ? new HostRule() : v;
            rule.seen += 1;
            return rule;
        });
        refreshHostTable();
    }

    private boolean isHostIncluded(String host) {
        if (host == null || host.isEmpty()) {
            return true;
        }
        HostRule rule = hostRules.get(host);
        return rule == null || rule.include;
    }

    /** Mirror the extension's domain filter to the backend: the in-scope set
     * is exactly the currently included hosts. Called whenever the user
     * changes inclusion (checkbox, filter actions, refresh, scope creation). */
    private void pushHostRulesToBackend() {
        String baseUrl = backendField.getText().trim();
        String scope = currentScope();
        if (baseUrl.isEmpty() || scope.isEmpty() || hostRules.isEmpty()) {
            return;
        }
        List<String> included = new ArrayList<>();
        for (Map.Entry<String, HostRule> entry : hostRules.entrySet()) {
            if (entry.getValue().include) {
                included.add(entry.getKey());
            }
        }
        if (included.isEmpty()) {
            return;
        }
        SentinelClient.ApiResult result = client.setIncludedHosts(baseUrl, scope, included);
        if (!result.success()) {
            log("Failed to push domain filter to backend (HTTP " + result.statusCode() + ").");
        }
    }

    private void refreshHostTable() {
        SwingUtilities.invokeLater(() -> {
            String selectedHost = "";
            int viewSelected = hostTable.getSelectedRow();
            if (viewSelected >= 0) {
                int modelSelected = hostTable.convertRowIndexToModel(viewSelected);
                selectedHost = String.valueOf(hostTableModel.getValueAt(modelSelected, 1));
            }

            hostTableModel.setRowCount(0);
            hostRules.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(entry -> {
                        HostRule r = entry.getValue();
                        hostTableModel.addRow(new Object[]{r.include, entry.getKey(), r.seen});
                    });

            if (!selectedHost.isEmpty()) {
                for (int modelRow = 0; modelRow < hostTableModel.getRowCount(); modelRow++) {
                    if (selectedHost.equals(hostTableModel.getValueAt(modelRow, 1))) {
                        int viewRow = hostTable.convertRowIndexToView(modelRow);
                        if (viewRow >= 0) {
                            hostTable.setRowSelectionInterval(viewRow, viewRow);
                        }
                        break;
                    }
                }
            }
        });
    }

    private int currentMaxId() {
        int max = 0;
        for (ProxyHttpRequestResponse item : api.proxy().history()) {
            max = Math.max(max, item.id());
        }
        return max;
    }

    private long intervalSeconds() {
        try {
            long v = Long.parseLong(intervalField.getText().trim());
            return Math.max(1, Math.min(v, 60));
        } catch (Exception ignored) {
            return 3;
        }
    }

    private String extractHost(String rawRequest) {
        if (rawRequest == null || rawRequest.isEmpty()) {
            return "";
        }
        String normalized = rawRequest.replace("\r\n", "\n");
        String[] lines = normalized.split("\n");
        for (String line : lines) {
            String lower = line.toLowerCase();
            if (lower.startsWith("host:")) {
                String value = line.substring(5).trim();
                int colon = value.indexOf(':');
                return colon > 0 ? value.substring(0, colon).trim().toLowerCase() : value.toLowerCase();
            }
        }
        return "";
    }

    private void log(String line) {
        SwingUtilities.invokeLater(() -> {
            logs.append(line + "\n");
            logs.setCaretPosition(logs.getDocument().getLength());
        });
    }

    public record CapturedItem(String request, String response, String tool, String timestamp) {}
    private record SyncBatch(List<CapturedItem> pending, int maxResponseId, int skippedByRule, int withResponseAfterCursor) {}

    private static final class HostRule {
        boolean include = true;
        int seen = 0;
    }

    private static final class PatternSafe {
        private PatternSafe() {}

        static String quote(String value) {
            return java.util.regex.Pattern.quote(value);
        }
    }
}
