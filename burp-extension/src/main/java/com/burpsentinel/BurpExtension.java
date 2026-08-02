package com.burpsentinel;

import burp.api.montoya.MontoyaApi;

public class BurpExtension implements burp.api.montoya.BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Sentinel Security Insights");

        SentinelSyncController controller = new SentinelSyncController(api);
        api.userInterface().registerSuiteTab("Sentinel Insights", controller.ui());

        controller.start();
        api.logging().logToOutput("Sentinel Security Insights initialized. Auto-sync is ON.");
    }
}
