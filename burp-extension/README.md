# Hermes Burp Auto-Sync Extension

This Burp extension streams Proxy request/response pairs to the Hermes backend
without manual copy/paste.

## Build

```bash
gradle clean jar
```

Output JAR:

`build/libs/hermes-burp-sync-0.2.0.jar`

## Load in Burp

1. `Extensions` -> `Installed` -> `Add`
2. Type: `Java`
3. Select `build/libs/hermes-burp-sync-0.2.0.jar`
4. Open Burp tab `Hermes Sync`

## Configure

- `Hermes Backend`: `http://localhost:8000`
- `Scope Name`: your target label (for Hermes summaries/quests)
- `Auto Sync Running`: enabled
- Use the domains/subdomains table to control analysis scope:
  - `Include` checked = sent to Hermes
  - `Include` unchecked = excluded from Hermes analysis
  - Select a host row and press `x` to toggle include/exclude quickly
- Use the `Filter` input above the domain table to search hosts/subdomains quickly
- Scope controls:
  - `Load Existing Scope`: pick an existing scope from Hermes
  - `Create Current Scope`: create/ensure the scope currently typed in the Scope field
  - `Delete Current Scope`: remove the selected scope and its stored Hermes model data

The extension sends traffic to:

`POST /proxy/import`

in batches every few seconds.

## View Hermes insights inside Burp

Use these buttons in the `Hermes Sync` tab:

- `View App Summary`: fetches `/app-summary/{scope_name}`
- `Generate + View Quests`: calls `/generate-quests`
- `Analyze Latest Captured`: sends latest included request/response to `/analyze-request`

Results are shown in the `Hermes Insights` pane in a human-readable format (not raw JSON).

## Rate limiting visibility

If Hermes (or an upstream model provider) returns a rate-limit response (`HTTP 429`),
the extension now shows a clear `RATE LIMIT` warning in:

- `Sync Logs`
- `Hermes Insights` pane (with backoff guidance)
