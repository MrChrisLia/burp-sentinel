# Burp Sentinel

An AI security copilot that lives inside Burp Suite. It watches the traffic
you proxy, keeps a structured model of your target (domains, endpoints,
features, JS findings), and lets you ask an LLM questions grounded in that
captured traffic — all locally.

```
Burp Suite ──syncs proxy traffic──▶ Sentinel backend (FastAPI, localhost:8000)
     ▲                                    │
     │        chat / summaries / quests   │ reads/writes
     └────────────────────────────────────┘        │
                                          local SQLite (sentinel.sqlite)
                                          └─ calls your LLM provider directly
                                             (any OpenAI-compatible API)
```

No proxy service, no gateway, no external account plumbing: the backend calls
the LLM provider of your choice (DeepSeek, OpenRouter, ...) with your own API
key. All captured traffic stays in a local SQLite database.

New here? Read [HOW_IT_WORKS.md](HOW_IT_WORKS.md) for a plain-English
walkthrough of the whole flow.

## Features

- **Scope = domain filter.** The extension's Domains/Subdomains panel defines
  what is in scope. The filter is pushed to the backend, so the AI only ever
  sees the hosts you included. `Load Scope` restores a saved filter; deleting a
  scope removes all of its data.
- **App summary.** Hosts classified (frontend / API / asset / third-party),
  endpoints with risk scores, business objects, roles, JS findings, and WSTG
  test recommendations.
- **Quests.** Auto-generated, WSTG-aligned testing checklists for the scope.
- **Chat grounded in traffic.** Answers are built from the scope summary plus
  the actual captured traffic: page titles, recent pages, and raw
  request/response blocks. A deterministic regex scan flags API keys, JWTs,
  tokens, and credential assignments inside the captured bodies.
- **Skills.** Markdown skills with trigger rules that match traffic evidence
  and feed into recommendations and quest generation.

## Requirements

- Python 3.10+
- Java 17+
- Gradle
- Burp Suite

Example (Ubuntu/Debian):

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-uvicorn openjdk-17-jdk gradle
```

Verify: `python3 --version`, `java -version`, `gradle -v`.

## Quick Start

### 1. Clone

```bash
git clone https://github.com/MrChrisLia/burp-sentinel.git
cd burp-sentinel
```

### 2. Install Python dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure `.env`

```bash
cp .env.example .env
```

Two runtime modes:

- **Mock mode** — `SENTINEL_PROVIDER=mock`. Chat returns deterministic mock
  responses; useful for testing the pipeline offline.
- **Real model mode** — any OpenAI-compatible provider. Example (DeepSeek):

```bash
SENTINEL_PROVIDER=openai_compatible
SENTINEL_BASE_URL=https://api.deepseek.com/
SENTINEL_MODEL=deepseek-v4-flash
SENTINEL_API_KEY=sk-************************************
```

`SENTINEL_MODEL` must be a model ID your provider accepts. The API key is your
own key for that provider.

### 4. Start the backend

```bash
source .venv/bin/activate
uvicorn sentinel_api.main:app --host 0.0.0.0 --port 8000
```

Verify:

```bash
curl -sS http://localhost:8000/health
```

Expected: `"provider": "openai_compatible"`, `"base_url": "https://api.deepseek.com/"`,
`"model": "deepseek-v4-flash"`.

### 5. Build the extension

```bash
cd burp-extension
gradle clean jar
cd ..
```

JAR: `burp-extension/build/libs/burp-sentinel-0.3.0.jar`

### 6. Load the extension in Burp

1. Burp -> `Extensions` -> `Installed` -> `Add`
2. Type: `Java`
3. Select: `burp-extension/build/libs/burp-sentinel-0.3.0.jar`
4. Open the `Sentinel Insights` tab
5. Set `Sentinel Backend` to `http://localhost:8000`

## Usage

### First workflow

1. In the extension scope menu, run `Create Scope`
2. Browse your target through the Burp Proxy (the extension syncs traffic automatically)
3. Run `View App Summary` and `Generate Quests`

### Domain filtering (read this — it defines what the AI sees)

The `Domains / Subdomains` panel lists every host seen in proxy history, each
with an include checkbox. Only included hosts are in scope:

- Type in the `Filter` box to narrow the list, then use the dropdown actions:
  `Only Include Filter Matches` (excludes everything else), `Include/Exclude
  Filter Matches`, `Include/Exclude Selected`, `Include/Exclude All`
- Select a row and press `x` to toggle a single host
- Every filter change is pushed to the backend: the AI's summaries, chat
  context, and quests only cover the included hosts
- `Load Scope` restores the scope's saved filter along with its data
- New hosts default to *included*; re-apply your filter after a Burp restart

### Chat

The `Sentinel Chat` panel answers questions about the current scope. It
resolves which host you mean (a host named in your question, otherwise the
most recently browsed one) and answers from that host's data.

Good prompts:

- "What is the title of the page I just browsed?"
- "Can you check what you saw in config.js?"
- "Can you check what that endpoint is?"
- "Do you see any API keys or potential vulnerabilities?"

Chat reads the captured request/response blocks (sensitive headers redacted)
and a deterministic secret scan (OpenAI-style keys, AWS keys, Google keys,
JWTs, Slack/GitHub tokens, private keys, credential assignments). First
answers on large scopes can take 20-60 seconds — the model is reasoning.

## Skills (WSTG + custom)

Check loaded skills:

```bash
curl -sS 'http://localhost:8000/skills?refresh=true'
```

Custom markdown skills live in `sentinel_api/skills` — format reference:
`sentinel_api/skills/README.md`.

## API overview

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Config + status |
| GET | `/scopes` | List scopes |
| POST | `/scopes` | Create a scope |
| DELETE | `/scopes/{name}` | Delete a scope (removes all its data) |
| GET/POST | `/scopes/{name}/hosts` | Read / update the per-host filter (`exclusive=true` = the list is the full in-scope set) |
| POST | `/proxy/import` | Ingest traffic from the extension |
| GET | `/app-summary/{scope}` | Full summary |
| POST | `/generate-quests` | Generate quests |
| POST | `/chat` | Ask the AI about a scope |
| GET | `/skills` | List loaded skills |

## Project layout

```
sentinel_api/          Python backend (FastAPI + SQLite)
  main.py              routes
  storage.py           SQLite store (scopes, endpoints, traffic, page titles)
  parser.py            HTTP parsing + redaction
  providers/           LLM providers (mock, openai_compatible)
  skills/              custom markdown skills
burp-extension/        Java extension (Gradle)
  src/main/java/com/burpsentinel/
  build/libs/burp-sentinel-*.jar
```

## Troubleshooting

### No `.jar` after clone

Expected. Build it: `cd burp-extension && gradle clean jar`.

### Extension sync fails

1. Backend running on `localhost:8000`? `curl -sS http://localhost:8000/health`
2. Extension `Sentinel Backend` is exactly `http://localhost:8000`

### App summary is empty

1. No Burp traffic captured yet
2. Wrong scope loaded
3. Relevant hosts excluded in the domain filter

### Chat does not use the expected model

`/health` is the source of truth. If `model` is empty/wrong: verify the
repo-root `.env` (`grep -n '^SENTINEL_' .env`), check for duplicate `.env`
files, restart the backend, re-check `/health`.

### Chat returns `404 Not Found` on `/chat/completions`

Wrong `SENTINEL_MODEL` for your provider, or the provider base URL is not
reachable. Set a model ID your provider accepts, restart, re-check `/health`.

### Chat fails with `account balance is too low`

The provider rejected the request for missing credits — the backend is
pointed at an endpoint/account you don't pay for. Switch `SENTINEL_BASE_URL`
and `SENTINEL_API_KEY` in `.env` to a provider you pay for, restart the
backend.

### Chat fails with `HTTP 0` / `I/O timeout`

The backend was reachable but the answer took too long (slow reasoning model,
big scope). Retry with a shorter prompt; if it keeps timing out, switch
`SENTINEL_MODEL` to a faster model.
