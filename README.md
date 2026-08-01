# Hermes Security Insights (Local Setup)

This project runs locally.

It includes:
- A local backend at `http://localhost:8000`
- A Hermes proxy for model access
- A Burp extension that syncs Proxy traffic into that backend

## 1) Install System Prerequisites

You need:
- Python 3.10+
- Java 17+
- Gradle
- Burp Suite

Hermes download/install page:
- [Hermes Agent Installation](https://hermes-agent.nousresearch.com/docs/getting-started/installation)

Example (Ubuntu/Debian):

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-uvicorn openjdk-17-jdk gradle
```

Why this step exists:
- Installs system tools (`python3`, `java`, `gradle`, etc.).
- Does not install this project’s Python packages.

Verify:

```bash
python3 --version
java -version
gradle -v
```

## 2) Clone Repository

```bash
git clone https://github.com/MrChrisLia/hermes-burpsuite-agent.git
cd hermes-burpsuite-agent
```

## 3) Install Python Dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 4) Configure `.env`

Create from template:

```bash
cp .env.example .env
```

Then choose one runtime mode.
### Hermes proxy mode (real model)

1. Start proxy in another terminal:

```bash
hermes proxy start
```

Optional:

```bash
hermes proxy start --provider nous --host 127.0.0.1 --port 8645
```

2. Verify proxy:

```bash
hermes proxy status
hermes proxy providers
```

List model IDs:

```bash
curl -sS http://127.0.0.1:8645/v1/models | jq -r '.data[].id'
```

3. Set `.env`:

```bash
HERMES_PROVIDER=hermes_agent
HERMES_BASE_URL=http://127.0.0.1:8645/v1
HERMES_MODEL=EXACT_MODEL_ID_FROM_V1_MODELS
HERMES_API_KEY=
```

Example `.env` (filled):

```bash
HERMES_PROVIDER=hermes_agent
HERMES_BASE_URL=http://127.0.0.1:8645/v1
HERMES_MODEL=openai/gpt-4o-mini
HERMES_API_KEY=sk-or-v1-********************************abcd
```

Notes:
- Use the exact host/port from your proxy command if you changed defaults.
- `HERMES_MODEL` must be an exact model ID returned by `/v1/models`.

## 5) Start Backend

After the `.env` is setup, start the backend:

```bash
source .venv/bin/activate
uvicorn hermes_api.main:app --host 0.0.0.0 --port 8000
```

In another terminal, verify:

```bash
curl -sS http://localhost:8000/health
```

For proxy mode, confirm `/health` shows:
- `"provider": "hermes_agent"`
- `"base_url": "http://127.0.0.1:8645/v1"` (or your custom proxy URL)
- `"model": "YOUR_MODEL_ID"`

## 6) Build Burp Extension

```bash
cd burp-extension
gradle clean jar
cd ..
```

JAR path:

`burp-extension/build/libs/hermes-burp-sync-0.2.0.jar`

## 7) Load Extension In Burp

1. Burp -> `Extensions` -> `Installed` -> `Add`
2. Type: `Java`
3. Select: `burp-extension/build/libs/hermes-burp-sync-0.2.0.jar`
4. Open extension tab: `Hermes Insights`
5. Set `Hermes Backend` to `http://localhost:8000`

## 8) First Workflow In Burp

1. In extension scope menu, run `Create Scope`
2. Browse target through Burp Proxy
3. Run:
   - `View App Summary`
   - `Generate Quests`

## 9) Use Hermes Chat In Burp

The `Hermes Insights` tab includes a `Hermes Chat` panel.

1. Keep backend running.
2. Load/create the correct scope.
3. Enter a question and press `Send` (or Enter).

Notes:
- Chat is scoped to the currently selected scope.
- Real model answers require working proxy/provider/model config.

## 10) Skills (WSTG + Custom)

Check loaded skills:

```bash
curl -sS 'http://localhost:8000/skills?refresh=true'
```

Custom markdown skills directory:
`hermes_api/skills`

Skill format reference:
`hermes_api/skills/README.md`

## 11) Troubleshooting

### `hermes proxy` only prints usage/help

Use:

```bash
hermes proxy start
```

Not:

```bash
hermes proxy
```

### No `.jar` after clone

Expected. Build in `burp-extension`:

```bash
gradle clean jar
```

### Extension sync fails

Check:
1. Backend is running on `localhost:8000`
2. Health endpoint responds:
   ```bash
   curl -sS http://localhost:8000/health
   ```
3. Burp extension backend URL is exactly `http://localhost:8000`

### App summary is empty

Usually:
1. No Burp traffic captured yet
2. Wrong scope loaded
3. Relevant hosts are excluded in domain filter

### Chat does not use expected model

Check:

```bash
curl -sS http://localhost:8000/health
```

If `model` is empty/wrong, backend config is wrong.

Fix:
1. Verify repo-root `.env`:
   ```bash
   grep -n '^HERMES_' .env
   ```
2. Check for duplicate `.env` files:
   ```bash
   find .. -maxdepth 3 -name .env
   ```
3. Fully restart backend from repo root:
   ```bash
   pkill -f "uvicorn hermes_api.main:app" || true
   uvicorn hermes_api.main:app --host 0.0.0.0 --port 8000
   ```
4. Re-check `/health` and only then test Burp chat.

### Chat returns `404 Not Found` on `/chat/completions`

Usually:
1. Wrong model name for the selected proxy provider.
2. Wrong provider selected when starting proxy.

Important: `hermes proxy start --provider nous` uses **Nous Portal** credentials/models, not your OpenRouter model picker.

Quick checks:

```bash
hermes proxy status
curl -sS http://127.0.0.1:8645/v1/models
```

Then set `HERMES_MODEL` to an ID returned by `/v1/models`.

If you want OpenRouter-specific models, do not use `--provider nous` unless that model is actually available there.

### Chat fails with `account balance is too low` / `requires available credits`

This means the request reached the **Nous Portal** with an account that has no
credits. `hermes proxy start --provider nous` authenticates against the Nous
Portal OAuth account (`~/.hermes/auth.json`) — **not** your DeepSeek/OpenRouter
API key. If you pay for a different provider, the proxy will still fail with
this error because it is billing the Portal account.

Fix: skip the proxy and point the backend at the provider you actually pay for.
Edit the repo-root `.env` (the file the backend reads at startup) to these
OpenAI-compatible values, then restart uvicorn:

```bash
HERMES_PROVIDER=openai_compatible
HERMES_BASE_URL=https://api.deepseek.com/
HERMES_MODEL=deepseek-v4-flash
HERMES_API_KEY=<your real provider key>
```

Restart uvicorn from the repo root, then confirm via `/health` that
`base_url`/`model` show your provider (not `127.0.0.1:8645`) before testing
chat in Burp. If you do want Portal models instead, add credits at
https://portal.nousresearch.com for the account used by `hermes login --provider nous`.

### Chat fails with `HTTP 0` and `I/O timeout`

This means Burp reached the Hermes backend, but the chat response took too long.
Large/slow models or temporary provider latency can trigger this.

Checks:

```bash
hermes proxy status
```

Then list available model IDs:

```bash
curl -sS http://127.0.0.1:8645/v1/models | jq -r '.data[].id'
```

Set `HERMES_MODEL` to a model ID returned by `/v1/models`.

Example:

```text
Hermes: LLM summary unavailable: provider call failed
(http://127.0.0.1:8645/v1/chat/completions: HTTP 404:
{"status":404,"message":"Model 'openai/gpt-5.3-codex' requires available credits. Your account balance is too low to use paid models ..."}
...)
```

Meaning:
- The selected model is paid for the current proxy provider/account.
- ChatGPT subscription login does not automatically grant provider API credits for proxy calls.
- This can happen even if you try `openrouter/owl-alpha`; treat that as a model suggestion only and verify it is available/usable in your `/v1/models` + current billing path.

Fix:
1. Pick a free model from `/v1/models`, or
2. Add credits to the provider account used by the proxy.

### Chat fails with `HTTP 0` and `I/O timeout`

This means backend was reachable, but response took too long.
