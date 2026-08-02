# Sentinel Security Insights (Local Setup)

This project runs locally.

It includes:
- A local backend at `http://localhost:8000`
- A Sentinel proxy for model access
- A Burp extension that syncs Proxy traffic into that backend

## 1) Install System Prerequisites

You need:
- Python 3.10+
- Java 17+
- Gradle
- Burp Suite

Sentinel download/install page:
- [Sentinel Agent Installation](https://sentinel-agent.nousresearch.com/docs/getting-started/installation)

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
git clone https://github.com/MrChrisLia/burp-sentinel.git
cd burp-sentinel
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

### Mock mode (no external model)

Keep `SENTINEL_PROVIDER=mock`. Chat returns deterministic mock responses — useful for offline testing.

### Real model mode (OpenAI-compatible provider, e.g. DeepSeek)

The backend calls the LLM provider directly — no proxy or gateway required. Set `.env`:

```bash
SENTINEL_PROVIDER=openai_compatible
SENTINEL_BASE_URL=https://api.deepseek.com/
SENTINEL_MODEL=deepseek-v4-flash
SENTINEL_API_KEY=sk-************************************
```

Any OpenAI-compatible endpoint works (DeepSeek, OpenRouter, etc.): point
`SENTINEL_BASE_URL` at it and set `SENTINEL_MODEL` to a model ID that provider
accepts. The API key is your own key for that provider.

## 5) Start Backend

After the `.env` is setup, start the backend:

```bash
source .venv/bin/activate
uvicorn sentinel_api.main:app --host 0.0.0.0 --port 8000
```

In another terminal, verify:

```bash
curl -sS http://localhost:8000/health
```

Confirm `/health` shows:
- `"provider": "openai_compatible"`
- `"base_url": "https://api.deepseek.com/"` (or your provider base URL)
- `"model": "deepseek-v4-flash"` (or your model)

## 6) Build Burp Extension

```bash
cd burp-extension
gradle clean jar
cd ..
```

JAR path:

`burp-extension/build/libs/burp-sentinel-0.3.0.jar`

## 7) Load Extension In Burp

1. Burp -> `Extensions` -> `Installed` -> `Add`
2. Type: `Java`
3. Select: `burp-extension/build/libs/burp-sentinel-0.3.0.jar`
4. Open extension tab: `Sentinel Insights`
5. Set `Sentinel Backend` to `http://localhost:8000`

## 8) First Workflow In Burp

1. In extension scope menu, run `Create Scope`
2. Browse target through Burp Proxy
3. Run:
   - `View App Summary`
   - `Generate Quests`

## 9) Use Sentinel Chat In Burp

The `Sentinel Insights` tab includes a `Sentinel Chat` panel.

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
`sentinel_api/skills`

Skill format reference:
`sentinel_api/skills/README.md`

## 11) Troubleshooting

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
   grep -n '^SENTINEL_' .env
   ```
2. Check for duplicate `.env` files:
   ```bash
   find .. -maxdepth 3 -name .env
   ```
3. Fully restart backend from repo root:
   ```bash
   pkill -f "uvicorn sentinel_api.main:app" || true
   uvicorn sentinel_api.main:app --host 0.0.0.0 --port 8000
   ```
4. Re-check `/health` and only then test Burp chat.

### Chat returns `404 Not Found` on `/chat/completions`

Usually:
1. Wrong model name for the selected provider.
2. Provider base URL not reachable.

Fix: set `SENTINEL_MODEL` in the repo-root `.env` to a model ID your provider
accepts, then restart uvicorn and re-check `/health`.

### Chat fails with `account balance is too low` / `requires available credits`

This error comes from the LLM provider rejecting the request for missing
credits. If the backend is pointed at an endpoint/account you do not pay for
(e.g. a portal-style endpoint), switch `SENTINEL_BASE_URL` and `SENTINEL_API_KEY`
in the repo-root `.env` to the provider you actually pay for (see section 4),
then restart uvicorn and re-check `/health`.

### Chat fails with `HTTP 0` and `I/O timeout`

This means Burp reached the Sentinel backend, but the chat response took too
long. Large/slow reasoning models or temporary provider latency can trigger
this — first answers on big scopes can take 20-60 seconds.

Checks:

1. Backend is still alive while chat is running:
   ```bash
   curl -sS http://localhost:8000/health
   ```
2. Retry with a short prompt.
3. If it consistently times out, the model is too slow for the provider —
   switch `SENTINEL_MODEL` to a faster model in the repo-root `.env` and restart
   the backend.
