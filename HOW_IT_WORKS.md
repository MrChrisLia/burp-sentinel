# How Burp Sentinel Works (Explained Simply)

Imagine you're a detective investigating a building, and you've spent all day
walking through it taking notes. Burp Sentinel is the assistant who sat next
to you the whole time, quietly writing everything down — and now you can just
ask them questions about the building, and they answer from **their notebook**,
not from what they vaguely know about buildings in general.

## The three pieces

1. **Burp Suite** — your web tool. It's the "proxy" that sits between your
   browser and the website you're testing. Every request and response passes
   through it.
2. **The Sentinel extension** — a plugin inside Burp that copies all that
   passing traffic and hands it to...
3. **The Sentinel backend** — a small program running on your computer
   (`localhost:8000`). It stores everything in a local database and talks to
   the AI (like DeepSeek) when you ask a question.

That's it. No cloud, no accounts, no extra servers. All the data lives on
your machine.

## How a session goes

1. **Create a scope.** You tell the extension to start a new project — like
   opening a fresh notebook.

2. **Browse the target.** You browse the site through Burp (you're doing this
   anyway). The extension quietly syncs: every page, every API call, every JS
   file gets stored. It also grabs useful bits: page titles, endpoint paths,
   whether something looks like an API, whether JS files contain suspicious
   strings.

3. **Decide what matters.** In the extension's `Domains / Subdomains` panel
   you check the boxes for the hosts you care about and uncheck the noise
   (ads, CDNs, whatever). This is the **scope** — and the AI is only allowed
   to look at checked hosts. This is the single most important concept:
   **what you check = what the AI sees.**

4. **Ask questions.** In the chat panel:
   - *"What's the title of the page I just browsed?"* — it reads the actual
     stored page.
   - *"Check config.js for secrets"* — it opens the actual captured file and
     quotes what's in it.
   - *"Any API keys or potential vulnerabilities?"* — it scans the captured
     request/response bodies with a regex net (API keys, JWTs, tokens) and
     reads them with the model.
   - *"Summarize this app"* — it builds a report: hosts, endpoints, features,
     risky areas, test suggestions.

5. **Get a checklist.** It can generate **quests** — a checklist of things to
   test (IDOR, auth bypass, etc.) based on what it actually saw.

## What it is NOT

- **Not an auto-hacker.** It doesn't attack anything for you. It's a memory +
  analysis copilot. If you never browsed a page, it knows nothing about it —
  which is exactly what you want, because it means answers are about *your*
  target, not hallucinations.
- **Not shared.** All traffic stays in your local SQLite file
  (`sentinel.sqlite`). Delete a scope and everything about it is gone.

## The one-minute mental model

- Burp = your eyes.
- Sentinel = the notebook + the assistant.
- You look, it writes. You ask, it answers from the notebook.
- You check the boxes to tell it which pages of the notebook count.
