# OPERATION DEAD DROP

**Turn suspicious messages into cyber investigations.**

Paste a suspicious email, text, or URL. Dead Drop runs local security forensics, hands the evidence to an AI analyst, and returns a full investigation: threat level, attacker objective, annotated evidence, a reconstruction of the attack, MITRE ATT&CK mapping, and exactly what to do next.

Built for RowdyHacks XII.

---

## How it works

```
Next.js UI ──► /api proxy (server-side) ──► FastAPI
                                             │
                     1. Deterministic forensics (analyzer.py)
                        URLs · domains · typosquats · homoglyphs · punycode
                        @-tricks · IP hosts · TLD risk · shorteners · redirect params
                        sender spoofing · 11 social-engineering pattern classes
                                             │  structured findings + indicators
                     2. AI analyst (Claude, forced tool-use JSON schema)
                                             │
                     3. Grounding gate — every "observed" claim and quote is
                        checked against the artifact; MITRE IDs checked against
                        an allowlist. Untraceable claims are discarded.
                                             │
                     4. Investigation object (DD-xxxxx) → UI
```

**Deterministic signals + AI reasoning.** The LLM is not the security engine — it is the analyst who interprets evidence the engine already found. If Claude is unavailable (no key, outage, timeout), a deterministic analyst produces the same schema, so the app never breaks mid-demo. The report always states which engine produced it.

### Safety properties
- Submitted links are **never visited, resolved, or executed** (static analysis only → no SSRF surface).
- No external verification is claimed; reports state that explicitly.
- API key stays server-side; the browser only talks to a Next.js route that proxies a whitelist of backend paths.
- Input limits (10k chars), control-char stripping, request-size guard, per-IP rate limit, `nosniff` / `no-store` headers.
- Artifact is rendered through React text nodes (no `dangerouslySetInnerHTML`); IOCs are displayed and copied **defanged** (`hxxps://evil[.]xyz`).
- Prompt-injection resistant: the artifact is treated as data, and the grounding gate drops anything the model can't trace to it.

---

## Local setup

Requirements: Python 3.11+, Node 20+.

```bash
# backend
cd backend
pip install -r requirements.txt
cp .env.example .env          # add ANTHROPIC_API_KEY (optional — runs deterministic-only without it)
uvicorn main:app --port 8000

# frontend (new terminal)
cd frontend
npm install
cp .env.example .env.local     # BACKEND_URL=http://127.0.0.1:8000
npm run dev                    # http://localhost:3000
```

Health check: `curl localhost:8000/health` → `ai_configured: true` when the key is loaded.

### API
| Method | Path | |
|---|---|---|
| POST | `/investigate` | `{ "content": "...", "demo_id": null }` → investigation |
| GET | `/investigations/{id}` | retrieve (in-memory) |
| GET | `/investigations` | recent cases |
| GET | `/demos` | built-in case files |
| GET | `/health` | status |

---

## Deploy

**Backend → Render / Railway**
- Root: `backend/` · Build: `pip install -r requirements.txt` · Start: `uvicorn main:app --host 0.0.0.0 --port $PORT` (Procfile included)
- Env: `ANTHROPIC_API_KEY`, `CLAUDE_MODEL` (default `claude-sonnet-5-5`), `ALLOWED_ORIGINS=https://<your-vercel-app>`

**Frontend → Vercel**
- Root: `frontend/` · Framework: Next.js
- Env: `BACKEND_URL=https://<your-backend>` (server-side only)

---

## Project layout
```
backend/
  main.py          FastAPI app, validation, rate limiting
  analyzer.py      deterministic forensics engine
  investigator.py  Claude analyst, schema, grounding gate, fallback analyst, timeline
  demos.py         3 built-in case files
frontend/src/
  app/page.tsx                     Operations Center
  app/api/[...path]/route.ts       server-side proxy
  components/InvestigationReport.tsx  results screen
  components/Scanning.tsx          pipeline animation
```

## Tech
Next.js 15 (App Router) · TypeScript · Tailwind CSS 4 · Lucide · IBM Plex (self-hosted) · Python · FastAPI · Pydantic · tldextract · Anthropic Claude API (structured tool-use output)
