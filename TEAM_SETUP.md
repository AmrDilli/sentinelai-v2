# SentinelAI v2 — Team Setup

Everything you need to get the project running on your own machine.

## 1. Prerequisites (install these once)

| Tool | Version | Why | Get it |
|------|---------|-----|--------|
| **Python** | 3.10+ | backend / pipeline | https://www.python.org/downloads/ |
| **Node.js** | 18+ (20+ ideal) | React dashboard | https://nodejs.org |
| **Git** | any | get + share the code | https://git-scm.com |
| Wireshark / tshark | optional | convert `.pcapng` → `.pcap` | https://www.wireshark.org |

Check they're installed:
```bash
python3 --version
node --version
git --version
```

## 2. Get the code

```bash
git clone https://github.com/YOUR_USERNAME/sentinelai-v2.git
cd sentinelai-v2
```

## 3. Backend (Python + FastAPI)

```bash
python3 samples/generate_samples.py     # makes test files in samples/generated/
cp .env.example .env                     # default AI_PROVIDER=mock works with NO key

cd backend
python3 -m venv .venv
source .venv/bin/activate                # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload            # → http://localhost:8000/docs
```

**Python dependencies** (installed by `requirements.txt`):
- `fastapi`, `uvicorn[standard]` — web server
- `python-multipart` — file uploads
- `requests` — AI providers + threat-intel lookups
- `python-evtx` — native `.evtx` parsing (optional; `.xml`/`.jsonl` work without it)
- `pefile` — richer PE imports (optional; basic PE parsing is built-in)
- `pytest` — tests

## 4. Frontend (React + Vite)

Open a **second terminal**:
```bash
cd sentinelai-v2/frontend
npm install                              # downloads node dependencies
npm run dev                              # → http://localhost:5173
```

**Node dependencies** (installed by `npm install`): `react`, `react-dom`,
`recharts` (charts), `vite`, `@vitejs/plugin-react`.

## 5. Use it

Open **http://localhost:5173**, drag in a file from `samples/generated/`
(`beaconing.pcap`, `compromise.xml`, or `fake_malware.bin`), and watch the report build.

## 6. (Optional) Turn on real AI + threat intel

Edit `.env` — no code changes needed:
```
AI_PROVIDER=deepseek
DEEPSEEK_API_KEY=sk-...        # platform.deepseek.com (cheap)
# or AI_PROVIDER=claude + ANTHROPIC_API_KEY=...
ABUSEIPDB_API_KEY=...          # optional, free tier — IP reputation
VIRUSTOTAL_API_KEY=...         # optional, free tier — malware hash lookup
```
Restart uvicorn after editing. **Never commit `.env`** — it's git-ignored.

## 7. Run the tests

```bash
cd backend
source .venv/bin/activate
pytest -q                                # all offline, uses mock AI
```

## Working in parallel

The pipeline is `Raw File → Parser → Pre-processor → AI → Scoring → Playbook → Dashboard`,
and every module outputs the same `Summary` shape (`backend/app/core/schema.py`).
That means you can split work cleanly — suggested ownership:
- **Network module** — `backend/app/modules/network/`
- **Forensics module** — `backend/app/modules/forensics/`
- **Malware module** — `backend/app/modules/malware/`
- **AI / scoring / playbook** — `backend/app/ai/`, `backend/app/core/`
- **Dashboard** — `frontend/src/`

Use git branches so you don't overwrite each other:
```bash
git checkout -b my-feature
# ...work...
git add . && git commit -m "what I did"
git push -u origin my-feature
# then open a Pull Request on GitHub
```

## Common gotchas

- **Dashboard shows "Backend offline"** → the backend isn't running, or not on port 8000.
- **`.pcapng` won't parse** → convert: `tshark -F pcap -r in.pcapng -w out.pcap`.
- **`pip` / `python` not found** → on Mac/Linux use `python3` and `pip3`.
- **Port already in use** → `uvicorn app.main:app --reload --port 8001` (and update the proxy
  target in `frontend/vite.config.js`).
- **Score appears with no API key** → expected; that's the rule-based heuristic floor. Add a
  key for real AI reasoning (step 6).
