# SentinelAI v2

An AI-powered cybersecurity **triage and response** platform. SentinelAI analyzes
network captures, Windows event logs, and suspicious files using an AI model as the
core reasoning engine — not just static rules. Every module maps findings to
**MITRE ATT&CK**, scores severity, generates a tailored **investigation playbook**,
and proposes tiered **automated response (SOAR)** actions.

It is built to be useful to a real analyst *and* readable for someone learning security.

---

## The key idea: pre-process, then let the AI reason

Raw security artifacts (a multi-megabyte PCAP, thousands of event-log records, a
binary) are far too large and noisy to hand directly to an AI, and doing so blows
the context window while burying the signal.

So SentinelAI puts a **deterministic pre-processor** in front of the model. The
pre-processor parses the raw file and emits a compact, structured **summary** — flows,
entropy scores, event sequences, extracted strings, IOCs. The AI then reasons over
that summary. This keeps full analytical accuracy while staying inside the context
window, and makes runs cheaper and more reproducible.

```
Raw File → Parser → Pre-processor → [Summary] → AI Analysis → Scoring → Playbook → SOAR → Dashboard
```

Every module's pre-processor outputs the **same** `Summary` JSON shape
(`backend/app/core/schema.py`). Because of that single contract, the AI engine,
scoring, playbook generator, MITRE mapping, and dashboard never need to know which
kind of file was analyzed. **Adding a new file type = writing one new pre-processor.**
Stages can be developed, tested, and swapped independently — and teammates can each
own a stage without stepping on each other.

---

## Modules

**Network (PCAP)** — dependency-free pcap parser (Ethernet/IP/TCP/UDP, DNS queries,
TLS ClientHello + SNI, **cleartext HTTP request lines**, and a **JA3-style TLS client
fingerprint**). The pre-processor reconstructs flows, computes payload entropy, and
detects beaconing (low-jitter periodic callbacks), high-entropy traffic on cleartext
ports, port scans, suspicious/DGA-like DNS, **DNS tunneling (volume-scored)**,
**known-bad JA3 fingerprints**, **tooling/empty HTTP user-agents**, legacy TLS,
plaintext protocols, and volume/baseline anomalies. Optional AbuseIPDB reputation +
IP geolocation enrichment (geolocation is plotted on a connection map in the dashboard).

**Forensics (Windows event logs)** — accepts `.evtx` (via optional `python-evtx`),
or `.xml`/`.jsonl` exports (stdlib). The pre-processor extracts event-ID frequencies
and a chronological timeline, then detects *sequences*: brute-force-then-success,
**password-spray (one source, many accounts)**, account-created-then-elevated,
**RDP lateral movement**, **persistence stacking (service + scheduled task)**,
**Defender tampering**, and log-clearing cover-ups — so the AI interprets the
**story**, not isolated IDs.

**Malware (static, no execution)** — hashes (MD5/SHA1/SHA256), whole-file and
per-section entropy (packing detection), stdlib PE header parsing (machine, compile
timestamp, sections, signature presence; richer imports via optional `pefile`),
string extraction with IOC classification (URLs, IPs, domains, registry Run keys,
wallet addresses, suspicious commands), capability inference from API combinations
(injection, ransomware sweep, keylogging, C2…), and a built-in **YARA-style rule
engine** (ransomware notes, shadow-copy deletion, log tampering, obfuscated
PowerShell, credential-dumping tooling, embedded PE droppers, C2 markers — easy to
extend in `modules/malware/rules.py`). Optional VirusTotal hash lookup.

**Cross-module correlation** — select two or more completed analyses and SentinelAI
produces a single unified score, combined ATT&CK matrix, and one investigation
playbook that connects findings across modules (e.g. network beaconing *and* a new
admin account created at the same time → one incident path).

---

## Engineering features

- **AI quality** — few-shot-steered prompts, an optional **self-verification pass**
  (`AI_SELF_VERIFY=1`) where the model critiques and corrects its own findings, a
  **response cache** keyed on summary content (`AI_CACHE=1`, identical input never
  re-calls the API), and **per-analysis token + USD cost** accounting shown in the report.
- **Performance & robustness** — PCAPs are **streamed off disk** in constant memory
  (`iter_pcap`), so multi-gigabyte captures don't blow up RAM. Failures degrade
  gracefully into user-facing error reports instead of crashing the pipeline.
- **Persistence** — analyses are stored in **SQLite** (`app/core/store.py`) and survive
  a server restart. The dashboard shows **live progress %** per analysis while it runs.
- **Dashboard** — animated risk gauge, interactive **MITRE ATT&CK kill-chain heatmap**,
  **connection-geography map** of external IPs, per-module telemetry charts, collapsible
  **IOC tables** (click to copy), toast notifications, and **JSON / PDF report export**.
- **Threat-intelligence feed** — JA3 fingerprints and known-bad IPs/domains drive the
  network module's highest-confidence detections. Ships with a **bundled offline snapshot**
  (`app/data/threat_intel.json`) so it works with zero keys, and can **refresh live from
  abuse.ch** on demand (`POST /api/threatintel/refresh`, cached to disk).
- **Live progress over WebSocket** — the dashboard subscribes to `/api/ws/analyses` and
  receives pushed updates as each stage completes, **falling back to polling** if the
  socket drops, so progress bars move in real time without hammering the API.
- **Explainable findings** — every finding has an **“✦ Explain”** drill-down that expands
  it into an analyst-grade writeup (what it means, why it matters, how to confirm,
  recommended response). Uses the live model when configured; deterministic under `mock`.
- **Formal IR report (PDF)** — `GET /api/analyses/{id}/report.pdf` renders a
  consulting-grade **incident response report** via **ReportLab**, structured the way a
  real SOC/IR team delivers it: **TLP:AMBER** classification marking on every page (FIRST
  TLP v2.0), cover page, document control + distribution + analyst sign-off, executive
  summary, incident overview, severity assessment, timeline, technical findings (F-001…),
  **MITRE ATT&CK** mapping, an actionable **IOC table** (annotated with threat-intel and
  reputation context), NIST SP 800-61r3 **containment/eradication/recovery**, tactical +
  strategic recommendations, analyst conclusion, and a methodology appendix. Degrades to a
  printable HTML view if ReportLab isn't installed.

## AI providers (one env var to switch)

`AI_PROVIDER` selects the engine:

- `mock` — **default**, fully offline and deterministic. Promotes pre-processor
  observations into findings so the entire pipeline, API, dashboard, and tests run
  with **no API key**. Great for development, demos, and CI.
- `deepseek` — OpenAI-compatible, cheap; recommended for development/testing.
- `claude` — Anthropic Messages API for the production/final version.

Switching is a single line in `.env`; no code changes (`backend/app/ai/provider.py`).

---

## Quick start

### 1. Generate sample data (no real malware/captures needed)

```bash
python samples/generate_samples.py
# → samples/generated/{beaconing.pcap, compromise.xml, fake_malware.bin}
```

### 2. Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # optional
pip install -r requirements.txt
cp ../.env.example ../.env          # defaults to AI_PROVIDER=mock — works offline
uvicorn app.main:app --reload       # http://localhost:8000/docs
```

### 3. Frontend

```bash
cd frontend
npm install
npm run dev                         # http://localhost:5173 (proxies /api → :8000)
```

Open the dashboard, drag in one of the sample files (or your own), and watch the
report build: overview + score, severity distribution, findings with MITRE tags and
remediation, activity timeline, ATT&CK matrix, investigation playbook, and SOAR
actions. Check two analyses to run a correlation.

### Run the tests

```bash
cd backend
pip install pytest
AI_PROVIDER=mock pytest -q
```

The suite covers each parser/pre-processor, scoring, MITRE mapping, SOAR tiers, the
full pipeline per module, cross-module correlation, observation de-duplication, the
account/session layer, and the REST API (auth gating, per-user scoping, the
report-embedding list endpoint, and an end-to-end upload→report run) — all offline.
Every push runs the same suite plus a frontend build in CI (`.github/workflows/ci.yml`).

---

## API

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/analyze` | Upload a file (multipart `file`, optional `module`); runs in background |
| `GET`  | `/api/analyses` | List analyses with status/score/severity (full report embedded for completed cases, so the aggregate views render in one request) |
| `GET`  | `/api/analyses/{id}` | Full report for one analysis |
| `GET`  | `/api/analyses/{id}/report.pdf` | Download the formal TLP:AMBER incident-response PDF |
| `POST` | `/api/analyses/{id}/explain` | Body `{finding_index}` → analyst-grade drill-down for one finding |
| `WS`   | `/api/ws/analyses?token=…` | Live progress stream (pushed `{analyses}` on any change) |
| `POST` | `/api/correlate` | Body: JSON array of ids → unified cross-module view |
| `POST` | `/api/soar/{id}/approve?action_index=N` | Approve a pending (medium-tier) action |
| `POST` | `/api/threatintel/refresh` | Pull fresh JA3/IP indicators from abuse.ch |
| `GET`  | `/api/health` | Provider, PDF, threat-intel + enrichment status |

---

## SOAR tiers

Response actions are gated by the overall score: **low → notify only**,
**medium → suggest and wait for analyst approval**, **high/critical → act
immediately** (execution is simulated/logged here; wiring real EDR/firewall APIs is
a clean integration point in `backend/app/core/soar.py`).

---

## Project layout

```
backend/
  app/
    core/        schema.py (the Summary contract), scoring, mitre, soar
    modules/
      network/   parser.py, preprocessor.py, enrich.py
      forensics/ parser.py, preprocessor.py
      malware/   parser.py, preprocessor.py, enrich.py
    ai/          provider.py (deepseek/claude/mock), analyzer.py, playbook.py
    pipeline/    orchestrator.py (wires all stages, + cross-module correlate)
    api/         routes.py
    main.py
  tests/         test_pipeline.py
frontend/        React + Vite dashboard (Recharts)
samples/         generate_samples.py
```

---

## Roadmap / stretch goals

- **Live capture mode** — the architecture is already live-ready: the orchestrator is
  designed so the pre-processor and AI run incrementally on a schedule instead of once,
  with throttling so the AI is only called on meaningful change. File-upload mode ships
  first; the dashboard polls today and can move to websockets/streaming.
- **Dynamic malware analysis** — run samples in an isolated sandbox VM to observe live
  behavior (kept as future work due to setup complexity).
- **Scale-out persistence** — analyses already persist to **SQLite** today
  (`backend/app/core/store.py`, behind a small swappable interface); the next step is a
  drop-in Postgres backend for multi-node deployments.

> Note: this is an educational/portfolio project. The bundled `fake_malware.bin` is a
> harmless byte pattern that *looks* suspicious to static analysis — it does not execute.
> pcapng captures should be converted first: `tshark -F pcap -r in.pcapng -w out.pcap`.
```
