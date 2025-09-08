# PIN0CCHI0 – Autonomous Web Bug‑Hunting AI

PIN0CCHI0 is an autonomous, modular security testing platform that behaves more like a bug hunter than a point‑and‑shoot scanner. It perceives targets, plans actions, executes tests, learns from results, and can converse (Jarvis‑style) via an AI chat endpoint.

The system integrates reconnaissance and testing tools, performs a deep scan pass with nuclei, and exposes a Web UI for real‑time progress, results, evidence viewing, and manual‑mode integration with Burp.


## Table of Contents
- [Highlights](#highlights)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Web UI](#web-ui)
  - [Manual Mode (Burp Integration)](#manual-mode-burp-integration)
  - [Evidence Viewer and PoC Export](#evidence-viewer-and-poc-export)
  - [Actionable AI (Jarvis)](#actionable-ai-jarvis)
- [CLI Usage](#cli-usage)
  - [Proxy and Capture from CLI](#proxy-and-capture-from-cli)
  - [Log and HAR/Curl Exporters](#log-and-harcurl-exporters)
- [Autonomous Mode](#autonomous-mode)
- [GraphQL Scanner](#graphql-scanner)
- [Configuration](#configuration)
- [Environment and Secrets](#environment-and-secrets)
- [Results and Logs](#results-and-logs)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Safety and Scope](#safety-and-scope)
- [Training and Knowledge Updates](#training-and-knowledge-updates)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)


## Highlights
- Autonomous agent loop: perceive → plan → act → learn
- Modular toolchain (recon and vuln testing) + nuclei deep scan
- Persistent memory with prioritized queue and adaptive payload selection
- Web UI: real‑time progress, vulnerabilities, Evidence Viewer, Manual Mode (Burp), HAR/Curl exporters
- Jarvis‑style chat and AI command endpoint for actionable control
- CLI parity for proxy routing and artifact export


## Architecture
Core components:
- `core/engine.py`
  - Orchestrates modules, autonomous loop, nuclei final pass
  - Uses memory for prioritization and learning
- `core/module_manager.py`
  - Discovers and loads modules (subclasses of BaseModule)
- `core/base_module.py`
  - Base classes: BaseModule, ReconModule, VulnTestingModule
- `core/memory.py`
  - SQLite memory (targets, scans, endpoints, findings, anomalies, failures, payload_stats)
  - AgentContext for plan/priorities and adaptive payload outcomes
- `core/payloads.py`
  - Payload library (SQLi/XSS/Command/NoSQL), tamper encoders, WAF hints
- `web_ui/app.py`
  - Flask + Socket.IO Web UI, API endpoints, AI chat/command
- `web_ui/templates/*`
  - Dashboard, scans, vulnerabilities, evidence viewer
- `pin0cchi0-cli.py`
  - CLI with scan, proxy toggles, and export subcommands

Selected modules:
- Recon: `modules/recon/*` (crawler, API discovery, tech fingerprinting, etc.)
- Vuln testing: `modules/vuln_testing/*` (xss_scanner, sql_injection, csrf_scanner, ssrf_scanner, lfi/path_traversal, etc.)
- New: `modules/vuln_testing/graphql_scanner.py` (introspection, depth/complexity, alias batching heuristics)
- Deep scan: nuclei runner


## Requirements
- Python 3.10+
- (Recommended) Linux/WSL for external tools
- pip for Python packages

External tools (optional)
- ProjectDiscovery suite: httpx, katana, naabu, nuclei
- Others: ffuf, gobuster, dirsearch, wfuzz, arjun, etc.


## Installation
```
python3 -m venv venv
# Linux/macOS
. venv/bin/activate
# Windows (PowerShell)
venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

Optional external tools (examples):
```
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```


## Quick Start
1) Install Python dependencies (see above)
2) Optionally install external tools
3) Run a scan via CLI:
```
python pin0cchi0-cli.py scan https://example.com
```
4) Start the Web UI:
```
python -m web_ui.app
# Open http://localhost:5000
```


## Web UI
Start the Web UI:
```
python -m web_ui.app
# Open http://localhost:5000
```

- Dashboard: start scans; monitor progress
- Scans page: view details, progress, logs
- Vulnerabilities page: review and filter findings
- Evidence Viewer: view nearest captured request/response and copy a curl PoC

### Manual Mode (Burp Integration)
Manual Mode routes the agent’s HTTP requests (made via the built‑in HTTP client) through an upstream proxy (e.g., Burp) and captures request/response pairs for export.

Steps:
1) Start Burp on 127.0.0.1:8080 (Proxy → Intercept off)
2) Enable Manual Mode in the Dashboard → Manual Mode & Exports card
   - Toggle “Manual Mode”
   - Set Proxy Address: http://127.0.0.1:8080
   - Click Apply
3) Optional: use “Proxy Browser” to see OS‑specific commands to start Chrome through the proxy

Notes:
- Manual Mode affects only traffic made by PIN0CCHI0’s HTTP client. External CLIs (e.g., sqlmap, ffuf) require their own proxy flags.
- Captured HTTP can be viewed/exported (see below) and used in the Evidence Viewer.

### Evidence Viewer and PoC Export
- On the Vulnerabilities page or Scan Details page, click “Evidence” next to a finding
- The modal shows:
  - Request (method, URL, headers, body)
  - Response (status, headers, body snippet)
  - “Copy curl” button to copy a ready‑to‑replay PoC
- You can also export all captured HTTP as HAR (see Exporters below)

### Actionable AI (Jarvis)
Ollama chat:
```
# Example (WSL/Ubuntu)
curl -fsSL https://ollama.com/install.sh | sh
ollama serve
ollama pull llama3.1
```
Set environment for the Web UI:
```
export OLLAMA_BASE_URL=http://localhost:11434
export OLLAMA_MODEL=llama3.1
```
Use in UI: the floating chat widget on the lower‑right.

Operational commands endpoint:
- POST /api/ai_command accepts simple commands such as:
  - “enable manual mode”, “set proxy to http://127.0.0.1:8080”, “disable manual mode”
  - “start scan https://example.com modules: xss, sql”
  - “export har”, “copy curl”
  - “submit to burp https://example.com” (if BURP_API_URL configured)


## CLI Usage
List modules:
```
python pin0cchi0-cli.py list
```
Run a targeted scan:
```
python pin0cchi0-cli.py scan https://example.com --modules xss_scanner,sql_injection
```
Run in autonomous mode:
```
python pin0cchi0-cli.py scan https://example.com --autonomous
```

### Proxy and Capture from CLI
Route the agent’s HTTP through Burp and capture traffic (Manual Mode from CLI):
```
python pin0cchi0-cli.py scan https://example.com --manual-proxy http://127.0.0.1:8080
```
Disable proxy routing:
```
python pin0cchi0-cli.py scan https://example.com --no-manual-proxy
```

### Log and HAR/Curl Exporters
Show captured HTTP log (default limit=200):
```
python pin0cchi0-cli.py http-log show --limit 100
```
Clear the HTTP log:
```
python pin0cchi0-cli.py http-log clear
```
Export HAR:
```
python pin0cchi0-cli.py har --export out.har.json
```
Generate PoC curl (for last entry unless index is provided):
```
python pin0cchi0-cli.py curl
python pin0cchi0-cli.py curl --index 3
```


## Autonomous Mode
- The agent loop (perceive → plan → act → learn) discovers endpoints, runs prioritized tests, and learns from outcomes
- Persistent memory tracks scans/endpoints/findings/failures and payload statistics with WAF hints
- Enable via CLI:
```
python pin0cchi0-cli.py scan https://example.com --autonomous
```


## GraphQL Scanner
- Module: `modules/vuln_testing/graphql_scanner.py`
- Safe checks:
  - Endpoint detection at common paths
  - Introspection detection (flags High if `__schema` present)
  - Depth/complexity heuristic (nested schema query → large/slow responses)
  - Alias batching heuristic (many aliases → slow response)
- Include in runs with `--modules graphql_scanner` or via the Web UI


## Environment and Secrets
- Copy `.env.example` to `.env` and set values for your environment. Do not commit `.env`.
- Common variables:
  - `PIN0CCHI0_HOST`, `PIN0CCHI0_PORT`, `PIN0CCHI0_DEBUG`
  - `OLLAMA_BASE_URL`, `OLLAMA_MODEL` (and `OLLAMA_API_KEY` if needed)
  - `BURP_PROXY` (default proxy address used when enabling Manual Mode from the UI)
  - `BURP_API_URL` (optional Burp REST bridge; enables /api/burp/* endpoints)
  - Bug bounty platform tokens (optional, for future modules/integrations):
    - `HACKERONE_API_TOKEN`, `HACKERONE_API_BASE`
    - `BUGCROWD_API_TOKEN`, `BUGCROWD_API_BASE`
    - `INTIGRITI_API_TOKEN`, `YESWEHACK_API_TOKEN`
  - Other integrations: `SLACK_WEBHOOK_URL`, `JIRA_*`

## Configuration
- Default config in `config/default.yaml`, CLI JSON overrides, and environment variables for the Web UI
- Useful Web UI env vars:
  - `PIN0CCHI0_HOST`, `PIN0CCHI0_PORT`, `PIN0CCHI0_DEBUG`
  - `OLLAMA_BASE_URL`, `OLLAMA_MODEL` (and `OLLAMA_API_KEY` if needed)
  - `BURP_API_URL` (optional REST bridge to Burp)


## Results and Logs
- Results per run: `results/<timestamp>-<target>/`
  - Module‑specific JSON result files
  - `results.json` for consolidated output (if using CLI `--json`)
- Web UI logs available at `/api/scan_log/<scan_id>`
- Captured HTTP: see `/api/http_log`, `/api/har`, `/api/curl` (Web) or CLI subcommands listed above


## Testing
- Python unit tests:
```
python -m unittest discover -s tests -p "test_*.py" -q
```
- Some tests require external tools or are skipped if missing


## Training and Knowledge Updates
See docs/training.md for:
- Automatic ingestion of public sources (Hacktivity, Crowdstream, NVD, KEV, nuclei templates)
- Normalization to local knowledge cards (JSON/YAML)
- Optional AI summarization to extract techniques/payloads/WAF hints
- Manual training to add payload overlays and tune modules
- Scheduling fetchers (cron/Task Scheduler)

## Troubleshooting
- Chat returns error:
  - Ensure `ollama serve` is running and `OLLAMA_BASE_URL` is set
- Proxy routing not visible in Burp:
  - Enable Manual Mode (Web) or use `--manual-proxy` (CLI); confirm that requests are made by the built‑in HTTP client (external CLIs require their own proxy flags)
- Evidence shows “No HTTP log entries”:
  - Capture must be enabled (Manual Mode on) before or during the scan
- Template/UI issues after updates:
  - Refresh without cache (Ctrl+Shift+R) or restart the Web app


## Safety and Scope
- Only test targets you are authorized to test
- Use allowlists and rate/budget limits to avoid disruption
- Sensitive evidence may be captured; handle results and HTTP logs responsibly


## Roadmap
- Extend adaptive payloads to SSRF/path traversal/LFI/RFI/NoSQL/LDAP/XPath and command injection
- Headless browser pass for DOM/stored XSS
- Tools Readiness page; Agent plan/queue view; streaming chat with action cards
- Test lab via Docker Compose and coverage matrix; exporters (SARIF/HTML/PDF); regression diffs; Slack/Jira


## Contributing
- Open issues for feature requests or bugs
- PRs should include a brief test/verification plan and be linted
- Avoid committing secrets; use environment variables/config


## License
This project is provided without warranty. Refer to LICENSE if present, otherwise follow your organization’s policies.
