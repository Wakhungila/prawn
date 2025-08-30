# PIN0CCHI0 – Autonomous Web Bug‑Hunting AI

PIN0CCHI0 is an autonomous, modular security testing platform that behaves more like a bug hunter than a point‑and‑shoot scanner. It perceives targets, plans actions, executes tests, learns from results, and can converse (Jarvis‑style) via an AI chat endpoint.

The system integrates modern reconnaissance and testing tools, uses a deep scanner (nuclei) as a final pass, and exposes a Web UI for real‑time progress and results.


## Table of Contents
- [Highlights](#highlights)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Web UI](#web-ui)
- [CLI Usage](#cli-usage)
- [Autonomous Mode](#autonomous-mode)
- [Tool Checker](#tool-checker)
- [Nuclei Integration (Final Pass)](#nuclei-integration-final-pass)
- [Ollama AI Chat (Jarvis)](#ollama-ai-chat-jarvis)
- [Configuration](#configuration)
- [Results and Logs](#results-and-logs)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Safety and Scope](#safety-and-scope)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)


## Highlights
- Autonomous agent loop: perceive → plan → act → learn
- Modern toolchain integration (httpx, katana, naabu, ffuf, gobuster, nuclei, and many more)
- Deep scanning with nuclei as the final “last resolve” step
- Web UI with real‑time progress and a dark, neon theme
- Jarvis‑style chat endpoint via Ollama (local AI server)
- Tool checker to verify external CLI tools are installed and ready
- Memory/prioritization layer scaffolded for persistent learning and planning


## Architecture
Key components:
- `core/engine.py`
  - Orchestrates module execution; runs nuclei at the end of a scan
  - Autonomous loop scaffold (perceive/plan/act/learn)
- `core/module_manager.py`
  - Discovers and loads modules (finds subclasses of BaseModule automatically)
- `core/base_module.py`
  - Base classes: BaseModule, ReconModule, VulnTestingModule (compat alias VulnerabilityTestingModule)
- `core/memory.py`
  - SQLite‑backed MemoryStore and AgentContext (prioritization, findings, actions, artifacts, signatures)
- `core/tool_checker.py`
  - Detects presence and versions of recommended tools (see Tool Checker section)
- Modules (selected examples)
  - Recon: `modules/recon/web_crawler.py`, `tech_fingerprint.py`, `api_discovery.py`, `dns_enum.py`, `dir_enum.py`, etc.
  - Vuln Testing: `modules/vuln_testing/*` (xss_scanner, sql_injection, csrf_scanner, insecure_design_scanner, etc.)
  - Deep scan: `modules/vuln_testing/nuclei_runner.py` (final pass)
- Web UI: `web_ui/app.py` (Flask + Socket.IO), templates and static assets
- CLI Launchers: `pin0cchi0.py`, `pin0cchi0-cli.py`


## Requirements
- Python 3.10+
- (Recommended) Linux/WSL for external tools
- pip for Python packages

Install Python deps:
```
python3 -m venv venv
. venv/bin/activate    # Windows (PowerShell): venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

External tools (pick and choose)
- Install via Go/pip/apt depending on tool. See Tool Checker below to verify status.
- Common setup (Ubuntu/WSL):
```
sudo apt update && sudo apt install -y golang build-essential python3-pip
export PATH=$PATH:$(go env GOPATH)/bin
```

Examples (ProjectDiscovery):
```
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Examples (others):
```
pip install dirsearch wfuzz cloud_enum SecretFinder linkfinder s3scanner
sudo apt install gobuster   # or: go install github.com/OJ/gobuster@latest

go install github.com/ffuf/ffuf@latest

go install github.com/lc/gau@latest

go install github.com/tomnomnom/waybackurls@latest

go install github.com/tomnomnom/qsreplace@latest

pip install arjun

go install github.com/assetnote/kiterunner@latest

go install github.com/gwen001/github-subdomains@latest

pip install trufflehog

go install github.com/damit5/gitdorks_go@latest

go install github.com/devanshbatham/FavFreak@latest

go install github.com/edoardottt/cariddi@latest

go install github.com/003random/getJS@latest
```


## Quick Start
1) Install Python requirements (see above).
2) Optionally install external tools you want to use.
3) Run a scan with the file‑based CLI:
```
python3 pin0cchi0.py -t https://example.com
```
4) Start the Web UI:
```
python3 -m web_ui.app
# Open http://localhost:5000
```


## Web UI
- Start: `python3 -m web_ui.app`
- Default: http://localhost:5000
- Endpoints:
  - `/` dashboard
  - `/scan/<scan_id>` scan details
  - `/vulnerabilities` list of findings (with pagination)
  - `/api/start_scan` start a scan (POST JSON: target, scan_type, options)
  - `/api/scans`, `/api/scan_status/<id>`, `/api/scan_results/<id>`, `/api/scan_log/<id>`
  - `/api/ai_chat` Jarvis‑style chat (GET for usage; POST to talk to the agent)


## CLI Usage
Two launchers are available:

- Simple engine runner:
```
python3 pin0cchi0.py -t https://example.com
```
- Feature‑rich CLI launcher (modules, autonomous mode, etc.):
```
python3 pin0cchi0-cli.py list
python3 pin0cchi0-cli.py scan https://example.com --modules web_crawler,http_security_scanner,insecure_design_scanner
python3 pin0cchi0-cli.py scan https://example.com --autonomous
```
Notes:
- The engine automatically runs nuclei as the final step if available.
- Many modules warn/skip if their external tool isn’t installed.


## Autonomous Mode
- The agent loop (perceive → plan → act → learn) is scaffolded:
  - Perceive: web crawling, API discovery, tech fingerprinting
  - Plan: pick next tests (HTTP security, insecure design, XSS/SQLi/CSRF, etc.)
  - Act: execute modules, collect findings
  - Learn: add new endpoints (limited by max_depth, max_actions); avoid duplicates
- Run via CLI launcher:
```
python3 pin0cchi0-cli.py scan https://example.com --autonomous
```
- Limits (example JSON config):
```
{
  "autonomous_limits": {"max_depth": 2, "max_actions": 30}
}
```


## Tool Checker
Check tool readiness:
```
python3 -m core.tool_checker
```
- Output includes present/missing counts and install URLs.
- amass is marked deprecated for this pipeline; modern alternatives are preferred.


## Nuclei Integration (Final Pass)
- A dedicated module `modules/vuln_testing/nuclei_runner.py` runs nuclei at the end of a scan.
- Alias: `nuclei` → `nuclei_runner` (you can include it explicitly via `--modules nuclei`).
- JSON output is parsed to add vulnerabilities to results.


## Ollama AI Chat (Jarvis)
Talk to the agent via REST.

1) Install and start Ollama (WSL/Ubuntu example):
```
curl -fsSL https://ollama.com/install.sh | sh
ollama serve
curl -s http://localhost:11434/api/tags
ollama pull llama3.1
```
2) Configure the web app environment (do not hardcode secrets):
```
export OLLAMA_BASE_URL='http://localhost:11434'
export OLLAMA_MODEL='llama3.1'
# Only set this if your endpoint requires it; local Ollama typically does not
# export OLLAMA_API_KEY='YOUR_TOKEN'
```
3) Start the Web UI: `python3 -m web_ui.app`

4) Use the chat endpoint:
- GET for usage:
```
curl -s http://localhost:5000/api/ai_chat | jq
```
- POST a message:
```
curl -s -X POST http://localhost:5000/api/ai_chat \
  -H 'Content-Type: application/json' \
  -d '{"message":"Hello Jarvis, summarize the last scan."}' | jq
```


## Configuration
- Most config is centralized in `config/default.yaml` and JSON overrides passed to CLIs.
- Engine config parameters:
  - `target`, `output_dir`
  - `modules`, `exclude_modules`
  - `autonomous_limits.max_depth` / `max_actions`
  - Tool‑specific options in respective modules
- Web UI environment variables:
  - `PIN0CCHI0_HOST`, `PIN0CCHI0_PORT`, `PIN0CCHI0_DEBUG`
  - `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `OLLAMA_API_KEY`


## Results and Logs
- Results per run: `results/<timestamp>-<target>/`
  - `web_crawl_results.json`, `api_discovery_results.json`, `tech_fingerprint_results.json`, etc.
  - `nuclei_results.json` / `nuclei_results.txt` (if nuclei present)
- Logs: `logs/pin0cchi0_YYYYMMDD_HHMMSS.log`
- Web UI exposes scan logs via `/api/scan_log/<scan_id>`


## Testing
- Python unit tests:
```
python -m unittest discover -s tests -p "test_*.py" -q
```
- Some tests require external tools (or will be skipped/warn).


## Troubleshooting
- `Method Not Allowed` on `/api/ai_chat`:
  - Use POST for chat; GET returns usage. The route supports both.
- `Connection refused` to Ollama:
  - Ensure `ollama serve` is running and `OLLAMA_BASE_URL` is correct.
- External tool warnings:
  - Use the tool checker to see what’s missing and install as needed.
- Windows vs WSL endpoints:
  - If the UI runs in WSL but Ollama runs in Windows, use the Windows IP/port reachable from WSL.
- No findings / instant completion:
  - Ensure the engine is using the new orchestrator (as in `pin0cchi0.py`). Many modules skip if tools are missing.
- Template errors in Web UI:
  - The app was updated to remove unsupported Jinja tags and to include `format_datetime` filter.


## Safety and Scope
- Only test targets you are authorized to test.
- Use allowlists and rate/budget limits to avoid disruption.
- Sensitive evidence may be captured; handle results responsibly.


## Roadmap
- Integrate cloud/JS/repo secrets modules and prefer modern toolchain over legacy paths
- Wire `core/memory.py` into the autonomous loop for persistent planning and prioritized next steps
- Tools page in the Web UI, plus richer dashboard (KPI cards; AI plan and queue)
- Ollama chat panel in the Web UI for conversational planning and triage
- Exporters (SARIF/HTML/PDF), Slack/Jira webhooks, and regression diffing


## Contributing
- Open an issue for feature requests or bugs.
- PRs should be linted and include a brief test/verification plan.
- Avoid committing secrets; use environment variables/config.


## License
This project is provided without warranty. Refer to the repository’s LICENSE file if present, otherwise default to your organization’s policies.
