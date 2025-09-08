# Training and Knowledge Updates

This document explains how to keep PIN0CCHI0 aware of the latest techniques, payloads, and real‑world issues from public sources (e.g., HackerOne, Bugcrowd/Crowdstream, CVE/NVD, ProjectDiscovery templates) and how to update the system both automatically and manually.

Important: PIN0CCHI0 uses a hybrid approach:
- Reasoning layer: an LLM (Ollama) that plans/triages and converses. It isn’t automatically “up to date.”
- Data layer: your curated feeds (Hacktivity, Crowdstream, NVD/CVE, KEV, templates, exploit feeds) and local memory.
- The assistant becomes “aware” by ingesting and summarizing new data, and by learning from payload outcomes (memory/payload_stats).


## Overview of Training Paths

1) Automatic ingestion (recommended)
   - Periodically fetch curated sources (Hacktivity/Crowdstream/CVE/etc.)
   - Normalize to JSON “knowledge cards” under `knowledge/` (not committed)
   - Optionally summarize with the LLM to extract key techniques, payloads, and WAF hints
   - Review and optionally add promising payloads to an overlay file for adaptive testing

2) Manual training
   - Manually add payloads and techniques to the payload library overlay
   - Manually add knowledge cards with examples/evidence
   - Prompt the assistant with context from recent knowledge when planning scans


## Directory Layout and Files

- `knowledge/` (local, ignored by git): normalized JSON/YAML knowledge cards harvested from feeds
  - Example: `knowledge/2025-01-05-hacktivity.json`
- `scripts/` (optional): your custom fetchers/transformers
- `.env`: API tokens for platforms if you have access and their APIs permit it

Note: `.gitignore` excludes `.env`, `knowledge/`, and sensitive outputs by default.


## Data Sources and Ingestion Targets

Suggested sources (public/unauthenticated unless noted):
- HackerOne Hacktivity (public activity feed)
- Bugcrowd Crowdstream (community write‑ups / RSS)
- NVD JSON data feeds (CVE / CPE) and CISA KEV catalog
- ProjectDiscovery nuclei templates (git repo)
- Exploit‑DB RSS feed
- GitHub Security Advisories API

Ingest each into a normalized schema, e.g.:
```json
{
  "source": "hackerone/hacktivity",
  "fetched_at": "2025-01-05T14:22:31Z",
  "items": [
    {
      "title": "DOM XSS in foo()",
      "url": "https://hackerone.com/reports/1234567",
      "date": "2025-01-05T13:00:00Z",
      "tags": ["xss", "dom"],
      "summary": "...",
      "payloads": ["<svg onload=alert(1)>", "\"><img src=x onerror=alert(1)>"]
    }
  ]
}
```


## Example Fetcher (Python)

Create `scripts/fetch_hacktivity.py` (not provided by default) like:
```python
#!/usr/bin/env python3
import os, json, time, datetime as dt
import requests

def main():
    url = "https://hackerone.com/hacktivity?sort_type=latest_disclosable_activity_at&filter=type%3Apublicly_disclosed"
    # This is a placeholder; for real scraping you may need headers, pagination, or HTML parsing
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    # TODO: parse actual items (HTML or API if available to you)
    items = [{
        "title": "Example",
        "url": url,
        "date": dt.datetime.utcnow().isoformat() + "Z",
        "tags": ["example"],
        "summary": "Replace with parsed content"
    }]

    out = {
        "source": "hackerone/hacktivity",
        "fetched_at": dt.datetime.utcnow().isoformat() + "Z",
        "items": items
    }
    os.makedirs("knowledge", exist_ok=True)
    fn = f"knowledge/{int(time.time())}-hacktivity.json"
    with open(fn, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(f"Wrote: {fn}")

if __name__ == "__main__":
    main()
```

Repeat this pattern for Crowdstream (RSS), NVD JSON, KEV, Exploit���DB RSS, etc. Parse and normalize.


## Summarization and Extraction (Optional)

Use the Web UI `/api/ai_chat` to summarize new knowledge cards and extract takeaways:
- Key techniques (e.g., exploitation sequences)
- Useful payload variants (with encodings/comment styles)
- WAF indicators and evasion tips

Example prompt:
```
Summarize the attached items. Extract:
- vulnerability types and root causes
- any working payloads (show variants/encodings)
- stack/WAF hints and bypass ideas
- short checklist to try
```
Attach the JSON snippet (or paste content) from `knowledge/*.json`. Save the AI response in `knowledge/notes/`.


## Updating Payloads (Manual)

The adaptive payload library supports stable keys. To add new payloads:
1) Review your knowledge cards and outcome stats (payload_stats in memory) to identify winners
2) Add or refine payloads in `core/payloads.py` (or maintain an overlay file such as `payloads_extra.json` and load in a custom module)
3) Keep keys stable so learning persists at the target level

Example (SQLi key addition in `core/payloads.py`):
```python
_SQLI.append({
  'key': 'sqli:boolean:or_true:alt1',
  'value': "' OR 'a'='a' -- ",
  'tags': ['sqli', 'boolean', 'generic'],
  'meta': {'comment': '--', 'dbms': 'generic'}
})
```


## Scheduling (Automatic)

Linux (cron):
```
*/30 * * * * /usr/bin/python3 /path/to/pin0cchi0/scripts/fetch_hacktivity.py >> /var/log/pin0cchi0_hacktivity.log 2>&1
```

Windows (Task Scheduler):
- Create a Basic Task → trigger (Daily/Every 30 minutes) → Action: start `python.exe` with `scripts\fetch_hacktivity.py`

After fetching, run a summarization step (optional) and update payload overlays manually if warranted.


## Using Knowledge in Scans

- Web: Paste recent summaries into the chat and ask the assistant to plan a scan using the latest techniques. Use `/api/ai_command` to apply proxy/exports/scan start.
- CLI: No chat by default; include new modules or custom overlays. Adjust module lists to test new techniques (e.g., `graphql_scanner`).


## Platform Tokens and APIs

If you have legitimate access to partner APIs (HackerOne/Bugcrowd/etc.), place tokens in `.env` and implement fetchers that respect ToS and rate limits. For example:
- `HACKERONE_API_TOKEN`, `HACKERONE_API_BASE`
- `BUGCROWD_API_TOKEN`, `BUGCROWD_API_BASE`
- `INTIGRITI_API_TOKEN`, `YESWEHACK_API_TOKEN`

Never commit `.env` or tokens; `.gitignore` excludes it.


## Manual Training Checklist

- Read: new posts (Hacktivity/Crowdstream/Advisories), nuclei template diffs, PoC repos
- Normalize: save a knowledge card under `knowledge/`
- Extract: summarize with AI, list payloads and WAF clues
- Update: add new payload keys (or overlay), tweak modules if necessary
- Validate: run against known targets/lab and confirm effectiveness
- Persist: knowledge cards + AI notes to `knowledge/notes/` (local only)


## Automatic vs Manual Training

- Automatic: focus on harvesting, normalizing, and (optionally) summarizing sources on a schedule; you approve integration into payloads
- Manual: you directly curate payloads and techniques, and guide the assistant with the latest context

Both approaches are complementary. Automatic harvesting keeps the knowledge base fresh; manual curation ensures quality and safety.
