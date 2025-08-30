#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tool Checker for PIN0CCHI0

Detects presence and versions of external tools used by the framework and provides
installation guidance links. This helps the autonomous agent adapt to the runtime
capabilities and guides the user to set up missing tools.

Note: Many of these tools are Go-based or Python-based CLI utilities and should be
installed according to each tool's documentation. This checker only detects and
reports status.
"""

import os
import re
import shutil
import logging
from typing import Dict, Any, List, Optional

from core.utils import run_command

logger = logging.getLogger('PIN0CCHI0.ToolChecker')

ToolSpec = Dict[str, Any]

# Define tools with command, args to fetch version, and an install URL (reference)
TOOLS: List[ToolSpec] = [
    # Recon/HTTP
    {"name": "httpx", "cmd": "httpx", "ver": ["-version"], "url": "https://github.com/projectdiscovery/httpx"},
    {"name": "naabu", "cmd": "naabu", "ver": ["-version"], "url": "https://github.com/projectdiscovery/naabu"},
    {"name": "katana", "cmd": "katana", "ver": ["-version"], "url": "https://github.com/projectdiscovery/katana"},

    # Directory/content discovery
    {"name": "ffuf", "cmd": "ffuf", "ver": ["-version"], "url": "https://github.com/ffuf/ffuf"},
    {"name": "gobuster", "cmd": "gobuster", "ver": ["-V"], "url": "https://github.com/OJ/gobuster"},
    {"name": "dirsearch", "cmd": "dirsearch", "ver": ["--version"], "url": "https://github.com/maurosoria/dirsearch"},
    {"name": "dirb", "cmd": "dirb", "ver": ["-h"], "url": "https://dirb.sourceforge.net/"},
    {"name": "wfuzz", "cmd": "wfuzz", "ver": ["-V"], "url": "https://github.com/xmendez/wfuzz"},

    # S3/cloud enumeration
    {"name": "lazys3", "cmd": "lazys3", "ver": ["-h"], "url": "https://github.com/nahamsec/lazys3"},
    {"name": "s3scanner", "cmd": "s3scanner", "ver": ["--help"], "url": "https://github.com/sa7mon/S3Scanner"},
    {"name": "cloud-enum", "cmd": "cloud_enum", "ver": ["-h"], "url": "https://github.com/initstring/cloud_enum"},
    {"name": "s3recon", "cmd": "s3recon", "ver": ["-h"], "url": "https://github.com/sa7mon/S3Recon"},
    {"name": "bucketfinder", "cmd": "bucket_finder.rb", "ver": ["-h"], "url": "https://digi.ninja/projects/bucket_finder.php"},

    # JS and secrets
    {"name": "getjs", "cmd": "getJS", "ver": ["-h"], "url": "https://github.com/003random/getJS"},
    {"name": "linkfinder", "cmd": "linkfinder", "ver": ["-h"], "url": "https://github.com/GerbenJavado/LinkFinder"},
    {"name": "secretfinder", "cmd": "secretfinder", "ver": ["-h"], "url": "https://github.com/m4ll0k/SecretFinder"},
    {"name": "cariddi", "cmd": "cariddi", "ver": ["-v"], "url": "https://github.com/edoardottt/cariddi"},

    # URL/wayback
    {"name": "gau", "cmd": "gau", "ver": ["-version"], "url": "https://github.com/lc/gau"},
    {"name": "waybackurls", "cmd": "waybackurls", "ver": ["-h"], "url": "https://github.com/tomnomnom/waybackurls"},

    # Param discovery/API
    {"name": "arjun", "cmd": "arjun", "ver": ["-h"], "url": "https://github.com/s0md3v/Arjun"},
    {"name": "kiterunner", "cmd": "kr", "ver": ["version"], "url": "https://github.com/assetnote/kiterunner"},
    {"name": "qsreplace", "cmd": "qsreplace", "ver": ["-h"], "url": "https://github.com/tomnomnom/qsreplace"},

    # Git/Secrets
    {"name": "github-subdomains", "cmd": "github-subdomains", "ver": ["-h"], "url": "https://github.com/gwen001/github-subdomains"},
    {"name": "trufflehog", "cmd": "trufflehog", "ver": ["--version"], "url": "https://github.com/trufflesecurity/trufflehog"},
    {"name": "gitdorks-go", "cmd": "gitdorks-go", "ver": ["-h"], "url": "https://github.com/damit5/gitdorks_go"},

    # Fingerprinting
    {"name": "favfreak", "cmd": "favfreak.py", "ver": ["-h"], "url": "https://github.com/devanshbatham/FavFreak"},

    # Nuclei (deep vuln scanning)
    {"name": "nuclei", "cmd": "nuclei", "ver": ["-version"], "url": "https://github.com/projectdiscovery/nuclei"},
]

DEPRECATED_TOOLS = [
    {"name": "amass", "reason": "slow runtime in this pipeline; replaced by httpx/naabu/katana and other recon tools"}
]

VERSION_REGEXES = [
    re.compile(r"\bversion[:=]?\s*([\w\.-]+)", re.I),
    re.compile(r"\b([\d]+\.[\w\.-]+)\b"),
]


def _which(cmd: str) -> bool:
    """Return True if the command is found on PATH."""
    # shutil.which works cross-platform
    return shutil.which(cmd) is not None


def _parse_version(text: str) -> Optional[str]:
    for rx in VERSION_REGEXES:
        m = rx.search(text or '')
        if m:
            return m.group(1)
    return None


def check_tool(spec: ToolSpec) -> Dict[str, Any]:
    """Check a single tool presence and version."""
    name = spec.get('name')
    cmd = spec.get('cmd')
    args = spec.get('ver') or ["--version"]
    status: Dict[str, Any] = {
        'name': name,
        'cmd': cmd,
        'present': False,
        'version': None,
        'url': spec.get('url')
    }
    if not cmd:
        return status

    if not _which(cmd):
        return status

    # Try running version command
    try:
        ver_cmd = " ".join([cmd] + args)
        result = run_command(ver_cmd)
        if result.get('success'):
            out = (result.get('stdout') or '') + "\n" + (result.get('stderr') or '')
            status['present'] = True
            status['version'] = _parse_version(out) or out.strip().splitlines()[0:1][0] if out.strip() else None
        else:
            status['present'] = True  # present on PATH but version query failed; still usable
            status['version'] = None
    except Exception:
        status['present'] = True
        status['version'] = None

    return status


def check_all_tools() -> Dict[str, Any]:
    """Check all recommended tools and return a report."""
    report: Dict[str, Any] = {
        'tools': [],
        'deprecated': DEPRECATED_TOOLS,
        'summary': {
            'present': 0,
            'missing': 0
        }
    }
    for spec in TOOLS:
        st = check_tool(spec)
        report['tools'].append(st)
    present = sum(1 for t in report['tools'] if t['present'])
    missing = len(report['tools']) - present
    report['summary']['present'] = present
    report['summary']['missing'] = missing
    return report


def pretty_report(report: Dict[str, Any]) -> str:
    lines = []
    lines.append("Recommended Tools Status:\n")
    for t in report.get('tools', []):
        status = "OK" if t['present'] else "MISSING"
        ver = t['version'] or ""
        url = t.get('url') or ""
        lines.append(f"- {t['name']:<18} [{status}]  {ver}  {url}")
    lines.append("")
    if report.get('deprecated'):
        lines.append("Deprecated:")
        for d in report['deprecated']:
            lines.append(f"- {d['name']}: {d['reason']}")
    lines.append("")
    s = report.get('summary', {})
    lines.append(f"Summary: {s.get('present', 0)} present, {s.get('missing', 0)} missing")
    return "\n".join(lines)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    rep = check_all_tools()
    print(pretty_report(rep))
