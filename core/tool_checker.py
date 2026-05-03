#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tool Checker for PRAWN

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
import argparse
from rich.console import Console
from rich.table import Table

from core.utils import run_command

logger = logging.getLogger('PRAWN.ToolChecker')

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

    # Elite Web3 Fuzzing & Dev Tools
    {"name": "forge", "cmd": "forge", "ver": ["--version"], "url": "https://book.getfoundry.sh/"},
    {"name": "echidna", "cmd": "echidna", "ver": ["--version"], "url": "https://github.com/crytic/echidna"},
    {"name": "wake", "cmd": "wake", "ver": ["--version"], "url": "https://github.com/Ackee-Blockchain/wake"},
    {"name": "medusa", "cmd": "medusa", "ver": ["--version"], "url": "https://github.com/crytic/medusa"},
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
        result = run_command(ver_cmd) # type: ignore
        out = (result.get('stdout') or '') + "\n" + (result.get('stderr') or '')
        if result.get('success') or out.strip():
            status['present'] = True
            status['version'] = _parse_version(out) or (out.strip().splitlines()[0] if out.strip() else None)
        else:
            status['present'] = True  # present on PATH but version query failed; still usable
            status['version'] = None
    except Exception:
        status['present'] = True
        status['version'] = None

    return status


def run_fix() -> bool:
    """Execute the setup.sh script to automatically resolve missing dependencies."""
    script_path = os.path.join('scripts', 'setup.sh')
    if not os.path.exists(script_path):
        # Fallback to current dir if running from root without proper structure
        script_path = 'setup.sh'

    logger.info(f"🦐 PRAWN attempting one-click fix using {script_path}...")
    
    try:
        # Ensure script is executable
        os.chmod(script_path, 0o755)
        # Run the installer with a 30 minute timeout for Go builds
        result = run_command(f"bash {script_path}", timeout=1800)
        return result.get('success', False)
    except Exception as e:
        logger.error(f"Failed to execute setup script: {e}")
        return False


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


def print_rich_report(report: Dict[str, Any]):
    console = Console()
    table = Table(title="[bold magenta]PRAWN Tool Inventory[/]", box=None)
    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Version", style="dim")
    table.add_column("Source", style="blue")

    for t in report.get('tools', []):
        status = "[green]OK[/]" if t['present'] else "[red]MISSING[/]"
        table.add_row(t['name'], status, t['version'] or "-", t['url'] or "")

    console.print(table)
    s = report['summary']
    console.print(f"\n[bold magenta]Inventory Summary:[/] [green]{s['present']} present[/], [red]{s['missing']} missing[/]\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PRAWN Tool Checker')
    parser.add_argument('--fix', action='store_true', help='Automatically run scripts/setup.sh for missing tools')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    rep = check_all_tools()
    print_rich_report(rep)
    
    if rep['summary']['missing'] > 0:
        if args.fix:
            run_fix()
        else:
            try:
                choice = input("\nMissing tools detected. Run one-click fix? [y/N]: ").lower()
                if choice == 'y':
                    run_fix()
            except (KeyboardInterrupt, EOFError):
                pass
