#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Nuclei Runner Module for PIN0CCHI0

Runs ProjectDiscovery's nuclei as a deep vulnerability scanning step
on the primary target and optionally on a list of discovered URLs.

- Attempts to use discovered URLs from web crawler results if available
- Saves nuclei output to JSON and text files under the scan's output directory
- Produces aggregated finding entries mapped from nuclei severity

Requirements:
- nuclei installed and available on PATH
"""

import os
import json
import logging
import shutil
import tempfile
from typing import List, Dict, Any

from core.base_module import VulnTestingModule
from core.utils import run_command

logger = logging.getLogger('PIN0CCHI0.VulnTesting.NucleiRunner')

SEV_MAP = {
    'critical': 'Critical',
    'high': 'High',
    'medium': 'Medium',
    'low': 'Low',
    'info': 'Info'
}

class NucleiRunnerModule(VulnTestingModule):
    """Module for running nuclei as a final deep scan."""

    def __init__(self):
        super().__init__(name='Nuclei Runner', description='Runs nuclei for deep vulnerability scanning')

    def run(self, target=None, output_dir=None, config=None, **kwargs):
        if not target:
            logger.error('Nuclei runner requires a target')
            return {'success': False, 'error': 'No target provided'}
        if shutil.which('nuclei') is None:
            logger.warning('nuclei not found on PATH; skipping nuclei runner')
            return {'success': False, 'error': 'nuclei not found'}

        output_dir = output_dir or os.path.join('results', 'nuclei')
        os.makedirs(output_dir, exist_ok=True)

        # Prepare output files
        json_out = os.path.join(output_dir, 'nuclei_results.json')
        txt_out = os.path.join(output_dir, 'nuclei_results.txt')

        # Build nuclei command(s)
        cmds = []
        # Always scan the root target URL
        cmds.append(f"nuclei -u {target} -silent -json -irr -o {json_out}")

        # If web crawler results present, scan that list as well
        list_file = self._prepare_url_list(target, output_dir, config)
        if list_file:
            cmds.append(f"nuclei -l {list_file} -silent -irr -o {txt_out}")

        findings: List[Dict[str, Any]] = []
        for cmd in cmds:
            logger.info(f'Running nuclei: {cmd}')
            result = run_command(cmd, timeout=900)
            if not result.get('success'):
                logger.warning(f'nuclei command failed (rc={result.get("returncode")}): {result.get("stderr") or result.get("stdout") or ""}')
            else:
                logger.info('nuclei execution completed')

        # Parse JSON output
        if os.path.exists(json_out):
            try:
                with open(json_out, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                            sev = SEV_MAP.get(str(item.get('severity', '')).lower(), 'Info')
                            host = item.get('host') or item.get('matched-at') or target
                            tmpl = item.get('template-id') or item.get('template', '')
                            name = item.get('info', {}).get('name', tmpl)
                            findings.append({
                                'type': f'Nuclei: {name}',
                                'severity': sev,
                                'url': host,
                                'evidence': item.get('matched-at', ''),
                                'template': tmpl
                            })
                        except Exception:
                            continue
            except Exception as e:
                logger.error(f'Failed to parse nuclei JSON output: {e}')

        # Parse text output for the list run (best-effort)
        if os.path.exists(txt_out):
            try:
                with open(txt_out, 'r', encoding='utf-8') as f:
                    for line in f:
                        # nuclei text line format varies; best-effort parse
                        s = line.strip()
                        if not s:
                            continue
                        findings.append({
                            'type': 'Nuclei Finding',
                            'severity': 'Info',
                            'url': '',
                            'evidence': s
                        })
            except Exception as e:
                logger.debug(f'Failed reading nuclei text output: {e}')

        # Add consolidated result
        self.add_result({
            'title': f'Nuclei Deep Scan for {target}',
            'severity': 'Info',
            'description': f'Collected {len(findings)} nuclei findings',
            'findings_count': len(findings),
            'json_output': json_out if os.path.exists(json_out) else None,
            'text_output': txt_out if os.path.exists(txt_out) else None
        })

        return {'success': True, 'vulnerabilities': findings, 'json_output': json_out, 'text_output': txt_out}

    def _prepare_url_list(self, target: str, output_dir: str, config: dict) -> str:
        """Try to build a URL list from web crawler results; returns path or '' if none."""
        # Common filename from WebCrawlerModule
        candidate = os.path.join(output_dir, '..', 'web_crawl_results.json')
        try:
            candidate = os.path.abspath(candidate)
            if os.path.exists(candidate):
                with open(candidate, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                urls = data.get('discovered_urls', []) or []
                if urls:
                    lf = os.path.join(output_dir, 'nuclei_urls.txt')
                    with open(lf, 'w') as w:
                        for u in urls:
                            w.write(u + '\n')
                    return lf
        except Exception:
            pass
        return ''
