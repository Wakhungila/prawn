#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 Core Engine

This module serves as the main engine for the PIN0CCHI0 offensive security AI framework.
It coordinates between different modules and provides the core functionality for
reconnaissance, vulnerability testing, exploitation, and reporting.
"""

import os
import sys
import logging
import argparse
from datetime import datetime
from core.memory import AgentContext

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('PIN0CCHI0')

class Engine:
    """Engine used by the Web UI and autonomous components."""
    def __init__(self, config_manager, module_manager):
        self.config_manager = config_manager
        self.module_manager = module_manager
        # Expose a mutable config dict compatible with app.py usage
        self.config = self.config_manager.config
        self._callbacks = {}
        # Persistent agent memory / prioritization
        try:
            self.ctx = AgentContext()
        except Exception:
            self.ctx = None

    def set_callback(self, event, func):
        """Register a callback for events like 'progress' and 'vulnerability'."""
        self._callbacks[event] = func

    def _emit(self, event, *args, **kwargs):
        cb = self._callbacks.get(event)
        if cb:
            try:
                cb(*args, **kwargs)
            except Exception as e:
                logger.debug(f"Callback error for {event}: {e}")

    def run(self):
        """Execute in autonomous agent mode when enabled; otherwise run selected modules."""
        cfg = self.config if isinstance(self.config, dict) else {}
        if cfg.get('autonomous'):
            return self._run_autonomous(cfg)

        # Non-autonomous: execute selected modules
        target = cfg.get('target')
        output_dir = cfg.get('output_dir')
        self.module_manager.discover_modules()
        all_meta = self.module_manager.get_modules() or []

        alias_map = {
            'xss': 'xss_scanner', 'sqli': 'sql_injection', 'csrf': 'csrf_scanner', 'lfi': 'lfi_scanner',
            'ssrf': 'ssrf_scanner', 'xxe': 'xxe_scanner', 'idor': 'idor_scanner', 'ssti': 'ssti_scanner',
            'open_redirect': 'open_redirect_scanner', 'pt': 'path_traversal', 'dir': 'dir_enum',
            'dns': 'dns_enum', 'subdomain': 'subdomain_enum',
            'nuclei': 'nuclei_runner'
        }
        requested = [alias_map.get(m.strip(), m.strip()) for m in (cfg.get('modules') or [])]
        exclude = [alias_map.get(m.strip(), m.strip()) for m in (cfg.get('exclude_modules') or [])]

        to_run = []
        if requested:
            names = set(requested)
            for m in all_meta:
                if m.get('name') in names:
                    to_run.append(m)
        else:
            to_run = list(all_meta)
        if exclude:
            excl = set(exclude)
            to_run = [m for m in to_run if m.get('name') not in excl]

        total = len(to_run)
        findings = []
        if total == 0:
            return {'target': target, 'vulnerabilities': findings}

        for idx, meta in enumerate(to_run, start=1):
            mod_name = meta.get('name', 'module')
            cat = meta.get('category')
            self._emit('progress', mod_name, int(((idx-1) * 100) / total), f"Starting {mod_name}")
            result = None
            try:
                result = self.module_manager.execute_module(cat, mod_name, target=target, output_dir=output_dir, config=cfg)
            except Exception as e:
                logger.error(f"Error executing {cat}/{mod_name}: {e}")
                # Persist failure for active learning
                try:
                    if self.ctx:
                        self.ctx.note_failure(target, cfg.get('scan_id', ''), f"{cat}/{mod_name}", target, str(e))
                except Exception:
                    pass
            if isinstance(result, dict):
                for v in result.get('vulnerabilities', []) or []:
                    self._emit('vulnerability', v)
                    findings.append(v)
            # Remember newly discovered endpoints from recon modules
            if cat == 'recon':
                try:
                    urls = (result or {}).get('discovered_urls') or []
                    if urls and self.ctx:
                        self.ctx.remember_endpoints(target, urls)
                except Exception:
                    pass
            self._emit('progress', mod_name, 100, "Module completed")

        # Final deep scan with nuclei as last resolve
        try:
            self._emit('progress', 'nuclei_runner', 95, 'Final deep scan with nuclei')
            nukeres = self.module_manager.execute_module('vuln_testing', 'nuclei_runner', target=target, output_dir=output_dir, config=cfg)
            if isinstance(nukeres, dict):
                for v in nukeres.get('vulnerabilities', []) or []:
                    self._emit('vulnerability', v)
                    findings.append(v)
            self._emit('progress', 'nuclei_runner', 100, 'Module completed')
        except Exception as e:
            logger.debug(f"nuclei runner error: {e}")

        return {'target': target, 'vulnerabilities': findings}

    def _run_autonomous(self, cfg):
        """Autonomous agent loop: perceive -> plan -> act -> learn."""
        import json as _json
        target = cfg.get('target')
        output_dir = cfg.get('output_dir')
        limits = cfg.get('autonomous_limits', {})
        max_depth = limits.get('max_depth', 2)
        max_actions = limits.get('max_actions', 30)

        self.module_manager.discover_modules()
        findings = []

        # Memory
        visited = set()
        queue = [(target, 0)] if target else []
        seen_endpoints = set()

        # Helper to execute a module and collect vulns
        def exec_mod(cat, name, progress_hint=0, message=""):
            self._emit('progress', name, progress_hint, message or f"Starting {name}")
            res = None
            try:
                res = self.module_manager.execute_module(cat, name, target=cur_target, output_dir=output_dir, config=cfg)
            except Exception as e:
                logger.debug(f"Error executing {cat}/{name} on {cur_target}: {e}")
                try:
                    if self.ctx:
                        self.ctx.note_failure(target, cfg.get('scan_id', ''), f"{cat}/{name}", cur_target, str(e))
                except Exception:
                    pass
            if isinstance(res, dict):
                for v in res.get('vulnerabilities', []) or []:
                    self._emit('vulnerability', v)
                    findings.append(v)
            self._emit('progress', name, min(progress_hint + 10, 95), f"Completed {name}")
            return res

        actions = 0
        while queue and actions < max_actions:
            cur_target, depth = queue.pop(0)
            if not cur_target or cur_target in visited:
                continue
            visited.add(cur_target)

            # Perceive: crawl and discover APIs; fingerprint tech
            # web_crawler
            res_crawl = exec_mod('recon', 'web_crawler', 5, 'Crawling')
            new_urls = (res_crawl or {}).get('discovered_urls') or []
            for u in new_urls:
                if u not in seen_endpoints:
                    seen_endpoints.add(u)
                    if depth + 1 <= max_depth:
                        queue.append((u, depth + 1))
            # Persist discovered endpoints
            try:
                if new_urls and self.ctx:
                    self.ctx.remember_endpoints(target, new_urls)
            except Exception:
                pass
            # Merge prioritized queue from memory (front-load high-score / low-coverage)
            try:
                if self.ctx:
                    pri = self.ctx.prioritize(target, limits={'limit': 20}) or []
                    for item in pri:
                        u = item.get('url')
                        if not u or u in seen_endpoints:
                            continue
                        seen_endpoints.add(u)
                        # Prepend high-priority endpoints with capped depth
                        queue.insert(0, (u, min(depth + 1, max_depth)))
                    # Provide focus endpoints hint to modules via config (optional usage)
                    cfg['focus_endpoints'] = [it.get('url') for it in pri[:10] if it.get('url')]
            except Exception:
                pass

            # api_discovery
            res_api = exec_mod('recon', 'api_discovery', 15, 'API discovery')
            # Pull endpoints from saved results file (module returns counts only)
            api_urls = []
            of = (res_api or {}).get('output_file')
            if of and os.path.exists(of):
                try:
                    with open(of, 'r') as f:
                        jr = _json.load(f)
                        for ep in jr.get('api_endpoints', []) or []:
                            ep_url = ep['url'] if isinstance(ep, dict) else ep
                            if ep_url and ep_url not in seen_endpoints:
                                api_urls.append(ep_url)
                                seen_endpoints.add(ep_url)
                                if depth + 1 <= max_depth:
                                    queue.append((ep_url, depth + 1))
                except Exception as e:
                    logger.debug(f"Failed reading API discovery results: {e}")
            # Persist API endpoints
            try:
                if api_urls and self.ctx:
                    self.ctx.remember_endpoints(target, api_urls)
            except Exception:
                pass
            # Update prioritized queue again after API discovery
            try:
                if self.ctx:
                    pri = self.ctx.prioritize(target, limits={'limit': 20}) or []
                    for item in pri:
                        u = item.get('url')
                        if not u or u in seen_endpoints:
                            continue
                        seen_endpoints.add(u)
                        queue.insert(0, (u, min(depth + 1, max_depth)))
                    cfg['focus_endpoints'] = [it.get('url') for it in pri[:10] if it.get('url')]
            except Exception:
                pass

            # tech_fingerprint (optional)
            try:
                exec_mod('recon', 'tech_fingerprint', 20, 'Tech fingerprinting')
            except Exception:
                pass

            # Plan: decide next tests based on what we saw
            # Heuristics: prioritize API endpoints, forms/params, and auth/admin paths
            # Memory-driven focus hint is available in cfg['focus_endpoints'] for modules that support it
            candidate_tests = [
                ('vuln_testing', 'http_security_scanner'),
                ('vuln_testing', 'insecure_design_scanner'),
            ]
            # If API endpoints exist, add mass-assignment/auth checks
            if api_urls:
                candidate_tests += [
                    ('vuln_testing', 'open_redirect_scanner'),
                ]
            # Always basic web tests on current target
            candidate_tests += [
                ('vuln_testing', 'xss_scanner'),
                ('vuln_testing', 'sql_injection'),
                ('vuln_testing', 'csrf_scanner'),
            ]

            # Act: run selected modules against current target
            for (cat, name) in candidate_tests:
                actions += 1
                if actions > max_actions:
                    break
                try:
                    exec_mod(cat, name, 30, f"Testing: {name}")
                except Exception as e:
                    logger.debug(f"Error in action {name}: {e}")

        # Done
        return {'target': target, 'vulnerabilities': findings}

    

class PIN0CCHI0Engine:
    """Main engine class for the PIN0CCHI0 framework."""
    
    def __init__(self, target=None, config_file=None, output_dir=None, verbose=False):
        """
        Initialize the PIN0CCHI0 engine.
        
        Args:
            target (str): Target URL, IP, or domain
            config_file (str): Path to configuration file
            output_dir (str): Directory to store output files
            verbose (bool): Enable verbose output
        """
        self.target = target
        self.config_file = config_file or os.path.join('config', 'default.yaml')
        self.output_dir = output_dir or os.path.join('output', datetime.now().strftime('%Y%m%d_%H%M%S'))
        
        if verbose:
            logger.setLevel(logging.DEBUG)
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        self.modules = {
            'recon': {},
            'vuln_testing': {},
            'exploitation': {},
            'reporting': {}
        }
        
        logger.info(f"PIN0CCHI0 Engine initialized with target: {self.target}")
    
    def load_modules(self):
        """Load all available modules."""
        logger.info("Loading modules...")
        # This will be implemented to dynamically load modules from the modules directory
        pass
    
    def run_reconnaissance(self):
        """Run reconnaissance modules."""
        logger.info("Starting reconnaissance phase...")
        # This will execute the reconnaissance modules
        pass
    
    def run_vulnerability_testing(self):
        """Run vulnerability testing modules."""
        logger.info("Starting vulnerability testing phase...")
        # This will execute the vulnerability testing modules
        pass
    
    def run_exploitation(self):
        """Run exploitation modules."""
        logger.info("Starting exploitation phase...")
        # This will execute the exploitation modules
        pass
    
    def generate_report(self):
        """Generate a comprehensive report."""
        logger.info("Generating report...")
        # This will generate a report based on findings
        pass
    
    def run(self):
        """Run the complete PIN0CCHI0 workflow."""
        logger.info(f"Starting PIN0CCHI0 assessment on target: {self.target}")
        
        self.load_modules()
        self.run_reconnaissance()
        self.run_vulnerability_testing()
        self.run_exploitation()
        self.generate_report()
        
        logger.info("PIN0CCHI0 assessment completed.")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='PIN0CCHI0 - Advanced Offensive Security AI')
    parser.add_argument('-t', '--target', required=True, help='Target URL, IP, or domain')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    parser.add_argument('-o', '--output', help='Directory to store output files')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    return parser.parse_args()


def main():
    """Main entry point for PIN0CCHI0."""
    args = parse_arguments()
    
    engine = PIN0CCHI0Engine(
        target=args.target,
        config_file=args.config,
        output_dir=args.output,
        verbose=args.verbose
    )
    
    engine.run()


if __name__ == '__main__':
    main()