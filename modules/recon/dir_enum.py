#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 Directory Enumeration Module

This module performs directory and file enumeration on web applications using tools like
dirsearch, gobuster, and ffuf.
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path

from core.base_module import ReconModule
from core.utils import run_command, save_json, ensure_directory, normalize_url

logger = logging.getLogger('PIN0CCHI0.Recon.DirEnum')

class DirEnumModule(ReconModule):
    """Module for directory and file enumeration."""
    
    def __init__(self):
        super().__init__(
            name="Directory Enumeration",
            description="Performs directory and file enumeration on web applications"
        )
        self.discovered_paths = set()
        self.wordlists = {
            'small': '/usr/share/wordlists/dirb/common.txt',
            'medium': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
            'large': '/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt'
        }
    
    def run(self, target=None, output_dir=None, config=None, wordlist_size='medium', extensions='php,html,js,txt', **kwargs):
        """
        Run directory enumeration on the target.
        
        Args:
            target (str): Target URL
            output_dir (str): Directory to save results
            config (dict): Module configuration
            wordlist_size (str): Size of wordlist to use (small, medium, large)
            extensions (str): File extensions to search for
            
        Returns:
            dict: Module results
        """
        if not target:
            logger.error("No target specified for directory enumeration")
            return {'success': False, 'error': 'No target specified'}
        
        # Normalize target URL
        target = normalize_url(target)
        
        logger.info(f"Starting directory enumeration on {target}")
        
        # Create output directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = output_dir or os.path.join('output', 'recon', 'dir_enum', timestamp)
        ensure_directory(output_dir)
        
        # Get wordlist path from config or use default
        if config and 'wordlists' in config and wordlist_size in config['wordlists']:
            wordlist = config['wordlists'][wordlist_size]
        else:
            wordlist = self.wordlists.get(wordlist_size, self.wordlists['medium'])
        
        # Run tools
        dirsearch_results = self._run_dirsearch(target, wordlist, extensions, output_dir)
        gobuster_results = self._run_gobuster(target, wordlist, extensions, output_dir)
        ffuf_results = self._run_ffuf(target, wordlist, extensions, output_dir)
        
        # Combine results
        self.discovered_paths.update(dirsearch_results)
        self.discovered_paths.update(gobuster_results)
        self.discovered_paths.update(ffuf_results)
        
        # Save combined results
        results = {
            'target': target,
            'discovered_paths': list(sorted(self.discovered_paths)),
            'wordlist': wordlist,
            'extensions': extensions
        }
        
        results_file = os.path.join(output_dir, 'dir_enum_results.json')
        save_json(results, results_file)
        
        logger.info(f"Directory enumeration completed for {target}. Discovered {len(self.discovered_paths)} paths.")
        
        # Add result
        result = {
            'title': f"Directory Enumeration for {target}",
            'severity': 'Info',
            'description': f"Discovered {len(self.discovered_paths)} paths",
            'discovered_paths': list(sorted(self.discovered_paths)),
            'output_file': results_file
        }
        
        self.add_result(result)
        
        return {
            'success': True,
            'discovered_paths': list(sorted(self.discovered_paths)),
            'output_file': results_file
        }
    
    def _run_dirsearch(self, target, wordlist, extensions, output_dir):
        """Run dirsearch tool."""
        logger.info(f"Running dirsearch on {target}")
        
        dirsearch_output = os.path.join(output_dir, 'dirsearch_output.json')
        
        cmd = [
            'dirsearch',
            '-u', target,
            '-w', wordlist,
            '-e', extensions,
            '-o', dirsearch_output,
            '-f', '-q', '-json'
        ]
        
        result = run_command(cmd)
        
        discovered_paths = set()
        
        if result['success'] and os.path.exists(dirsearch_output):
            try:
                with open(dirsearch_output, 'r') as f:
                    data = json.load(f)
                    for entry in data.get('results', []):
                        discovered_paths.add(entry.get('path', ''))
            except Exception as e:
                logger.error(f"Failed to parse dirsearch output: {e}")
        else:
            logger.warning(f"dirsearch failed or produced no output: {result.get('error', 'Unknown error')}")
        
        return discovered_paths
    
    def _run_gobuster(self, target, wordlist, extensions, output_dir):
        """Run gobuster tool."""
        logger.info(f"Running gobuster on {target}")
        
        gobuster_output = os.path.join(output_dir, 'gobuster_output.txt')
        
        cmd = [
            'gobuster', 'dir',
            '-u', target,
            '-w', wordlist,
            '-x', extensions,
            '-o', gobuster_output,
            '-q'
        ]
        
        result = run_command(cmd)
        
        discovered_paths = set()
        
        if result['success'] and os.path.exists(gobuster_output):
            try:
                with open(gobuster_output, 'r') as f:
                    for line in f:
                        if line.startswith('/'):
                            path = line.split(' ')[0].strip()
                            discovered_paths.add(path)
            except Exception as e:
                logger.error(f"Failed to parse gobuster output: {e}")
        else:
            logger.warning(f"gobuster failed or produced no output: {result.get('error', 'Unknown error')}")
        
        return discovered_paths
    
    def _run_ffuf(self, target, wordlist, extensions, output_dir):
        """Run ffuf tool."""
        logger.info(f"Running ffuf on {target}")
        
        ffuf_output = os.path.join(output_dir, 'ffuf_output.json')
        
        # Convert comma-separated extensions to ffuf format
        ext_list = extensions.split(',')
        ext_param = ','.join([f'FUZZ.{ext}' for ext in ext_list])
        
        cmd = [
            'ffuf',
            '-u', f"{target}/FUZZ",
            '-w', f"{wordlist}:FUZZ",
            '-e', ext_param,
            '-o', ffuf_output,
            '-of', 'json',
            '-s'
        ]
        
        result = run_command(cmd)
        
        discovered_paths = set()
        
        if result['success'] and os.path.exists(ffuf_output):
            try:
                with open(ffuf_output, 'r') as f:
                    data = json.load(f)
                    for result in data.get('results', []):
                        url = result.get('url', '')
                        path = url.replace(target, '')
                        if path:
                            discovered_paths.add(path)
            except Exception as e:
                logger.error(f"Failed to parse ffuf output: {e}")
        else:
            logger.warning(f"ffuf failed or produced no output: {result.get('error', 'Unknown error')}")
        
        return discovered_paths