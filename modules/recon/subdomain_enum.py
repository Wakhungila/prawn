#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 Subdomain Enumeration Module

This module performs subdomain enumeration using various techniques and tools.
"""

import os
import re
import json
import logging
from datetime import datetime

from core.base_module import ReconModule
from core.utils import run_command, save_json, ensure_directory, extract_domain

logger = logging.getLogger('PIN0CCHI0.Recon.SubdomainEnum')

class SubdomainEnumModule(ReconModule):
    """Module for subdomain enumeration."""
    
    def __init__(self):
        super().__init__(
            name="Subdomain Enumeration",
            description="Discovers subdomains using various techniques and tools"
        )
        self.tools = {
            'subfinder': self._check_tool_exists('subfinder'),
            'amass': self._check_tool_exists('amass'),
            'assetfinder': self._check_tool_exists('assetfinder')
        }
        self.subdomains = set()
    
    def _check_tool_exists(self, tool_name):
        """Check if a tool exists in the system PATH."""
        result = run_command(f"which {tool_name} || where {tool_name} 2>nul")
        return result['success']
    
    def run(self, target=None, output_dir=None, config=None, **kwargs):
        """
        Run subdomain enumeration on the target.
        
        Args:
            target (str): Target domain
            output_dir (str): Directory to save results
            config (dict): Module configuration
            
        Returns:
            dict: Module results
        """
        if not target:
            logger.error("No target specified for subdomain enumeration")
            return {'success': False, 'error': 'No target specified'}
        
        # Extract domain from URL if needed
        domain = extract_domain(target) or target
        
        logger.info(f"Starting subdomain enumeration for {domain}")
        
        # Create output directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = output_dir or os.path.join('output', 'recon', 'subdomains', timestamp)
        ensure_directory(output_dir)
        
        # Run different subdomain enumeration tools
        self._run_subfinder(domain, output_dir)
        self._run_amass(domain, output_dir)
        self._run_assetfinder(domain, output_dir)
        
        # Save combined results
        results_file = os.path.join(output_dir, 'combined_subdomains.txt')
        with open(results_file, 'w') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        
        logger.info(f"Found {len(self.subdomains)} unique subdomains for {domain}")
        
        # Add result
        result = {
            'title': f"Subdomain Enumeration for {domain}",
            'severity': 'Info',
            'description': f"Discovered {len(self.subdomains)} unique subdomains",
            'subdomains': list(sorted(self.subdomains)),
            'output_file': results_file
        }
        
        self.add_result(result)
        
        return {
            'success': True,
            'subdomains': list(sorted(self.subdomains)),
            'count': len(self.subdomains),
            'output_file': results_file
        }
    
    def _run_subfinder(self, domain, output_dir):
        """Run subfinder tool for subdomain enumeration."""
        if not self.tools['subfinder']:
            logger.warning("subfinder not found, skipping")
            return
        
        logger.info(f"Running subfinder on {domain}")
        
        output_file = os.path.join(output_dir, 'subfinder_results.txt')
        cmd = f"subfinder -d {domain} -o {output_file}"
        
        result = run_command(cmd)
        
        if result['success']:
            # Parse results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain:
                            self.subdomains.add(subdomain)
                logger.info(f"subfinder found {len(self.subdomains)} subdomains")
            else:
                logger.warning(f"subfinder output file not found: {output_file}")
        else:
            logger.error(f"Error running subfinder: {result['stderr']}")
    
    def _run_amass(self, domain, output_dir):
        """Run amass tool for subdomain enumeration."""
        if not self.tools['amass']:
            logger.warning("amass not found, skipping")
            return
        
        logger.info(f"Running amass on {domain}")
        
        output_file = os.path.join(output_dir, 'amass_results.txt')
        cmd = f"amass enum -d {domain} -o {output_file}"
        
        result = run_command(cmd, timeout=300)  # Amass can take a while
        
        if result['success']:
            # Parse results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain:
                            self.subdomains.add(subdomain)
                logger.info(f"amass found {len(self.subdomains)} subdomains")
            else:
                logger.warning(f"amass output file not found: {output_file}")
        else:
            logger.error(f"Error running amass: {result['stderr']}")
    
    def _run_assetfinder(self, domain, output_dir):
        """Run assetfinder tool for subdomain enumeration."""
        if not self.tools['assetfinder']:
            logger.warning("assetfinder not found, skipping")
            return
        
        logger.info(f"Running assetfinder on {domain}")
        
        output_file = os.path.join(output_dir, 'assetfinder_results.txt')
        cmd = f"assetfinder {domain} > {output_file}"
        
        result = run_command(cmd)
        
        if result['success']:
            # Parse results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain and domain in subdomain:  # Filter only relevant subdomains
                            self.subdomains.add(subdomain)
                logger.info(f"assetfinder found {len(self.subdomains)} subdomains")
            else:
                logger.warning(f"assetfinder output file not found: {output_file}")
        else:
            logger.error(f"Error running assetfinder: {result['stderr']}")