#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 Port Scanner Module

This module performs port scanning using nmap and masscan.
"""

import os
import re
import json
import logging
from datetime import datetime

from core.base_module import ReconModule
from core.utils import run_command, save_json, ensure_directory, is_valid_ip, normalize_url

logger = logging.getLogger('PIN0CCHI0.Recon.PortScanner')

class PortScannerModule(ReconModule):
    """Module for port scanning."""
    
    def __init__(self):
        super().__init__(
            name="Port Scanner",
            description="Scans for open ports and services using nmap and masscan"
        )
        self.tools = {
            'nmap': self._check_tool_exists('nmap'),
            'masscan': self._check_tool_exists('masscan')
        }
        self.results = []
    
    def _check_tool_exists(self, tool_name):
        """Check if a tool exists in the system PATH."""
        result = run_command(f"which {tool_name} || where {tool_name} 2>nul")
        return result['success']
    
    def run(self, target=None, output_dir=None, config=None, ports=None, scan_type='default', **kwargs):
        """
        Run port scanning on the target.
        
        Args:
            target (str): Target IP or domain
            output_dir (str): Directory to save results
            config (dict): Module configuration
            ports (str): Ports to scan (e.g., '80,443,8080' or '1-1000')
            scan_type (str): Type of scan ('default', 'quick', 'full')
            
        Returns:
            dict: Module results
        """
        if not target:
            logger.error("No target specified for port scanning")
            return {'success': False, 'error': 'No target specified'}
        
        # Normalize target
        if not is_valid_ip(target) and '://' in target:
            target = normalize_url(target)
        
        logger.info(f"Starting port scan on {target}")
        
        # Create output directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = output_dir or os.path.join('output', 'recon', 'port_scans', timestamp)
        ensure_directory(output_dir)
        
        # Set default ports based on scan type
        if not ports:
            if scan_type == 'quick':
                ports = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080'
            elif scan_type == 'full':
                ports = '1-65535'
            else:  # default
                ports = '1-1000'
        
        # Run port scanning tools
        nmap_results = self._run_nmap(target, ports, output_dir)
        masscan_results = self._run_masscan(target, ports, output_dir)
        
        # Combine results
        combined_results = self._combine_results(nmap_results, masscan_results)
        
        # Save combined results
        results_file = os.path.join(output_dir, 'combined_port_scan.json')
        save_json(combined_results, results_file)
        
        logger.info(f"Port scan completed for {target}. Found {len(combined_results.get('open_ports', []))} open ports.")
        
        # Add result
        result = {
            'title': f"Port Scan for {target}",
            'severity': 'Info',
            'description': f"Discovered {len(combined_results.get('open_ports', []))} open ports",
            'open_ports': combined_results.get('open_ports', []),
            'output_file': results_file
        }
        
        self.add_result(result)
        
        return {
            'success': True,
            'open_ports': combined_results.get('open_ports', []),
            'count': len(combined_results.get('open_ports', [])),
            'output_file': results_file
        }
    
    def _run_nmap(self, target, ports, output_dir):
        """Run nmap for port scanning."""
        if not self.tools['nmap']:
            logger.warning("nmap not found, skipping")
            return {}
        
        logger.info(f"Running nmap on {target} (ports: {ports})")
        
        xml_output = os.path.join(output_dir, 'nmap_results.xml')
        cmd = f"nmap -sV -sC -p {ports} -oX {xml_output} {target}"
        
        result = run_command(cmd)
        
        if result['success']:
            logger.info(f"nmap scan completed for {target}")
            
            # Parse XML output (simplified for now)
            open_ports = []
            if os.path.exists(xml_output):
                # Extract open ports from stdout
                port_pattern = re.compile(r'(\d+)/tcp\s+open\s+([\w-]+)\s*(.*)?')
                for match in port_pattern.finditer(result['stdout']):
                    port, service, version = match.groups()
                    open_ports.append({
                        'port': int(port),
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': service,
                        'version': version.strip() if version else ''
                    })
                
                return {
                    'tool': 'nmap',
                    'open_ports': open_ports,
                    'raw_output': result['stdout'],
                    'output_file': xml_output
                }
            else:
                logger.warning(f"nmap output file not found: {xml_output}")
        else:
            logger.error(f"Error running nmap: {result['stderr']}")
        
        return {}
    
    def _run_masscan(self, target, ports, output_dir):
        """Run masscan for port scanning."""
        if not self.tools['masscan']:
            logger.warning("masscan not found, skipping")
            return {}
        
        logger.info(f"Running masscan on {target} (ports: {ports})")
        
        json_output = os.path.join(output_dir, 'masscan_results.json')
        cmd = f"masscan -p {ports} --rate=1000 -oJ {json_output} {target}"
        
        result = run_command(cmd)
        
        if result['success']:
            logger.info(f"masscan scan completed for {target}")
            
            # Parse JSON output
            open_ports = []
            if os.path.exists(json_output):
                try:
                    with open(json_output, 'r') as f:
                        masscan_data = json.load(f)
                    
                    for port_data in masscan_data.get('ports', []):
                        open_ports.append({
                            'port': port_data.get('port'),
                            'protocol': port_data.get('proto', 'tcp'),
                            'state': 'open',
                            'service': '',
                            'version': ''
                        })
                    
                    return {
                        'tool': 'masscan',
                        'open_ports': open_ports,
                        'raw_output': result['stdout'],
                        'output_file': json_output
                    }
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse masscan JSON output: {json_output}")
            else:
                logger.warning(f"masscan output file not found: {json_output}")
        else:
            logger.error(f"Error running masscan: {result['stderr']}")
        
        return {}
    
    def _combine_results(self, nmap_results, masscan_results):
        """Combine results from different scanning tools."""
        combined_ports = {}
        
        # Add nmap results
        for port_data in nmap_results.get('open_ports', []):
            port = port_data['port']
            combined_ports[port] = port_data
        
        # Add masscan results (nmap results take precedence for service info)
        for port_data in masscan_results.get('open_ports', []):
            port = port_data['port']
            if port not in combined_ports:
                combined_ports[port] = port_data
        
        return {
            'open_ports': list(combined_ports.values()),
            'nmap_results': nmap_results,
            'masscan_results': masscan_results
        }