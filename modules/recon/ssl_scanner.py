#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 SSL/TLS Scanner Module

This module performs SSL/TLS configuration scanning to identify misconfigurations,
weak ciphers, and vulnerabilities in SSL/TLS implementations.
"""

import os
import json
import logging
from datetime import datetime

from core.base_module import ReconModule
from core.utils import run_command, save_json, ensure_directory

logger = logging.getLogger('PIN0CCHI0.Recon.SSLScanner')

class SSLScannerModule(ReconModule):
    """Module for SSL/TLS scanning."""
    
    def __init__(self):
        super().__init__(
            name="SSL/TLS Scanner",
            description="Scans SSL/TLS configurations for vulnerabilities and misconfigurations"
        )
        self.ssl_issues = []
        self.certificate_info = {}
        self.supported_protocols = {}
        self.supported_ciphers = {}
        self.vulnerabilities = []
    
    def run(self, target=None, output_dir=None, config=None, port=443, **kwargs):
        """
        Run SSL/TLS scanning on the target.
        
        Args:
            target (str): Target hostname or IP
            output_dir (str): Directory to save results
            config (dict): Module configuration
            port (int): Port to scan (default: 443)
            
        Returns:
            dict: Module results
        """
        if not target:
            logger.error("No target specified for SSL/TLS scanning")
            return {'success': False, 'error': 'No target specified'}
        
        logger.info(f"Starting SSL/TLS scanning on {target}:{port}")
        
        # Create output directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = output_dir or os.path.join('output', 'recon', 'ssl_scan', timestamp)
        ensure_directory(output_dir)
        
        # Run SSL/TLS scanning tools
        self._run_sslscan(target, port, output_dir)
        self._run_sslyze(target, port, output_dir)
        self._run_testssl(target, port, output_dir)
        
        # Analyze results and identify vulnerabilities
        self._analyze_results()
        
        # Save results
        results = {
            'target': target,
            'port': port,
            'certificate_info': self.certificate_info,
            'supported_protocols': self.supported_protocols,
            'supported_ciphers': self.supported_ciphers,
            'vulnerabilities': self.vulnerabilities
        }
        
        results_file = os.path.join(output_dir, 'ssl_scan_results.json')
        save_json(results, results_file)
        
        logger.info(f"SSL/TLS scanning completed for {target}:{port}. Found {len(self.vulnerabilities)} vulnerabilities.")
        
        # Add result
        result = {
            'title': f"SSL/TLS Scan for {target}:{port}",
            'severity': 'Info' if not self.vulnerabilities else 'High',
            'description': f"Scanned SSL/TLS configuration and found {len(self.vulnerabilities)} vulnerabilities",
            'certificate_info': self.certificate_info,
            'vulnerabilities': self.vulnerabilities,
            'output_file': results_file
        }
        
        self.add_result(result)
        
        return {
            'success': True,
            'vulnerabilities_count': len(self.vulnerabilities),
            'output_file': results_file
        }
    
    def _run_sslscan(self, target, port, output_dir):
        """Run sslscan tool."""
        logger.info(f"Running sslscan on {target}:{port}")
        
        sslscan_output = os.path.join(output_dir, 'sslscan_output.xml')
        
        cmd = ['sslscan', '--xml=' + sslscan_output, f"{target}:{port}"]
        result = run_command(cmd)
        
        if result['success'] and os.path.exists(sslscan_output):
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(sslscan_output)
                root = tree.getroot()
                
                # Extract certificate information
                cert_elem = root.find('.//certificate')
                if cert_elem is not None:
                    self.certificate_info = {
                        'subject': cert_elem.find('subject').text if cert_elem.find('subject') is not None else '',
                        'issuer': cert_elem.find('issuer').text if cert_elem.find('issuer') is not None else '',
                        'valid_from': cert_elem.find('not-valid-before').text if cert_elem.find('not-valid-before') is not None else '',
                        'valid_until': cert_elem.find('not-valid-after').text if cert_elem.find('not-valid-after') is not None else '',
                        'self_signed': cert_elem.get('self-signed') == 'true' if cert_elem.get('self-signed') else False
                    }
                
                # Extract supported protocols
                for protocol in root.findall('.//protocol'):
                    protocol_type = protocol.get('type')
                    protocol_enabled = protocol.get('enabled') == '1'
                    
                    if protocol_type:
                        self.supported_protocols[protocol_type] = protocol_enabled
                
                # Extract supported ciphers
                for cipher in root.findall('.//cipher'):
                    cipher_status = cipher.get('status')
                    if cipher_status == 'accepted':
                        protocol = cipher.get('sslversion', '')
                        bits = cipher.get('bits', '')
                        cipher_name = cipher.get('cipher', '')
                        
                        if protocol not in self.supported_ciphers:
                            self.supported_ciphers[protocol] = []
                        
                        self.supported_ciphers[protocol].append({
                            'name': cipher_name,
                            'bits': bits
                        })
                
                logger.info(f"sslscan completed for {target}:{port}")
            except Exception as e:
                logger.error(f"Failed to parse sslscan output: {e}")
        else:
            logger.warning(f"sslscan failed or produced no output: {result.get('error', 'Unknown error')}")
    
    def _run_sslyze(self, target, port, output_dir):
        """Run sslyze tool."""
        logger.info(f"Running sslyze on {target}:{port}")
        
        sslyze_output = os.path.join(output_dir, 'sslyze_output.json')
        
        cmd = ['sslyze', '--json_out=' + sslyze_output, f"{target}:{port}"]
        result = run_command(cmd)
        
        if result['success'] and os.path.exists(sslyze_output):
            try:
                with open(sslyze_output, 'r') as f:
                    data = json.load(f)
                
                # Extract vulnerabilities
                target_results = None
                for scan_result in data.get('server_scan_results', []):
                    if scan_result.get('server_info', {}).get('server_location', {}).get('hostname') == target:
                        target_results = scan_result
                        break
                
                if target_results:
                    scan_commands = target_results.get('scan_commands_results', {})
                    
                    # Check for Heartbleed
                    heartbleed = scan_commands.get('heartbleed', {})
                    if heartbleed.get('is_vulnerable_to_heartbleed'):
                        self.vulnerabilities.append({
                            'name': 'Heartbleed',
                            'severity': 'High',
                            'description': 'Server is vulnerable to the Heartbleed attack (CVE-2014-0160)'
                        })
                    
                    # Check for ROBOT
                    robot = scan_commands.get('robot', {})
                    if robot.get('robot_result_enum') not in ['NOT_VULNERABLE', 'UNKNOWN']:
                        self.vulnerabilities.append({
                            'name': 'ROBOT',
                            'severity': 'High',
                            'description': 'Server is vulnerable to the ROBOT attack (Return Of Bleichenbacher\'s Oracle Threat)'
                        })
                    
                    # Check for CRIME
                    compression = scan_commands.get('compression', {})
                    if compression.get('supports_compression'):
                        self.vulnerabilities.append({
                            'name': 'CRIME',
                            'severity': 'Medium',
                            'description': 'Server is potentially vulnerable to the CRIME attack due to TLS compression being enabled'
                        })
                    
                    # Check for weak cipher suites
                    cipher_suites = scan_commands.get('cipher_suites', {})
                    if cipher_suites:
                        for protocol, result in cipher_suites.items():
                            accepted_ciphers = result.get('accepted_cipher_suites', [])
                            for cipher in accepted_ciphers:
                                cipher_name = cipher.get('cipher_suite', {}).get('name', '')
                                if 'NULL' in cipher_name or 'EXPORT' in cipher_name or 'RC4' in cipher_name or 'DES' in cipher_name:
                                    self.vulnerabilities.append({
                                        'name': 'Weak Cipher',
                                        'severity': 'Medium',
                                        'description': f"Server supports weak cipher: {cipher_name} in {protocol}"
                                    })
                
                logger.info(f"sslyze completed for {target}:{port}")
            except Exception as e:
                logger.error(f"Failed to parse sslyze output: {e}")
        else:
            logger.warning(f"sslyze failed or produced no output: {result.get('error', 'Unknown error')}")
    
    def _run_testssl(self, target, port, output_dir):
        """Run testssl.sh tool."""
        logger.info(f"Running testssl.sh on {target}:{port}")
        
        testssl_output = os.path.join(output_dir, 'testssl_output.json')
        
        cmd = ['testssl.sh', '--json', '--quiet', '--logfile', testssl_output, f"{target}:{port}"]
        result = run_command(cmd)
        
        if result['success'] and os.path.exists(testssl_output):
            try:
                with open(testssl_output, 'r') as f:
                    data = json.load(f)
                
                # Extract vulnerabilities
                for finding in data:
                    severity = finding.get('severity', '')
                    finding_id = finding.get('id', '')
                    finding_name = finding.get('finding', '')
                    cve = finding.get('cve', '')
                    
                    if severity in ['HIGH', 'CRITICAL', 'MEDIUM'] and finding_id:
                        description = finding_name
                        if cve:
                            description += f" ({cve})"
                        
                        # Check if vulnerability already exists
                        exists = False
                        for vuln in self.vulnerabilities:
                            if vuln.get('name') == finding_id:
                                exists = True
                                break
                        
                        if not exists:
                            self.vulnerabilities.append({
                                'name': finding_id,
                                'severity': severity.capitalize(),
                                'description': description
                            })
                
                logger.info(f"testssl.sh completed for {target}:{port}")
            except Exception as e:
                logger.error(f"Failed to parse testssl.sh output: {e}")
        else:
            logger.warning(f"testssl.sh failed or produced no output: {result.get('error', 'Unknown error')}")
    
    def _analyze_results(self):
        """Analyze results and identify additional vulnerabilities."""
        # Check for expired or self-signed certificate
        if self.certificate_info.get('self_signed'):
            self.vulnerabilities.append({
                'name': 'Self-Signed Certificate',
                'severity': 'Medium',
                'description': 'Server is using a self-signed certificate which will trigger browser warnings'
            })
        
        # Check for SSLv2 and SSLv3 support
        if self.supported_protocols.get('SSLv2', False):
            self.vulnerabilities.append({
                'name': 'SSLv2 Enabled',
                'severity': 'High',
                'description': 'Server supports SSLv2, which is insecure and deprecated'
            })
        
        if self.supported_protocols.get('SSLv3', False):
            self.vulnerabilities.append({
                'name': 'SSLv3 Enabled',
                'severity': 'High',
                'description': 'Server supports SSLv3, which is vulnerable to the POODLE attack'
            })
        
        # Check for TLS 1.0 and TLS 1.1
        if self.supported_protocols.get('TLSv1.0', False):
            self.vulnerabilities.append({
                'name': 'TLS 1.0 Enabled',
                'severity': 'Medium',
                'description': 'Server supports TLS 1.0, which is deprecated and has known vulnerabilities'
            })
        
        if self.supported_protocols.get('TLSv1.1', False):
            self.vulnerabilities.append({
                'name': 'TLS 1.1 Enabled',
                'severity': 'Low',
                'description': 'Server supports TLS 1.1, which is deprecated and has known vulnerabilities'
            })
        
        # Check if TLS 1.2 or TLS 1.3 is supported
        if not self.supported_protocols.get('TLSv1.2', False) and not self.supported_protocols.get('TLSv1.3', False):
            self.vulnerabilities.append({
                'name': 'No Modern TLS Support',
                'severity': 'High',
                'description': 'Server does not support TLS 1.2 or TLS 1.3, which are the recommended secure protocols'
            })