#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 OSINT Module

This module performs Open Source Intelligence gathering on targets using various
tools and techniques.
"""

import os
import json
import logging
from datetime import datetime

from core.base_module import ReconModule
from core.utils import run_command, save_json, ensure_directory

logger = logging.getLogger('PIN0CCHI0.Recon.OSINT')

class OSINTModule(ReconModule):
    """Module for OSINT reconnaissance."""
    
    def __init__(self):
        super().__init__(
            name="OSINT",
            description="Performs Open Source Intelligence gathering on targets"
        )
        self.email_results = []
        self.social_media_results = []
        self.whois_results = {}
        self.shodan_results = {}
        self.censys_results = {}
        self.github_results = []
    
    def run(self, target=None, output_dir=None, config=None, **kwargs):
        """
        Run OSINT reconnaissance on the target.
        
        Args:
            target (str): Target domain or organization name
            output_dir (str): Directory to save results
            config (dict): Module configuration
            
        Returns:
            dict: Module results
        """
        if not target:
            logger.error("No target specified for OSINT reconnaissance")
            return {'success': False, 'error': 'No target specified'}
        
        logger.info(f"Starting OSINT reconnaissance on {target}")
        
        # Create output directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = output_dir or os.path.join('output', 'recon', 'osint', timestamp)
        ensure_directory(output_dir)
        
        # Run OSINT tools
        self._run_whois(target)
        self._run_theHarvester(target, output_dir)
        self._run_shodan(target, config)
        self._run_censys(target, config)
        self._run_github_recon(target, config)
        
        # Save results
        results = {
            'target': target,
            'email_results': self.email_results,
            'social_media_results': self.social_media_results,
            'whois_results': self.whois_results,
            'shodan_results': self.shodan_results,
            'censys_results': self.censys_results,
            'github_results': self.github_results
        }
        
        results_file = os.path.join(output_dir, 'osint_results.json')
        save_json(results, results_file)
        
        logger.info(f"OSINT reconnaissance completed for {target}")
        
        # Add result
        result = {
            'title': f"OSINT Reconnaissance for {target}",
            'severity': 'Info',
            'description': f"Discovered {len(self.email_results)} email addresses, {len(self.social_media_results)} social media profiles, and information from WHOIS, Shodan, Censys, and GitHub",
            'email_results': self.email_results,
            'social_media_results': self.social_media_results,
            'whois_results': self.whois_results,
            'shodan_results': self.shodan_results,
            'censys_results': self.censys_results,
            'github_results': self.github_results,
            'output_file': results_file
        }
        
        self.add_result(result)
        
        return {
            'success': True,
            'email_count': len(self.email_results),
            'social_media_count': len(self.social_media_results),
            'has_whois': bool(self.whois_results),
            'has_shodan': bool(self.shodan_results),
            'has_censys': bool(self.censys_results),
            'github_count': len(self.github_results),
            'output_file': results_file
        }
    
    def _run_whois(self, target):
        """Run WHOIS lookup on the target."""
        logger.info(f"Running WHOIS lookup on {target}")
        
        cmd = ['whois', target]
        result = run_command(" ".join(cmd))
        
        if result['success']:
            output = result['stdout']
            
            # Parse WHOIS output
            whois_data = {}
            current_key = None
            
            for line in output.strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('%') or line.startswith('#'):
                    continue
                
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if value:
                        whois_data[key] = value
                        current_key = key
                elif current_key and line:
                    # Continuation of previous value
                    whois_data[current_key] += f" {line}"
            
            self.whois_results = whois_data
            logger.info(f"WHOIS lookup completed for {target}")
        else:
            logger.warning(f"WHOIS lookup failed for {target}: {result.get('error', 'Unknown error')}")
    
    def _run_theHarvester(self, target, output_dir):
        """Run theHarvester for email and social media reconnaissance."""
        logger.info(f"Running theHarvester on {target}")
        
        harvester_output = os.path.join(output_dir, 'theharvester_output.xml')
        
        # Define sources to use
        sources = 'bing,google,linkedin,twitter,github,hunter,censys,certspotter,crtsh,dnsdumpster,duckduckgo,netcraft,securitytrails,threatcrowd,trello,urlscan,virustotal' # type: ignore
        
        cmd = ['theHarvester', '-d', target, '-b', sources, '-f', harvester_output]
        result = run_command(cmd)
        
        if result['success'] and os.path.exists(harvester_output):
            # Parse XML output
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(harvester_output)
                root = tree.getroot()
                
                # Extract emails
                for email in root.findall('.//email'):
                    if email.text and email.text not in self.email_results:
                        self.email_results.append(email.text)
                
                # Extract social media profiles
                for profile in root.findall('.//profile'):
                    if profile.text and profile.text not in self.social_media_results:
                        self.social_media_results.append(profile.text)
                
                logger.info(f"theHarvester found {len(self.email_results)} email addresses and {len(self.social_media_results)} social media profiles")
            except Exception as e:
                logger.error(f"Failed to parse theHarvester output: {e}")
        else:
            logger.warning(f"theHarvester failed or produced no output: {result.get('error', 'Unknown error')}")
    
    def _run_shodan(self, target, config):
        """Run Shodan lookup on the target."""
        logger.info(f"Running Shodan lookup on {target}")
        
        # Check if Shodan API key is available
        shodan_api_key = None
        if config and 'api_keys' in config and 'shodan' in config['api_keys']:
            shodan_api_key = config['api_keys']['shodan']
        
        if not shodan_api_key:
            logger.warning("No Shodan API key available. Skipping Shodan lookup.")
            return
        
        try:
            import shodan
            api = shodan.Shodan(shodan_api_key)
            
            # Search Shodan
            results = api.search(f'hostname:{target}')
            
            if results['total'] > 0:
                self.shodan_results = {
                    'total': results['total'],
                    'matches': []
                }
                
                for match in results['matches']:
                    self.shodan_results['matches'].append({
                        'ip': match.get('ip_str'),
                        'hostnames': match.get('hostnames', []),
                        'ports': match.get('ports', []),
                        'org': match.get('org'),
                        'isp': match.get('isp'),
                        'country': match.get('location', {}).get('country_name'),
                        'vulns': match.get('vulns', [])
                    })
                
                logger.info(f"Shodan found {results['total']} results for {target}")
            else:
                logger.info(f"No Shodan results found for {target}")
        except ImportError:
            logger.warning("Shodan Python module not installed. Skipping Shodan lookup.")
        except Exception as e:
            logger.error(f"Shodan lookup failed: {e}")
    
    def _run_censys(self, target, config):
        """Run Censys lookup on the target."""
        logger.info(f"Running Censys lookup on {target}")
        
        # Check if Censys API credentials are available
        censys_api_id = None
        censys_api_secret = None
        
        if config and 'api_keys' in config and 'censys' in config['api_keys']:
            censys_api_id = config['api_keys']['censys'].get('id')
            censys_api_secret = config['api_keys']['censys'].get('secret')
        
        if not censys_api_id or not censys_api_secret:
            logger.warning("No Censys API credentials available. Skipping Censys lookup.")
            return
        
        try:
            from censys.search import CensysHosts
            
            # Initialize Censys API client
            h = CensysHosts(api_id=censys_api_id, api_secret=censys_api_secret)
            
            # Search Censys
            query = f"services.tls.certificates.leaf_data.subject.common_name: {target} OR services.tls.certificates.leaf_data.subject.organization: {target}"
            results = h.search(query, per_page=10)
            
            if results:
                self.censys_results = {
                    'total': results.get('total', 0),
                    'matches': []
                }
                
                for match in results.get('hits', []):
                    self.censys_results['matches'].append({
                        'ip': match.get('ip'),
                        'services': match.get('services', []),
                        'location': match.get('location', {}),
                        'autonomous_system': match.get('autonomous_system', {})
                    })
                
                logger.info(f"Censys found {self.censys_results['total']} results for {target}")
            else:
                logger.info(f"No Censys results found for {target}")
        except ImportError:
            logger.warning("Censys Python module not installed. Skipping Censys lookup.")
        except Exception as e:
            logger.error(f"Censys lookup failed: {e}")
    
    def _run_github_recon(self, target, config):
        """Run GitHub reconnaissance on the target."""
        logger.info(f"Running GitHub reconnaissance on {target}")
        
        # Check if GitHub API token is available
        github_token = None
        if config and 'api_keys' in config and 'github' in config['api_keys']:
            github_token = config['api_keys']['github']
        
        if not github_token:
            logger.warning("No GitHub API token available. Skipping GitHub reconnaissance.")
            return
        
        try:
            from github import Github
            
            # Initialize GitHub API client
            g = Github(github_token)
            
            # Search for organization
            try:
                org = g.get_organization(target)
                
                # Get organization repositories
                repos = []
                for repo in org.get_repos():
                    repos.append({
                        'name': repo.name,
                        'description': repo.description,
                        'url': repo.html_url,
                        'language': repo.language,
                        'stars': repo.stargazers_count,
                        'forks': repo.forks_count,
                        'created_at': repo.created_at.isoformat() if repo.created_at else None,
                        'updated_at': repo.updated_at.isoformat() if repo.updated_at else None
                    })
                
                self.github_results.append({
                    'type': 'organization',
                    'name': org.name,
                    'login': org.login,
                    'url': org.html_url,
                    'email': org.email,
                    'repos_count': org.public_repos,
                    'repos': repos
                })
                
                logger.info(f"Found GitHub organization {org.login} with {org.public_repos} public repositories")
            except Exception:
                # Not an organization, try searching for repositories
                repos = g.search_repositories(f"{target} in:name,description,readme")
                
                repo_results = []
                for repo in repos[:20]:  # Limit to 20 repositories
                    repo_results.append({
                        'name': repo.name,
                        'owner': repo.owner.login,
                        'description': repo.description,
                        'url': repo.html_url,
                        'language': repo.language,
                        'stars': repo.stargazers_count,
                        'forks': repo.forks_count,
                        'created_at': repo.created_at.isoformat() if repo.created_at else None,
                        'updated_at': repo.updated_at.isoformat() if repo.updated_at else None
                    })
                
                if repo_results:
                    self.github_results.append({
                        'type': 'repositories',
                        'query': target,
                        'total_count': repos.totalCount,
                        'repos': repo_results
                    })
                    
                    logger.info(f"Found {repos.totalCount} GitHub repositories related to {target}")
                else:
                    logger.info(f"No GitHub repositories found for {target}")
                
                # Search for users
                users = g.search_users(target)
                
                user_results = []
                for user in users[:10]:  # Limit to 10 users
                    user_results.append({
                        'login': user.login,
                        'name': user.name,
                        'url': user.html_url,
                        'email': user.email,
                        'company': user.company,
                        'location': user.location,
                        'public_repos': user.public_repos
                    })
                
                if user_results:
                    self.github_results.append({
                        'type': 'users',
                        'query': target,
                        'total_count': users.totalCount,
                        'users': user_results
                    })
                    
                    logger.info(f"Found {users.totalCount} GitHub users related to {target}")
                else:
                    logger.info(f"No GitHub users found for {target}")
                
                # Search for code
                code = g.search_code(f"{target} in:file")
                
                code_results = []
                for item in code[:20]:  # Limit to 20 code results
                    code_results.append({
                        'name': item.name,
                        'path': item.path,
                        'repository': item.repository.full_name,
                        'url': item.html_url
                    })
                
                if code_results:
                    self.github_results.append({
                        'type': 'code',
                        'query': target,
                        'total_count': code.totalCount,
                        'items': code_results
                    })
                    
                    logger.info(f"Found {code.totalCount} GitHub code results related to {target}")
                else:
                    logger.info(f"No GitHub code results found for {target}")
        except ImportError:
            logger.warning("GitHub Python module not installed. Skipping GitHub reconnaissance.")
        except Exception as e:
            logger.error(f"GitHub reconnaissance failed: {e}")