#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PRAWN - Powerful Research Agent for Web & Web3

This is the main entry point for the PRAWN framework.
"""

import os
import sys
import logging
import argparse
import time
from datetime import datetime

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import core modules
from core.engine import Engine
from core.config_manager import ConfigManager
from core.module_manager import ModuleManager

# Setup logging (ensure logs directory exists before creating FileHandler)
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
log_dir = os.path.join('logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f'prawn_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
logging.basicConfig(
    level=logging.INFO,
    format=log_format,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file, mode='w')
    ]
)

logger = logging.getLogger('PRAWN')

# ASCII Art Banner
BANNER = r"""
██████╗ ██████╗  █████╗ ██╗    ██╗███╗   ██╗
██╔══██╗██╔══██╗██╔══██╗██║    ██║████╗  ██║
██████╔╝██████╔╝███████║██║ █╗ ██║██╔██╗ ██║
██╔═══╝ ██╔══██╗██╔══██║██║███╗██║██║╚██╗██║
██║     ██║  ██║██║  ██║╚███╔███╔╝██║ ╚████║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═══╝
                                                                   
        Powerful Research Agent for Web & Web3 - v0.1.0
"""

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='PRAWN - Powerful Research Agent for Web & Web3')
    
    # Target specification
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('-t', '--target', help='Target URL, IP, or domain')
    target_group.add_argument('-l', '--target-list', help='File containing list of targets')
    
    # Configuration
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument('-c', '--config', help='Path to configuration file')
    config_group.add_argument('-o', '--output', help='Directory to store output files')
    
    # Module selection
    module_group = parser.add_argument_group('Modules')
    module_group.add_argument('--recon', action='store_true', help='Run reconnaissance modules')
    module_group.add_argument('--vuln', action='store_true', help='Run vulnerability testing modules')
    module_group.add_argument('--exploit', action='store_true', help='Run exploitation modules')
    module_group.add_argument('--report', action='store_true', help='Generate report only')
    
    # Miscellaneous
    misc_group = parser.add_argument_group('Miscellaneous')
    misc_group.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    misc_group.add_argument('--list-modules', action='store_true', help='List available modules')
    misc_group.add_argument('--version', action='version', version='PRAWN v0.1.0')
    
    return parser.parse_args()

def setup_directories():
    """Set up necessary directories."""
    directories = ['logs', 'output']
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logger.debug(f"Created directory: {directory}")

def main():
    """Main entry point for PIN0CCHI0."""
    print(BANNER)
    
    args = parse_arguments()
    
    # Set up directories
    setup_directories()
    
    # Set logging level
    if args.verbose:
        logging.getLogger('PRAWN').setLevel(logging.DEBUG)
    
    # List modules if requested
    if args.list_modules:
        from core.module_manager import ModuleManager
        module_manager = ModuleManager()
        modules = module_manager.discover_modules()
        
        print("\nAvailable Modules:")
        for category, category_modules in modules.items():
            print(f"\n[{category.upper()}]")
            for module_name in category_modules:
                print(f"  - {module_name}")
        
        return
    
    # Check if target is specified
    if not args.target and not args.target_list:
        logger.error("No target specified. Use -t/--target or -l/--target-list to specify a target.")
        return
    
    # Use the new Engine orchestrator
    output_dir = args.output or os.path.join('results', f"{int(time.time())}-{(args.target or 'scan').replace('://','-').replace('/','-')}")
    os.makedirs(output_dir, exist_ok=True)

    config_manager = ConfigManager(args.config) if args.config else ConfigManager()
    module_manager = ModuleManager(config_manager)
    engine = Engine(config_manager, module_manager)
    engine.config.update({
        'target': args.target,
        'output_dir': output_dir
    })

    logger.info(f"Output directory: {output_dir}")
    result = engine.run()

    # Print a brief summary if available
    try:
        vulns = result.get('vulnerabilities', []) if isinstance(result, dict) else []
        logger.info(f"Completed. Vulnerabilities found: {len(vulns)}")
    except Exception:
        pass

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nPIN0CCHI0 terminated by user.")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)