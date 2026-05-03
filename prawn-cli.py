#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PRAWN 🦐 - Powerful Research Agent for Web & Web3
Direct Multi-Agent CLI
"""

import os
import sys
import asyncio
import argparse
import logging
import time
from datetime import datetime
from core.schemas import ScanConfig
from core.engine import PrawnOrchestrator
from core.git_diff import GitDiffModule
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text

# Configure logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('prawn.cli')

class PrawnCLI:
    def __init__(self):
        self.console = Console()
        self.vulnerabilities_found = 0
        self.status = None

    def create_parser(self):
        parser = argparse.ArgumentParser(description='PRAWN 🦐 - Advanced Security Research CLI')
        subparsers = parser.add_subparsers(dest='command', required=True)

        # Research command (Multi-Agent Loop)
        research_parser = subparsers.add_parser('research', help='Start autonomous research')
        research_parser.add_argument('target', help='Target URL or RPC endpoint')
        research_parser.add_argument('--output', '-o', default='./results', help='Output directory')
        research_parser.add_argument('--0day', dest='zero_day_mode', action='store_true', help='Enable 0-day hypothesis generation')
        research_parser.add_argument('--web3', '--web3-enabled', dest='web3_enabled', action='store_true', help='Enable Web3/EVM discovery')
        research_parser.add_argument('--model', default='prawn-researcher', help='Ollama model to use')
        research_parser.add_argument('--economic', action='store_true', help='Prioritize economic threat modeling')
        research_parser.add_argument('--delta', help='Audit git diff delta only (e.g. v2.0..HEAD)')

        # Audit command (Source Code Review)
        audit_parser = subparsers.add_parser('audit', help='Audit local source code files')
        audit_parser.add_argument('path', help='Path to file or directory')
        audit_parser.add_argument('--model', default='prawn-researcher', help='Ollama model to use')

        return parser

    async def run_research(self, args):
        config = ScanConfig(
            target=args.target,
            output_dir=os.path.join(args.output, f"research-{int(time.time())}"),
            zero_day_mode=args.zero_day_mode,
            web3_enabled=args.web3_enabled,
            economic_threat_model=args.economic,
            ollama_model=args.model
        )

        orchestrator = PrawnOrchestrator(config)
        
        # Modern UI Callback logic
        def on_progress(p):
            pass # Progress handled by status updates now

        def on_status(msg):
            if self.status:
                # Extract the verb and apply bold magenta (Claude-style emphasis)
                parts = msg.split(" ", 1)
                verb = parts[0]
                rest = parts[1] if len(parts) > 1 else ""
                self.status.update(f"[bold magenta]{verb}[/] [cyan]{rest}...[/]")

        def on_vulnerability(v):
            self.vulnerabilities_found += 1
            color = "bold red" if v.severity == "CRITICAL" else "bold bright_yellow"
            self.console.print(f"[{color}]• Identified {v.type}[/] at [dim]{v.target}[/]")

        orchestrator._callbacks['progress'] = on_progress
        orchestrator._callbacks['status'] = on_status
        orchestrator._callbacks['vulnerability'] = on_vulnerability

        self.console.print(Panel(
            Text.from_markup(f"🦐 [bold white]PRAWN Research Session[/]\n[dim]Target: {config.target}[/]\n[dim]Mode: {'0-Day' if config.zero_day_mode else 'Standard'}[/]"),
            border_style="bold magenta",
            expand=False
        ))

        start_time = time.time()
        try:
            with self.console.status("[bold magenta]INITIATING[/] research loop...") as status:
                self.status = status
                report = await orchestrator.execute_research()
            
            duration = time.time() - start_time
            
            summary_table = Table(title="[bold magenta]Session Summary[/]", box=None)
            summary_table.add_column("Metric", style="magenta")
            summary_table.add_column("Value", style="bold white")
            
            summary_table.add_row("Duration", f"{int(duration)}s")
            summary_table.add_row("Findings Validated", str(len(report.findings)))
            summary_table.add_row("0-Day Hypotheses", str(len(report.hypotheses)))
            
            self.console.print("\n")
            self.console.print(summary_table)
            self.console.print(f"\n📄 [dim white]Strategic Report:[/] [dim]{config.output_dir}/prawn_audit_report.md[/]\n")
            
        except Exception as e:
            logger.error(f"Research failed: {e}")
            return 1
        return 0

    async def run_audit(self, args):
        from core.code_auditor import CodeAuditorAgent
        
        config = ScanConfig(
            target=args.path,
            output_dir='./results',
            ollama_model=args.model
        )
        
        auditor = CodeAuditorAgent(config)

        # Principle 1: Automatic Git Delta Extraction
        if args.delta:
            git_helper = GitDiffModule(args.path)
            changed_files = git_helper.get_changed_files(args.delta)
            print(f"🔎 Delta-Audit: Found {len(changed_files)} changed files in range {args.delta}")
            output = await auditor.run(changed_files)
            for f in output.findings:
                print(f"[{f.severity}] {f.type} in {f.target}: {f.description}")
            return 0

        files = []
        if os.path.isfile(args.path):
            files = [args.path]
        else:
            for root, _, filenames in os.walk(args.path):
                for f in filenames:
                    files.append(os.path.join(root, f))

        print(f"🦐 PRAWN Auditing {len(files)} files...")
        output = await auditor.run(files)
        
        for f in output.findings:
            print(f"[{f.severity}] {f.type} in {f.target}: {f.description}")
        
        print(f"\nAudit complete. Found {len(output.findings)} issues.")
        return 0

    def main(self):
        parser = self.create_parser()
        args = parser.parse_args()

        if args.command == 'research':
            return asyncio.run(self.research_loop(args))
        elif args.command == 'audit':
            return asyncio.run(self.run_audit(args))
        
        return 0

    async def research_loop(self, args):
        try:
            return await self.run_research(args)
        except KeyboardInterrupt:
            print("\nSession interrupted.")
            return 130

if __name__ == "__main__":
    cli = PrawnCLI()
    sys.exit(cli.main())