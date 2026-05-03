#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PRAWN Core Engine
Orchestrates the sequential multi-agent research loop.
"""

import os
import logging
import asyncio
from typing import List, Dict, Any, Callable
from core.schemas import Finding, Anomaly, AgentOutput, ScanConfig
from core.memory import AgentMemory
from core.finder import FinderAgent
from core.judge import JudgeAgent
from core.senator import SenatorAgent
from core.researcher import ResearcherAgent
from core.wake_test_runner import WakeTestRunner
from core.code_auditor import CodeAuditorAgent
from core.git_diff import GitDiffModule

logger = logging.getLogger('PRAWN.Engine')

class PrawnOrchestrator:
    """
    Professional Multi-Agent Orchestrator.
    Sequential execution optimized for 8GB RAM.
    """
    def __init__(self, config: ScanConfig):
        self.config = config
        self.memory = AgentMemory()
        self._callbacks = {}
        
        # Initialize specialized agents
        self.finder = FinderAgent(config)
        self.judge = JudgeAgent(config)
        self.researcher = ResearcherAgent(config)
        self.auditor = CodeAuditorAgent(config)
        self.senator = SenatorAgent(config)

    def set_callback(self, event: str, callback: Callable):
        self._callbacks[event] = callback

    def _emit(self, event: str, data: Any):
        if event in self._callbacks:
            self._callbacks[event](data)

    async def execute_research(self) -> AgentOutput:
        """
        Main Autonomous Loop: Finder -> Judge -> Researcher -> Senator.
        Sequential processing to stay within memory limits.
        """
        logger.info(f"PRAWN Engine engaged for target: {self.config.target}")
        self._emit('status', "SURVEYING target environment")

        # Rule: Start Interactive Discovery Environment
        if self.config.target.startswith("http"):
            self._emit('status', "LAUNCHING Burp Suite & Firefox (Interactive Mode)")
            from core.utils import launch_research_browser
            # Pass credentials to the navigator context
            credentials = {
                "accounts": ["pin0ccs+1@wearehackerone.com", "pin0ccs+2@wearehackerone.com"],
                "password": "10_PrawnyHack"
            }
            browser_success = await launch_research_browser(self.config.target, credentials)
            if browser_success:
                self._emit('status', "INTERVENTION: User accounts ready. Waiting for system navigation...")
                # Wait for user to complete OTP/OAuth if detected
                print(f"\n[!] Interactive Navigation Active. Target: {self.config.target}")
                input("[?] Press ENTER once you have finished manual navigation in Firefox...")

        # 1. FINDER PHASE (Discovery)
        # Logic: If local repo, prioritize Git Delta (Principle 1)
        if os.path.isdir(self.config.target) and self.config.delta_audit:
            self._emit('status', f"DISSECTING codebase delta ({self.config.delta_audit})") # type: ignore
            git_helper = GitDiffModule(self.config.target)
            changed_files = git_helper.get_changed_files(self.config.delta_audit)
            if changed_files:
                audit_out = await self.auditor.run(changed_files)
                # Promote audit findings to anomalies for the Judge to validate
                raw_audit_anomalies = [Anomaly(target=f.target, observation=f.description, confidence=0.9, suggested_vector="Delta Audit") for f in audit_out.findings]
                self.memory.record_anomalies(raw_audit_anomalies)

        self._emit('status', "SCOURING attack surface area")
        self._emit('progress', 20)
        raw_data = await self.finder.run(self.config.target)
        self.memory.record_anomalies(raw_data.anomalies)

        # Fork Conflict Resolution & Automated Reproduction
        test_results = None
        if os.path.isdir(self.config.target):
            # Trigger reproduction tests if discrepancies were found
            runner = WakeTestRunner(self.config.target)
            test_results = await runner.execute_reproduction_tests()

        # 2. JUDGE PHASE (Validation)
        self._emit('status', "SIFTING identified anomalies")
        self._emit('progress', 40)
        validated_output = await self.judge.run(raw_data)
        self.memory.record_findings(validated_output.findings)
        for finding in validated_output.findings:
            self._emit('vulnerability', finding)

        # 3. RESEARCHER PHASE (0-Day Deep Dive)
        # This only triggers if anomalies are high confidence or explicitly requested
        hypotheses = []
        if self.config.zero_day_mode:
            self._emit('progress', 70)
            mode_label = "economic threat vectors" if self.config.economic_threat_model else "0-day hypotheses"
            self._emit('status', f"SYNTHESIZING {mode_label}")
            research_out = await self.researcher.run(validated_output)
            hypotheses = research_out.hypotheses

            # Multi-stage hypothesis refinement loop
            for stage in range(self.config.max_recursion_depth):
                self._emit('status', f"TEMPERING attack chains (Stage {stage + 1})")
                eval_data = await self.senator.evaluate_hypotheses(hypotheses, validated_output.findings)
                feedback = eval_data.get("feedback")
                roadmap = eval_data.get("roadmap")
                
                if not feedback:
                    break
                
                refinement_out = await self.researcher.refine_hypotheses(validated_output, hypotheses, feedback, roadmap=roadmap)
                hypotheses = refinement_out.hypotheses

        # 4. SENATOR PHASE (Strategic Triage & Reporting)
        self._emit('status', "FINALIZING strategic security report")
        self._emit('progress', 90)
        final_strategic_output = await self.senator.run(validated_output, hypotheses, test_results=test_results)
        
        self._emit('progress', 100)
        self._emit('complete', final_strategic_output)
        
        return final_strategic_output