import logging
import os
import json
from typing import List, Optional, Dict, Any
from core.schemas import Finding, ResearchHypothesis, AgentOutput, ScanConfig, Report
from core.ollama_client import OllamaClient

logger = logging.getLogger("PRAWN.Senator")

class SenatorAgent:
    """
    Senator Agent: The strategic layer of PRAWN.
    Consolidates findings, hypotheses, and produces professional Markdown reports.
    """
    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = OllamaClient(config.ollama_model)

    async def run(self, judge_output: AgentOutput, hypotheses: List[ResearchHypothesis], test_results: Optional[Dict] = None) -> AgentOutput:
        """
        Reviews the assessment data and produces the final audit report.
        
        Args:
            judge_output: Output from the Judge phase containing validated findings.
            hypotheses: Output from the Researcher phase containing 0-day hypotheses.
            test_results: Results from the Wake reproduction verification.
        """
        logger.info(f"🏛️ Senator reviewing results for {self.config.target}...")
        
        # 1. Strategic synthesis using Ollama
        summary_prompt = self._build_summary_prompt(judge_output.findings, hypotheses, test_results)
        report_data = await self.client.generate_structured(summary_prompt, Report)
        
        strategic_summary = "Audit finalized."
        if report_data:
            report_data.findings = judge_output.findings
            strategic_summary = report_data.summary
            
            # 2. Produce professional Markdown report with verification results
            report_md = self.generate_markdown_report(report_data, test_results=test_results)
            self._save_report(report_md)
            
        return AgentOutput(
            agent_name="Senator",
            findings=judge_output.findings,
            hypotheses=hypotheses,
            next_actions=["Remediation verification"] if report_data else ["Further recursive discovery"],
            strategic_summary=strategic_summary
        )

    async def evaluate_hypotheses(self, hypotheses: List[ResearchHypothesis], findings: List[Finding]) -> Dict[str, Any]:
        """Evaluates hypotheses and generates a strategic roadmap for Researcher refinement."""
        if not hypotheses:
            return {"feedback": None, "roadmap": []}
            
        h_ctx = "\n".join([f"- {h.title}: {h.potential_impact}" for h in hypotheses])
        f_ctx = "\n".join([f"- [{f.severity}] {f.type} at {f.target}" for f in findings])
        
        prompt = f"""
        System: You are the SenatorAgent. Evaluate these hypotheses against findings to define a strategic_roadmap.
        
        CURRENT FINDINGS:
        {f_ctx}

        Hypotheses:
        {h_ctx}

        Provide a JSON object:
        - feedback: Critique for the Researcher agent. Return 'null' if high-quality.
        - roadmap: A list of prioritized security objectives (the 'strategic_roadmap').
        """
        
        response = await self.client.generate_text(prompt)
        try:
            data = json.loads(response)
            return {
                "feedback": data.get("feedback") if str(data.get("feedback")).lower() != 'null' else None,
                "roadmap": data.get("roadmap", [])
            }
        except Exception:
            return {"feedback": response if response.lower() != 'null' else None, "roadmap": []}

    def _build_summary_prompt(self, findings: List[Finding], hypotheses: List[ResearchHypothesis], test_results: Optional[Dict] = None) -> str:
        f_ctx = "\n".join([f"- [{f.severity}] {f.type} at {f.target}" for f in findings])
        h_ctx = "\n".join([f"- {h.title} (Impact: {h.potential_impact})" for h in hypotheses])
        t_ctx = f"Wake Test Execution: {'Success' if test_results and test_results.get('success') else 'Failed/No Tests'}"
        
        return f"""
        Review the following security assessment results for: {self.config.target}

        FINDINGS:
        {f_ctx}

        0-DAY HYPOTHESES:
        {h_ctx}

        TEST VERIFICATION STATUS:
        {t_ctx}

        FEASIBILITY REQUIREMENT:
        For each 0-DAY HYPOTHESIS, scrutinize the 'EconomicFlow' steps. Compare them against the CURRENT FINDINGS evidence and TEST VERIFICATION STATUS. 
        If a step in the flow assumes a vulnerability or state transition that isn't supported by finding evidence, flag the hypothesis as 'High Risk/Unverified'.
        Only include attack scenarios that are technically feasible based on the available proof.

        GOAL: Frame impact for a $1M+ bounty (Immunefi Style). Emphasize "Funds at Risk" and the "Economic Attack Surface".

        Produce a JSON object conforming to the 'Report' schema:
        - target: The target domain or contract.
        - summary: High-level executive overview of the security posture.
        - root_cause: Specific function/logic violation (Plain string).
        - attack_scenario: Step-by-step extraction flow (List of plain strings).
        - funds_at_risk: Conservative vs Aggressive TVL impact.
        - strategic_roadmap: A list of 3-5 prioritized security improvements (List of plain strings).
        """

    def generate_markdown_report(self, report: Report, test_results: Optional[Dict] = None) -> str:
        """Formats the report data into a professional Markdown document."""
        lines = [
            f"# PRAWN 🦐 Security Audit Report",
            f"\n## Target: `{report.target}`",
            f"\n## 💸 Estimated Funds at Risk: {getattr(report, 'funds_at_risk', 'Critical/High')}",
            f"\n## Executive Summary\n{report.summary}",
            f"\n## Root Cause Analysis\n{getattr(report, 'root_cause', 'Logic desynchronization at trust boundary.')}",
            f"\n> **Researcher Note**: This PoC identifies a gap between what auditors assumed and reality.",
            f"\n## Attack Scenario\n"
        ]
        for step in getattr(report, 'attack_scenario', []):
            lines.append(f"1. {step}")
            
        
        if not report.findings:
            lines.append("\n*No significant vulnerabilities were identified during this assessment cycle.*")
        else:
            for f in report.findings:
                lines.append(f"\n### [{f.severity}] {f.type}")
                lines.append(f"- **Target**: {f.target}\n- **Description**: {f.description}\n- **Remediation**: {f.remediation}")

        if test_results and test_results.get("stdout"):
            lines.append("\n## 🔬 Automated Reproduction Evidence")
            lines.append("The following trace was captured during autonomous verification:")
            lines.append("\n```text")
            lines.append(test_results["stdout"])
            lines.append("```")

        lines.append(f"\n## Strategic Roadmap")
        for step in report.strategic_roadmap:
            lines.append(f"- {step}")
            
        return "\n".join(lines)

    def _save_report(self, content: str):
        path = os.path.join(self.config.output_dir, "prawn_audit_report.md")
        os.makedirs(self.config.output_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"📄 Strategic report successfully saved to: {path}")