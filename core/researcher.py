import logging
import json
import re
import os
from typing import List
from core.schemas import AgentOutput, ScanConfig, Finding, FindingType, ResearchHypothesis
from core.zero_day_researcher import ZeroDayResearcher
from core.economic_analyzer import EconomicAnalyzer
from core.echidna_harness import EchidnaHarnessGenerator
from core.utils import run_command

try:
    import prawn_core
except ImportError:
    prawn_core = None

logger = logging.getLogger('PRAWN.ResearcherAgent')

class ResearcherAgent:
    """
    Researcher Agent: Orchestrates the 0-day hypothesis generation phase.
    Wraps the ZeroDayResearcher module to correlate findings into complex attack chains.
    """
    def __init__(self, config: ScanConfig):
        self.config = config
        self.researcher = ZeroDayResearcher(config)
        self.economic_analyzer = EconomicAnalyzer()

    async def run(self, judge_output: AgentOutput) -> AgentOutput:
        """
        Orchestrates the analysis of correlations between validated findings.
        
        Args:
            judge_output: Output from the JudgeAgent containing validated Findings.
            
        Returns:
            AgentOutput: Containing generated ResearchHypotheses.
        """
        if not self.config.zero_day_mode:
            logger.info("Zero-day mode disabled; skipping research phase.")
            return judge_output

        logger.info("🧪 Researcher initiating 0-day hypothesis generation...")
        # Shift focus from code-path to economic-path
        hypotheses = await self.researcher.analyze_correlations(judge_output)
        # Economic Verification Phase
        if self.config.economic_threat_model:
            for h in hypotheses:
                # Find related bytecode in findings to run simulation
                related_finding = next((f for f in judge_output.findings if f.target in h.attack_chain), None)
                if related_finding and "eth_getCode" in related_finding.evidence:
                    sim_result = await self.economic_analyzer.analyze_hypothesis("0x6080...", h)
                    if sim_result:
                        h.funds_at_risk_estimate = f"${sim_result['delta']} profit simulated"
        
        # Analyze cross-chain vectors by correlating EVM findings with bridge anomalies
        cross_chain_hypotheses = await self._analyze_cross_chain_vectors(judge_output)
        hypotheses.extend(cross_chain_hypotheses)

        # Enhance with native bytecode analysis if EVM findings are present
        if prawn_core:
            native_hypotheses = await self._analyze_unreachable_code(judge_output.findings)
            hypotheses.extend(native_hypotheses)
            
        # Boundary Hunting: Identifying seams between systems
        boundary_vectors = await self._hunt_system_boundaries(judge_output)
        hypotheses.extend(boundary_vectors)

        # Verification Phase: Echidna property-based fuzzing for 0-day hypotheses
        if self.config.zero_day_mode and os.path.isdir(self.config.target):
            generator = EchidnaHarnessGenerator(os.path.join(self.config.output_dir, "harnesses"), project_root=self.config.target)
            for h in hypotheses:
                harness_path = generator.generate(h)
                logger.info(f"Running Echidna verification for hypothesis: {h.title}")
                
                # Execute Echidna to refute/validate the hypothesis
                echidna_res = run_command(f"echidna {harness_path} --config {self.config.target}/echidna.yaml", timeout=600)
                if echidna_res.get('success'):
                    if "Fuzzing passed" not in echidna_res.get('stdout', ''):
                        h.funds_at_risk_estimate = "Validated via Echidna (Property Violation)"

        summary = f"Researcher generated {len(hypotheses)} 0-day hypotheses."
        logger.info(summary)

        return AgentOutput(
            agent_name="Researcher",
            findings=judge_output.findings,
            hypotheses=hypotheses,
            next_actions=["Pass to Senator"],
            strategic_summary=summary
        )

    async def _hunt_system_boundaries(self, output: AgentOutput) -> List[ResearchHypothesis]:
        """
        Principle 4: Hunt at trust boundaries (EVM <-> Bridge, Proxy <-> Implementation, Oracle <-> Math).
        """
        boundaries = []
        # Logic to identify if findings involve boundary components
        # e.g. Anomaly in an Oracle and a Finding in Liquidation Math
        boundary_context = [f.target for f in output.findings] + [a.target for a in output.anomalies]
        
        if any(x in str(boundary_context).lower() for x in ['proxy', 'bridge', 'oracle', 'hook', 'gateway']):
            boundaries.append(ResearchHypothesis(
                title="Trust Boundary Violation Hypothesis",
                attack_chain=["Identify inconsistent state across trust boundary", "Desync implementation assumptions"],
                economic_flow=["Manipulate boundary asset pricing", "Extract discrepancy"],
                prerequisites=["Boundary Component Detected"],
                potential_impact="Critical desynchronization leading to protocol-wide insolvency."
            ))
            
        # Native Storage Collision Detection for Boundary Analysis
        if prawn_core:
            for finding in output.findings:
                # Extract potential hex bytecode from evidence (length check for sanity)
                match = re.search(r'0x[a-fA-F0-9]{128,}', finding.evidence)
                if match:
                    bytecode = match.group(0)
                    try:
                        # Identify slots in the implementation and check against common Proxy admin slots (like EIP-1967)
                        impl_slots = [int(s, 16) for s in re.findall(r'60([a-fA-F0-9]{2})55', bytecode)]
                        proxy_admin_slots = [0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103] # EIP-1967 Admin Slot
                        collisions = prawn_core.detect_storage_collisions_native(proxy_admin_slots, impl_slots)
                        if collisions:
                            boundaries.append(ResearchHypothesis(
                                title="Proxy/Implementation Storage Collision",
                                attack_chain=["Identify low-slot storage usage in Implementation", "Correlate with Proxy admin slots", "Trigger state overwrite"],
                                economic_flow=["Overwrite critical implementation state (e.g. Owner)", "Drain funds via unauthorized access"],
                                prerequisites=collisions,
                                potential_impact="Complete takeover of Proxy state via storage collision."
                            ))
                    except Exception:
                        continue

        return boundaries

    async def refine_hypotheses(self, judge_output: AgentOutput, previous_hypotheses: List[ResearchHypothesis], feedback: str, roadmap: List[str] = None) -> AgentOutput:
        """Refines hypotheses using feedback loop context."""
        logger.info(f"Researcher refining hypotheses based on feedback: {feedback[:50]}...")
        
        refined = await self.researcher.refine(judge_output, previous_hypotheses, feedback, roadmap=roadmap)
        
        return AgentOutput(
            agent_name="Researcher",
            findings=judge_output.findings,
            hypotheses=refined,
            next_actions=["Pass to Senator"],
            strategic_summary=f"Refined {len(refined)} hypotheses using feedback loop."
        )

    async def _analyze_cross_chain_vectors(self, output: AgentOutput) -> List[ResearchHypothesis]:
        """
        Identifies cross-chain 0-day hypotheses by correlating EVM logic flaws 
        with identified bridge anomalies or gateway exposures.
        """
        bridge_keywords = ['bridge', 'cross-chain', 'gateway', 'relay', 'oracle', 'wormhole', 'layerzero']
        evm_logic_types = [FindingType.REENTRANCY, FindingType.ACCESS_CONTROL, FindingType.STORAGE_COLLISION]
        
        has_evm_logic_flaw = any(f.type in evm_logic_types for f in output.findings)
        has_bridge_anomaly = any(
            any(k in a.observation.lower() or k in a.target.lower() for k in bridge_keywords)
            for a in output.anomalies
        )
        
        hypotheses = []
        if has_evm_logic_flaw and has_bridge_anomaly:
            hypotheses.append(ResearchHypothesis(
                title="Cross-Chain State Desynchronization via Logic Mutation",
                attack_chain=[
                    "Exploit EVM logic flaw (e.g., Reentrancy) on source contract during bridge interaction",
                    "Mutate internal state before cross-chain message emission",
                    "Relay inconsistent state proof to bridge gateway",
                    "Trigger unauthorized action on destination chain via desynced state"
                ],
                prerequisites=["Identified Bridge/Gateway Anomaly", "Mutable State Flaw in Source Contract"],
                potential_impact="Liquidity drainage across chains or unauthorized minting on destination networks."
            ))
        return hypotheses

    async def _analyze_unreachable_code(self, findings: List[Finding]) -> List[ResearchHypothesis]:
        """
        Uses native EVM CFG generation to identify unreachable code paths.
        """
        extra_hypotheses = []
        for finding in findings:
            # Look for EVM targets with bytecode in evidence or metadata
            if finding.type == FindingType.REENTRANCY or "eth_getCode" in finding.evidence:
                # Extract potential hex bytecode from evidence
                match = re.search(r'0x[a-fA-F0-9]{64,}', finding.evidence)
                if match:
                    bytecode = match.group(0)
                    logger.info(f"Reconstructing native CFG for {finding.target} to find dead code...")
                    
                    try:
                        cfg_json = prawn_core.generate_evm_cfg(bytecode)
                        cfg = json.loads(cfg_json)
                        blocks = cfg.get("blocks", {})
                        
                        if blocks:
                            # Traverse reachability from entry point (PC 0)
                            reachable = {0}
                            stack = [0]
                            while stack:
                                curr = stack.pop()
                                b_data = blocks.get(str(curr), {})
                                for succ in b_data.get("successors", []):
                                    if succ not in reachable:
                                        reachable.add(succ)
                                        stack.append(succ)
                            
                            unreachable_pcs = [int(pc) for pc in blocks.keys() if int(pc) not in reachable]
                            if unreachable_pcs:
                                extra_hypotheses.append(ResearchHypothesis(
                                    title="Unreachable Bytecode Path Identified",
                                    attack_chain=["EVM CFG Reconstruction", "Reachability Analysis", "Dead Code Identification"],
                                    prerequisites=["Native Core (Rust) Access"],
                                    potential_impact="Identified unreachable code paths which may contain hidden logic or indicate post-deployment tampering."
                                ))
                    except Exception as e:
                        logger.debug(f"Native CFG analysis failed: {e}")
        
        return extra_hypotheses