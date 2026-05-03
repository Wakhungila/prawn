import logging
import json
from typing import List
import httpx
from core.schemas import Finding, ResearchHypothesis, AgentOutput, ScanConfig

logger = logging.getLogger('PRAWN.ZeroDayResearcher')

class ZeroDayResearcher:
    """
    Zero-Day Research Module: Performs creative correlation of findings.
    Identifies complex attack chains and multi-stage logic flows.
    """
    def __init__(self, config: ScanConfig):
        self.config = config
        self.ollama_endpoint = "http://localhost:11434/api/generate"

    async def analyze_correlations(self, validated_output: AgentOutput) -> List[ResearchHypothesis]:
        """
        Correlates disparate findings into high-impact 0-day hypotheses.
        
        Args:
            validated_output: The output from the Judge phase containing validated Findings.
            
        Returns:
            List[ResearchHypothesis]: A list of hypothesized attack chains.
        """
        if not validated_output.findings:
            logger.info("No findings available for correlation.")
            return []

        # Build finding context for the LLM to analyze connections
        findings_context = "\n".join([
            f"- [{f.severity}] {f.type} @ {f.target}: {f.description}" 
            for f in validated_output.findings
        ])

        prompt = f"""
        System: You are a world-class 0-day researcher. 
        Tasks: Correlate these disparate findings into complex, multi-stage attack hypotheses:

        Strategic Focus:
        - Perform deep 'System Boundary' analysis, specifically at the interface between Proxy contracts and their Implementations.
        - Scrutinize storage layout compatibility, initialization gaps, and delegated execution context confusion.
        - Look for state desynchronization between what the Proxy assumes and what the core Implementation executes.

        {findings_context}

        Output a JSON list of objects matching the 'ResearchHypothesis' schema.
        """

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.ollama_endpoint,
                    json={
                        "model": self.config.ollama_model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json"
                    },
                    timeout=90.0
                )
                
                result = response.json()
                data = json.loads(result.get("response", "[]"))
                
                if isinstance(data, dict):
                    data = [data]
                    
                return [ResearchHypothesis(**h) for h in data]
                
        except Exception as e:
            logger.error(f"Zero-day research correlation failed: {e}")
            return []

    async def refine(self, validated_output: AgentOutput, previous: List[ResearchHypothesis], feedback: str, roadmap: List[str] = None) -> List[ResearchHypothesis]:
        """Refines existing research hypotheses based on SenatorAgent feedback."""
        logger.info("🧪 Refining hypotheses via local LLM...")
        
        h_ctx = "\n".join([f"- {h.title}: {h.potential_impact}" for h in previous])
        prompt = f"""
        System: You are an elite 0-day researcher. Refine the following hypotheses based on the Senator's critique.
        Prioritize hypotheses that directly impact the established strategic roadmap.
        Explicitly refine 'System Boundary' logic gaps between Proxy and core Implementation flows.
        
        Critique/Feedback: {feedback}
        Strategic Roadmap Context: {roadmap if roadmap else "N/A"}
        
        Previous Hypotheses:
        {h_ctx}

        Output a refined JSON list of objects matching the 'ResearchHypothesis' schema.
        """

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.ollama_endpoint,
                    json={
                        "model": self.config.ollama_model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json"
                    },
                    timeout=90.0
                )
                data = json.loads(response.json().get("response", "[]"))
                return [ResearchHypothesis(**h) for h in (data if isinstance(data, list) else [data])]
        except Exception as e:
            logger.error(f"Hypothesis refinement failed: {e}")
            return previous