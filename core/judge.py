"""
PRAWN Judge Agent
Validates anomalies into findings using structured LLM reasoning.
Location: prawn/agents/judge.py
"""
import logging
import json
import re
from typing import Optional
from core.schemas import Finding, Anomaly, AgentOutput, ScanConfig
from core.utils import make_request # Import make_request for active probing
from core.ollama_client import OllamaClient

logger = logging.getLogger("PRAWN.Judge")

try: # Python string manipulation instead of Rust syntax
    import prawn_core
except ImportError:
    prawn_core = None

class JudgeAgent:
    """
    Judge Agent: Responsible for validating anomalies and determining severity.
    Uses LLM reasoning to filter noise and promote valid anomalies to Findings.
    """
    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = OllamaClient(config.ollama_model)

    async def run(self, finder_output: AgentOutput) -> AgentOutput:
        """
        Processes anomalies from the Finder and promotes them to Findings if valid.
        
        Args:
            finder_output: The output from the Finder phase containing raw anomalies.
            
        Returns:
            AgentOutput: Containing validated Findings.
        """
        logger.info(f"⚖️ Judge assessing {len(finder_output.anomalies)} anomalies...")
        
        validated_findings = []
        
        for anomaly in finder_output.anomalies:
            finding = await self._evaluate_anomaly(anomaly)
            if finding:
                validated_findings.append(finding)
                
        summary = f"Judge validated {len(validated_findings)} findings from {len(finder_output.anomalies)} anomalies."
        logger.info(summary)
        
        return AgentOutput(
            agent_name="Judge",
            findings=validated_findings,
            next_actions=["Pass to Researcher" if self.config.zero_day_mode else "Pass to Senator"],
            strategic_summary=summary
        )

    async def _evaluate_anomaly(self, anomaly: Anomaly) -> Optional[Finding]:
        """
        Consults the local LLM to judge if an anomaly is a real vulnerability.
        Uses Pydantic for strict output validation of the LLM's response.
        """
        # Handle gRPC validation with specialized reasoning
        if "gRPC Reflection" in anomaly.observation:
            prompt = f"""
            System: You are an elite API researcher. Analyze the following gRPC reflection discovery.
            Target: {anomaly.target}
            Discovery: {anomaly.observation}
            
            Evaluate the service methods. If you identify sensitive administrative, internal, or debug methods, 
            generate a 'Finding' with 'HIGH' severity. If methods appear safe (e.g., standard health checks), return 'null'.
            Output ONLY the raw JSON fields matching the 'Finding' schema. Do not wrap the result in a parent 'Finding' key.
            """
            
            # Active verification using payload examples
            payload_examples = anomaly.metadata.get("payload_examples", {})
            if payload_examples:
                logger.info(f"Judge: Actively verifying gRPC methods for {anomaly.target} using generated payloads.")
                active_verification_results = []
                for method, example_payload in payload_examples.items():
                    # Construct gRPC request for active verification
                    # This is a heuristic; actual gRPC calls are complex and require protobuf definitions
                    # For this context, we'll simulate a POST with JSON, assuming some gRPC gateways might accept it
                    # or that the response indicates a valid interaction.
                    
                    # gRPC method names are typically in the format /Service.Name/MethodName
                    # We need to extract ServiceName and MethodName from the full method string
                    match = re.match(r'([a-zA-Z0-9._]+)\/([a-zA-Z0-9._]+)', method)
                    if not match:
                        continue # Skip if method name format is unexpected
                    service_name, method_name = match.groups()

                    # Construct a generic gRPC-like JSON request
                    grpc_request_body = {
                        "method": f"/{service_name}/{method_name}",
                        "params": [example_payload] # Assuming params can be a list of objects
                    }
                    
                    headers = {"Content-Type": "application/json"} # Some gRPC gateways accept JSON
                    
                    # Attempt to make the request
                    resp = make_request(anomaly.target, method="POST", headers=headers, data=json.dumps(grpc_request_body), timeout=15)
                    
                    if resp.get("success") and resp.get("status_code") == 200:
                        response_text = resp.get("text", "").lower()
                        # Look for signs of successful execution or sensitive data
                        if "error" not in response_text and "unimplemented" not in response_text and "unauthenticated" not in response_text:
                            active_verification_results.append(f"Method '{method}' responded successfully. Response: {response_text[:100]}...")

                if active_verification_results:
                    prompt += "\n\nACTIVE VERIFICATION RESULTS:\n" + "\n".join(active_verification_results)
                    prompt += "\nBased on these active verification results, confirm the severity and impact."
        else:
            prompt = f"""
            As an elite security auditor, validate this anomaly:
            Target: {anomaly.target}
            Observation: {anomaly.observation}
            Confidence: {anomaly.confidence}
            Suggested Vector: {anomaly.suggested_vector}
    
            Output ONLY valid raw JSON matching the 'Finding' schema if this is a real vulnerability. Do not wrap the result in a parent key.
            If it is a false positive or low-value noise, return 'null'.
            """

        symbolic_context = ""
        # Perform technical reachability verification for reentrancy anomalies via native CFG
        if ("reentrancy" in anomaly.observation.lower() or "0xf1" in anomaly.observation) and prawn_core:
            bytecode = anomaly.metadata.get("bytecode")
            if bytecode and isinstance(bytecode, str):
                try: # Python string manipulation instead of Rust syntax
                    code = bytecode.replace("0x", "")
                    cfg_json = prawn_core.generate_evm_cfg(bytecode)
                    cfg = json.loads(cfg_json)
                    blocks = cfg.get("blocks", {})
                    
                    reachable_pcs = {0}
                    stack = [0]
                    while stack:
                        curr = stack.pop()
                        b_data = blocks.get(str(curr), {})
                        for succ in b_data.get("successors", []):
                            if succ not in reachable_pcs:
                                reachable_pcs.add(succ)
                                stack.append(succ)
                    
                    # Find reachable blocks containing CALL-like opcodes
                    reachable_calls = []
                    for pc in reachable_pcs:
                        block = blocks.get(str(pc), {})
                        if any(op in ['0xf1', '0xf2', '0xf4'] for op in block.get("instructions", [])):
                            reachable_calls.append(pc)

                    if not reachable_calls:
                        logger.info(f"Judge discarded unreachable reentrancy anomaly at {anomaly.target}")
                        return None

                    # Perform symbolic analysis on the branching logic guarding these calls
                    for call_pc in reachable_calls:
                        # Find predecessors that end in JUMPI (0x57)
                        for b_pc, b_data in blocks.items():
                            if int(call_pc) in b_data.get("successors", []) and "0x57" in b_data.get("instructions", []):
                                jump_pc = b_data.get("end")
                                try:
                                    sym_result = prawn_core.solve_jump_condition(bytecode, jump_pc)
                                    sym_data = json.loads(sym_result)
                                    symbolic_context += f"\n- Guarding Jump at PC {jump_pc}: {sym_data.get('symbolic_values')}"
                                except Exception:
                                    continue

                except Exception as e:
                    logger.debug(f"Judge CFG reachability check failed: {e}")

        # Incorporate ReentrancyGuard metadata from CodeAuditorAgent
        guard_status = anomaly.metadata.get("reentrancy_guard")
        if guard_status:
            symbolic_context += f"\n- Source Code Audit: {guard_status}"

        if symbolic_context:
            prompt += f"\n\nSYMBOLIC EXECUTION CONTEXT:{symbolic_context}\n"
            prompt += "Use the symbolic values above to determine if the path is guarded by a ReentrancyGuard or AccessControl."

        finding = await self.client.generate_structured(prompt, Finding)
        if not finding:
            logger.debug(f"Judge filtered anomaly as noise: {anomaly.target}")
            return None
            
        return finding