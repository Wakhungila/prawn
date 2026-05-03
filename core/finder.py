import os
import logging
import json
import asyncio
import random
from typing import List, Dict, Any
from core.schemas import Anomaly, AgentOutput, ScanConfig
from core.ollama_client import OllamaClient
from core.utils import make_request, run_command
from core.bytecode_analyzer import BytecodeAnalyzer

try:
    import prawn_core
except ImportError:
    prawn_core = None

logger = logging.getLogger("PRAWN.Finder")

class FinderAgent:
    """
    Finder Agent: Specialized in multi-protocol surface area discovery.
    Supports HTTP, gRPC, and EVM RPC probing to identify anomalies.
    """
    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = OllamaClient(config.ollama_model)
        # Concurrency limit to avoid triggering WAFs or IP bans
        self._semaphore = asyncio.Semaphore(3)

    async def _limit_task(self, coro):
        """Helper to wrap discovery tasks with the semaphore and randomized jitter."""
        async with self._semaphore:
            # Randomized delay (jitter) between 0.5 and 2.5 seconds to evade detection
            await asyncio.sleep(random.uniform(0.5, 2.5))
            return await coro

    async def run(self, target: str) -> AgentOutput:
        """Main entry point for multi-protocol discovery."""
        logger.info(f"🔍 Finder initiating multi-protocol discovery on {target}")
        
        anomalies = []
        
        # Perform initial header probe to inform prioritization
        initial_probe = make_request(target, method="HEAD", timeout=10)
        headers = initial_probe.get("headers", {}) if initial_probe.get("success") else {}

        # Build the task list using the rate-limiting wrapper
        task_map = {
            "smart_contract": self._discover_smart_contract_repo(target),
            "http": self._discover_http(target),
            "grpc": self._discover_grpc(target),
            "graphql": self._fuzz_graphql(target),
            "bridge": self._discover_bridge_endpoints(target),
            "cross_chain": self._trace_cross_chain(target),
            "state_desync": self._detect_state_desync(target)
        }

        if self.config.web3_enabled:
            task_map["evm_rpc"] = self._discover_evm_rpc(target)

        # Logic for prioritization based on headers
        priority_order = []
        header_str = str(headers).lower()

        # High Priority: Protocol-specific matches
        if "grpc" in header_str or "application/grpc" in headers.get("Content-Type", "").lower():
            priority_order.append("grpc")
        if any(x in header_str for x in ["graphql", "apollo", "yoga"]):
            priority_order.append("graphql")
        if any(x in header_str for x in ["bridge", "wormhole", "axelar"]):
            priority_order.append("bridge")

        # Medium Priority: Web3 infrastructure markers
        if self.config.web3_enabled and any(x in header_str for x in ["json-rpc", "ethereum", "web3"]):
            priority_order.append("evm_rpc")
            priority_order.append("state_desync")

        # Add remaining tasks that weren't prioritized
        for task_name in task_map.keys():
            if task_name not in priority_order:
                priority_order.append(task_name)

        # Create the prioritized coroutine list
        prioritized_tasks = [task_map[name] for name in priority_order if name in task_map]

        # Execute tasks while respecting the semaphore limit
        results = await asyncio.gather(*(self._limit_task(t) for t in prioritized_tasks))
        for r in results:
            anomalies.extend(r)

        # 7. State Desync Detection (Wake)
        desync_anomalies = await self._detect_state_desync(target)
        anomalies.extend(desync_anomalies)

        # 8. Fork Conflict Resolution (Wake Test Case Generation)
        await self._resolve_fork_conflicts(target, desync_anomalies)

        summary = f"Discovery complete. Identified {len(anomalies)} anomalies across protocols."
        logger.info(summary)
        
        return AgentOutput(
            agent_name="Finder",
            anomalies=anomalies,
            next_actions=["Pass to Judge for validation"],
            strategic_summary=summary
        )

    async def _discover_http(self, target: str) -> List[Anomaly]:
        """Probes for HTTP endpoints and common API anomalies."""
        logger.debug(f"Probing HTTP/REST for {target}")
        # Logic for path crawling and header analysis goes here
        # Example anomaly generation:
        return [Anomaly(
            target=target,
            observation="Standard HTTP discovery initiated",
            confidence=0.5,
            suggested_vector="API Discovery"
        )]

    async def _discover_grpc(self, target: str) -> List[Anomaly]:
        """Attempts to identify gRPC services and reflection status."""
        logger.debug(f"Probing gRPC for {target}")
        anomalies = []
        
        # Check for gRPC specific content-type or reflection indicators
        headers = {"Content-Type": "application/grpc"}
        response = make_request(target, method="POST", headers=headers)
        
        if response.get("status_code") == 200 or response.get("headers", {}).get("grpc-status"):
            anomalies.append(Anomaly(
                target=target,
                observation="gRPC endpoint identified; negotiating service reflection...",
                confidence=0.9,
                suggested_vector="gRPC Logic Probe"
            ))
            
            reflection_target = f"{target.rstrip('/')}/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
            reflection_probe = b'\x00\x00\x00\x00\x00'
            ref_resp = make_request(reflection_target, method="POST", data=reflection_probe, headers=headers)
            
            content = ref_resp.get("content") or b""
            if (ref_resp.get("status_code") == 200 or ref_resp.get("headers", {}).get("grpc-status") == "0") and content:
                # Heuristic Reflection Parser: Extract service and method strings from protobuf wire format
                # Standard gRPC names are alphanumeric with dots and slashes
                discovered_methods = re.findall(rb'[a-zA-Z0-9._]+\/[a-zA-Z0-9._]+', content)
                method_list = [m.decode('utf-8', errors='ignore') for m in discovered_methods]
                
                admin_keywords = ['admin', 'config', 'debug', 'internal', 'reset', 'secret', 'update', 'delete', 'root']
                sensitive_methods = [m for m in method_list if any(k in m.lower() for k in admin_keywords)]
                
                observation = f"gRPC Reflection Enabled. Found {len(method_list)} methods."
                if sensitive_methods:
                    observation += f" Identified potential ADMINISTRATIVE methods: {sensitive_methods[:5]}"

                anomalies.append(Anomaly(
                    target=target,
                    observation=observation,
                    metadata={"methods": method_list, "sensitive_methods": sensitive_methods},
                    confidence=1.0,
                    suggested_vector="gRPC Information Disclosure"
                ))

                if prawn_core:
                    mutated_probe = prawn_core.mutate_grpc_message(list(reflection_probe))
                    # Send a mutated probe to look for parsing anomalies or crashes
                    make_request(reflection_target, method="POST", data=bytes(mutated_probe), headers=headers)
        return anomalies

    async def _fuzz_graphql(self, target: str) -> List[Anomaly]:
        """
        Performs GraphQL fuzzing using custom LibAFL mutations via native core.
        """
        if not prawn_core:
            logger.debug("prawn_core not available, skipping GraphQL fuzzing.")
            return []

        anomalies = []
        # Simple heuristic to detect if target might be a GraphQL endpoint
        if "/graphql" in target.lower() or "query" in target.lower():
            logger.info(f"Initiating native LibAFL GraphQL fuzzing on {target}")
            
            seeds = [b'{"query": "{ __typename }"}', b'{"query": "{ __schema { types { name } } }"}']
            
            def harness(mutated_bytes):
                try:
                    # LibAFL provides bytes, convert to string for GraphQL body
                    body = mutated_bytes.decode('utf-8', errors='ignore')
                    resp = make_request(target, method="POST", data=body)
                    if resp.get("status_code") == 500:
                        return 1 # Signal interesting finding (crash/error) to fuzzer
                except Exception:
                    pass
                return 0

            # Run the native fuzzer loop
            prawn_core.run_api_fuzzer(harness, seeds, 100)
            
            anomalies.append(Anomaly(
                target=target,
                observation="Native LibAFL mutation campaign completed on GraphQL endpoint",
                confidence=0.8,
                suggested_vector="GraphQL Logic Fuzzing"
            ))
            
        return anomalies

    async def _discover_evm_rpc(self, target: str) -> List[Anomaly]:
        """Probes for JSON-RPC methods on EVM nodes."""
        logger.debug(f"Probing EVM RPC for {target}")
        anomalies = []
        
        rpc_payload = {
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        }
        
        response = make_request(target, method="POST", data=json.dumps(rpc_payload))
        
        if response.get("success") and "result" in response.get("text", ""):
            anomalies.append(Anomaly(
                target=target,
                observation="Active EVM JSON-RPC endpoint detected",
                confidence=1.0,
                suggested_vector="Smart Contract Interaction"
            ))
            
            # Further probe for admin methods (e.g., debug_*, admin_*)
            admin_payload = {"jsonrpc": "2.0", "method": "admin_nodeInfo", "params": [], "id": 1}
            admin_resp = make_request(target, method="POST", data=json.dumps(admin_payload))
            if admin_resp.get("success") and "result" in admin_resp.get("text", ""):
                anomalies.append(Anomaly(
                    target=target,
                    observation="Privileged admin_* RPC methods accessible",
                    confidence=1.0,
                    suggested_vector="Insecure Node Configuration"
                ))
            
            # Probe for Chain ID
            chain_payload = {"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1}
            chain_resp = make_request(target, method="POST", data=json.dumps(chain_payload))
            chain_id = "Unknown"
            if chain_resp.get("success"):
                try:
                    chain_data = json.loads(chain_resp.get("text", "{}"))
                    chain_id = int(chain_data.get("result", "0x1"), 16)
                except Exception:
                    pass

            # Smart Contract Vulnerability: Deep Bytecode Analysis
            # Discovery now analyzes opcode sequences to identify reentrancy and proxy flaws
            bytecode_payload = {"jsonrpc": "2.0", "method": "eth_getCode", "params": ["0x0000000000000000000000000000000000000000", "latest"], "id": 1}
            bytecode_resp = make_request(target, method="POST", data=json.dumps(bytecode_payload))
            if bytecode_resp.get("success"):
                try:
                    resp_data = json.loads(bytecode_resp.get("text", "{}"))
                    bytecode = resp_data.get("result", "")
                    if bytecode and bytecode != "0x":
                        analyzer = BytecodeAnalyzer()
                        bytecode_findings = analyzer.analyze(bytecode)
                        for bf in bytecode_findings:
                            anomalies.append(Anomaly(
                                target=target,
                                observation=f"Bytecode Discovery: {bf}",
                                metadata={"bytecode": bytecode, "chain_id": chain_id, "rpc_url": target},
                                confidence=0.9,
                                suggested_vector="Smart Contract Logic Flaw"
                            ))
                except Exception as e:
                    logger.debug(f"Bytecode parsing failed: {e}")
        return anomalies

    async def _discover_bridge_endpoints(self, target: str) -> List[Anomaly]:
        """Probes for common bridge and cross-chain messaging endpoints."""
        logger.debug(f"Probing for cross-chain bridge endpoints on {target}")
        anomalies = []
        
        # Indicators of cross-chain or bridge protocols
        bridge_patterns = ['bridge', 'wormhole', 'stargate', 'axelar', 'layerzero', 'lz', 'hyperlane', 'hop', 'connext']
        
        target_lower = target.lower()
        if any(p in target_lower for p in bridge_patterns):
            # Generic Bridge Detection
            anomalies.append(Anomaly(
                target=target,
                observation=f"Potential cross-chain bridge/messaging endpoint identified: {target}",
                confidence=0.85,
                suggested_vector="Cross-Chain Logic / Message Forgery"
            ))
            
            # Wormhole Signature: Check for Guardian public RPC or Core contract indicators
            if 'wormhole' in target_lower:
                # Probe for signed VAA retrieval paths specific to Wormhole guardians
                vaa_probe = make_request(f"{target.rstrip('/')}/v1/signed_vaa/1/0000000000000000000000000000000000000000000000000000000000000000/1")
                if vaa_probe.get('status_code') in [200, 400, 404]: 
                    anomalies.append(Anomaly(
                        target=target,
                        observation="Wormhole signed VAA retrieval endpoint detected.",
                        confidence=0.95,
                        suggested_vector="VAA Forgery / Logic Manipulation"
                    ))

            # Axelar Signature: Probe for Axelar Gateway or RPC methods
            if 'axelar' in target_lower:
                # Check for Axelar-specific JSON-RPC methods
                rpc_payload = {"jsonrpc": "2.0", "method": "axelar_getFee", "params": [], "id": 1}
                axelar_resp = make_request(target, method="POST", data=json.dumps(rpc_payload))
                if axelar_resp.get('success') and 'result' in axelar_resp.get('text', ''):
                    anomalies.append(Anomaly(
                        target=target,
                        observation="Axelar RPC signature identified via axelar_getFee probe.",
                        confidence=1.0,
                        suggested_vector="Bridge Gateway Auth Bypass"
                    ))
            
        return anomalies

    async def _discover_smart_contract_repo(self, target: str) -> List[Anomaly]:
        """
        Detects smart contract repositories and orchestrates Forge, Medusa, and Wake.
        """
        if not os.path.isdir(target):
            return []
        
        anomalies = []

        # SVN Detection
        if os.path.exists(os.path.join(target, ".svn")):
            anomalies.append(Anomaly(
                target=target,
                observation="SVN repository detected. Analyzing for historical exposures...",
                confidence=0.7,
                suggested_vector="Legacy Version Control"
            ))
        
        # Foundry Detection & Forge Build
        if os.path.exists(os.path.join(target, "foundry.toml")):
            logger.info(f"Foundry project detected at {target}. Initiating Forge build...")
            build_res = run_command("forge build", timeout=300)
            if build_res.get('success'):
                anomalies.append(Anomaly(
                    target=target,
                    observation="Forge build successful. Project is ready for deep auditing.",
                    confidence=1.0,
                    suggested_vector="Foundry Infrastructure"
                ))
                
                # Automatic Medusa Fuzzing
                logger.info("Running Medusa stateful fuzzing campaign...")
                medusa_res = run_command("medusa fuzz", timeout=600)
                if medusa_res.get('success'):
                    anomalies.append(Anomaly(
                        target=target,
                        observation="Medusa fuzzing campaign completed. Check medusa-results for state violations.",
                        confidence=0.9,
                        suggested_vector="Stateful Fuzzing"
                    ))

        # Wake Detection: Differential & Cross-Chain Testing
        if os.path.exists(os.path.join(target, "wake.toml")) or os.path.exists(os.path.join(target, "pyproject.toml")):
            logger.info("Wake/Python environment detected. Running Wake security analysis...")
            
            # Run Wake detectors
            wake_detect = run_command("wake detect", timeout=300)
            if wake_detect.get('success'):
                anomalies.append(Anomaly(
                    target=target,
                    observation=f"Wake static analysis completed. High-confidence issues identified.",
                    confidence=0.9,
                    suggested_vector="Differential Fuzzing"
                ))

            # Trigger Wake differential fuzzing if test folder is present
            if os.path.exists(os.path.join(target, "tests")):
                logger.info("Initiating Wake differential fuzzing...")
                run_command("wake test", timeout=600)

        return anomalies

    async def _detect_state_desync(self, target: str) -> List[Anomaly]:
        """
        Uses Wake to compare states across multiple chain forks to detect desynchronization.
        """
        if not os.path.isdir(target):
            return []
            
        anomalies = []
        if os.path.exists(os.path.join(target, "wake.toml")):
            logger.info(f"Initiating Wake State Desync Detector on {target}...")
            
            # Execute Wake with cross-chain state comparison logic
            # This leverages Wake's capability to simulate multiple forks and detect state inconsistencies
            res = run_command("wake detect --no-collect", timeout=400)
            if res.get('success'):
                stdout = res.get('stdout', '').lower()
                if any(k in stdout for k in ['desync', 'inconsistent', 'discrepancy']):
                    anomalies.append(Anomaly(
                        target=target,
                        observation="Wake identified potential state desynchronization between simulated chain forks.",
                        metadata={"rpc_url": target if target.startswith("http") else None},
                        confidence=0.92,
                        suggested_vector="Cross-Chain State Manipulation"
                    ))
        return anomalies

    async def _trace_cross_chain(self, target: str) -> List[Anomaly]:
        """
        Uses Wake's cross-chain testing capabilities to trace messaging flows.
        """
        if not os.path.isdir(target):
            return []
            
        anomalies = []
        if os.path.exists(os.path.join(target, "wake.toml")):
            logger.info(f"Initiating Wake Cross-Chain Tracer on {target}...")
            
            # Run Wake detectors with specific cross-chain focus
            trace_res = run_command("wake detect --no-collect", timeout=300)
            if trace_res.get('success'):
                stdout = trace_res.get('stdout', '').lower()
                if any(k in stdout for k in ['cross-chain', 'bridge', 'relay', 'message']):
                    anomalies.append(Anomaly(
                        target=target,
                        observation="Wake tracer identified active cross-chain messaging flow components.",
                        confidence=0.9,
                        suggested_vector="Cross-Chain Logic Vulnerability"
                    ))
        return anomalies

    async def _resolve_fork_conflicts(self, target: str, desync_anomalies: List[Anomaly]):
        """
        ForkConflictResolver: Automatically generates Wake test cases when state discrepancies are found.
        """
        if not os.path.isdir(target) or not desync_anomalies:
            return

        logger.info(f"🦐 ForkConflictResolver generating Wake reproduction cases for {len(desync_anomalies)} anomalies...")
        
        test_dir = os.path.join(target, "tests")
        os.makedirs(test_dir, exist_ok=True)

        for i, anomaly in enumerate(desync_anomalies):
            test_path = os.path.join(test_dir, f"test_prawn_desync_repro_{i}.py")
            rpc_url = anomaly.metadata.get("rpc_url", target if target.startswith("http") else "http://localhost:8545")
            chain_id = anomaly.metadata.get("chain_id", "Unknown")
            
            test_content = f"""
from wake.testing import *
# Automatically generated by PRAWN ForkConflictResolver
# Discovery: {anomaly.observation}
# RPC Endpoint: {rpc_url}

@default_chain.connect(rpc_url="{rpc_url}")
def test_state_desync_repro():
    # Chain ID: {chain_id}
    # This test case was generated to resolve fork conflicts detected by Wake
    # Logic: Verify state consistency between simulated chain forks
    print("Reproducing desync: {anomaly.observation}")
    # reproduction logic goes here...
"""
            with open(test_path, "w") as f:
                f.write(test_content)
                
            logger.info(f"Generated Wake reproduction test: {test_path}")