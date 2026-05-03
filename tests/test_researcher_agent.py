import pytest
import os
import sys
from unittest.mock import MagicMock

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.schemas import AgentOutput, Finding, FindingType, Anomaly, Severity, ScanConfig, ResearchHypothesis
from core.researcher import ResearcherAgent

@pytest.fixture
def scan_config():
    return ScanConfig(
        target="https://defi-bridge.io",
        output_dir="./test_results",
        zero_day_mode=True
    )

@pytest.fixture
def researcher_agent(scan_config):
    return ResearcherAgent(scan_config)

@pytest.mark.asyncio
async def test_analyze_cross_chain_vectors_detection(researcher_agent):
    """
    Test that ResearcherAgent correctly correlates EVM findings with bridge anomalies.
    """
    # Create mock findings (EVM logic flaw)
    mock_findings = [
        Finding(
            id="FIND-101",
            type=FindingType.REENTRANCY,
            severity=Severity.HIGH,
            target="0xSourceContract",
            description="Reentrancy vector in message emission",
            evidence="...",
            remediation="..."
        )
    ]
    
    # Create mock anomalies (Bridge/Gateway keyword match)
    mock_anomalies = [
        Anomaly(
            target="https://layerzero-gateway.local",
            observation="Unauthenticated relay access detected",
            confidence=0.9,
            suggested_vector="Bridge Exploitation"
        )
    ]
    
    output = AgentOutput(
        agent_name="Judge",
        findings=mock_findings,
        anomalies=mock_anomalies,
        next_actions=[]
    )
    
    hypotheses = await researcher_agent._analyze_cross_chain_vectors(output)
    
    assert len(hypotheses) == 1
    assert hypotheses[0].title == "Cross-Chain State Desynchronization via Logic Mutation"
    assert "Reentrancy" in hypotheses[0].attack_chain[0]

@pytest.mark.asyncio
async def test_analyze_cross_chain_vectors_no_correlation(researcher_agent):
    """
    Test that no hypothesis is generated when correlation factors are missing.
    """
    output = AgentOutput(
        agent_name="Judge",
        findings=[],
        anomalies=[
            Anomaly(
                target="https://api.standard.com",
                observation="Information disclosure in headers",
                confidence=0.5,
                suggested_vector="Recon"
            )
        ],
        next_actions=[]
    )
    
    hypotheses = await researcher_agent._analyze_cross_chain_vectors(output)
    assert len(hypotheses) == 0