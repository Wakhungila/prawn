import pytest
import respx
import json
from httpx import Response
from core.judge import JudgeAgent
from core.schemas import ScanConfig, Anomaly, AgentOutput, Severity, FindingType

@pytest.fixture
def scan_config():
    return ScanConfig(
        target="https://target.com",
        output_dir="./results",
        ollama_model="prawn-researcher"
    )

@pytest.fixture
def judge_agent(scan_config):
    return JudgeAgent(scan_config)

@pytest.mark.asyncio
@respx.mock
async def test_judge_evaluate_anomaly_success(judge_agent):
    # Mock Anomaly
    anomaly = Anomaly(
        target="https://target.com/api",
        observation="Unusual latency on large inputs",
        confidence=0.8,
        suggested_vector="Potential Reentrancy"
    )

    # Mock LLM response returning a valid Finding JSON
    mock_finding_data = {
        "id": "FIND-001",
        "type": "Reentrancy",
        "severity": "HIGH",
        "target": "https://target.com/api",
        "description": "Validated reentrancy via latency probe",
        "evidence": "Delay of 500ms observed",
        "remediation": "Implement nonReentrant modifier",
        "metadata": {}
    }
    
    respx.post("http://localhost:11434/api/generate").mock(return_value=Response(200, json={
        "response": json.dumps(mock_finding_data)
    }))

    finding = await judge_agent._evaluate_anomaly(anomaly)
    
    assert finding is not None
    assert finding.type == FindingType.REENTRANCY
    assert finding.severity == Severity.HIGH

@pytest.mark.asyncio
@respx.mock
async def test_judge_evaluate_anomaly_noise(judge_agent):
    anomaly = Anomaly(
        target="https://target.com/api",
        observation="404 on favicon",
        confidence=0.1,
        suggested_vector="Noise"
    )

    # Mock LLM returning 'null' for noise
    respx.post("http://localhost:11434/api/generate").mock(return_value=Response(200, json={
        "response": "null"
    }))

    finding = await judge_agent._evaluate_anomaly(anomaly)
    assert finding is None

@pytest.mark.asyncio
@respx.mock
async def test_judge_run_loop(judge_agent):
    finder_output = AgentOutput(agent_name="Finder", anomalies=[])
    # No anomalies should result in empty findings summary
    output = await judge_agent.run(finder_output)
    assert output.agent_name == "Judge"
    assert len(output.findings) == 0