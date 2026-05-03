import pytest
import json
from prawn.core.models import ScanConfig, Anomaly
from agents.finder import FinderAgent
from agents.judge import JudgeAgent

@pytest.fixture
def config():
    return ScanConfig(
        target="http://localhost:8545",
        output_dir="./test_results",
        web3_enabled=True,
        ollama_model="prawn-researcher"
    )

def test_native_core_import():
    """Verify Rust bindings are correctly installed."""
    import prawn_core
    assert prawn_core.detect_reentrancy_native("0x6001f155") is True

@pytest.mark.asyncio
async def test_finder_evm_discovery(config, mocker):
    """Test Finder's ability to use native core for bytecode anomalies."""
    # Mock the make_request utility to simulate an EVM node
    mock_resp = {
        "success": True, 
        "text": json.dumps({"result": "0x6001f155"}) # Reentrancy pattern
    }
    mocker.patch("agents.finder.make_request", return_value=mock_resp)
    
    finder = FinderAgent(config)
    output = await finder.run(config.target)
    
    assert any("Reentrancy" in a.observation for a in output.anomalies)

@pytest.mark.asyncio
async def test_judge_cfg_validation(config, mocker):
    """Test Judge utilizing native CFG to filter anomalies."""
    import prawn_core
    judge = JudgeAgent(config)
    
    # Anomaly with bytecode that is actually dead code
    anomaly = Anomaly(
        target="0x123",
        observation="Potential reentrancy 0xf1",
        confidence=0.9,
        metadata={"bytecode": "0xfe6001f155"}, # Starts with INVALID (0xfe)
        suggested_vector="reentrancy"
    )
    
    # The Judge should run native CFG and find this is unreachable
    finding = await judge._evaluate_anomaly(anomaly)
    assert finding is None