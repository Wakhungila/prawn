from __future__ import annotations
import re
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict, field_validator
from datetime import datetime

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FindingType(str, Enum):
    REENTRANCY = "Reentrancy"
    IDOR = "IDOR"
    BUSINESS_LOGIC = "Business Logic Flaw"
    ACCESS_CONTROL = "Broken Access Control"
    ACCOUNT_CONFUSION = "SVM Account Confusion"
    STORAGE_COLLISION = "Storage Collision"
    API_EXPOSURE = "API Data Exposure"
    ZERO_DAY = "0-Day Hypothesis"
    STATIC_ANALYSIS = "Static Analysis Finding"

class Finding(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    
    id: str
    type: FindingType
    severity: Severity
    target: str
    description: str
    evidence: str
    remediation: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    @field_validator('target')
    @classmethod
    def validate_eth_address(cls, v: str) -> str:
        if v.startswith('0x') and len(v) == 42:
            if not re.match(r'^0x[a-fA-F0-9]{40}$', v):
                raise ValueError('Invalid Ethereum address format')
        return v

class Anomaly(BaseModel):
    target: str
    observation: str
    confidence: float = Field(ge=0.0, le=1.0)
    suggested_vector: str

class ResearchHypothesis(BaseModel):
    title: str
    attack_chain: List[str]
    economic_flow: List[str] = Field(..., description="Path of capital or value extraction")
    prerequisites: List[str]
    potential_impact: str
    funds_at_risk_estimate: str = "TBD"

class AgentOutput(BaseModel):
    agent_name: str
    findings: List[Finding] = []
    anomalies: List[Anomaly] = []
    hypotheses: List[ResearchHypothesis] = []
    next_actions: List[str]
    strategic_summary: Optional[str] = None
    boundary_analysis: List[str] = []

class ScanConfig(BaseModel):
    target: str
    output_dir: str
    zero_day_mode: bool = False
    web3_enabled: bool = False
    api_focus: bool = True
    max_recursion_depth: int = 2
    ollama_model: str = "prawn-researcher"
    delta_audit: Optional[str] = None  # e.g. "v1.0.0..HEAD"
    economic_threat_model: bool = True