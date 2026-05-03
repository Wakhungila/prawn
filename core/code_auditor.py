import logging
import os
from typing import List, Optional
from core.schemas import Finding, AgentOutput, ScanConfig
from core.ollama_client import OllamaClient

logger = logging.getLogger("PRAWN.CodeAuditor")

class CodeAuditorAgent:
    """
    CodeAuditor Agent: Performs contextual static analysis using LLM reasoning.
    Supports Solidity, Go, JavaScript, and Rust.
    """
    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = OllamaClient(config.ollama_model)
        self.max_chunk_size = 12000  # Character limit per chunk
        self.chunk_overlap = 1500    # Overlap to maintain context between chunks
        self.supported_extensions = {
            ".sol": "Solidity",
            ".go": "Go",
            ".js": "JavaScript",
            ".jsx": "JavaScript",
            ".ts": "TypeScript",
            ".rs": "Rust"
        }

    def _chunk_text(self, text: str) -> List[str]:
        """Splits text into overlapping chunks for large file processing."""
        if len(text) <= self.max_chunk_size:
            return [text]
        
        chunks = []
        start = 0
        while start < len(text):
            end = start + self.max_chunk_size
            chunks.append(text[start:end])
            start += (self.max_chunk_size - self.chunk_overlap)
        return chunks

    async def run(self, files: List[str]) -> AgentOutput:
        """
        Runs the audit loop over a list of provided file paths.
        """
        logger.info(f"📄 CodeAuditor initiating audit for {len(files)} files...")
        all_findings = []
        
        for file_path in files:
            if not os.path.exists(file_path):
                logger.warning(f"File not found: {file_path}")
                continue
                
            ext = os.path.splitext(file_path)[1].lower()
            if ext not in self.supported_extensions:
                logger.debug(f"Skipping unsupported file type: {file_path}")
                continue
                
            lang = self.supported_extensions[ext]
            findings = await self.audit_file(file_path, lang)
            all_findings.extend(findings)
            
        summary = f"Code audit completed. Found {len(all_findings)} issues across {len(files)} files."
        logger.info(summary)
        
        return AgentOutput(
            agent_name="CodeAuditor",
            findings=all_findings,
            next_actions=["Pass to Senator"],
            strategic_summary=summary
        )

    async def audit_file(self, file_path: str, language: str) -> List[Finding]:
        """
        Reads a file and consults Ollama for a deep contextual audit.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return []

        chunks = self._chunk_text(code_content)
        file_findings = []
        seen_vulnerabilities = set() # For deduplication

        for i, chunk in enumerate(chunks):
            prompt = f"""
            System: You are an elite security researcher specialized in {language} source code review.
            Task: Audit the provided source code chunk ({i+1}/{len(chunks)}) for vulnerabilities.
            
            Logic Check:
            - Automatically detect and flag 'ReentrancyGuard' implementations or similar state-locking mechanisms. Incorporate this status into the metadata of any reentrancy-related findings.
            
            FILE: {file_path}
            LANGUAGE: {language}
            CODE SEGMENT:
            {chunk}
            
            Output a JSON object matching the 'AgentOutput' schema. 
            Focus on high-impact vulnerabilities. If no issues are found in this chunk, return empty findings.
            """
            
            result = await self.client.generate_structured(prompt, AgentOutput)
            if result and result.findings:
                for finding in result.findings:
                    # Deduplicate based on description and target/line context
                    finding_hash = hash(f"{finding.type}:{finding.description}:{finding.target}")
                    if finding_hash not in seen_vulnerabilities:
                        file_findings.append(finding)
                        seen_vulnerabilities.add(finding_hash)
            
        return file_findings