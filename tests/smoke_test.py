import asyncio
import logging
from core.schemas import ScanConfig
from core.engine import PrawnOrchestrator

logging.basicConfig(level=logging.INFO)

async def main():
    config = ScanConfig(
        target="https://api.github.com", # Replace with a safe local test target
        output_dir="./smoke_results",
        zero_day_mode=True
    )
    
    orchestrator = PrawnOrchestrator(config)
    report = await orchestrator.execute_research()
    print(f"Research Summary: {report.strategic_summary}")

if __name__ == "__main__":
    asyncio.run(main())